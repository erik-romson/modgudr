"""`mg-hook` (M20): what it blocks, what it allows, and how it fails.

The hook is fed PreToolUse JSON as strings; the commands in them are never executed. The target
list comes from a stub server on a temporary `agent.sock`; `TMPDIR` is a temporary directory.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from modgudr.client.agent import hook
from tests.support.stubbroker import StubBroker

HOST = "db-test.example.net"
TARGETS = {
    "targets": [
        {"name": "ora-test", "destinations": [f"{HOST}:1521", "[::1]:1522"]},
        {"name": "aks-test", "destinations": []},
    ]
}


class Setup:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.socket = root / "a.sock"
        self.tmp = root / "tmp"
        self.tmp.mkdir()
        self.clock = 1_000_000.0

    @property
    def environ(self) -> dict[str, str]:
        return {"MODGUDR_SOCKET": str(self.socket), "TMPDIR": str(self.tmp)}

    def broker(self, *, silent: bool = False) -> StubBroker:
        return StubBroker(self.socket, {"targets": TARGETS}, silent=silent)

    def run(self, command: str) -> tuple[int, str]:
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
        return self.feed(payload)

    def feed(self, payload: str) -> tuple[int, str]:
        err = io.StringIO()
        code = hook.main(
            stdin=io.StringIO(payload),
            stderr=err,
            environ=self.environ,
            now=lambda: self.clock,
        )
        return code, err.getvalue()


@pytest.fixture
def setup(shortdir: Path) -> Setup:
    return Setup(shortdir)


BLOCKED = [
    "kubectl get pods",
    "/usr/local/bin/kubectl x",
    "sudo kubectl x",
    "sudo -u root kubectl x",
    "env X=1 kubectl x",
    "env -i X=1 kubectl x",
    "timeout 5 kubectl x",
    "timeout -s KILL 5 kubectl x",
    "nice -n 5 kubectl x",
    "nohup kubectl x",
    "stdbuf -oL kubectl x",
    "xargs -n 1 kubectl x",
    "time kubectl x",
    "command kubectl x",
    "FOO=1 BAR=2 kubectl x",
    "cd x && kubectl y",
    "cd x; kubectl y",
    "false || kubectl y",
    "echo a | kubectl y",
    "echo a & kubectl y",
    "echo a\nkubectl y",
    "echo $(kubectl get pods)",
    'echo "$(kubectl get pods)"',
    "echo `kubectl get pods`",
    "'kubectl' get pods",
    "\\kubectl get pods",
    "az account show",
    "kubelogin get-token",
    "sqlplus u/p@db",
    "sql u/p@db",
    "snowsql -a x",
    "snow sql -q x",
    "bw unlock",
    "bws secret list",
    "security find-generic-password -s x",
    f"curl https://{HOST}/",
    f"curl -s -H 'X: y' https://user:pw@{HOST}:1521/x?y=1",
    f"wget http://{HOST}/",
    f"http GET {HOST}/path",
    f"curl --url=https://{HOST}/",
    "curl http://[::1]:1522/",
]

ALLOWED = [
    'echo "a; kubectl"',
    'git commit -m "fix kubectl && retry"',
    "grep kubectl README",
    "which kubectl",
    "command -v kubectl",
    "brew install kubectl",
    "modgudr targets",
    "modgudr aks-test kubectl get pods",
    "curl https://example.com",
    "ls",
    "echo 'kubectl' # kubectl",
    "echo 2>&1 done",
    'echo "$(date)" kubectl',
    "FOO=kubectl true",
    "",
]


@pytest.mark.parametrize("command", BLOCKED)
def test_blocks(setup: Setup, command: str) -> None:
    with setup.broker():
        code, message = setup.run(command)
    assert code == 2, command
    assert "modgudr targets" in message and "modgudr <target>" in message
    assert message.count("\n") == 1


@pytest.mark.parametrize("command", ALLOWED)
def test_allows(setup: Setup, command: str) -> None:
    with setup.broker():
        code, message = setup.run(command)
    assert (code, message) == (0, ""), command


def test_the_message_names_the_tool_and_the_host(setup: Setup) -> None:
    with setup.broker():
        assert "`kubectl`" in setup.run("kubectl x")[1]
        assert HOST in setup.run(f"curl https://{HOST}/")[1]


def test_static_blocks_work_with_the_broker_down(setup: Setup) -> None:
    code, message = setup.run("sudo kubectl x")
    assert code == 2 and "modgudr targets" in message


def test_the_host_check_is_skipped_with_the_broker_down(setup: Setup) -> None:
    assert setup.run(f"curl https://{HOST}/") == (0, "")
    assert not list(setup.tmp.iterdir())  # nothing cached from a failed fetch


def test_a_hung_broker_costs_at_most_the_timeout(setup: Setup) -> None:
    with setup.broker(silent=True):
        started = time.monotonic()
        result = setup.run(f"curl https://{HOST}/")
        elapsed = time.monotonic() - started
    assert result == (0, "")
    assert elapsed < 2


def test_an_error_answer_skips_the_host_check(setup: Setup) -> None:
    with StubBroker(setup.socket, {}):
        assert setup.run(f"curl https://{HOST}/") == (0, "")


def test_the_targets_are_cached_for_30_seconds_in_a_0600_file(setup: Setup) -> None:
    broker = setup.broker()
    with broker:
        assert setup.run(f"curl https://{HOST}/")[0] == 2
        assert broker.ops == ["targets"]
        (cache,) = list(setup.tmp.iterdir())
        assert cache.stat().st_mode & 0o777 == 0o600
        assert json.loads(cache.read_text())["hosts"] == ["::1", HOST]
        assert setup.run(f"curl https://{HOST}/")[0] == 2
        assert broker.ops == ["targets"]  # served from the cache
        setup.clock += 29
        assert setup.run(f"curl https://{HOST}/")[0] == 2
        assert broker.ops == ["targets"]
        setup.clock += 2
        assert setup.run(f"curl https://{HOST}/")[0] == 2
        assert broker.ops == ["targets", "targets"]


def test_the_cache_serves_when_the_broker_is_gone(setup: Setup) -> None:
    with setup.broker():
        assert setup.run(f"curl https://{HOST}/")[0] == 2
    assert setup.run(f"curl https://{HOST}/")[0] == 2
    setup.clock += 31
    assert setup.run(f"curl https://{HOST}/") == (0, "")


def test_a_cache_file_that_others_can_write_is_ignored(setup: Setup) -> None:
    cache = setup.tmp / f"modgudr-hook-{os.getuid()}.json"
    cache.write_text(json.dumps({"ts": setup.clock, "hosts": [HOST]}))
    cache.chmod(0o666)
    assert setup.run(f"curl https://{HOST}/") == (0, "")


def test_a_symlinked_cache_is_ignored(setup: Setup) -> None:
    real = setup.root / "real.json"
    real.write_text(json.dumps({"ts": setup.clock, "hosts": [HOST]}))
    real.chmod(0o600)
    (setup.tmp / f"modgudr-hook-{os.getuid()}.json").symlink_to(real)
    assert setup.run(f"curl https://{HOST}/") == (0, "")


@pytest.mark.parametrize("payload", ["", "not json", "{", "\x00"])
def test_garbage_stdin_allows_with_one_line(setup: Setup, payload: str) -> None:
    code, message = setup.feed(payload)
    assert code == 0
    assert message.count("\n") == 1 and message.startswith("mg-hook:")


@pytest.mark.parametrize(
    "payload",
    [
        "[]",
        "{}",
        '{"tool_input": []}',
        '{"tool_input": {"command": 5}}',
        '{"tool_input": {"file_path": "x"}}',
    ],
)
def test_input_without_a_command_is_allowed(setup: Setup, payload: str) -> None:
    assert setup.feed(payload) == (0, "")


def test_an_internal_error_allows_with_one_line(
    setup: Setup, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(command: str, hosts: object) -> str:
        raise RuntimeError("injected")

    monkeypatch.setattr(hook, "decide", boom)
    code, message = setup.run("kubectl x")
    assert code == 0
    assert message == "mg-hook: internal error (RuntimeError: injected); allowing\n"


def test_split_commands() -> None:
    assert hook.split_commands('a "b c" ; d && e || f | g & h') == [
        ["a", "b c"],
        ["d"],
        ["e"],
        ["f"],
        ["g"],
        ["h"],
    ]
    assert hook.split_commands("echo '$(x)' \"it's\" 'a\"b'") == [["echo", "$(x)", "it's", 'a"b']]
    # A substitution is its own command; the enclosing command resumes after it.
    assert hook.split_commands("echo $(a b) c") == [["a", "b"], ["echo", "", "c"]]
    assert hook.split_commands("a `b c` d") == [["b", "c"], ["a", "", "d"]]
    assert hook.split_commands("a # b\nc") == [["a"], ["c"]]


def test_the_script_runs_under_isolated_python(setup: Setup) -> None:
    env = {"MODGUDR_SOCKET": str(setup.socket), "TMPDIR": str(setup.tmp)}
    payload = json.dumps({"tool_input": {"command": "kubectl get pods"}})
    done = subprocess.run(
        [sys.executable, "-I", hook.__file__],
        input=payload,
        capture_output=True,
        text=True,
        env=env,
        timeout=20,
        check=False,
    )
    assert done.returncode == 2
    assert "modgudr targets" in done.stderr
    done = subprocess.run(
        [sys.executable, "-I", hook.__file__],
        input=json.dumps({"tool_input": {"command": "ls"}}),
        capture_output=True,
        text=True,
        env=env,
        timeout=20,
        check=False,
    )
    assert (done.returncode, done.stderr) == (0, "")
