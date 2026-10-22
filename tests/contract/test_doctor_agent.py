"""`modgudr doctor --agent claude` against a real in-process broker and the fake `claude`.

`PATH` is built by `fakebin` (`<bin>:/usr/bin:/bin`), so the real `claude` is unreachable. The
probe of the `run-probe` scenario runs for real, against a temporary `HOME` and the test broker's
own sockets; `security` and `launchctl` are fakes as well.
"""

from __future__ import annotations

import hashlib
import io
import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from modgudr.client.agent import doctor, probe
from modgudr.client.agent.doctor import Context, claude_command, run_agent_doctor
from modgudr.client.errors import CannotRun
from tests.support.brokerfx import RootFstat
from tests.support.brokerthread import BrokerThread, cli_environ, run_cli
from tests.support.fakebin import FakeBin, clean_environ
from tests.support.shortdir import make_shortdir

EXPECTED_KEYS = {
    "PATH",
    "HOME",
    "TERM",
    "MODGUDR_SOCKET",
    "MODGUDR_SESSION",
    "KUBECONFIG",
    "AZURE_CONFIG_DIR",
    "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB",
}
#: Added by the operating system or by the fake's interpreter (locale coercion sets LC_CTYPE in a
#: C locale), not by the client.
SYSTEM_KEYS = {"__CF_USER_TEXT_ENCODING", "LC_CTYPE"}


class Setup:
    def __init__(
        self, served: BrokerThread, fake: FakeBin, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self.served = served
        self.fake = fake
        self.root = served.env.root
        self.user = self.root / "u"
        (self.user / ".azure").mkdir()
        (self.user / ".azure" / "msal_token_cache.json").write_text("{}")
        (self.user / ".zshrc").write_text("# mine\n")
        monkeypatch.setenv("MODGUDR_SOCKET", str(served.env.agent_socket))
        self.dropin = served.env.settings_dir / "50-test.json"
        self.dropin.parent.mkdir(parents=True)
        self.dropin.write_text('{"testSettings": true}\n')

    def scenario(self, mode: str) -> None:
        self.fake.set_scenario({"claude": {"mode": mode}})

    def environ(self, **extra: str) -> dict[str, str]:
        return clean_environ(
            self.fake,
            self.user,
            TERM="xterm",
            MODGUDR_SOCKET=str(self.served.env.agent_socket),
            PGPASSWORD="pg-secret",
            GH_TOKEN="gh-secret",
            KUBECONFIG=str(self.user / ".kube" / "config"),
            MODGUDR_ENV="prod",
            **extra,
        )

    def context(self) -> Context:
        return Context(
            user_home=str(self.user),
            managed_base=self.served.env.settings_base,
            managed_dir=self.served.env.settings_dir,
            fstat=RootFstat(),
        )

    def run(self, *, environ: dict[str, str] | None = None) -> tuple[int, str]:
        out = io.StringIO()
        code = run_agent_doctor(
            self.context(),
            environ=environ if environ is not None else self.environ(),
            reach=lambda _host, _port: False,
            timeout=60.0,
            out=out,
        )
        return code, out.getvalue()


@pytest.fixture
def setup(served: BrokerThread, fakebin: FakeBin, monkeypatch: pytest.MonkeyPatch) -> Setup:
    return Setup(served, fakebin, monkeypatch)


def status_of(setup: Setup) -> dict[str, Any]:
    return doctor.fetch_meta("status")


def probe_files(setup: Setup) -> list[Path]:
    return list(setup.user.glob(f"{probe.PROBE_PREFIX}*"))


def test_run_probe_finds_the_unsandboxed_probe_reachable(setup: Setup) -> None:
    setup.scenario("run-probe")
    code, out = setup.run()
    assert code == 1
    status = status_of(setup)
    azure = str(setup.user / ".azure")
    assert f"FAIL REACHABLE  read {azure}" in out
    assert f"FAIL REACHABLE  read {status['home']}" in out
    assert "FAIL REACHABLE  connect human.sock" in out
    assert "FAIL REACHABLE  create a file in $HOME" in out
    assert "FAIL REACHABLE  append to ~/.zshrc" in out
    assert "OK   REACHABLE  connect agent.sock" in out
    assert not probe_files(setup)  # the persistence probe file is removed afterwards
    assert (setup.user / ".zshrc").read_text() == "# mine\n"
    assert "doctor --agent:" in out and "failed" in out
    if status["platform"] == "darwin":
        assert "WARN REACHABLE  security find-generic-password" in out
        assert len(setup.fake.entries("security")) == 1
        assert len(setup.fake.entries("launchctl")) == 1


def test_all_blocked_passes_and_records_what_it_tested(setup: Setup) -> None:
    setup.scenario("all-blocked")
    code, out = setup.run()
    assert code == 0, out
    digest = hashlib.sha256(setup.dropin.read_bytes()).hexdigest()
    assert f"{digest}  {setup.dropin}" in out
    assert "OK   REACHABLE  connect agent.sock" in out
    assert "OK   BLOCKED    connect human.sock" in out
    assert "tokens" in out  # the announcement
    (entry,) = setup.fake.entries("claude")
    status = status_of(setup)
    spec = entry["probe_input"]
    # The sockets and the home are exactly what the broker reports, never recomputed.
    assert spec["agentSocket"] == status["agentSocket"]
    assert spec["humanSocket"] == status["humanSocket"]
    assert spec["home"] == status["home"]
    assert not status["home"].endswith("/.modgudr")  # a non-default home
    assert status["home"] in spec["credentialPaths"]
    assert str(setup.user / ".azure") in spec["credentialPaths"]
    assert spec["persistenceHome"] == str(setup.user)
    assert entry["argv"] == claude_command("claude")[1:]
    assert Path(entry["cwd"]).name.startswith("mg-doctor-")
    assert not Path(entry["cwd"]).exists()  # the work directory is removed


def test_the_child_environment_is_the_m21_allowlist(setup: Setup) -> None:
    setup.scenario("all-blocked")
    code, _ = setup.run()
    assert code == 0
    (entry,) = setup.fake.entries("claude")
    env = {k: v for k, v in entry["env"].items() if k not in SYSTEM_KEYS}
    assert set(env) == EXPECTED_KEYS
    assert env["KUBECONFIG"] == "/dev/null"
    assert env["CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"] == "1"
    assert env["MODGUDR_SOCKET"] == str(setup.served.env.agent_socket)
    assert env["PATH"] == setup.fake.path_env()
    assert "PGPASSWORD" not in env and "GH_TOKEN" not in env and "MODGUDR_ENV" not in env
    assert not Path(env["AZURE_CONFIG_DIR"]).exists()  # an empty temporary directory, removed


def test_a_target_the_doctor_cannot_reach_is_not_tested(setup: Setup) -> None:
    setup.scenario("all-blocked")
    code, out = setup.run()
    assert code == 0
    assert "WARN NOT_TESTED tcp echo.example.net:7000" in out


@pytest.mark.parametrize(
    ("mode", "expected"),
    [("no-probe", "inconclusive"), ("not-logged-in", "not logged in")],
)
def test_no_verdict_is_69(setup: Setup, mode: str, expected: str) -> None:
    setup.scenario(mode)
    with pytest.raises(CannotRun) as caught:
        setup.run()
    assert caught.value.exit_code == 69
    assert expected in caught.value.message
    assert not probe_files(setup)


def test_claude_missing_is_69(setup: Setup) -> None:
    empty = make_shortdir()
    try:
        with pytest.raises(CannotRun) as caught:
            setup.run(environ=setup.environ(PATH=empty))
        assert caught.value.exit_code == 69 and "claude" in caught.value.message
        assert not setup.fake.entries()
    finally:
        shutil.rmtree(empty, ignore_errors=True)


def test_a_broker_that_is_down_is_69(setup: Setup, monkeypatch: pytest.MonkeyPatch) -> None:
    setup.scenario("all-blocked")
    monkeypatch.setenv("MODGUDR_SOCKET", str(setup.root / "nowhere.sock"))
    with pytest.raises(CannotRun) as caught:
        setup.run()
    assert caught.value.exit_code == 69 and "broker" in caught.value.message
    assert not setup.fake.entries()


def test_the_cli_exits_69_without_claude(served: BrokerThread) -> None:
    empty = make_shortdir()
    try:
        environ = cli_environ(served.env, PATH=empty)
        for args in (("doctor", "--agent", "claude"), ("agent", "run", "claude")):
            done = run_cli(environ, *args)
            assert done.returncode == 69, (args, done.stderr)
            assert "claude was not found" in done.stderr
    finally:
        shutil.rmtree(empty, ignore_errors=True)


def test_the_commands_have_help(served: BrokerThread) -> None:
    # The plain doctor is not run through the CLI: it looks at the account's real home, which a
    # subprocess cannot be pointed away from (M3). The in-process tests use a temporary home.
    environ = cli_environ(served.env)
    for args in (("doctor",), ("agent", "run", "claude"), ("agent-docs",)):
        done = run_cli(environ, *args, "--help")
        assert done.returncode == 0, (args, done.stderr)
        assert "usage: modgudr" in done.stdout


def test_agent_docs_prints_the_skill(served: BrokerThread) -> None:
    done = run_cli(cli_environ(served.env), "agent-docs", "claude")
    assert done.returncode == 0
    skill = (Path(doctor.__file__).parents[1] / "docs" / "SKILL.md").read_text("utf-8")
    assert done.stdout == skill
    for needle in (
        "modgudr targets",
        "modgudr describe",
        "modgudr explain",
        "-p ",
        "--dry-run",
        "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB",
    ):
        assert needle in done.stdout, needle
    for code in "234567":
        assert f"| {code} |" in done.stdout
    assert "modgudr" in done.stdout and "`mg`" not in done.stdout
    assert json.dumps(done.stdout)  # printable text
    assert run_cli(cli_environ(served.env), "agent-docs", "codex").returncode == 64
