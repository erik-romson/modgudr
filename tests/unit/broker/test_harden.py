"""Start-up hardening (M23). The hardening replaces the process environment, so every test that
applies it does so in a child process and probes the child from the parent."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from modgudr.broker import harden
from modgudr.broker.harden import Hardening, HardeningError, Libc, permission_warnings
from modgudr.broker.scrub import REDACTED
from tests.support.brokerfx import call, make_env, result_data, running

SECRET = "hunter2-correct-horse-battery"
TIMEOUT = 60

#: Applies the hardening in the child, with the secret registered, then reports what it sees.
APPLY = """
import faulthandler, json, logging, os, resource, sys
from pathlib import Path
from modgudr.broker import harden
from modgudr.broker.scrub import Scrubber

scrubber = Scrubber()
facts = harden.apply(scrubber, Path(sys.argv[1]))
scrubber.add(sys.argv[2])
logging.getLogger("modgudr.test").warning("connecting with %s", sys.argv[2])
print(json.dumps({
    "env": sorted(os.environ),
    "core": resource.getrlimit(resource.RLIMIT_CORE),
    "faulthandler": faulthandler.is_enabled(),
    "isolated": sys.flags.isolated,
    "facts": facts.to_json(),
    "snowflakeLogger": logging.getLogger("snowflake.connector").level,
}))
"""

#: Hardens, announces itself, and waits so that the parent can probe it.
HOLD = """
import sys
from pathlib import Path
from modgudr.broker import harden
from modgudr.broker.scrub import Scrubber

harden.apply(Scrubber(), Path(sys.argv[1]))
print("ready", flush=True)
sys.stdin.readline()
"""

#: The daemon's main with an injected hardener that raises.
INJECTED = """
import sys
from modgudr.broker import daemon, harden

def boom(scrubber, policy_dir):
    raise harden.HardeningError("injected")

sys.exit(daemon.main([], hardener=boom))
"""


def child_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {"PATH": "/usr/bin:/bin", "HOME": "/tmp", "LANG": "C.UTF-8"}
    env.update(extra or {})
    return env


def run_child(
    code: str, *args: str, env: dict[str, str], isolated: bool = False
) -> subprocess.CompletedProcess[str]:
    flags = ["-I"] if isolated else []
    return subprocess.run(
        [sys.executable, *flags, "-c", code, *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )


# --- the re-exec ---------------------------------------------------------------------------------


def test_the_console_script_re_executes_under_dash_i(shortdir: Path) -> None:
    script = Path(sys.executable).parent / "modgudr-broker"
    assert script.exists()
    proc = subprocess.run(
        [os.fspath(script), "--version"],
        env=child_env({"HOME": os.fspath(shortdir)}),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert re.fullmatch(r"modgudr-broker \S+ \(isolated=1\)\n", proc.stdout), proc.stdout


def test_reexec_does_nothing_when_already_isolated() -> None:
    code = "from modgudr.broker import harden; harden.reexec(['--version']); print('same process')"
    proc = run_child(code, env=child_env(), isolated=True)
    assert proc.stdout == "same process\n", proc.stderr


# --- the hardening -------------------------------------------------------------------------------


def test_the_environment_is_replaced_by_the_allowlist(shortdir: Path) -> None:
    env = child_env(
        {
            "PYTHONPATH": os.fspath(shortdir),
            "HTTPS_PROXY": "http://proxy.example.net:3128",
            "TNS_ADMIN": os.fspath(shortdir),
            "AZURE_CONFIG_DIR": os.fspath(shortdir),
            "SNOWFLAKE_HOME": os.fspath(shortdir),
            "MODGUDR_HOME": os.fspath(shortdir),
            "LC_ALL": "C.UTF-8",
        }
    )
    proc = run_child(APPLY, os.fspath(shortdir), SECRET, env=env)
    assert proc.returncode == 0, proc.stderr
    seen = json.loads(proc.stdout)
    allowed = {"PATH", "HOME", "LANG", "SF_TELEMETRY_DISABLE_CONNECTION_SHAPE"}
    assert {k for k in seen["env"] if not k.startswith("LC_")} <= allowed
    assert "SF_TELEMETRY_DISABLE_CONNECTION_SHAPE" in seen["env"]
    assert {"PATH", "HOME", "LANG", "LC_ALL"} <= set(seen["env"])
    assert seen["core"] == [0, 0]
    assert seen["faulthandler"] is False
    assert seen["snowflakeLogger"] == 30


def test_the_facts_describe_what_was_done(shortdir: Path) -> None:
    proc = run_child(APPLY, os.fspath(shortdir), SECRET, env=child_env())
    assert proc.returncode == 0, proc.stderr
    facts = json.loads(proc.stdout)["facts"]
    assert facts["applied"] is True
    assert facts["isolated"] is False
    assert facts["coreLimit"] == [0, 0]
    assert facts["faulthandler"] is False
    assert facts["logFilter"] is True
    assert facts["quietLoggers"] == ["snowflake.connector", "oracledb", "sqlglot"]
    assert facts["antiDebug"]["result"] == 0
    assert set(facts["environmentKept"]) >= {
        "PATH",
        "HOME",
        "SF_TELEMETRY_DISABLE_CONNECTION_SHAPE",
    }


def test_the_facts_report_isolation_under_dash_i(shortdir: Path) -> None:
    proc = run_child(APPLY, os.fspath(shortdir), SECRET, env=child_env(), isolated=True)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["facts"]["isolated"] is True


@pytest.mark.skipif(sys.platform != "darwin", reason="ptrace(PT_DENY_ATTACH) is macOS")
def test_macos_ptrace_deny_attach_returns_zero(shortdir: Path) -> None:
    proc = run_child(APPLY, os.fspath(shortdir), SECRET, env=child_env())
    assert proc.returncode == 0, proc.stderr
    anti_debug = json.loads(proc.stdout)["facts"]["antiDebug"]
    assert anti_debug == {"mechanism": "ptrace(PT_DENY_ATTACH)", "result": 0}


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="/proc is Linux")
def test_linux_proc_environ_of_the_hardened_child_is_unreadable(shortdir: Path) -> None:
    with subprocess.Popen(
        [sys.executable, "-c", HOLD, os.fspath(shortdir)],
        env=child_env(),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    ) as child:
        assert child.stdin is not None and child.stdout is not None
        try:
            assert child.stdout.readline() == "ready\n"
            with pytest.raises(PermissionError):
                Path(f"/proc/{child.pid}/environ").read_bytes()
        finally:
            child.stdin.write("\n")
            child.stdin.flush()
            child.wait(timeout=TIMEOUT)


def test_the_root_logger_redacts_a_registered_secret(shortdir: Path) -> None:
    proc = run_child(APPLY, os.fspath(shortdir), SECRET, env=child_env())
    assert proc.returncode == 0, proc.stderr
    assert SECRET not in proc.stderr
    assert f"connecting with {REDACTED}" in proc.stderr


def test_the_filter_redacts_exception_text(shortdir: Path) -> None:
    code = """
import logging, sys
from pathlib import Path
from modgudr.broker import harden
from modgudr.broker.scrub import Scrubber

scrubber = Scrubber()
harden.apply(scrubber, Path(sys.argv[1]))
scrubber.add(sys.argv[2])
try:
    raise RuntimeError("bad " + sys.argv[2])
except RuntimeError:
    logging.getLogger("modgudr.test").exception("failed")
"""
    proc = run_child(code, os.fspath(shortdir), SECRET, env=child_env())
    assert proc.returncode == 0, proc.stderr
    assert "RuntimeError: bad" in proc.stderr
    assert SECRET not in proc.stderr


def test_a_hardening_step_that_raises_makes_the_daemon_exit_78(shortdir: Path) -> None:
    env = child_env(
        {
            "MODGUDR_HOME": os.fspath(shortdir / "h"),
            "MODGUDR_SOCKET": os.fspath(shortdir / "a.sock"),
        }
    )
    proc = run_child(INJECTED, env=env)
    assert proc.returncode == 78, proc.stderr
    assert "hardening failed: injected" in proc.stderr
    assert not (shortdir / "h").exists()
    assert not (shortdir / "a.sock").exists()


# --- the pieces, without touching this process ---------------------------------------------------


class FakeLibc:
    """Stands in for the C library: `ptrace` and `prctl` are plain functions, as ctypes has."""

    def __init__(self, result: int) -> None:
        self.calls: list[tuple[object, ...]] = []

        def fake(*args: object) -> int:
            self.calls.append(args)
            return result

        def fake_prctl(*args: object) -> int:
            return fake(*args)

        self.ptrace = fake
        self.prctl = fake_prctl


def test_a_nonzero_anti_debug_result_is_an_error() -> None:
    libc: Libc = FakeLibc(-1)
    with pytest.raises(HardeningError, match=r"returned -1"):
        harden.deny_attach("darwin", libc)
    with pytest.raises(HardeningError, match=r"returned -1"):
        harden.deny_attach("linux", libc)


def test_each_platform_makes_its_own_call() -> None:
    mac = FakeLibc(0)
    assert harden.deny_attach("darwin", mac) == ("ptrace(PT_DENY_ATTACH)", 0)
    assert mac.calls == [(31, 0, None, 0)]
    linux = FakeLibc(0)
    assert harden.deny_attach("linux", linux) == ("prctl(PR_SET_DUMPABLE)", 0)
    assert linux.calls == [(4, 0, 0, 0, 0)]


def test_an_unknown_platform_is_refused() -> None:
    with pytest.raises(HardeningError, match="no anti-debug mechanism"):
        harden.deny_attach("win32", FakeLibc(0))


def test_the_environment_reset_keeps_only_the_allowlist() -> None:
    environ = {
        "PATH": "/usr/bin",
        "HOME": "/h",
        "LANG": "C",
        "LC_ALL": "C",
        "TNS_ADMIN": "/x",
        "HTTPS_PROXY": "http://p",
    }
    kept = harden.reset_environment(environ)
    assert sorted(environ) == list(kept)
    assert set(environ) == {
        "PATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "SF_TELEMETRY_DISABLE_CONNECTION_SHAPE",
    }
    assert environ["SF_TELEMETRY_DISABLE_CONNECTION_SHAPE"] == "true"


def test_writable_policy_dirs_and_venvs_are_warned_about(shortdir: Path) -> None:
    policy = shortdir / "policy.d"
    venv = shortdir / "venv"
    policy.mkdir()
    venv.mkdir()
    policy.chmod(0o755)
    venv.chmod(0o755)
    assert permission_warnings(policy, venv) == ()
    policy.chmod(0o775)
    venv.chmod(0o757)
    warnings = permission_warnings(policy, venv)
    assert len(warnings) == 2
    assert "the policy directory" in warnings[0] and "0775" in warnings[0]
    assert "the virtual environment" in warnings[1] and "0757" in warnings[1]


def test_a_missing_policy_dir_is_not_a_permission_warning(shortdir: Path) -> None:
    assert permission_warnings(shortdir / "missing", shortdir) == ()


# --- status --json -------------------------------------------------------------------------------


async def test_a_factory_built_broker_reports_hardening_as_not_applied(shortdir: Path) -> None:
    env = make_env(shortdir)
    async with running(env):
        status = result_data(await call(env.agent_socket, "status"))
    assert status["hardening"] == {"applied": False}


async def test_status_carries_the_daemons_hardening_facts(shortdir: Path) -> None:
    facts = Hardening(
        isolated=True,
        environment_kept=("HOME", "PATH"),
        anti_debug="ptrace(PT_DENY_ATTACH)",
        anti_debug_result=0,
        core_limit=(0, 0),
        faulthandler_enabled=False,
        log_filter=True,
        quiet_loggers=("oracledb",),
        warnings=("the policy directory /p is group- or world-writable (0775)",),
    )
    env = make_env(shortdir, hardening=facts)
    async with running(env):
        status = result_data(await call(env.agent_socket, "status"))
    assert status["hardening"] == facts.to_json()
    assert status["hardening"] == {
        "applied": True,
        "isolated": True,
        "environmentKept": ["HOME", "PATH"],
        "antiDebug": {"mechanism": "ptrace(PT_DENY_ATTACH)", "result": 0},
        "coreLimit": [0, 0],
        "faulthandler": False,
        "logFilter": True,
        "quietLoggers": ["oracledb"],
        "warnings": ["the policy directory /p is group- or world-writable (0775)"],
    }
