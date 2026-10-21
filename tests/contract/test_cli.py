"""The `modgudr` CLI as a subprocess against an in-process broker with the test connectors."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from tests.support.brokerfx import BrokerEnv, read_audit
from tests.support.brokerthread import BrokerThread, cli_command, cli_environ, run_cli
from tests.support.shortdir import make_shortdir

# --- helpers -----------------------------------------------------------------------------------


def cli(
    env: BrokerEnv, *args: str, stdin: str | None = None, **extra: str
) -> subprocess.CompletedProcess[str]:
    return run_cli(cli_environ(env, **extra), *args, stdin=stdin)


def wait_until(predicate: Callable[[], bool], timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "timed out"
        time.sleep(0.02)


def completions(env: BrokerEnv) -> list[dict[str, object]]:
    return [r for r in read_audit(env.audit_dir) if r["type"] == "completion"]


# --- row ops and formats -----------------------------------------------------------------------


def test_echo_prints_a_tsv_with_a_header(unlocked: BrokerThread) -> None:
    done = cli(unlocked.env, "echo-test", "echo", "hello")
    assert (done.returncode, done.stdout, done.stderr) == (0, "text\nhello\n", "")


def test_tsv_escapes_what_the_contract_escapes(unlocked: BrokerThread) -> None:
    done = cli(unlocked.env, "echo-test", "echo", "a\tb\\N")
    assert done.stdout == "text\na\\tb\\\\N\n"


@pytest.mark.parametrize("fmt", ["csv", "json", "ndjson", "table"])
def test_every_format_renders(unlocked: BrokerThread, fmt: str) -> None:
    done = cli(unlocked.env, "echo-test", "echo", "x,y", "--format", fmt)
    assert done.returncode == 0 and done.stderr == ""
    expected = {
        "csv": 'text\r\n"x,y"\r\n',
        "ndjson": '{"text":"x,y"}\n',
        "table": "text\n----\nx,y\n",
    }
    if fmt == "json":
        assert json.loads(done.stdout) == {
            "columns": [{"name": "text", "type": "string"}],
            "rows": [{"text": "x,y"}],
        }
    else:
        assert done.stdout == expected[fmt]


def test_an_empty_result_prints_its_header(unlocked: BrokerThread) -> None:
    env = unlocked.env
    empty = ("echo-test", "slow", "--rows", "0", "--delay-ms", "0")
    assert cli(env, *empty).stdout == "i\n"
    assert cli(env, *empty, "--format", "csv").stdout == "i\r\n"
    assert cli(env, *empty, "--format", "ndjson").stdout == ""
    assert json.loads(cli(env, *empty, "--format", "json").stdout) == {
        "columns": [{"name": "i", "type": "integer"}],
        "rows": [],
    }
    quiet = cli(env, *empty, "--no-header")
    assert (quiet.returncode, quiet.stdout, quiet.stderr) == (0, "", "")


def test_options_may_come_after_the_arguments(unlocked: BrokerThread) -> None:
    done = cli(unlocked.env, "echo-test", "echo", "hi", "--format=ndjson", "--no-header")
    assert done.stdout == '{"text":"hi"}\n'


# --- limits ------------------------------------------------------------------------------------


def slow(rows: int, *extra: str) -> tuple[str, ...]:
    return ("echo-test", "slow", "--rows", str(rows), "--delay-ms", "0", *extra)


def test_max_rows_exactly_is_exit_0(unlocked: BrokerThread) -> None:
    done = cli(unlocked.env, *slow(3, "--max-rows", "3"))
    assert (done.returncode, done.stdout, done.stderr) == (0, "i\n0\n1\n2\n", "")


def test_one_row_over_max_rows_is_exit_4_with_the_rows_written(unlocked: BrokerThread) -> None:
    done = cli(unlocked.env, *slow(4, "--max-rows", "3"))
    assert done.returncode == 4
    assert done.stdout == "i\n0\n1\n2\n"
    assert "maxRows" in done.stderr and "3 rows" in done.stderr


def test_allow_truncated_makes_a_read_exit_0_and_keeps_the_note(unlocked: BrokerThread) -> None:
    done = cli(unlocked.env, *slow(4, "--max-rows", "3", "--allow-truncated"))
    assert done.returncode == 0
    assert done.stdout == "i\n0\n1\n2\n"
    assert "maxRows" in done.stderr


def test_truncated_json_is_valid_and_says_so(unlocked: BrokerThread) -> None:
    done = cli(unlocked.env, *slow(4, "--max-rows", "3", "--format", "json"))
    assert done.returncode == 4
    doc = json.loads(done.stdout)
    assert doc["truncated"] is True and [r["i"] for r in doc["rows"]] == ["0", "1", "2"]


@pytest.mark.parametrize("value", ["0", "-1", "abc"])
def test_a_bad_max_rows_is_a_usage_error(unlocked: BrokerThread, value: str) -> None:
    done = cli(unlocked.env, "echo-test", "echo", "x", "--max-rows", value)
    assert done.returncode == 64 and done.stdout == ""
    assert "max-rows" in done.stderr


def test_max_rows_above_the_hard_limit_is_denied(unlocked: BrokerThread) -> None:
    done = cli(unlocked.env, "echo-test", "echo", "x", "--max-rows", "50001")
    assert done.returncode == 2
    assert "maxRowsHard" in done.stderr


def test_a_write_that_times_out_stays_exit_4_with_allow_truncated(unlocked: BrokerThread) -> None:
    # echo-fast has a 1 s deadline; `put` is a write (it takes --dry-run), so it is not a read.
    done = cli(unlocked.env, "echo-fast", "put", "x", "--delay-ms", "3000", "--allow-truncated")
    assert done.returncode == 4
    assert "deadline" in done.stderr


def test_a_read_that_times_out_is_exit_0_with_allow_truncated(unlocked: BrokerThread) -> None:
    args = ("echo-fast", "slow", "--rows", "10", "--delay-ms", "400")
    plain = cli(unlocked.env, *args)
    assert plain.returncode == 4 and plain.stdout.startswith("i\n0\n")
    allowed = cli(unlocked.env, *args, "--allow-truncated")
    assert allowed.returncode == 0 and "deadline" in allowed.stderr


# --- statements from files, binds, writes ------------------------------------------------------


def test_f_reads_the_statement_from_a_file_and_from_stdin(unlocked: BrokerThread) -> None:
    env = unlocked.env
    sql = env.root / "q.sql"
    sql.write_text("select 1\n")
    from_file = cli(env, "probe-test", "query", "-f", str(sql), "--format", "ndjson")
    assert from_file.returncode == 0
    assert json.loads(from_file.stdout.splitlines()[0]) == {"name": "sql", "value": "select 1\n"}
    from_stdin = cli(env, "probe-test", "query", "-f", "-", "--format", "ndjson", stdin="select 2")
    assert json.loads(from_stdin.stdout.splitlines()[0])["value"] == "select 2"


def test_f_failures_are_usage_errors(unlocked: BrokerThread) -> None:
    env = unlocked.env
    empty = env.root / "empty.sql"
    empty.write_text("  \n")
    binary = env.root / "bad.sql"
    binary.write_bytes(b"select \xff\xfe")
    for args, stdin in (
        (("-f", str(env.root / "missing.sql")), None),
        (("-f", str(empty)), None),
        (("-f", str(binary)), None),
        (("-f", "-"), ""),
        (("-f", str(empty), "select 1"), None),
        ((), None),
    ):
        done = cli(env, "probe-test", "query", *args, stdin=stdin)
        assert done.returncode == 64, (args, done.stderr)
        assert done.stdout == ""


def test_binds_are_typed_and_reach_the_op(unlocked: BrokerThread) -> None:
    done = cli(
        unlocked.env,
        "probe-test",
        "query",
        "select :a",
        "-p",
        "a:int=7",
        "-p",
        "since:date=2026-10-01",
        "-p",
        "n:null",
        "--format",
        "ndjson",
    )
    rows = [json.loads(line) for line in done.stdout.splitlines()]
    assert {"name": "param:a", "value": "int:7"} in rows
    assert {"name": "param:since", "value": "date:2026-10-01"} in rows
    assert {"name": "param:n", "value": "null:None"} in rows
    audit = json.dumps(read_audit(unlocked.env.audit_dir))
    assert "2026-10-01" not in audit  # bind values are never audited


def test_a_bad_bind_is_a_usage_error(unlocked: BrokerThread) -> None:
    done = cli(unlocked.env, "probe-test", "query", "select 1", "-p", "a:int=x")
    assert done.returncode == 64


def test_a_write_prints_its_facts_as_a_row(unlocked: BrokerThread) -> None:
    done = cli(unlocked.env, "probe-test", "write", "update t", "--dry-run")
    assert (done.returncode, done.stdout) == (
        0,
        "affectedRows\tcommitted\tdryRun\n1\tfalse\ttrue\n",
    )
    real = cli(unlocked.env, "probe-test", "write", "update t", "--format", "ndjson")
    assert json.loads(real.stdout) == {"affectedRows": "1", "committed": True, "dryRun": False}


def test_flagged_and_integer_arguments(unlocked: BrokerThread) -> None:
    done = cli(
        unlocked.env, "probe-test", "tables", "--like", "PO%", "--format", "ndjson", "--no-header"
    )
    assert json.loads(done.stdout) == {"name": "like", "value": "PO%"}
    sample = cli(unlocked.env, "probe-test", "sample", "PO", "3", "--format", "ndjson")
    assert {"name": "n", "value": "3"} in [json.loads(x) for x in sample.stdout.splitlines()]
    assert cli(unlocked.env, "probe-test", "sample", "PO", "x").returncode == 64


# --- passthrough ops ---------------------------------------------------------------------------


def test_a_passthrough_op_sends_everything_after_its_name_verbatim(unlocked: BrokerThread) -> None:
    env = unlocked.env
    logs = cli(env, "probe-test", "argv", "logs", "pod/x", "-p")
    assert (logs.returncode, json.loads(logs.stdout)) == (0, ["logs", "pod/x", "-p"])
    fmt = cli(env, "probe-test", "argv", "get", "pods", "--format", "json")
    assert json.loads(fmt.stdout) == ["get", "pods", "--format", "json"]


def test_client_flags_of_a_passthrough_op_come_before_its_name(unlocked: BrokerThread) -> None:
    done = cli(unlocked.env, "probe-test", "--allow-truncated", "argv", "get", "pods")
    assert done.returncode == 0 and json.loads(done.stdout) == ["get", "pods"]


def test_one_quoted_argument_is_refused_with_a_hint(unlocked: BrokerThread) -> None:
    done = cli(unlocked.env, "probe-test", "argv", "get pods -n app")
    assert done.returncode == 64 and done.stdout == ""
    assert "separate words" in done.stderr
    assert unlocked.broker is not None
    assert all(
        c["type"] != "decision" or c["op"] != "argv" for c in read_audit(unlocked.env.audit_dir)
    )


def test_an_unknown_option_before_the_op_name_is_refused(unlocked: BrokerThread) -> None:
    assert cli(unlocked.env, "probe-test", "--nosuch", "argv").returncode == 64


# --- errors and exit codes ---------------------------------------------------------------------


def test_denied_is_exit_2_with_the_reason(unlocked: BrokerThread) -> None:
    done = cli(unlocked.env, "echo-prod", "put", "x")
    assert done.returncode == 2 and "prod" in done.stderr


def test_locked_is_exit_3(served: BrokerThread) -> None:
    done = cli(served.env, "echo-test", "echo", "x")
    assert done.returncode == 3 and "modgudr unlock" in done.stderr


def test_upstream_is_exit_5_and_internal_is_exit_70(unlocked: BrokerThread) -> None:
    assert cli(unlocked.env, "echo-test", "leak").returncode == 5
    assert cli(unlocked.env, "echo-test", "boom").returncode == 70


def test_unknown_target_op_and_option_are_usage_errors(unlocked: BrokerThread) -> None:
    env = unlocked.env
    assert cli(env, "nosuch", "echo", "x").returncode == 64
    missing = cli(env, "echo-test", "nosuch")
    assert missing.returncode == 64 and "operations: echo, put" in missing.stderr
    assert cli(env, "echo-test", "echo", "x", "--nosuch").returncode == 64
    assert cli(env, "echo-test").returncode == 64
    assert cli(env, "--nosuch").returncode == 64
    assert cli(env).returncode == 64


def test_a_mistyped_modgudr_env_is_exit_64_naming_the_environment(unlocked: BrokerThread) -> None:
    done = cli(unlocked.env, "echo", "echo", "x", MODGUDR_ENV="stage")
    assert done.returncode == 64
    assert "stage" in done.stderr


def test_modgudr_env_selects_the_environment(unlocked: BrokerThread) -> None:
    done = cli(unlocked.env, "echo", "echo", "x", MODGUDR_ENV="test")
    assert done.returncode == 0
    done = cli(unlocked.env, "echo@test", "echo", "x")
    assert done.returncode == 0


def test_broker_down_is_exit_6(shortdir: Path) -> None:
    environ = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(shortdir),
        "MODGUDR_HOME": str(shortdir / "h"),
        "MODGUDR_SOCKET": str(shortdir / "none.sock"),
    }
    for args in (("targets",), ("echo-test", "echo", "x"), ("status",)):
        done = run_cli(environ, *args)
        assert done.returncode == 6, args
        assert "broker not running; start it in your own terminal" in done.stderr


def test_status_quiet_is_the_gate_for_scripts(served: BrokerThread, shortdir: Path) -> None:
    env = served.env
    locked = cli(env, "status", "--quiet")
    assert (locked.returncode, locked.stdout, locked.stderr) == (3, "", "")
    served.unlock()
    unlocked = cli(env, "status", "--quiet")
    assert (unlocked.returncode, unlocked.stdout, unlocked.stderr) == (0, "", "")
    down = run_cli(
        {**cli_environ(env), "MODGUDR_SOCKET": str(shortdir / "none.sock")}, "status", "--quiet"
    )
    assert (down.returncode, down.stdout, down.stderr) == (6, "", "")


def test_status_lists_both_protocol_versions(served: BrokerThread) -> None:
    done = cli(served.env, "status")
    assert done.returncode == 0
    assert "protocol: client v1, broker v1" in done.stdout
    assert "state: locked" in done.stdout
    as_json = json.loads(cli(served.env, "status", "--json").stdout)
    assert as_json["protocol"]["broker"] == [1]


# --- metadata commands -------------------------------------------------------------------------


def test_targets_describe_actions_explain_and_policy(served: BrokerThread) -> None:
    env = served.env
    listed = cli(env, "targets")
    assert listed.returncode == 0
    assert "echo-test" in listed.stdout and "probe-test" in listed.stdout
    as_json = json.loads(cli(env, "targets", "--json", "--system", "probe").stdout)
    assert [t["name"] for t in as_json["targets"]] == ["probe-test"]
    assert cli(env, "targets", "--system", "nosuch").returncode == 64

    described = cli(env, "describe", "probe-test")
    assert described.returncode == 0
    assert "query [<sql>] [-f FILE] [-p name[:type]=value]..." in described.stdout
    assert "argv <arguments...>" in described.stdout

    actions = cli(env, "actions", "probe")
    assert "probe:write" in actions.stdout and "write" in actions.stdout

    explained = cli(env, "explain", "echo-prod", "put", "x")
    assert explained.returncode == 0
    assert "denied: echo:put (write) on echo-prod." in explained.stdout
    assert "layer: ceiling" in explained.stdout
    allowed = cli(env, "explain", "probe-test", "query", "select 1", "-p", "a=1")
    assert "decision: allow" in allowed.stdout

    shown = json.loads(cli(env, "policy", "show", "echo-test").stdout)
    assert shown["target"] == "echo-test"
    lint = cli(env, "policy", "lint")
    assert lint.returncode == 0


def test_help_exits_0_and_option_errors_exit_64(served: BrokerThread) -> None:
    env = served.env
    assert cli(env, "--help").returncode == 0
    assert "usage: modgudr" in cli(env, "--help").stdout
    assert cli(env, "targets", "--help").returncode == 0
    helped = cli(env, "probe-test", "query", "--help")
    assert helped.returncode == 0 and "--format" in helped.stdout
    assert cli(env, "targets", "--nosuch").returncode == 64
    assert cli(env, "targets", "--sys", "x").returncode == 64  # no abbreviations


@pytest.mark.parametrize("command", ["agent-setup", "agent", "doctor", "agent-docs", "login"])
def test_later_commands_are_stubs(served: BrokerThread, command: str) -> None:
    done = cli(served.env, command)
    assert done.returncode == 64 and "added in a later step" in done.stderr


# --- admin commands ----------------------------------------------------------------------------


def test_lock_goes_to_human_sock(unlocked: BrokerThread) -> None:
    done = cli(unlocked.env, "lock")
    assert done.returncode == 0 and "locked" in done.stderr
    assert cli(unlocked.env, "status", "--quiet").returncode == 3


def test_unlock_without_a_terminal_is_exit_64(served: BrokerThread) -> None:
    done = cli(served.env, "unlock")
    assert done.returncode == 64
    assert "unlock needs a terminal" in done.stderr
    assert cli(served.env, "status", "--quiet").returncode == 3


def test_admin_commands_without_human_sock_say_agent_session(served: BrokerThread) -> None:
    other = make_shortdir()
    try:
        environ = cli_environ(served.env, MODGUDR_HOME=other)
        for args in (("unlock",), ("lock",), ("audit", "tail")):
            done = run_cli(environ, *args)
            assert done.returncode == 6, args
            assert "admin commands are not available from an agent session" in done.stderr
    finally:
        import shutil

        shutil.rmtree(other, ignore_errors=True)


def test_admin_commands_with_the_broker_down_say_so(shortdir: Path) -> None:
    environ = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(shortdir),
        "MODGUDR_HOME": str(shortdir / "h"),
        "MODGUDR_SOCKET": str(shortdir / "none.sock"),
    }
    for args in (("unlock",), ("lock",), ("audit", "tail")):
        done = run_cli(environ, *args)
        assert done.returncode == 6
        assert "broker not running; start it in your own terminal" in done.stderr


@pytest.mark.filterwarnings("ignore:This process:DeprecationWarning")
def test_unlock_reads_the_credential_from_the_terminal(served: BrokerThread) -> None:
    import pty

    environ = cli_environ(served.env)
    pid, fd = pty.fork()
    if pid == 0:  # pragma: no cover - the child
        os.chdir(environ["HOME"])
        os.execve(sys.executable, cli_command("unlock"), environ)
    output = b""
    try:
        while b"hidden): " not in output:
            output += os.read(fd, 1024)
        os.write(fd, b"correct horse\n")
        while True:
            try:
                chunk = os.read(fd, 1024)
            except OSError:
                break
            if not chunk:
                break
            output += chunk
    finally:
        _, status = os.waitpid(pid, 0)
        os.close(fd)
    assert os.waitstatus_to_exitcode(status) == 0
    assert b"correct horse" not in output  # the terminal did not echo it
    assert cli(served.env, "status", "--quiet").returncode == 0


# --- audit tail --------------------------------------------------------------------------------


def test_audit_tail_filters_cli_and_python_calls(unlocked: BrokerThread) -> None:
    import modgudr

    env = unlocked.env
    for session in ("s-a", "s-b"):
        assert cli(env, "echo-test", "echo", "x", MODGUDR_SESSION=session).returncode == 0
        py = modgudr.connect(env.agent_socket, session=session)
        assert py.call("echo-test", "echo", text="y").fetchall() == [("y",)]

    def tail(*args: str) -> list[dict[str, object]]:
        done = cli(env, "audit", "tail", *args)
        assert done.returncode == 0, done.stderr
        return [json.loads(line) for line in done.stdout.splitlines()]

    everything = tail("-n", "1000")
    assert [r["type"] for r in everything[:2]] == ["broker.start", "unlock"]
    calls = [r for r in everything if r["type"] in ("decision", "completion")]
    assert [r["session"] for r in calls] == ["s-a"] * 4 + ["s-b"] * 4

    only_a = tail("--session", "s-a")
    assert len(only_a) == 4 and {r["session"] for r in only_a} == {"s-a"}
    only_target = tail("--target", "echo-test")
    assert len(only_target) == 8 and {r["target"] for r in only_target} == {"echo-test"}
    only_py = tail("--client", "python")
    assert len(only_py) == 4
    assert {r["client"]["name"] for r in only_py} == {"python"}  # type: ignore[index]
    combined = tail("--client", "cli", "--session", "s-b")
    assert len(combined) == 2
    last_two = tail("-n", "2")
    assert last_two == everything[-2:]
    assert last_two[0]["type"] == "decision" and last_two[1]["type"] == "completion"


def test_audit_tail_bad_n_is_exit_64(served: BrokerThread) -> None:
    assert cli(served.env, "audit", "tail", "-n", "0").returncode == 64
    assert cli(served.env, "audit", "tail", "-n", "1001").returncode == 64
    assert cli(served.env, "audit", "tail", "-n", "x").returncode == 64
    assert cli(served.env, "audit", "nosuch").returncode == 64


# --- interruption ------------------------------------------------------------------------------


def start_stream(env: BrokerEnv) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        cli_command("echo-test", "slow", "--rows", "100", "--delay-ms", "100"),
        env=cli_environ(env),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cli_environ(env)["HOME"],
        start_new_session=True,
    )


def cancelled_by_client(env: BrokerEnv) -> bool:
    return any(c["cancelled"] == "client" for c in completions(env))


def test_ctrl_c_mid_stream_is_exit_130_without_a_traceback(unlocked: BrokerThread) -> None:
    proc = start_stream(unlocked.env)
    assert proc.stdout is not None and proc.stderr is not None
    assert proc.stdout.readline() == b"i\n"
    assert proc.stdout.readline() == b"0\n"
    proc.send_signal(signal.SIGINT)
    assert proc.wait(30) == 130
    assert proc.stderr.read() == b""
    wait_until(lambda: cancelled_by_client(unlocked.env))


def test_a_closed_stdout_is_exit_141_without_a_traceback(unlocked: BrokerThread) -> None:
    proc = start_stream(unlocked.env)
    assert proc.stdout is not None and proc.stderr is not None
    assert proc.stdout.readline() == b"i\n"  # what `head -1` reads
    proc.stdout.close()
    assert proc.wait(30) == 141
    assert proc.stderr.read() == b""
    wait_until(lambda: cancelled_by_client(unlocked.env))
