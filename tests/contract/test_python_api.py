"""`import modgudr`: the Python API against an in-process broker with the test connectors."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from datetime import date
from decimal import Decimal
from pathlib import Path

import pytest

import modgudr
from modgudr.client.protocol import Column
from tests.support.brokerfx import BrokerEnv, read_audit
from tests.support.brokerthread import BrokerThread


def wait_until(predicate: Callable[[], bool], timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "timed out"
        time.sleep(0.02)


def connect(broker_env: BrokerEnv, **kwargs: str) -> modgudr.Client:
    return modgudr.connect(broker_env.agent_socket, **kwargs)


# --- results -----------------------------------------------------------------------------------


def test_rows_are_named_tuples_and_columns_are_known(unlocked: BrokerThread) -> None:
    mg = connect(unlocked.env)
    result = mg.call("echo-test", "echo", text="hello")
    assert result.columns == [Column("text", "string")]
    rows = result.fetchall()
    assert rows == [("hello",)] and rows[0].text == "hello"


def test_a_streamed_result_is_iterated_lazily(unlocked: BrokerThread) -> None:
    mg = connect(unlocked.env)
    with mg.call("echo-test", "slow", rows=5, delayMs=0) as result:
        first = next(iter(result))
        assert first.i == 0


def test_text_ops_and_facts(unlocked: BrokerThread) -> None:
    mg = connect(unlocked.env)
    result = mg.call("probe-test", "argv", args=["get", "pods", "-n", "app"])
    assert result.stdout == '["get", "pods", "-n", "app"]'
    assert result.stderr == ""
    assert result.fetchall() == []
    assert result.audit_id is not None and result.truncated is False


def test_a_write_returns_its_facts(unlocked: BrokerThread) -> None:
    sql = connect(unlocked.env).sql("probe-test")
    preview = sql.write("update t set a = :a", dry_run=True, a=1)
    assert (preview.affected_rows, preview.committed, preview.dry_run) == (1, False, True)


def test_sql_wrappers_send_the_documented_arguments(unlocked: BrokerThread) -> None:
    env = unlocked.env
    sql = connect(env).sql("probe-test")
    result = sql.query(
        "select :a, :b, :c, :d",
        a="OPEN",
        b=Decimal("1.50"),
        c=date(2026, 10, 1),
        d=None,
        max_rows=10,
    )
    assert dict(result.fetchall()) == {
        "sql": "select :a, :b, :c, :d",
        "param:a": "str:OPEN",
        "param:b": "decimal:1.50",
        "param:c": "date:2026-10-01",
        "param:d": "null:None",
    }
    assert dict(sql.tables("PO%").fetchall()) == {"like": "PO%"}
    assert dict(sql.describe("PO").fetchall()) == {"table": "PO"}
    assert dict(sql.count("PO", "status = :s", s="X").fetchall()) == {
        "table": "PO",
        "where": "status = :s",
        "param:s": "str:X",
    }
    assert dict(sql.sample("PO", 3).fetchall()) == {"table": "PO", "n": "3"}
    assert dict(sql.sample("PO").fetchall()) == {"table": "PO"}
    audit = str(read_audit(env.audit_dir))
    assert "2026-10-01" not in audit and "OPEN" not in audit


def test_params_is_an_alternative_to_keywords(unlocked: BrokerThread) -> None:
    sql = connect(unlocked.env).sql("probe-test")
    both = dict(sql.query("q", params={"a": 1}, b=2).fetchall())
    assert both["param:a"] == "int:1" and both["param:b"] == "int:2"
    with pytest.raises(modgudr.UsageError, match="both"):
        sql.query("q", params={"a": 1}, A=2)
    with pytest.raises(TypeError, match="float"):
        sql.query("q", a=1.5)


def test_a_bind_named_like_an_option_goes_through_params(unlocked: BrokerThread) -> None:
    sql = connect(unlocked.env).sql("probe-test")
    rows = dict(sql.query("q", params={"sql": "x"}).fetchall())
    assert rows["param:sql"] == "str:x"


def test_the_environment_comes_from_the_call_the_client_or_the_variable(
    unlocked: BrokerThread, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = unlocked.env
    assert connect(env, env="test").call("echo", "echo", text="a").fetchall() == [("a",)]
    assert connect(env).call("echo", "echo", env="test", text="b").fetchall() == [("b",)]
    monkeypatch.setenv("MODGUDR_ENV", "test")
    assert modgudr.connect(env.agent_socket).call("echo", "echo", text="c").fetchall() == [("c",)]
    monkeypatch.setenv("MODGUDR_ENV", "stage")
    with pytest.raises(modgudr.UsageError, match="stage"):
        modgudr.connect(env.agent_socket).call("echo", "echo", text="d")


def test_the_client_identifies_itself_in_the_audit(
    unlocked: BrokerThread, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MODGUDR_SESSION", "s-env")
    monkeypatch.setenv("CLAUDECODE", "1")
    connect(unlocked.env).call("echo-test", "echo", text="a").fetchall()
    connect(unlocked.env, session="s-arg").call("echo-test", "echo", text="b").fetchall()
    decisions = [r for r in read_audit(unlocked.env.audit_dir) if r["type"] == "decision"]
    assert [d["session"] for d in decisions] == ["s-env", "s-arg"]
    client = decisions[0]["client"]
    assert isinstance(client, dict)
    assert client["name"] == "python" and client["agentHint"] == "claude-code"
    assert client["cwd"] == str(Path.cwd())


# --- errors ------------------------------------------------------------------------------------


def test_denied(unlocked: BrokerThread) -> None:
    mg = connect(unlocked.env)
    with pytest.raises(modgudr.Denied) as caught:
        mg.call("echo-prod", "put", value="x")
    assert caught.value.layer == "ceiling" and caught.value.rule == "read"
    assert caught.value.audit_id is not None
    with pytest.raises(modgudr.Denied, match="maxRowsHard"):
        mg.call("echo-test", "echo", text="x", max_rows=50001)


def test_locked(served: BrokerThread) -> None:
    with pytest.raises(modgudr.Locked):
        connect(served.env).call("echo-test", "echo", text="x")


def test_limit_exceeded_carries_the_partial_rows(unlocked: BrokerThread) -> None:
    mg = connect(unlocked.env)
    with pytest.raises(modgudr.LimitExceeded, match="maxRows") as caught:
        mg.call("echo-test", "slow", rows=4, delayMs=0, max_rows=3).fetchall()
    assert [r.i for r in caught.value.partial] == [0, 1, 2]
    ok = mg.call("echo-test", "slow", rows=4, delayMs=0, max_rows=3, allow_truncated=True)
    assert [r.i for r in ok.fetchall()] == [0, 1, 2]
    assert ok.truncated is True


def test_a_timeout_is_limit_exceeded(unlocked: BrokerThread) -> None:
    with pytest.raises(modgudr.LimitExceeded, match="deadline") as caught:
        connect(unlocked.env).call("echo-fast", "slow", rows=10, delayMs=400).fetchall()
    assert len(caught.value.partial) >= 1


def test_upstream_and_internal(unlocked: BrokerThread) -> None:
    mg = connect(unlocked.env)
    with pytest.raises(modgudr.UpstreamError):
        mg.call("echo-test", "leak").fetchall()
    with pytest.raises(modgudr.Error) as caught:
        mg.call("echo-test", "boom").fetchall()
    assert type(caught.value) is modgudr.Error and caught.value.code == "internal"


def test_broker_unavailable(shortdir: Path) -> None:
    mg = modgudr.connect(shortdir / "none.sock")
    with pytest.raises(modgudr.BrokerUnavailable, match="broker not running"):
        mg.call("echo-test", "echo", text="x")


def test_usage_errors(unlocked: BrokerThread) -> None:
    mg = connect(unlocked.env)
    with pytest.raises(modgudr.UsageError, match="ops: echo"):
        mg.call("echo-test", "nosuch")
    with pytest.raises(modgudr.UsageError):
        mg.call("nosuch", "echo", text="x")
    with pytest.raises(modgudr.UsageError):
        mg.call("echo-test", "echo", text="x", bogus=1)
    with pytest.raises(modgudr.UsageError, match="one string"):
        mg.call("probe-test", "argv", args="get pods")  # type: ignore[arg-type]
    with pytest.raises(modgudr.UsageError, match="twice"):
        mg.call("echo-test", "echo", args={"text": "a"}, text="b")


def test_throttled(unlocked: BrokerThread) -> None:
    mg = connect(unlocked.env)
    held = [mg.call("echo-test", "slow", rows=50, delayMs=100) for _ in range(2)]
    try:
        with pytest.raises(modgudr.Throttled) as caught:
            mg.call("echo-test", "echo", text="x")
        assert caught.value.retry_after == 1.0
    finally:
        for result in held:
            result.close()


# --- cancelling, threads -----------------------------------------------------------------------


def cancelled_ops(env: BrokerEnv) -> list[object]:
    return [
        r["op"]
        for r in read_audit(env.audit_dir)
        if r["type"] == "completion" and r["cancelled"] == "client"
    ]


def test_closing_a_result_cancels_the_call(unlocked: BrokerThread) -> None:
    result = connect(unlocked.env).call("echo-test", "slow", rows=50, delayMs=100)
    assert next(iter(result)).i == 0
    result.close()
    wait_until(lambda: cancelled_ops(unlocked.env) == ["slow"])
    assert unlocked.connector.targets["echo-test"].cancelled == ["slow"]


def test_abandoning_the_iterator_closes_the_socket(unlocked: BrokerThread) -> None:
    result = connect(unlocked.env).call("echo-test", "slow", rows=50, delayMs=100)
    for row in result:
        assert row.i == 0
        break
    wait_until(lambda: cancelled_ops(unlocked.env) == ["slow"])
    assert unlocked.connector.targets["echo-test"].cancelled == ["slow"]


def test_two_threads_get_independent_results(unlocked: BrokerThread) -> None:
    mg = connect(unlocked.env)
    seen: dict[str, list[str]] = {}
    errors: list[BaseException] = []

    def work(name: str) -> None:
        try:
            for _ in range(5):
                seen.setdefault(name, []).extend(
                    row.text for row in mg.call("echo-fast", "echo", text=name)
                )
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(n,)) for n in ("one", "two")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert not errors
    assert seen == {"one": ["one"] * 5, "two": ["two"] * 5}
