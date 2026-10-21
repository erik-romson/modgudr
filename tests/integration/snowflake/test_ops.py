"""The `sql` operations against fakesnow, through the whole broker pipeline (M14, M15)."""

from __future__ import annotations

import asyncio
import threading
from datetime import date
from pathlib import Path
from typing import Any

import pytest
from snowflake.connector import errors

from modgudr.broker.app import Broker
from tests.support.brokerfx import BrokerEnv, call, error, lock, read_audit, wait_for
from tests.support.snowflakefx import TARGETS_ONE, Spy, sf_env

Frames = list[dict[str, Any]]


async def run(env: BrokerEnv, op: str, target: str = "sf-test", **args: object) -> Frames:
    return await call(env.agent_socket, op, target, args=args)  # type: ignore[return-value]


def rows(frames: Frames) -> list[list[Any]]:
    return [f["v"] for f in frames if f["t"] == "row"]


def trailer(frames: Frames) -> dict[str, Any]:
    assert frames[-1]["t"] == "trailer", frames
    return frames[-1]


def param(kind: str, value: object) -> dict[str, object]:
    return {"t": kind, "v": value}


QUERY = "select id from po where status = :status and created >= :since order by id"


async def test_a_query_binds_server_side(broker: Broker, env: BrokerEnv, spy: Spy) -> None:
    params = {"status": param("str", "OPEN"), "since": param("date", "2026-10-01")}
    frames = await run(env, "query", sql=QUERY, params=params)
    assert rows(frames) == [["1"]]
    executed = spy.tagged()[0]
    assert executed["sql"] == "select id from po where status = :1 and created >= :2 order by id"
    assert executed["params"] == ("OPEN", date(2026, 10, 1))
    assert "OPEN" not in executed["sql"] and "2026" not in executed["sql"]
    assert executed["kwargs"]["_statement_params"] == {"QUERY_TAG": trailer(frames)["auditId"]}
    assert isinstance(executed["kwargs"]["timeout"], int) and executed["kwargs"]["timeout"] > 0
    assert not any("alter session" in s.lower() for s in spy.statements())


async def test_every_statement_is_tagged_and_ends_in_a_rollback(
    broker: Broker, env: BrokerEnv, spy: Spy
) -> None:
    frames = await run(env, "query", sql="select 1 as one")
    audit_id = trailer(frames)["auditId"]
    assert spy.statements() == ["select 1 as one", "ROLLBACK"]
    for executed in spy.tagged():
        assert executed["kwargs"]["_statement_params"] == {"QUERY_TAG": audit_id}
        assert "timeout" in executed["kwargs"]


async def test_result_types(broker: Broker, env: BrokerEnv) -> None:
    sql = "select id, amount, doc, seen, raw, flag, created from po where id in (1, 2) order by id"
    frames = await run(env, "query", sql=sql)
    columns = {c["name"]: c["type"] for c in frames[0]["columns"]}
    assert columns == {
        "ID": "integer",
        "AMOUNT": "number",
        "DOC": "variant",
        "SEEN": "timestamp_tz",
        "RAW": "binary",
        "FLAG": "boolean",
        "CREATED": "date",
    }
    first, second = rows(frames)
    assert first[:3] == ["1", "10.50", '{"a":[1,2]}']
    assert first[3].startswith("2026-10-01T") and first[3][-6:] in ("+00:00", "+02:00")
    assert first[4:] == ["yv4=", True, "2026-10-02"]
    assert second == ["2", "1.50", None, None, None, False, "2026-09-01"]


async def test_numbers_are_plain_strings(broker: Broker, env: BrokerEnv) -> None:
    sql = "select 12345678901234567890123456789012345678 as big, 0.000010 as tiny"
    frames = await run(env, "query", sql=sql)
    ((big, tiny),) = rows(frames)
    assert big == "12345678901234567890123456789012345678"
    assert "e" not in tiny.lower() and tiny.startswith("0.00001")


async def test_template_ops(broker: Broker, env: BrokerEnv, spy: Spy) -> None:
    frames = await run(env, "tables")
    assert ["PUBLIC", "PO", "BASE TABLE"] in rows(frames)
    assert rows(await run(env, "tables", like="NOPE%")) == []
    described = rows(await run(env, "describe", table="PO"))
    assert [r[0] for r in described][:3] == ["ID", "STATUS", "BUYER"]
    count = await run(
        env, "count", table="PO", where="status = :s", params={"s": param("str", "X")}
    )
    assert rows(count) == [["0"]]
    count = await run(env, "count", table="PO")
    assert rows(count) == [["4"]]
    assert len(rows(await run(env, "sample", table="PO", n=3))) == 3
    assert len(rows(await run(env, "sample", table="PO"))) == 4
    sql = [s for s in spy.statements() if "ROLLBACK" not in s]
    assert "select count(*) from PO where status = :1" in sql
    assert "select * from PO limit 3" in sql


@pytest.mark.parametrize("table", ["PO; drop table t", "a.b.c.d", "1abc", "", "a b", '"x', "po--"])
async def test_a_bad_identifier_is_a_bad_request(
    broker: Broker, env: BrokerEnv, spy: Spy, table: str
) -> None:
    for op in ("describe", "count", "sample"):
        err = error(await run(env, op, table=table))
        assert err["code"] == "bad_request", (op, table, err)
    assert spy.tagged() == []


async def test_a_quoted_identifier_is_accepted(broker: Broker, env: BrokerEnv) -> None:
    assert rows(await run(env, "count", table='"PO"')) == [["4"]]
    assert rows(await run(env, "count", table="APPDB.PUBLIC.PO")) == [["4"]]


@pytest.mark.parametrize(
    "where",
    ["1=1) or exists(select 1 from secrets", "1=1; drop table po", "id = 1 or ("],
)
async def test_a_hostile_fragment_is_classified_with_the_whole_statement(
    broker: Broker, env: BrokerEnv, spy: Spy, where: str
) -> None:
    err = error(await run(env, "count", table="PO", where=where))
    assert err["code"] == "denied", err
    assert spy.tagged() == []


@pytest.mark.parametrize("n", [0, -1])
async def test_sample_needs_a_positive_n(broker: Broker, env: BrokerEnv, n: int) -> None:
    err = error(await run(env, "sample", table="PO", n=n))
    assert err["code"] == "bad_request" and "positive" in str(err["message"])


async def test_sample_is_at_most_max_rows(broker: Broker, env: BrokerEnv) -> None:
    frames = await call(
        env.agent_socket, "sample", "sf-test", args={"table": "PO", "n": 3, "maxRows": 2}
    )
    assert error(frames)["code"] == "bad_request"


@pytest.mark.parametrize(
    ("op", "sql", "needle"),
    [
        ("query", "update po set buyer = 'x' where id = 1", "Use the `write` op"),
        ("query", "delete from po where id = 1", "Use the `write` op"),
        ("query", "select id from po for update", "use the `write` op"),
        ("query", "show tables", "the query op runs SELECT"),
        ("write", "select 1", "exactly one INSERT, UPDATE, MERGE or DELETE"),
        ("write", "truncate table po", "exactly one INSERT, UPDATE, MERGE or DELETE"),
        ("write", "create table t (a int)", "exactly one INSERT, UPDATE, MERGE or DELETE"),
        (
            "write",
            "update po set buyer='x' where id=1; update po set buyer='y' where id=2",
            "one statement",
        ),
        ("query", "select 1; select 2", "one statement"),
    ],
)
async def test_the_op_contract_refuses(
    broker: Broker, env: BrokerEnv, spy: Spy, op: str, sql: str, needle: str
) -> None:
    err = error(await run(env, op, sql=sql))
    assert err["code"] == "denied", err
    assert needle in str(err["message"]), err
    assert spy.tagged() == []


async def test_a_read_is_truncated_and_the_session_is_reused(
    broker: Broker, env: BrokerEnv, spy: Spy
) -> None:
    frames = await call(
        env.agent_socket, "query", "sf-test", args={"sql": "select id from po", "maxRows": 2}
    )
    assert trailer(frames)["truncated"] is True and trailer(frames)["reason"] == "rows"
    assert len(rows(frames)) == 2
    assert len(rows(await run(env, "query", sql="select id from po"))) == 4
    assert len(spy.logins()) == 1


async def test_a_dead_pooled_session_reconnects_once_for_a_read(
    broker: Broker, env: BrokerEnv, spy: Spy
) -> None:
    await run(env, "query", sql="select 1 as one")
    dead = [True]

    def before(sql: str) -> None:
        if dead and sql.startswith("select"):
            dead.clear()
            raise errors.ProgrammingError(msg="Authentication token has expired", errno=390114)

    spy.before = before
    frames = await run(env, "query", sql="select 2 as two")
    assert rows(frames) == [["2"]]
    assert len(spy.logins()) == 2


async def test_a_write_never_reconnects(broker: Broker, env: BrokerEnv, spy: Spy) -> None:
    await run(env, "query", sql="select 1 as one")

    def before(sql: str) -> None:
        if sql.startswith("update"):
            raise errors.ProgrammingError(msg="Authentication token has expired", errno=390114)

    spy.before = before
    frames = await run(env, "write", sql="update po set buyer='x' where id=1")
    assert error(frames)["code"] == "upstream"
    assert len(spy.logins()) == 1
    assert trailer_free(frames)


def trailer_free(frames: Frames) -> bool:
    return not any(f["t"] == "trailer" for f in frames)


async def test_a_statement_the_server_refuses_keeps_the_session(
    broker: Broker, env: BrokerEnv, spy: Spy
) -> None:
    err = error(await run(env, "query", sql="select * from nosuchtable"))
    assert err["code"] == "upstream" and "NOSUCHTABLE" in str(err["message"]).upper()
    assert rows(await run(env, "query", sql="select 1 as one")) == [["1"]]
    assert len(spy.logins()) == 1


@pytest.fixture
def shortdir_one(shortdir: Path) -> BrokerEnv:
    return sf_env(shortdir, targets=TARGETS_ONE)


async def test_pool_throttles_and_lock_closes_sessions(shortdir_one: BrokerEnv, spy: Spy) -> None:
    from tests.support.brokerfx import running, unlock

    env = shortdir_one
    started, release = threading.Event(), threading.Event()

    def before(sql: str) -> None:
        if sql == "select 1 as slow":
            started.set()
            release.wait(10)

    spy.before = before
    async with running(env):
        await unlock(env)
        first = asyncio.create_task(run(env, "query", sql="select 1 as slow"))
        await wait_for(started.is_set)
        second = await run(env, "query", sql="select 2 as other")
        assert error(second)["code"] == "throttled"
        closes = spy.closes
        await lock(env)
        release.set()
        locked = error(await first)
        assert locked["code"] == "locked"
        await wait_for(lambda: spy.closes > closes)
        audit = [r for r in read_audit(env.audit_dir) if r.get("type") == "completion"]
        assert any(r.get("cancelled") == "lock" for r in audit)
