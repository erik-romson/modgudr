"""The `sql` operations against Oracle Free, through the whole broker pipeline (M14, M16)."""

from __future__ import annotations

import asyncio
from datetime import date

import pytest

from modgudr.broker.app import Broker
from tests.support.brokerfx import BrokerEnv, call, error, read_audit
from tests.support.oraclefx import (
    OracleDb,
    Spy,
    param,
    rows,
    run,
    trailer,
)

pytestmark = pytest.mark.oracle


async def test_service_and_sid_targets_connect_through_connect_params(
    broker: Broker, env: BrokerEnv, spy: Spy
) -> None:
    import oracledb

    for target in ("ora-test", "ora-sid"):
        frames = await run(env, "query", target, sql="select 1 from dual")
        assert rows(frames) == [["1"]], (target, frames)
    logins = spy.logins()
    assert len(logins) == 2
    assert all(isinstance(c["params"], oracledb.ConnectParams) for c in logins)
    service, sid = (c["params"] for c in logins)
    assert (service.service_name, service.sid) == ("FREEPDB1", None)
    assert (sid.service_name, sid.sid) == (None, "FREE")
    assert service.retry_count == 0 and service.tcp_connect_timeout >= 1


async def test_binds_are_by_name_and_case_insensitive(broker: Broker, env: BrokerEnv) -> None:
    frames = await run(
        env,
        "query",
        sql="select id, buyer from app.po where id = :ID",
        params={"id": param("int", 1)},
    )
    assert rows(frames) == [["1", "acme"]]
    columns = {c["name"]: c["type"] for c in frames[0]["columns"]}
    assert columns == {"ID": "integer", "BUYER": "string"}


async def test_a_date_bind_and_a_null_bind(broker: Broker, env: BrokerEnv, db: OracleDb) -> None:
    frames = await run(
        env,
        "query",
        sql="select to_char(:d, 'YYYY-MM-DD') as d, nvl(:n, 'was null') as n from dual",
        params={"d": param("date", "2026-10-22"), "n": param("null", None)},
    )
    assert rows(frames) == [["2026-10-22", "was null"]]
    assert date(2026, 10, 22).isoformat() == rows(frames)[0][0]


async def test_an_empty_string_is_null_as_oracle_has_it(broker: Broker, env: BrokerEnv) -> None:
    frames = await run(
        env,
        "query",
        sql="select case when :s is null then 'null' else 'not null' end as r from dual",
        params={"s": param("str", "")},
    )
    assert rows(frames) == [["null"]]
    frames = await run(
        env,
        "query",
        sql="select :s as s from dual",
        params={"s": param("str", "")},
    )
    assert rows(frames) == [[None]]


async def test_a_timestamp_with_a_zone_is_a_bad_request(
    broker: Broker, env: BrokerEnv, spy: Spy
) -> None:
    frames = await run(
        env,
        "query",
        sql="select :t as t from dual",
        params={"t": param("timestamp", "2026-10-22T10:00:00+02:00")},
    )
    err = error(frames)
    assert err["code"] == "bad_request" and "FROM_TZ" in str(err["message"])
    assert spy.logins() == []


async def test_a_wall_clock_timestamp_binds(broker: Broker, env: BrokerEnv) -> None:
    frames = await run(
        env,
        "query",
        sql="select to_char(:t, 'YYYY-MM-DD HH24:MI:SS') as t from dual",
        params={"t": param("timestamp", "2026-10-22T10:11:12")},
    )
    assert rows(frames) == [["2026-10-22 10:11:12"]]


async def test_template_ops(broker: Broker, env: BrokerEnv) -> None:
    tables = rows(await run(env, "tables", like="po"))
    assert ["APP", "PO", "TABLE"] in tables
    assert rows(await run(env, "tables", like="NOPE%")) == []
    assert rows(await run(env, "count", table="app.po")) == [["4"]]
    count = await run(
        env,
        "count",
        table="app.po",
        where="status = :s",
        params={"s": param("str", "OPEN")},
    )
    assert rows(count) == [["3"]]
    assert len(rows(await run(env, "sample", table="app.po", n=3))) == 3
    assert len(rows(await run(env, "sample", table="app.po"))) == 4
    described = await run(env, "describe", table="app.po")
    assert [c["name"] for c in described[0]["columns"]] == [
        "ID",
        "STATUS",
        "BUYER",
        "AMOUNT",
        "NOTE",
    ]
    assert rows(described) == []


async def test_a_query_runs_in_a_read_only_transaction(
    broker: Broker, env: BrokerEnv, db: OracleDb
) -> None:
    frames = await run(env, "query", sql="select app.f_side() from dual")
    err = error(frames)
    assert err["code"] == "upstream" and "ORA-14551" in str(err["message"])
    assert db.po() == [
        (1, "OPEN", "acme"),
        (2, "OPEN", "beta"),
        (3, "OPEN", "gamma"),
        (4, "DONE", "delta"),
    ]


async def test_a_read_only_transaction_refuses_a_session_that_wrote(
    broker: Broker, env: BrokerEnv, db: OracleDb, spy: Spy
) -> None:
    """The connector begins every read with SET TRANSACTION READ ONLY (M14)."""
    statements: list[str] = []
    import oracledb

    real_execute = oracledb.Cursor.execute

    def execute(
        self: oracledb.Cursor, statement: str | None, *args: object, **kw: object
    ) -> object:
        statements.append(str(statement))
        return real_execute(self, statement, *args, **kw)  # type: ignore[arg-type]

    oracledb.Cursor.execute = execute  # type: ignore[method-assign]
    try:
        frames = await run(env, "query", sql="select 1 as one from dual")
    finally:
        oracledb.Cursor.execute = real_execute  # type: ignore[method-assign]
    assert rows(frames) == [["1"]]
    assert statements[-2:] == ["SET TRANSACTION READ ONLY", "select 1 as one from dual"]


async def test_the_op_contract_refuses_before_a_session_opens(
    broker: Broker, env: BrokerEnv, spy: Spy
) -> None:
    for sql in ("update app.po set buyer='x' where id=1", "alter session set current_schema=app"):
        assert error(await run(env, "query", sql=sql))["code"] == "denied", sql
    assert spy.logins() == []


async def test_a_read_is_truncated_and_the_session_is_reused(
    broker: Broker, env: BrokerEnv, spy: Spy
) -> None:
    frames = await call(
        env.agent_socket,
        "query",
        "ora-test",
        args={"sql": "select id from app.po order by id", "maxRows": 2},
    )
    assert trailer(frames)["truncated"] is True and trailer(frames)["reason"] == "rows"  # type: ignore[arg-type]
    assert len(rows(frames)) == 2  # type: ignore[arg-type]
    assert len(rows(await run(env, "query", sql="select id from app.po"))) == 4
    assert len(spy.logins()) == 1


async def test_max_concurrent_one_throttles_the_second_call(broker: Broker, env: BrokerEnv) -> None:
    slow = "select count(*) from all_objects a, all_objects b, all_objects c"
    first = asyncio.create_task(run(env, "query", "ora-one", sql=slow))
    await asyncio.sleep(1.0)
    second = await run(env, "query", "ora-one", sql="select 1 from dual")
    err = error(second)
    assert err["code"] == "throttled"
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first


async def test_module_action_and_client_identifier_during_a_call(
    broker: Broker, env: BrokerEnv, db: OracleDb
) -> None:
    sql = "select count(*) from all_objects a, all_objects b, all_objects c"
    task = asyncio.create_task(run(env, "query", sql=sql))
    seen: list[tuple[str, str, str]] = []

    async def look() -> None:
        while not seen:
            found = await asyncio.to_thread(
                db.query,
                "select module, action, client_identifier from v$session "
                "where username = 'APP_RO' and module = 'modgudr'",
            )
            if found:
                seen.append(found[0])
            else:
                await asyncio.sleep(0.2)

    async with asyncio.timeout(30):
        await look()
    module, action, client_identifier = seen[0]
    assert (module, action) == ("modgudr", "query")
    assert str(client_identifier).startswith("a-")
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_a_session_shows_no_tags_after_the_call(
    broker: Broker, env: BrokerEnv, db: OracleDb
) -> None:
    frames = await run(env, "query", sql="select 1 from dual")
    assert trailer(frames)["rows"] == 1
    found = await asyncio.to_thread(
        db.query,
        "select module, action, client_identifier from v$session where username = 'APP_RO'",
    )
    assert found == [(None, None, None)]


async def test_schema_is_set_for_the_call_and_reset_for_the_next(
    broker: Broker, env: BrokerEnv
) -> None:
    sql = "select sys_context('USERENV', 'CURRENT_SCHEMA') as s from dual"
    assert rows(await run(env, "query", sql=sql, schema="APP")) == [["APP"]]
    assert rows(await run(env, "query", sql=sql)) == [["APP_RO"]]
    # unqualified names resolve in the schema of the call
    assert rows(await run(env, "count", table="po", schema="APP")) == [["4"]]
    assert error(await run(env, "count", table="po"))["code"] == "upstream"
    record = next(r for r in read_audit(env.audit_dir) if r.get("type") == "decision")
    assert record["args"] == {"schema": "APP"}


async def test_a_bad_schema_is_a_bad_request(broker: Broker, env: BrokerEnv, spy: Spy) -> None:
    for schema in ("APP; drop user x", "1APP", 'A"B', "A.B"):
        err = error(await run(env, "query", sql="select 1 from dual", schema=schema))
        assert err["code"] == "bad_request", schema
    assert spy.logins() == []


async def test_plan_shows_the_plan_of_a_select(broker: Broker, env: BrokerEnv) -> None:
    frames = await run(
        env,
        "plan",
        sql="select * from app.po where id = :ID",
        params={"id": param("int", 1)},
    )
    text = "\n".join(str(r[0]) for r in rows(frames))
    assert [c["name"] for c in frames[0]["columns"]] == ["PLAN_TABLE_OUTPUT"]
    assert "Plan hash value" in text and "PO" in text


async def test_plan_refuses_anything_but_a_select(broker: Broker, env: BrokerEnv, spy: Spy) -> None:
    err = error(await run(env, "plan", sql="delete from po"))
    assert err["code"] == "denied" and "plan op explains SELECT" in str(err["message"])
    assert spy.logins() == []


async def test_concurrent_plans_see_only_their_own(broker: Broker, env: BrokerEnv) -> None:
    async def plan(table_filter: str) -> str:
        frames = await run(env, "plan", sql=f"select * from app.po where {table_filter}")
        return "\n".join(str(r[0]) for r in rows(frames))

    first, second = await asyncio.gather(plan("id = 1"), plan("buyer = 'acme' and status = 'OPEN'"))
    assert "ID" in first and "BUYER" not in first.split("Predicate Information")[-1]
    assert "BUYER" in second and "STATUS" in second
    assert first.count("Plan hash value") == 1 and second.count("Plan hash value") == 1
