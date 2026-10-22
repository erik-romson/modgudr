"""Writes, constraints, timeouts, cancellation and lock against Oracle Free (M5, M6, M7, M14)."""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Iterator

import pytest

from modgudr.broker.app import Broker
from tests.support.brokerfx import BrokerEnv, error, line, lock, read_audit, request, wait_for
from tests.support.oraclefx import OracleDb, Spy, completion, param, run, trailer

pytestmark = pytest.mark.oracle

ORIGINAL = [(1, "OPEN", "acme"), (2, "OPEN", "beta"), (3, "OPEN", "gamma"), (4, "DONE", "delta")]
SLOW = "select count(*) from all_objects a, all_objects b, all_objects c"


@pytest.fixture(autouse=True)
def restore(db: OracleDb) -> Iterator[None]:
    """PO is back to its four rows after every test."""
    yield
    conn = db.system()
    try:
        cur = conn.cursor()
        cur.execute("delete from app.po where id > 4")
        cur.execute("update app.po set buyer = 'acme' where id = 1")
        cur.execute("update app.po set buyer = 'beta' where id = 2")
        cur.execute("update app.po set buyer = 'gamma' where id = 3")
        cur.execute("update app.po set buyer = 'delta' where id = 4")
        conn.commit()
    finally:
        conn.close()


async def write(env: BrokerEnv, sql: str, target: str = "ora-rw", **args: object) -> list:  # type: ignore[type-arg]
    return await run(env, "write", target, sql=sql, **args)


async def test_a_write_within_the_limit_commits(
    broker: Broker, env: BrokerEnv, db: OracleDb
) -> None:
    frames = await write(
        env,
        "update app.po set buyer = 'x' where id = :id",
        params={"id": param("int", 1)},
    )
    done = trailer(frames)
    assert (done["affectedRows"], done["committed"], done["dryRun"]) == (1, True, False)
    assert db.po()[0] == (1, "OPEN", "x")
    record = completion(env)
    assert (record["committed"], record["affectedRows"]) == (True, 1)


async def test_a_breach_rolls_back_and_is_denied(
    broker: Broker, env: BrokerEnv, db: OracleDb
) -> None:
    frames = await write(env, "update app.po set buyer = 'x' where status = 'OPEN'")
    err = error(frames)
    assert err["code"] == "denied" and err["layer"] == "constraint"
    assert err["rule"] == "maxAffectedRows" and "3 rows, limit 2" in str(err["message"])
    assert db.po() == ORIGINAL
    record = completion(env)
    assert record["committed"] is False and record["affectedRows"] == 3


async def test_a_dry_run_counts_and_changes_nothing(
    broker: Broker, env: BrokerEnv, db: OracleDb
) -> None:
    frames = await write(env, "update app.po set buyer = 'x' where id = 2", dryRun=True)
    done = trailer(frames)
    assert (done["affectedRows"], done["committed"], done["dryRun"]) == (1, False, True)
    assert db.po() == ORIGINAL


async def test_a_delete_without_where_is_refused_before_running(
    broker: Broker, env: BrokerEnv, db: OracleDb, spy: Spy
) -> None:
    err = error(await write(env, "delete from app.po"))
    assert err["code"] == "denied" and err["rule"] == "requireWhere"
    assert spy.logins() == []
    assert db.po() == ORIGINAL


async def test_a_write_to_a_prod_target_is_refused_at_the_ceiling(
    broker: Broker, env: BrokerEnv, db: OracleDb, spy: Spy
) -> None:
    err = error(await write(env, "update app.po set buyer = 'x' where id = 1", "ora-rw-prod"))
    assert err["code"] == "denied"
    assert spy.logins() == []
    assert db.po() == ORIGINAL


async def test_a_write_the_database_refuses_is_upstream_and_changes_nothing(
    broker: Broker, env: BrokerEnv, db: OracleDb
) -> None:
    """APP_RO may not update: ORA-41900 from the server, the session stays usable."""
    err = error(await write(env, "update app.po set buyer = 'x' where id = 1", "ora-test"))
    assert err["code"] == "upstream" and "ORA-41900" in str(err["message"])
    assert db.po() == ORIGINAL
    frames = await run(env, "query", sql="select 1 from dual")
    assert trailer(frames)["rows"] == 1


async def test_an_insert_commits_and_a_second_session_sees_it(
    broker: Broker, env: BrokerEnv, db: OracleDb
) -> None:
    frames = await write(env, "insert into app.po (id, status, buyer) values (:i, 'NEW', 'zed')",
                         params={"i": param("int", 50)})  # fmt: skip
    assert trailer(frames)["committed"] is True
    assert (50, "NEW", "zed") in db.po()


async def test_a_timeout_ends_with_exit_4_and_discards_the_connection(
    broker: Broker, env: BrokerEnv, db: OracleDb, spy: Spy
) -> None:
    await run(env, "query", "ora-fast", sql="select 1 from dual")  # the session is pooled
    spy.cancels = 0
    logins = len(spy.logins())
    started = time.monotonic()
    err = error(await run(env, "query", "ora-fast", sql=SLOW))
    assert err["code"] == "timeout"
    assert time.monotonic() - started < 2.0
    await wait_for(lambda: spy.cancels >= 1)
    await _wait_for_sessions(db, 0)  # discarded, not pooled
    assert completion(env)["cancelled"] == "timeout"
    # The slot is free again and the broken session is not reused.
    frames = await run(env, "query", "ora-fast", sql="select 1 from dual")
    assert trailer(frames)["rows"] == 1
    assert len(spy.logins()) == logins + 1


async def _sessions(db: OracleDb) -> int:
    found = await asyncio.to_thread(
        db.query, "select count(*) from v$session where username = 'APP_RO'"
    )
    return int(found[0][0])


async def _wait_for_sessions(db: OracleDb, count: int) -> None:
    async with asyncio.timeout(30):
        while await _sessions(db) != count:
            await asyncio.sleep(0.2)


async def _send(env: BrokerEnv, target: str, sql: str) -> asyncio.StreamWriter:
    _, writer = await asyncio.open_unix_connection(str(env.agent_socket))
    writer.write(line(request("query", target, args={"sql": sql})))
    await writer.drain()
    return writer


async def test_a_killed_client_cancels_the_query(
    broker: Broker, env: BrokerEnv, db: OracleDb, spy: Spy
) -> None:
    writer = await _send(env, "ora-test", SLOW)
    await _wait_for_sessions(db, 1)
    await asyncio.sleep(0.5)
    writer.close()
    await wait_for(lambda: spy.cancels >= 1, timeout=10)
    await _wait_for_sessions(db, 0)
    await wait_for(
        lambda: any(
            r.get("type") == "completion" and r.get("cancelled") == "client"
            for r in read_audit(env.audit_dir)
        )
    )


async def test_a_client_that_leaves_during_a_chunked_lob_read_cancels_and_discards(
    broker: Broker, env: BrokerEnv, db: OracleDb, spy: Spy
) -> None:
    release = threading.Event()
    spy.before_read = lambda offset, amount: release.wait(30)
    try:
        writer = await _send(env, "ora-test", "select c from app.lobs where id = 2")
        await wait_for(lambda: len(spy.reads) >= 1, timeout=20)
        writer.close()
        await wait_for(lambda: spy.cancels >= 1, timeout=10)
        await wait_for(
            lambda: any(
                r.get("type") == "completion" and r.get("cancelled") == "client"
                for r in read_audit(env.audit_dir)
            )
        )
    finally:
        release.set()
    await _wait_for_sessions(db, 0)


async def test_a_lock_cancels_the_running_query_and_discards_the_session(
    broker: Broker, env: BrokerEnv, db: OracleDb, spy: Spy
) -> None:
    task = asyncio.create_task(run(env, "query", sql=SLOW))
    await _wait_for_sessions(db, 1)
    await asyncio.sleep(0.5)
    await lock(env)
    err = error(await task)
    assert err["code"] == "locked"
    await wait_for(lambda: spy.cancels >= 1, timeout=10)
    await _wait_for_sessions(db, 0)
    assert completion(env)["cancelled"] == "lock"
