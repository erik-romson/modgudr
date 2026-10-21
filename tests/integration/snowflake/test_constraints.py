"""Writes, constraints and the transaction against fakesnow (M14, M5)."""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from typing import Any

import pytest

from modgudr.broker.app import Broker
from modgudr.sql.dialects.snowflake.driver_snowflake import SnowflakeStatement
from tests.support.brokerfx import (
    BrokerEnv,
    call,
    error,
    lock,
    read_audit,
    result_data,
    running,
    unlock,
    wait_for,
)
from tests.support.snowflakefx import Spy, sf_env, table_rows

Frames = list[dict[str, Any]]
ORIGINAL = [(1, "acme"), (2, "beta"), (3, "gamma"), (4, "delta")]


async def write(env: BrokerEnv, sql: str, target: str = "sf-test", **args: object) -> Frames:
    return await call(env.agent_socket, "write", target, args={"sql": sql, **args})  # type: ignore[return-value]


def completion(env: BrokerEnv) -> dict[str, Any]:
    return [r for r in read_audit(env.audit_dir) if r.get("type") == "completion"][-1]


async def test_a_write_within_the_limit_commits(broker: Broker, env: BrokerEnv, spy: Spy) -> None:
    sql = "update po set buyer='x' where id = :id"
    frames = await write(env, sql, params={"id": {"t": "int", "v": 1}})
    last = frames[-1]
    assert last["t"] == "trailer"
    assert (last["affectedRows"], last["committed"], last["dryRun"]) == (1, True, False)
    assert table_rows()[0] == (1, "x")
    assert spy.statements() == ["update po set buyer='x' where id = :1", "COMMIT"]
    assert (completion(env)["committed"], completion(env)["affectedRows"]) == (True, 1)


async def test_a_breach_rolls_back_and_is_denied(broker: Broker, env: BrokerEnv, spy: Spy) -> None:
    frames = await write(env, "update po set buyer='x' where id < 4")
    err = error(frames)
    assert err["code"] == "denied" and err["layer"] == "constraint"
    assert err["rule"] == "maxAffectedRows" and "3 rows, limit 2" in str(err["message"])
    assert table_rows() == ORIGINAL
    assert spy.statements() == ["update po set buyer='x' where id < 4", "ROLLBACK"]
    done = completion(env)
    assert done["committed"] is False and done["affectedRows"] == 3
    assert done["error"]["code"] == "denied"


@pytest.mark.parametrize(("where", "denied"), [("id < 4", True), ("id < 3", False)])
async def test_a_dry_run_takes_the_same_decision_and_never_changes_the_table(
    broker: Broker, env: BrokerEnv, where: str, denied: bool
) -> None:
    frames = await write(env, f"update po set buyer='x' where {where}", dryRun=True)
    if denied:
        err = error(frames)
        assert err["code"] == "denied" and "3 rows, limit 2" in str(err["message"])
    else:
        last = frames[-1]
        assert (last["affectedRows"], last["committed"], last["dryRun"]) == (2, False, True)
    assert table_rows() == ORIGINAL


async def test_requirewhere_refuses_before_anything_runs(
    broker: Broker, env: BrokerEnv, spy: Spy
) -> None:
    for sql in ("delete from po", "update po set buyer = 'x'", "delete from po where 1 = 1"):
        err = error(await write(env, sql))
        assert err["code"] == "denied" and err["rule"] == "requireWhere", err
        assert err["layer"] == "constraint"
    assert spy.tagged() == [] and spy.logins() == []
    assert table_rows() == ORIGINAL


async def test_prod_refuses_a_dry_run_before_any_connect(
    broker: Broker, env: BrokerEnv, spy: Spy
) -> None:
    frames = await write(env, "update po set buyer='x' where id = 1", "sf-prod", dryRun=True)
    err = error(frames)
    assert err["code"] == "denied" and err["layer"] == "ceiling"
    assert spy.connects == [] and spy.executes == []


async def test_an_unavailable_rowcount_fails_closed(
    broker: Broker, env: BrokerEnv, spy: Spy, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(SnowflakeStatement, "rowcount", property(lambda self: None))
    err = error(await write(env, "update po set buyer='x' where id = 1"))
    assert err["code"] == "denied" and err["layer"] == "constraint"
    assert "did not report" in str(err["message"])
    assert table_rows() == ORIGINAL
    assert "COMMIT" not in spy.statements()


async def test_explain_names_the_layer_and_the_rule(broker: Broker, env: BrokerEnv) -> None:
    args = {"target": "sf-test", "op": "write", "args": {"sql": "delete from po where id=1"}}
    data = result_data(await call(env.agent_socket, "explain", None, args=args))
    assert (data["decision"], data["layer"], data["rule"]) == ("allow", "environment", "delete")
    args["target"] = "sf-prod"
    data = result_data(await call(env.agent_socket, "explain", None, args=args))
    assert (data["decision"], data["layer"], data["rule"]) == ("deny", "ceiling", "read")
    assert "Environment prod allows read only" in str(data["explanation"])


async def test_a_lock_before_the_commit_rolls_back(shortdir: Path, spy: Spy) -> None:
    env = sf_env(shortdir)
    started, release = threading.Event(), threading.Event()

    def before(sql: str) -> None:
        if sql.startswith("update"):
            started.set()
            release.wait(10)

    spy.before = before
    async with running(env):
        await unlock(env)
        task = asyncio.create_task(write(env, "update po set buyer='x' where id = 1"))
        await wait_for(started.is_set)
        await lock(env)
        err = error(await task)
        release.set()
        assert err["code"] == "locked"
    assert table_rows() == ORIGINAL
    assert "COMMIT" not in spy.statements()


async def test_a_lock_after_the_commit_was_sent_records_committed(shortdir: Path, spy: Spy) -> None:
    env = sf_env(shortdir)
    started, release = threading.Event(), threading.Event()

    def after(sql: str) -> None:
        if sql == "COMMIT":
            started.set()
            release.wait(10)

    spy.after = after
    async with running(env):
        await unlock(env)
        task = asyncio.create_task(write(env, "update po set buyer='x' where id = 1"))
        await wait_for(started.is_set)
        lock_task = asyncio.create_task(lock(env))
        await asyncio.sleep(0.2)
        release.set()
        await task
        await lock_task
        await wait_for(
            lambda: any(r.get("type") == "completion" for r in read_audit(env.audit_dir))
        )
        done = completion(env)
    assert done["committed"] is True and done["cancelled"] == "lock"
    assert table_rows()[0] == (1, "x")
