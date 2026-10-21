"""The same queries against a real Snowflake account (post-run check R3).

Opt in with `MODGUDR_SF_LIVE=1`; the account comes from `MODGUDR_SF_ACCOUNT`, `MODGUDR_SF_USER`,
`MODGUDR_SF_ROLE`, `MODGUDR_SF_WAREHOUSE` and an unencrypted PEM key at `MODGUDR_SF_KEY_FILE`.
Skipped otherwise: the run never reaches a real account.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from tests.support.brokerfx import BrokerEnv, call, make_env, running, unlock
from tests.support.snowflakefx import COMPANY

pytestmark = pytest.mark.snowflake_live


def _live_env(root: Path) -> BrokerEnv:
    account = os.environ["MODGUDR_SF_ACCOUNT"]
    host = account.lower().replace("_", "-") + ".snowflakecomputing.com"
    targets = f"""\
targets:
  sf-live:
    type: sql
    system: sf
    env: test
    dialect: snowflake
    account: {account}
    user: {os.environ["MODGUDR_SF_USER"]}
    role: {os.environ["MODGUDR_SF_ROLE"]}
    warehouse: {os.environ["MODGUDR_SF_WAREHOUSE"]}
    secret: file:sf-key
    credential: {{ tier: dedicated }}
"""
    key = Path(os.environ["MODGUDR_SF_KEY_FILE"]).read_text()
    secrets = {"sf-key": {"value": key, "hosts": [f"{host}:443"]}}
    return make_env(root, company=COMPANY, targets=targets, secrets=secrets)


@pytest.fixture
async def live(shortdir: Path) -> AsyncIterator[BrokerEnv]:
    env = _live_env(shortdir)
    async with running(env):
        await unlock(env)
        yield env


async def test_a_query_with_binds(live: BrokerEnv) -> None:
    args = {
        "sql": "select :n as n, :d as d, :s as s",
        "params": {
            "n": {"t": "int", "v": 7},
            "d": {"t": "date", "v": "2026-10-01"},
            "s": {"t": "str", "v": "x"},
        },
    }
    frames = await call(live.agent_socket, "query", "sf-live", args=args)
    assert frames[-1]["t"] == "trailer", frames
    assert [f["v"] for f in frames if f["t"] == "row"] == [["7", "2026-10-01", "x"]]


async def test_the_query_tag_is_the_audit_id(live: BrokerEnv) -> None:
    first = await call(live.agent_socket, "query", "sf-live", args={"sql": "select 1 as one"})
    audit_id = first[-1]["auditId"]
    history = (
        "select query_tag from table(information_schema.query_history_by_session("
        "result_limit => 20)) where query_tag = :tag"
    )
    args = {"sql": history, "params": {"tag": {"t": "str", "v": audit_id}}}
    frames = await call(live.agent_socket, "query", "sf-live", args=args)
    assert [f["v"] for f in frames if f["t"] == "row"], "the audit id is not in the query history"
