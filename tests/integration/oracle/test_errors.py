"""Login and connection failures against Oracle Free, in the words of M16 and the rules of M8."""

from __future__ import annotations

import time

import pytest

from modgudr.broker.app import Broker
from tests.support.brokerfx import BrokerEnv, error, read_audit
from tests.support.oraclefx import OracleDb, Spy, run, trailer

pytestmark = pytest.mark.oracle


async def test_nothing_listening_says_to_check_the_vpn(
    broker: Broker, env: BrokerEnv, spy: Spy
) -> None:
    started = time.monotonic()
    err = error(await run(env, "query", "ora-down", sql="select 1 from dual"))
    assert err["code"] == "upstream"
    assert "cannot reach 127.0.0.1:" in str(err["message"])
    assert "check that your VPN is up" in str(err["message"])
    assert time.monotonic() - started < 10
    done = [r for r in read_audit(env.audit_dir) if r.get("type") == "completion"][-1]
    assert done["error"]["code"] == "upstream"


async def test_an_unknown_service_says_service(broker: Broker, env: BrokerEnv) -> None:
    err = error(await run(env, "query", "ora-nosvc", sql="select 1 from dual"))
    assert err["code"] == "upstream"
    assert "service" in str(err["message"]) and "NOSUCHSVC" in str(err["message"])
    assert "VPN" not in str(err["message"])


async def test_an_unknown_sid_says_sid(broker: Broker, env: BrokerEnv) -> None:
    err = error(await run(env, "query", "ora-nosid", sql="select 1 from dual"))
    assert err["code"] == "upstream"
    assert "SID" in str(err["message"]) and "`sid`" in str(err["message"])
    assert "VPN" not in str(err["message"])


async def test_a_locked_account_is_never_retried_and_latches(
    broker: Broker, env: BrokerEnv, spy: Spy
) -> None:
    first = error(await run(env, "query", "ora-locked", sql="select 1 from dual"))
    assert first["code"] == "upstream" and "ORA-28000" in str(first["message"])
    second = error(await run(env, "query", "ora-locked", sql="select 1 from dual"))
    assert second["code"] == "upstream"
    assert len(spy.logins()) == 1


async def test_a_session_killed_on_the_server_reconnects_once_for_a_read(
    broker: Broker, env: BrokerEnv, db: OracleDb, spy: Spy
) -> None:
    assert trailer(await run(env, "query", sql="select 1 from dual"))["rows"] == 1
    assert len(spy.logins()) == 1
    for sid, serial in db.query("select sid, serial# from v$session where username = 'APP_RO'"):
        db.execute(f"alter system kill session '{sid},{serial}' immediate")
    time.sleep(1.0)
    frames = await run(env, "query", sql="select 2 as two from dual")
    assert [f["v"] for f in frames if f["t"] == "row"] == [["2"]]
    assert len(spy.logins()) == 2
