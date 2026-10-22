"""Nothing secret leaves the broker through a login failure, an error or a result (M8, M9)."""

from __future__ import annotations

import json
import logging

import pytest

from modgudr.broker.app import Broker
from tests.support.brokerfx import BrokerEnv, audit_text, error
from tests.support.oraclefx import OracleDb, Spy, param, rows, run

pytestmark = pytest.mark.oracle


def everything(
    env: BrokerEnv, frames: list[dict[str, object]], caplog: pytest.LogCaptureFixture
) -> str:
    return "\n".join(
        [json.dumps(frames), audit_text(env.audit_dir), caplog.text, env.stderr.getvalue()]
    )


async def test_a_wrong_password_is_one_attempt_then_a_latch_and_never_leaks(
    broker: Broker, env: BrokerEnv, spy: Spy, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    password = (
        env.config.secrets_file.read_text().split("ora-bad:")[1].split("value:")[1].split()[0]
    )
    assert len(password) >= 8
    first = await run(env, "query", "ora-bad", sql="select 1 from dual")
    err = error(first)
    assert err["code"] == "upstream" and "ORA-01017" in str(err["message"])
    second = await run(env, "query", "ora-bad", sql="select 1 from dual")
    assert error(second)["code"] == "upstream"
    assert len(spy.logins()) == 1  # the second call never reached the server
    blob = everything(env, first + second, caplog)
    assert password not in blob
    assert "wrong-" not in blob


async def test_the_login_secret_in_a_result_is_scrubbed(
    broker: Broker, env: BrokerEnv, db: OracleDb, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    password = db.passwords["APP_RO"]
    frames = await run(
        env,
        "query",
        sql="select :p as p from dual",
        params={"p": param("str", password)},
    )
    assert rows(frames) == [["[modgudr:redacted]"]]
    assert password not in everything(env, frames, caplog)


async def test_a_database_error_that_quotes_the_password_is_scrubbed(
    broker: Broker, env: BrokerEnv, db: OracleDb, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    password = db.passwords["APP_RO"]
    frames = await run(env, "query", sql=f'select "{password}" from dual')
    err = error(frames)
    assert err["code"] == "upstream"
    assert password not in everything(env, frames, caplog)
