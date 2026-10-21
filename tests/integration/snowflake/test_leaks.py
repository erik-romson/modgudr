"""Nothing secret leaves the broker through a driver failure, a timeout or a login failure."""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from snowflake.connector import errors

from modgudr.broker.app import Broker
from tests.support.brokerfx import (
    BrokerEnv,
    audit_text,
    call,
    error,
    running,
    unlock,
    write_secrets,
)
from tests.support.snowflakefx import (
    HOST,
    TARGETS,
    Spy,
    private_key_pem,
    sf_env,
)
from tests.support.snowflakefx import secrets as sf_secrets

JWT = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJhY21lLmFwcCJ9.c2lnbmF0dXJlLXNpZ25hdHVyZQ"
PEM = private_key_pem()
BODY = PEM.splitlines()[3]
MESSAGE = f"login to {HOST} failed for key\n{PEM}\nwith token {JWT}"


def blob(env: BrokerEnv, frames: list[dict[str, Any]], caplog: pytest.LogCaptureFixture) -> str:
    return "\n".join(
        [json.dumps(frames), audit_text(env.audit_dir), caplog.text, env.stderr.getvalue()]
    )


def assert_clean(text: str) -> None:
    assert JWT not in text and "c2lnbmF0dXJl" not in text
    assert BODY not in text and "BEGIN PRIVATE KEY" not in text


async def query(env: BrokerEnv, sql: str = "select 1 as one") -> list[dict[str, Any]]:
    return await call(env.agent_socket, "query", "sf-test", args={"sql": sql})  # type: ignore[return-value]


async def test_a_driver_error_with_the_key_and_a_jwt_is_scrubbed(
    broker: Broker, env: BrokerEnv, spy: Spy, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)

    def before(sql: str) -> None:
        if sql.startswith("select"):
            raise errors.ProgrammingError(msg=MESSAGE, errno=2003)

    spy.before = before
    frames = await query(env)
    err = error(frames)
    assert err["code"] == "upstream" and "failed for key" in str(err["message"])
    assert_clean(blob(env, frames, caplog))


async def test_a_login_failure_with_the_key_and_a_jwt_is_scrubbed(
    broker: Broker, env: BrokerEnv, spy: Spy, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    spy.connect_error = lambda: errors.OperationalError(msg=MESSAGE, errno=250003)
    frames = await query(env)
    assert error(frames)["code"] == "upstream"
    assert_clean(blob(env, frames, caplog))


async def test_an_authentication_failure_is_scrubbed_and_latches_the_target(
    broker: Broker, env: BrokerEnv, spy: Spy, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    spy.connect_error = lambda: errors.DatabaseError(msg=MESSAGE, errno=390144)
    first = await query(env)
    assert error(first)["code"] == "upstream"
    assert "authentication failed" in str(error(first)["message"])
    second = await query(env)
    assert error(second)["code"] == "upstream" and "latched" in str(error(second)["message"])
    assert len(spy.logins()) == 1
    assert_clean(blob(env, first + second, caplog))


async def test_an_account_locked_error_is_never_retried(
    broker: Broker, env: BrokerEnv, spy: Spy
) -> None:
    spy.connect_error = lambda: errors.DatabaseError(msg="user locked", errno=390102)
    assert error(await query(env))["code"] == "upstream"
    assert len(spy.logins()) == 1


async def test_a_timeout_is_a_timeout_and_scrubbed(
    shortdir: Path, spy: Spy, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    env = sf_env(
        shortdir, targets=TARGETS.replace("    env: test\n", "    env: test\n    timeout: 1s\n")
    )
    release = threading.Event()

    def before(sql: str) -> None:
        if sql.startswith("select"):
            release.wait(5)

    spy.before = before
    async with running(env):
        await unlock(env)
        frames = await query(env)
        release.set()
        err = error(frames)
        assert err["code"] == "timeout"
        await asyncio.sleep(0.1)
        assert_clean(blob(env, frames, caplog))


async def test_the_server_timeout_error_is_a_timeout(
    broker: Broker, env: BrokerEnv, spy: Spy
) -> None:
    def before(sql: str) -> None:
        if sql.startswith("select"):
            raise errors.ProgrammingError(msg="Statement reached its statement timeout", errno=630)

    spy.before = before
    assert error(await query(env))["code"] == "timeout"


async def test_an_unusable_key_is_refused_without_echoing_it(
    shortdir: Path, spy: Spy, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    garbage = (
        "-----BEGIN PRIVATE KEY-----\nZ2FyYmFnZS1nYXJiYWdlLWdhcmJhZ2U=\n-----END PRIVATE KEY-----"
    )
    env = sf_env(shortdir)
    write_secrets(env.secrets_file, sf_secrets(garbage))
    async with running(env):
        await unlock(env)
        frames = await query(env)
        err = error(frames)
        assert err["code"] == "upstream" and "not a PEM private key" in str(err["message"])
        text = blob(env, frames, caplog)
        assert "Z2FyYmFnZS1nYXJiYWdl" not in text
    assert spy.logins() == []


async def test_an_encrypted_key_is_refused(shortdir: Path, spy: Spy) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"pw"),
    ).decode()
    env = sf_env(shortdir)
    write_secrets(env.secrets_file, sf_secrets(pem))
    async with running(env):
        await unlock(env)
        err = error(await query(env))
        assert "encrypted keys are not supported in the MVP" in str(err["message"])
    assert spy.logins() == []


async def test_a_pem_with_crlf_works(shortdir: Path, spy: Spy) -> None:
    env = sf_env(shortdir)
    write_secrets(env.secrets_file, sf_secrets(PEM.replace("\n", "\r\n")))
    async with running(env):
        await unlock(env)
        frames = await query(env)
        assert frames[-1]["t"] == "trailer"
