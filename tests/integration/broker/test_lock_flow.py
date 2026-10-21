"""The lock flow over real sockets: the lock gate, `lock` with calls in flight, the auth latch
driven by the echo connector's `auth` op, and a store session that dies mid-session."""

from __future__ import annotations

import asyncio
import json
import os
import time
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from modgudr.broker.app import Broker
from modgudr.spi import ResolvedSecret, SecretRef, StoreSessionInvalid
from tests.support.brokerfx import (
    PROD_SECRET,
    SECRET,
    SECRETS,
    TARGETS,
    BrokerEnv,
    call,
    error,
    line,
    lock,
    make_env,
    read_audit,
    request,
    result_data,
    running,
    unlock,
    wait_for,
    write_secrets,
)

NEW_SECRET = "n3w-echo-value-8910"

#: Room for four concurrent calls on echo-test.
WIDE_TARGETS = TARGETS.replace("    maxConcurrent: 2\n", "    maxConcurrent: 6\n", 1)


@pytest.fixture
def env(shortdir: Path) -> BrokerEnv:
    return make_env(shortdir, targets=WIDE_TARGETS)


@pytest.fixture
async def broker(env: BrokerEnv) -> AsyncIterator[Broker]:
    async with running(env) as b:
        yield b


def records(env: BrokerEnv, record_type: str) -> list[dict[str, object]]:
    return [r for r in read_audit(env.audit_dir) if r["type"] == record_type]


class Stream:
    """A call whose frames are read as they arrive."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer
        self.frames: list[dict[str, object]] = []

    @classmethod
    async def open(cls, path: Path, payload: dict[str, object]) -> Stream:
        reader, writer = await asyncio.open_unix_connection(os.fspath(path))
        writer.write(line(payload))
        await writer.drain()
        return cls(reader, writer)

    async def read_until(self, kind: str, count: int = 1) -> None:
        while sum(f["t"] == kind for f in self.frames) < count:
            self.frames.append(json.loads(await self.reader.readline()))

    async def rest(self) -> list[dict[str, object]]:
        async with asyncio.timeout(10):
            while chunk := await self.reader.readline():
                self.frames.append(json.loads(chunk))
        self.writer.close()
        return self.frames


class HeldResolve:
    """Holds the store's resolve until released: a call waiting on a refetch."""

    def __init__(self, broker: Broker) -> None:
        self.inner = broker.store.resolve
        self.waiting = asyncio.Event()
        self.release = asyncio.Event()

    async def __call__(self, ref: SecretRef) -> ResolvedSecret:
        self.waiting.set()
        await self.release.wait()
        return await self.inner(ref)


# --- the lock gate -----------------------------------------------------------------------------


async def test_a_call_while_locked_is_locked_but_a_denial_comes_first(
    env: BrokerEnv, broker: Broker
) -> None:
    locked = error(await call(env.agent_socket, "echo", "echo-test", args={"text": "x"}))
    assert locked["code"] == "locked"
    assert "modgudr unlock" in str(locked["message"])
    denied = error(await call(env.agent_socket, "put", "echo-prod", args={"value": "x"}))
    assert (denied["code"], denied["layer"]) == ("denied", "ceiling")
    assert [r["auditId"] for r in records(env, "locked")] == [locked["auditId"]]
    assert env.connector.targets["echo-test"].executed == []


async def test_lock_twice_is_idempotent(env: BrokerEnv, broker: Broker) -> None:
    assert (await lock(env))["alreadyLocked"] is True
    await unlock(env)
    first = await lock(env)
    second = await lock(env)
    assert (first["alreadyLocked"], second["alreadyLocked"]) == (False, True)
    assert second["cancelled"] == 0
    assert [r["reason"] for r in records(env, "lock")] == ["manual"]
    assert error(await call(env.agent_socket, "echo", "echo-test", args={"text": "x"}))["code"] == (
        "locked"
    )


# --- lock with calls in flight -----------------------------------------------------------------


async def test_lock_cancels_three_in_flight_calls_and_returns_at_once(
    env: BrokerEnv, broker: Broker, monkeypatch: pytest.MonkeyPatch
) -> None:
    await unlock(env)
    sock = env.agent_socket
    # Both secrets in the cache, so the calls below reach the store only through a refetch.
    for target in ("echo-test", "echo-prod"):
        await call(sock, "echo", target, args={"text": "warm"})
    held = HeldResolve(broker)
    monkeypatch.setattr(broker.store, "resolve", held)
    echo = env.connector.targets["echo-test"]
    echo.rejected.add(SECRET)
    assert len(broker.scrubber) == 2

    stream = await Stream.open(sock, request("slow", "echo-prod", args={"rows": 100}))
    await stream.read_until("row", 2)
    put = await Stream.open(sock, request("put", "echo-test", args={"value": "v", "delayMs": 9000}))
    await wait_for(lambda: "put" in echo.executed)
    auth = await Stream.open(sock, request("auth", "echo-test"))
    await asyncio.wait_for(held.waiting.wait(), 5)
    assert len(broker.flights) == 3

    started = time.monotonic()
    data = await lock(env)
    assert time.monotonic() - started < 1.0
    assert (data["alreadyLocked"], data["cancelled"], data["reason"]) == (False, 3, "manual")
    # Caches, latches and the scrubber's set are gone before `lock` returns.
    assert len(broker.scrubber) == 0
    assert broker.secrets.cached() == ()

    slow_frames = await stream.rest()
    kinds = [f["t"] for f in slow_frames]
    assert kinds[0] == "header" and kinds.count("row") >= 2 and kinds[-1] == "error"
    for frames in (slow_frames, await put.rest(), await auth.rest()):
        err = error(frames)
        assert err["code"] == "locked"
        assert "the call was cancelled" in str(err["message"])
        assert "trailer" not in [f["t"] for f in frames]
    completions = records(env, "completion")[-3:]
    assert {r["op"] for r in completions} == {"slow", "put", "auth"}
    assert {(r["outcome"], r["cancelled"]) for r in completions} == {("cancelled", "lock")}
    (put_record,) = [r for r in completions if r["op"] == "put"]
    assert put_record["committed"] is False
    # The refetch never finished: no second login.
    assert echo.opens == 1
    (lock_record,) = records(env, "lock")
    assert (lock_record["reason"], lock_record["cancelled"]) == ("manual", 3)
    assert error(await call(sock, "echo", "echo-test", args={"text": "x"}))["code"] == "locked"
    assert not broker.flights
    assert {t.slots.used for t in broker.targets.values()} == {0}
    assert all(t.closed for t in env.connector.targets.values())


async def test_unlock_then_lock_clears_the_latch_and_the_cache(
    env: BrokerEnv, broker: Broker
) -> None:
    await unlock(env)
    echo = env.connector.targets["echo-test"]
    echo.rejected.add(SECRET)
    assert error(await call(env.agent_socket, "auth", "echo-test"))["code"] == "upstream"
    assert broker.secrets.latched() == ("echo-test",)
    assert broker.secrets.cached() == ("file:echo-test",)
    await lock(env)
    assert broker.secrets.latched() == () and broker.secrets.cached() == ()
    await unlock(env)
    echo.rejected.clear()
    frames = await call(env.agent_socket, "auth", "echo-test")
    assert frames[-1]["t"] == "trailer" and frames[1]["v"] == ["2"]


async def test_an_unlock_while_unlocked_clears_the_latch(env: BrokerEnv, broker: Broker) -> None:
    await unlock(env)
    echo = env.connector.targets["echo-test"]
    echo.rejected.add(SECRET)
    await call(env.agent_socket, "auth", "echo-test")
    assert broker.secrets.latched() == ("echo-test",)
    assert (await unlock(env))["reauthenticated"] is True
    assert broker.secrets.latched() == ()


# --- the auth latch through the echo connector -------------------------------------------------


async def test_auth_unchanged_is_not_retried_and_the_latch_fails_fast(
    env: BrokerEnv, broker: Broker
) -> None:
    await unlock(env)
    echo = env.connector.targets["echo-test"]
    echo.rejected.add(SECRET)
    first = error(await call(env.agent_socket, "auth", "echo-test"))
    assert first["code"] == "upstream"
    assert "not retried" in str(first["message"]) and "latched for 5 minutes" in str(
        first["message"]
    )
    for _ in range(3):
        again = error(await call(env.agent_socket, "auth", "echo-test"))
        assert again["code"] == "upstream" and "is latched" in str(again["message"])
    assert echo.opens == 1
    completion = records(env, "completion")[-1]
    assert (completion["stage"], completion["outcome"]) == ("login", "failed")
    assert SECRET not in json.dumps(read_audit(env.audit_dir))


async def test_auth_with_a_changed_value_retries_once_and_succeeds(
    env: BrokerEnv, broker: Broker
) -> None:
    await unlock(env)
    await call(env.agent_socket, "echo", "echo-test", args={"text": "warm"})
    echo = env.connector.targets["echo-test"]
    echo.rejected.add(SECRET)
    write_secrets(
        env.secrets_file,
        {**SECRETS, "echo-test": {**SECRETS["echo-test"], "value": NEW_SECRET}},
    )
    frames = await call(env.agent_socket, "auth", "echo-test")
    assert frames[-1]["t"] == "trailer"
    assert frames[1]["v"] == ["2"]
    assert broker.secrets.latched() == ()


@pytest.mark.parametrize(("changed", "opens"), [(False, 1), (True, 2)])
async def test_four_concurrent_auth_calls_open_at_most_twice(
    env: BrokerEnv, broker: Broker, changed: bool, opens: int
) -> None:
    await unlock(env)
    await call(env.agent_socket, "echo", "echo-test", args={"text": "warm"})
    echo = env.connector.targets["echo-test"]
    echo.rejected.update({SECRET, NEW_SECRET})
    echo.login_delay = 0.1
    if changed:
        write_secrets(
            env.secrets_file,
            {**SECRETS, "echo-test": {**SECRETS["echo-test"], "value": NEW_SECRET}},
        )
    results = await asyncio.gather(*(call(env.agent_socket, "auth", "echo-test") for _ in range(4)))
    assert [error(frames)["code"] for frames in results] == ["upstream"] * 4
    assert echo.opens == opens


async def test_an_account_locked_error_is_never_retried(env: BrokerEnv, broker: Broker) -> None:
    await unlock(env)
    echo = env.connector.targets["echo-test"]
    echo.account_locked = True
    err = error(await call(env.agent_socket, "auth", "echo-test"))
    assert "never retried" in str(err["message"])
    assert error(await call(env.agent_socket, "auth", "echo-test"))["code"] == "upstream"
    assert echo.opens == 1


# --- the store session dies mid-session --------------------------------------------------------


async def test_a_rejected_store_session_locks_store_invalid_not_upstream(
    env: BrokerEnv, broker: Broker, monkeypatch: pytest.MonkeyPatch
) -> None:
    await unlock(env)
    await call(env.agent_socket, "echo", "echo-test", args={"text": "warm"})

    async def revoked(ref: SecretRef) -> ResolvedSecret:
        raise StoreSessionInvalid("the access token was revoked")

    monkeypatch.setattr(broker.store, "resolve", revoked)
    err = error(await call(env.agent_socket, "echo", "echo-prod", args={"text": "x"}))
    assert err["code"] == "locked"
    assert "store session expired" in str(err["message"])
    assert "modgudr unlock" in str(err["message"])
    await wait_for(lambda: bool(records(env, "lock")))
    assert records(env, "lock")[0]["reason"] == "store-invalid"
    assert result_data(await call(env.agent_socket, "status"))["state"] == "locked"
    assert len(broker.scrubber) == 0
    text = json.dumps(read_audit(env.audit_dir))
    assert SECRET not in text and PROD_SECRET not in text
