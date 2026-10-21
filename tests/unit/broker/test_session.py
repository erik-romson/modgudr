"""The store session (M7): states, the idle and absolute timers on an injected wall clock, failed
unlocks, and the same rules driven through an in-process broker."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from pathlib import Path

import pytest

from modgudr.broker.session import (
    BACKWARDS,
    FAILED_UNLOCK_LIMIT,
    Expiry,
    LockReason,
    Session,
)
from modgudr.spi import UnlockRefused
from tests.support.brokerfx import (
    BrokerEnv,
    FakeClock,
    audit_text,
    call,
    error,
    make_env,
    read_audit,
    result_data,
    running,
    unlock,
    wait_for,
)

HOUR = 3600.0
MINUTE = 60.0


def session(clock: FakeClock) -> Session:
    return Session(clock=clock, idle_lock=HOUR, absolute_lock=10 * HOUR)


def records(env: BrokerEnv, record_type: str) -> list[dict[str, object]]:
    return [r for r in read_audit(env.audit_dir) if r["type"] == record_type]


# --- the state machine -------------------------------------------------------------------------


def test_it_starts_locked_and_lock_is_idempotent() -> None:
    s = session(FakeClock())
    assert not s.unlocked and s.reason is None
    assert s.lock(LockReason.MANUAL) is False
    assert s.unlocked_now() is False
    assert s.unlocked
    epoch = s.epoch
    assert s.is_current(epoch)
    assert s.lock(LockReason.MANUAL) is True
    assert (s.reason, s.epoch) == (LockReason.MANUAL, epoch + 1)
    assert not s.is_current(epoch)
    assert s.lock(LockReason.IDLE) is False
    assert s.reason is LockReason.MANUAL


def test_a_second_unlock_is_a_reauthentication_that_resets_both_timers() -> None:
    clock = FakeClock()
    s = session(clock)
    s.unlocked_now()
    clock.advance(9 * HOUR)
    assert s.unlocked_now() is True
    clock.advance(9 * HOUR)
    s.call_started()
    s.call_finished()
    assert s.expiry() is None
    clock.advance(1 * HOUR)
    assert s.expiry() == Expiry(LockReason.ABSOLUTE)


def test_calls_every_50_minutes_keep_idle_off_until_the_absolute_deadline() -> None:
    clock = FakeClock()
    s = session(clock)
    s.unlocked_now()
    expired_at: list[tuple[float, Expiry]] = []
    for step in range(1, 14):  # 13 x 50 minutes = 10 h 50
        clock.advance(50 * MINUTE)
        expiry = s.expiry()
        if expiry is not None:
            expired_at.append((step * 50 / 60, expiry))
            break
        s.call_started()
        s.call_finished()
    assert expired_at == [(10.0, Expiry(LockReason.ABSOLUTE))]


def test_idle_counts_from_the_last_start_or_finish_and_a_call_in_flight_holds_it_off() -> None:
    clock = FakeClock()
    s = session(clock)
    s.unlocked_now()
    clock.advance(59 * MINUTE)
    s.call_started()
    clock.advance(3 * HOUR)
    assert s.expiry() is None
    s.call_finished()
    clock.advance(59 * MINUTE)
    assert s.expiry() is None
    clock.advance(1 * MINUTE)
    assert s.expiry() == Expiry(LockReason.IDLE)


def test_a_clock_moving_backwards_past_the_unlock_locks() -> None:
    clock = FakeClock()
    s = session(clock)
    s.unlocked_now()
    clock.advance(-1)
    assert s.expiry() == Expiry(LockReason.ABSOLUTE, BACKWARDS)


def test_failed_unlocks_are_limited_to_five_per_minute() -> None:
    clock = FakeClock()
    s = session(clock)
    for _ in range(FAILED_UNLOCK_LIMIT):
        assert s.unlock_retry_after() is None
        s.unlock_failed()
        clock.advance(5)
    assert s.unlock_retry_after() == 35.0
    clock.advance(34)
    assert s.unlock_retry_after() == 1.0
    clock.advance(1)
    assert s.unlock_retry_after() is None
    s.unlock_failed()
    s.unlocked_now()
    assert s.unlock_retry_after() is None


# --- through the broker ------------------------------------------------------------------------


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def env(shortdir: Path, clock: FakeClock) -> BrokerEnv:
    return make_env(shortdir, clock=clock)


async def echo(env: BrokerEnv) -> list[dict[str, object]]:
    return await call(env.agent_socket, "echo", "echo-test", args={"text": "x"})


async def test_six_unlocks_in_a_minute_the_sixth_is_throttled_untested(
    env: BrokerEnv, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with running(env) as broker:
        tested: list[str] = []
        accept = broker.store.unlock

        async def picky(credential: str) -> None:
            tested.append(credential)
            if credential != "right-token-0123":
                raise UnlockRefused("the credential is wrong")
            await accept(credential)

        monkeypatch.setattr(broker.store, "unlock", picky)
        for _ in range(FAILED_UNLOCK_LIMIT):
            err = error(await call(env.human_socket, "unlock", args={"credential": "guess-4567"}))
            assert err["code"] == "denied"
            assert "stays locked" in str(err["message"])
            clock.advance(5)
        sixth = error(
            await call(env.human_socket, "unlock", args={"credential": "right-token-0123"})
        )
        assert (sixth["code"], sixth["retryAfter"]) == ("throttled", 35.0)
        assert len(tested) == FAILED_UNLOCK_LIMIT
        assert result_data(await call(env.agent_socket, "status"))["state"] == "locked"
        clock.advance(MINUTE)
        assert (await unlock(env, "right-token-0123"))["state"] == "unlocked"
        assert len(tested) == FAILED_UNLOCK_LIMIT + 1
        assert (await echo(env))[-1]["t"] == "trailer"
    failed = records(env, "unlock.failed")
    assert len(failed) == FAILED_UNLOCK_LIMIT
    assert all(r["code"] == "denied" and r["channel"] == "human" for r in failed)
    (throttled,) = records(env, "unlock.throttled")
    assert throttled["auditId"] == sixth["auditId"]
    assert len(records(env, "unlock")) == 1
    text = audit_text(env.audit_dir)
    assert "guess-4567" not in text and "right-token-0123" not in text


async def test_idle_never_fires_with_calls_every_50_minutes_and_absolute_fires_at_10_hours(
    env: BrokerEnv, clock: FakeClock
) -> None:
    async with running(env):
        await unlock(env)
        outcomes: list[str] = []
        for _ in range(13):  # 13 x 50 minutes = 10 h 50
            clock.advance(50 * MINUTE)
            frames = await echo(env)
            outcomes.append(str(frames[-1]["code"]) if frames[-1]["t"] == "error" else "ok")
    assert outcomes == ["ok"] * 11 + ["locked", "locked"]
    assert [r["reason"] for r in records(env, "lock")] == ["absolute"]


async def test_a_12_hour_clock_jump_locks_at_the_next_request(
    env: BrokerEnv, clock: FakeClock
) -> None:
    async with running(env) as broker:
        await unlock(env)
        assert (await echo(env))[-1]["t"] == "trailer"
        clock.advance(12 * HOUR)
        assert broker.session.unlocked  # no timer has run
        err = error(await echo(env))
        assert err["code"] == "locked"
        assert "(absolute)" in str(err["message"])
        assert not broker.session.unlocked
    assert [r["reason"] for r in records(env, "lock")] == ["absolute"]


async def test_a_clock_moving_backwards_locks_the_broker_at_the_next_request(
    env: BrokerEnv, clock: FakeClock
) -> None:
    async with running(env) as broker:
        await unlock(env)
        clock.advance(-30)
        status = result_data(await call(env.agent_socket, "status"))
        assert status["state"] == "locked"
        assert not broker.session.unlocked
    (record,) = records(env, "lock")
    assert (record["reason"], record["detail"]) == ("absolute", BACKWARDS)


async def test_the_timer_locks_an_idle_session(shortdir: Path, clock: FakeClock) -> None:
    env = make_env(shortdir, clock=clock, watchdog_interval=0.05)
    async with running(env) as broker:
        await unlock(env)
        clock.advance(HOUR + 1)
        await wait_for(lambda: not broker.session.unlocked)
        await wait_for(lambda: bool(records(env, "lock")))
        assert records(env, "lock")[0]["reason"] == "idle"
        err = error(await echo(env))
        assert err["code"] == "locked" and "(idle)" in str(err["message"])


async def test_denials_and_metadata_ops_do_not_reset_the_idle_timer(
    env: BrokerEnv, clock: FakeClock
) -> None:
    async with running(env) as broker:
        await unlock(env)
        for _ in range(5):
            clock.advance(10 * MINUTE)
            await call(env.agent_socket, "targets")
            denied = error(await call(env.agent_socket, "put", "echo-prod", args={"value": "x"}))
            assert denied["code"] == "denied"
        clock.advance(10 * MINUTE)
        assert error(await echo(env))["code"] == "locked"
        assert broker.session.reason is LockReason.IDLE


async def test_a_concurrent_second_unlock_reports_already_unlocked(
    env: BrokerEnv, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with running(env) as broker:
        entered = asyncio.Event()
        release = asyncio.Event()
        tested: list[str] = []
        accept = broker.store.unlock

        async def slow(credential: str) -> None:
            tested.append(credential)
            entered.set()
            await release.wait()
            await accept(credential)

        arrived: list[str] = []
        serve_unlock = broker.unlock

        async def counted(credential: str, audit_id: str, fields: Mapping[str, object]) -> object:
            arrived.append(audit_id)
            return await serve_unlock(credential, audit_id, fields)

        monkeypatch.setattr(broker.store, "unlock", slow)
        monkeypatch.setattr(broker, "unlock", counted)
        first = asyncio.create_task(unlock(env))
        await entered.wait()
        second = asyncio.create_task(unlock(env))
        # Neither blocks other requests.
        status = result_data(await call(env.agent_socket, "status"))
        assert status["state"] == "locked"
        await wait_for(lambda: len(arrived) == 2)
        release.set()
        one, two = await asyncio.gather(first, second)
        assert (one["alreadyUnlocked"], two["alreadyUnlocked"]) == (False, True)
        assert len(tested) == 1
        # A later unlock while unlocked re-authenticates.
        again = await unlock(env)
        assert (again["alreadyUnlocked"], again["reauthenticated"]) == (False, True)
        assert len(tested) == 2
    assert [r.get("alreadyUnlocked") for r in records(env, "unlock")] == [None, True, None]


async def test_unlock_arguments_are_checked_without_echoing_the_credential(
    env: BrokerEnv,
) -> None:
    async with running(env):
        bad = error(await call(env.human_socket, "unlock", args={"credential": 42}))
        assert bad["code"] == "bad_request" and "42" not in str(bad["message"])
        extra = error(
            await call(env.human_socket, "unlock", args={"credential": "c-1", "x": "secret-9"})
        )
        assert extra["code"] == "bad_request"
        assert "secret-9" not in str(extra["message"])
        assert "arguments: credential" in str(extra["message"])
        # The file store accepts any input, including none.
        assert result_data(await call(env.human_socket, "unlock"))["state"] == "unlocked"
    assert "secret-9" not in audit_text(env.audit_dir)


async def test_unlock_and_lock_records_carry_the_trailer_audit_id(env: BrokerEnv) -> None:
    async with running(env):
        frames = await call(env.human_socket, "unlock", args={"credential": "c"})
        assert frames[0]["data"] == {
            "state": "unlocked",
            "alreadyUnlocked": False,
            "reauthenticated": False,
        }
        (record,) = records(env, "unlock")
        assert record["auditId"] == frames[1]["auditId"]
        assert record["client"] is not None and record["channel"] == "human"
        frames = await call(env.human_socket, "lock")
        assert frames[0]["data"] == {
            "state": "locked",
            "alreadyLocked": False,
            "reason": "manual",
            "cancelled": 0,
        }
        (lock_record,) = records(env, "lock")
        assert lock_record["auditId"] == frames[1]["auditId"]
        assert (lock_record["reason"], lock_record["cancelled"]) == ("manual", 0)


async def test_shutdown_of_an_unlocked_broker_locks_with_reason_shutdown(env: BrokerEnv) -> None:
    async with running(env) as broker:
        await unlock(env)
        await echo(env)
        assert len(broker.scrubber) == 1
    assert [r["reason"] for r in records(env, "lock")] == ["shutdown"]
    assert read_audit(env.audit_dir)[-1]["type"] == "broker.stop"
