"""The secret service (M8) with a fake store and an injected clock: the 10-minute cache, scrubber
registration, the refetch rule, the 5-minute latch, single-flight logins, pins on refetch, and
what lock and unlock clear."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import pytest

from modgudr.broker.app import build
from modgudr.broker.pins import EnvPin, PinError
from modgudr.broker.scrub import REDACTED, Scrubber
from modgudr.broker.secrets import (
    CACHE_SECONDS,
    LATCH_SECONDS,
    CallScope,
    Latched,
    LoginFailed,
    SecretService,
    SessionLocked,
    TargetSecrets,
    call_scope,
)
from modgudr.broker.session import LockReason, Session
from modgudr.spi import (
    AuthFailed,
    Call,
    Destination,
    ResolvedSecret,
    ResultSink,
    SecretRef,
    StoreError,
    StoreSessionInvalid,
    UpstreamFailure,
)
from tests.support.brokerfx import FakeClock, make_env

REF = SecretRef("file", "db1")
V1 = "first-password-0001"
V2 = "second-password-0002"
V3 = "third-password-0003"
PINNED = ("db1.example.net:1521",)


class FakeStore:
    """A store whose value tests change, that counts resolves and can hold one back."""

    scheme = "file"

    def __init__(self) -> None:
        self.secret = ResolvedSecret(REF, V1, hosts=PINNED)
        self.resolves = 0
        self.gate: asyncio.Event | None = None
        self.waiting = asyncio.Event()
        self.invalid = False
        self.missing = False

    def set(self, value: str, *, hosts: Sequence[str] = PINNED, env: Sequence[str] = ()) -> None:
        self.secret = ResolvedSecret(REF, value, hosts=tuple(hosts), env=tuple(env))

    async def unlock(self, credential: str) -> None:
        return None

    async def lock(self) -> None:
        return None

    def is_unlocked(self) -> bool:
        return True

    async def resolve(self, ref: SecretRef) -> ResolvedSecret:
        self.resolves += 1
        if self.gate is not None:
            self.waiting.set()
            await self.gate.wait()
        if self.invalid:
            raise StoreSessionInvalid("the access token was revoked")
        if self.missing:
            raise StoreError(f"secret {ref} is not in the store")
        return self.secret


class FakeTarget:
    default_port = 1521

    def destinations(self) -> frozenset[Destination]:
        return frozenset({Destination("db1.example.net", 1521)})

    async def execute(self, call: Call, sink: ResultSink) -> None:
        return None

    async def aclose(self) -> None:
        return None


class Server:
    """The database: counts logins, refuses `rejected` values."""

    def __init__(self, *rejected: str, final: bool = False, delay: float = 0.0) -> None:
        self.rejected = set(rejected)
        self.final = final
        self.delay = delay
        self.opens: list[str] = []

    async def connect(self, secret: ResolvedSecret) -> str:
        self.opens.append(secret.value)
        await asyncio.sleep(self.delay)
        if self.final:
            raise AuthFailed("ORA-28000: the account is locked", final=True)
        if secret.value in self.rejected:
            raise AuthFailed("ORA-01017: invalid username/password; logon denied")
        return f"session for {secret.value}"


@dataclass
class Harness:
    clock: FakeClock
    session: Session
    store: FakeStore
    scrubber: Scrubber
    service: SecretService
    secrets: TargetSecrets
    invalidated: list[int]

    async def login(self, server: Server, env: str = "test") -> str:
        with call_scope(CallScope(env, self.session.epoch)):
            return await self.secrets.login(server.connect)


@pytest.fixture
def h(shortdir: Path) -> Harness:
    policy = build(make_env(shortdir).config).policy
    clock = FakeClock()
    session = Session(clock=clock, idle_lock=3600, absolute_lock=36000)
    session.unlocked_now()
    store = FakeStore()
    scrubber = Scrubber()
    invalidated: list[int] = []

    def on_invalid() -> None:
        invalidated.append(1)
        session.lock(LockReason.STORE_INVALID)

    service = SecretService(store, scrubber, session, on_store_invalid=on_invalid)
    secrets = TargetSecrets(service, policy, target="db1-test", declared_env="test", ref=REF)
    secrets.attach(FakeTarget())
    return Harness(clock, session, store, scrubber, service, secrets, invalidated)


# --- the cache and the scrubber ----------------------------------------------------------------


async def test_values_are_cached_for_ten_minutes_and_registered_with_the_scrubber(
    h: Harness,
) -> None:
    assert await h.secrets.check() == EnvPin("test", None)
    assert h.store.resolves == 1
    assert h.scrubber.error(f"password {V1}") == f"password {REDACTED}"
    assert h.service.length(REF) == len(V1)
    h.clock.advance(CACHE_SECONDS - 1)
    await h.secrets.check()
    assert h.store.resolves == 1
    h.store.set(V2)
    h.clock.advance(1)
    await h.secrets.check()
    assert h.store.resolves == 2
    assert len(h.scrubber) == 2


async def test_lock_drops_the_cache_and_latches(h: Harness) -> None:
    await h.secrets.check()
    with pytest.raises(LoginFailed):
        await h.login(Server(V1))
    assert h.service.cached() == ("file:db1",) and h.service.latched() == ("db1-test",)
    h.service.drop()
    assert h.service.cached() == () and h.service.latched() == ()
    assert h.service.length(REF) is None


async def test_unlock_clears_the_latch_and_the_cache(h: Harness) -> None:
    server = Server(V1)
    with pytest.raises(LoginFailed):
        await h.login(server)
    h.service.on_unlock()
    assert h.service.cached() == () and h.service.latched() == ()
    server.rejected.clear()
    assert await h.login(server) == f"session for {V1}"
    assert server.opens == [V1, V1]


async def test_a_fetch_that_finishes_after_a_lock_is_discarded(h: Harness) -> None:
    h.store.gate = asyncio.Event()
    task = asyncio.create_task(h.secrets.check())
    await h.store.waiting.wait()
    h.session.lock(LockReason.MANUAL)
    h.store.gate.set()
    with pytest.raises(SessionLocked):
        await task
    assert h.service.cached() == () and len(h.scrubber) == 0


async def test_a_store_session_rejected_mid_session_locks_store_invalid(h: Harness) -> None:
    h.store.invalid = True
    with pytest.raises(SessionLocked):
        await h.secrets.check()
    assert h.invalidated == [1]
    assert h.session.reason is LockReason.STORE_INVALID
    with pytest.raises(SessionLocked):
        await h.secrets.check()


async def test_a_missing_item_is_a_store_error(h: Harness) -> None:
    h.store.missing = True
    with pytest.raises(StoreError, match="file:db1"):
        await h.secrets.check()


# --- authentication failures -------------------------------------------------------------------


async def test_unchanged_value_no_retry_then_latched_for_five_minutes(h: Harness) -> None:
    server = Server(V1)
    with pytest.raises(LoginFailed) as caught:
        await h.login(server)
    message = str(caught.value)
    assert "unchanged, so the login was not retried" in message
    assert "latched for 5 minutes" in message
    assert server.opens == [V1]
    assert h.store.resolves == 2  # the first fetch and the refetch
    assert isinstance(caught.value, UpstreamFailure)

    h.clock.advance(LATCH_SECONDS - 1)
    with pytest.raises(Latched, match="db1-test is latched"):
        await h.login(server)
    assert server.opens == [V1]

    h.clock.advance(1)
    with pytest.raises(LoginFailed):
        await h.login(server)
    assert server.opens == [V1, V1]


async def test_a_changed_value_is_retried_once_and_succeeds(h: Harness) -> None:
    await h.secrets.check()
    h.store.set(V2)
    server = Server(V1)
    assert await h.login(server) == f"session for {V2}"
    assert server.opens == [V1, V2]
    assert h.service.latched() == ()
    assert h.scrubber.error(f"{V1} {V2}") == f"{REDACTED} {REDACTED}"


async def test_a_changed_value_that_fails_too_latches_both(h: Harness) -> None:
    await h.secrets.check()
    h.store.set(V2)
    server = Server(V1, V2)
    with pytest.raises(LoginFailed, match="new value and it failed as well"):
        await h.login(server)
    assert server.opens == [V1, V2]
    with pytest.raises(Latched):
        await h.login(server)
    assert server.opens == [V1, V2]


async def test_a_changed_store_value_clears_the_latch(h: Harness) -> None:
    server = Server(V1)
    with pytest.raises(LoginFailed):
        await h.login(server)
    with pytest.raises(Latched):
        await h.login(server)
    h.store.set(V3)
    assert await h.login(server) == f"session for {V3}"
    assert server.opens == [V1, V3]
    assert h.service.latched() == ()


async def test_account_locked_or_expired_is_never_retried(h: Harness) -> None:
    await h.secrets.check()
    h.store.set(V2)
    server = Server(final=True)
    with pytest.raises(LoginFailed, match="locked or expired, so the login is never retried"):
        await h.login(server)
    assert server.opens == [V1]
    assert h.store.resolves == 1
    with pytest.raises(LoginFailed):
        # V2 has not failed: the latch lets it try once, and it fails the same way.
        await h.login(server)
    assert server.opens == [V1, V2]


@pytest.mark.parametrize(("changed", "opens"), [(False, 1), (True, 2)])
async def test_four_concurrent_logins_with_a_bad_password_open_at_most_twice(
    h: Harness, changed: bool, opens: int
) -> None:
    await h.secrets.check()
    if changed:
        h.store.set(V2)
    server = Server(V1, V2, delay=0.05)
    with call_scope(CallScope("test", h.session.epoch)):
        tasks = [asyncio.create_task(h.secrets.login(server.connect)) for _ in range(4)]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    assert len(server.opens) == opens
    assert all(isinstance(r, UpstreamFailure) for r in results), results
    assert [type(r) for r in results].count(LoginFailed) == 1


# --- pins and scope at login -------------------------------------------------------------------


async def test_a_refetched_value_must_pass_the_pins_before_it_is_used(h: Harness) -> None:
    await h.secrets.check()
    h.store.set(V2, hosts=("db9.example.net:1521",))
    server = Server(V1)
    with pytest.raises(PinError, match=r"db1\.example\.net:1521, which no pin"):
        await h.login(server)
    assert server.opens == [V1]


async def test_an_environment_pin_that_changes_under_a_call_refuses_it(h: Harness) -> None:
    await h.secrets.check()
    h.store.set(V2, env=("prod",))
    server = Server(V1)
    with pytest.raises(PinError, match="decided for test"):
        await h.login(server)
    assert server.opens == [V1]


async def test_login_runs_only_inside_a_call_of_the_current_session(h: Harness) -> None:
    server = Server()
    with pytest.raises(RuntimeError, match="only while a call executes"):
        await h.secrets.login(server.connect)
    epoch = h.session.epoch
    h.session.lock(LockReason.MANUAL)
    h.session.unlocked_now()
    with call_scope(CallScope("test", epoch)), pytest.raises(SessionLocked):
        await h.secrets.login(server.connect)
    assert server.opens == []
