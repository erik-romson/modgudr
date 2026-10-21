"""The secret service (M8): cache, pins, the refetch rule, the auth latch, single-flight logins.

- **Cache.** References resolve through the store, and the value is cached for 10 minutes. The
  cache is dropped on lock.
- **Scrubber.** Every resolved value is registered with the scrubber when it enters memory; the
  broker clears the scrubber's set on lock.
- **Pins.** M6 step 7 checks the destination and environment pins (`TargetSecrets.check`), and
  `login` checks them again for whatever value it hands to the connector: a refetched value
  carries its own pins, and its environment pin must give the environment the call was decided
  with.
- **Authentication failures** are raised only while connecting. The service drops the cache entry
  and refetches, and retries once **only if the refetched value differs**. After a confirmed
  failure the target is latched for 5 minutes: logins fail at once with `upstream` and never
  reach the server. Lock, unlock or a changed store value clears the latch: a latched login asks
  the store (not the server) for the current value, so a fixed secret works at the next call.
  "Account locked or expired" failures (`AuthFailed(final=True)`, ORA-28000, ORA-28001) are
  never retried.
- **Single flight.** Logins are serialised per target, so an agent in a loop cannot lock a shared
  account: of four concurrent calls with a bad password at most two logins reach the server.
- **Lock.** A fetch that finishes after the session locked is discarded (`SessionLocked`). A store
  that rejects its session mid-session (`StoreSessionInvalid`) locks the broker with reason
  `store-invalid`.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from collections.abc import Awaitable, Callable, Generator, Iterable
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime

from ..spi import (
    AuthFailed,
    ResolvedSecret,
    SecretRef,
    SecretStore,
    StoreError,
    StoreSessionInvalid,
    Target,
    UpstreamFailure,
)
from .pins import RULE_ENV, EnvPin, PinError, Pins, check_destinations, env_pin, pins_of
from .policy.load import Policy
from .scrub import Scrubber
from .session import Session

log = logging.getLogger("modgudr.broker")

#: How long a resolved value is served from memory (M8).
CACHE_SECONDS = 600.0
#: How long a target stays latched after a confirmed authentication failure (M8).
LATCH_SECONDS = 300.0

_CLEARS = (
    "Fix the secret in the store (a changed value ends the latch), or run `modgudr lock` and "
    "`modgudr unlock` in your own terminal"
)


class SessionLocked(Exception):
    """The session locked, or the store rejected its session, while a secret was in use."""


class LoginFailed(UpstreamFailure):
    """A confirmed authentication failure; the target is latched now."""

    stage = "login"


class Latched(UpstreamFailure):
    """A login refused at once: the target is latched after an authentication failure."""

    stage = "login"


@dataclass(frozen=True)
class CallScope:
    """What one executing call was decided with: its effective environment and the session
    epoch it passed the lock gate in."""

    env: str
    epoch: int


_SCOPE: ContextVar[CallScope | None] = ContextVar("modgudr_call_scope", default=None)


@contextmanager
def call_scope(scope: CallScope) -> Generator[None]:
    """Tasks created inside see `scope`; `login` runs only inside one."""
    token = _SCOPE.set(scope)
    try:
        yield
    finally:
        _SCOPE.reset(token)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()


def _utc(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, UTC).strftime("%H:%M:%S")


@dataclass(frozen=True)
class Fetched:
    """A secret as the cache holds it, with its parsed pins or the reason they refuse it."""

    secret: ResolvedSecret
    #: When it was fetched (wall-clock seconds).
    at: float
    #: SHA-256 of the value, for the latch.
    digest: str
    pins: Pins | None = None
    pin_error: PinError | None = None


@dataclass
class Latch:
    until: float
    #: SHA-256 digests of the values that failed to log in.
    failed: set[str] = field(default_factory=set[str])
    reason: str = ""


class SecretService:
    """The broker's secrets: one store, one cache, the latches of every target."""

    def __init__(
        self,
        store: SecretStore,
        scrubber: Scrubber,
        session: Session,
        *,
        on_store_invalid: Callable[[], object],
    ) -> None:
        self.store = store
        self.scrubber = scrubber
        self.session = session
        self._on_store_invalid = on_store_invalid
        self._cache: dict[str, Fetched] = {}
        self._lengths: dict[str, int] = {}
        self._latches: dict[str, Latch] = {}

    # --- values ---------------------------------------------------------------------------------

    async def current(self, ref: SecretRef) -> Fetched:
        """The cached value while it is younger than 10 minutes, else a fresh one."""
        cached = self._cache.get(str(ref))
        if cached is not None and 0 <= self.session.now() - cached.at < CACHE_SECONDS:
            return cached
        return await self._fetch(ref)

    async def refetch(self, ref: SecretRef, stale: Fetched) -> Fetched:
        """Drop `stale` from the cache and fetch the value again (after an auth failure)."""
        if self._cache.get(str(ref)) is stale:
            del self._cache[str(ref)]
        return await self._fetch(ref)

    async def _fetch(self, ref: SecretRef) -> Fetched:
        session = self.session
        epoch = session.epoch
        if not session.unlocked:
            raise SessionLocked
        try:
            secret = await self.store.resolve(ref)
        except StoreSessionInvalid:
            if session.is_current(epoch):
                self._on_store_invalid()
            raise SessionLocked from None
        if not session.is_current(epoch):
            # Locked while the store answered: the value is not kept.
            raise SessionLocked
        if not secret.value:
            raise StoreError(f"secret {ref} is empty")
        self.scrubber.add(secret.value)
        pins: Pins | None = None
        error: PinError | None = None
        try:
            pins = pins_of(secret)
        except PinError as exc:
            error = exc
        else:
            for warning in pins.warnings:
                log.warning("secret %s: %s", ref, warning)
        fetched = Fetched(secret, session.now(), _digest(secret.value), pins, error)
        self._cache[str(ref)] = fetched
        self._lengths[str(ref)] = len(secret.value)
        return fetched

    def length(self, ref: SecretRef) -> int | None:
        """The length of the last value resolved for `ref` (for `scrub: partial`)."""
        return self._lengths.get(str(ref))

    def cached(self) -> tuple[str, ...]:
        """The references the cache holds."""
        return tuple(self._cache)

    # --- latches --------------------------------------------------------------------------------

    def latch(self, target: str) -> Latch | None:
        latch = self._latches.get(target)
        if latch is not None and self.session.now() >= latch.until:
            del self._latches[target]
            return None
        return latch

    def set_latch(self, target: str, digests: Iterable[str], reason: str) -> Latch:
        old = self.latch(target)
        failed = set(digests) | (old.failed if old is not None else set[str]())
        latch = Latch(self.session.now() + LATCH_SECONDS, failed, reason)
        self._latches[target] = latch
        return latch

    def clear_latch(self, target: str) -> None:
        self._latches.pop(target, None)

    def latched(self) -> tuple[str, ...]:
        """The targets latched now."""
        return tuple(name for name in tuple(self._latches) if self.latch(name) is not None)

    # --- lock and unlock ------------------------------------------------------------------------

    def on_unlock(self) -> None:
        """A successful unlock clears every latch and starts with an empty cache."""
        self._latches.clear()
        self._cache.clear()

    def drop(self) -> None:
        """Lock (M7): the cache, the latches and what is known about the values go."""
        self._cache.clear()
        self._lengths.clear()
        self._latches.clear()


class TargetSecrets:
    """What one target gets as `Secrets` at `open` (M8), and its M6 step 7."""

    def __init__(
        self,
        service: SecretService,
        policy: Policy,
        *,
        target: str,
        declared_env: str,
        ref: SecretRef,
    ) -> None:
        self._service = service
        self._policy = policy
        self.name = target
        self.declared_env = declared_env
        self.ref = ref
        self._target: Target | None = None
        self._login = asyncio.Lock()

    def attach(self, target: Target) -> None:
        """The opened target, whose `destinations()` the pins are checked against."""
        self._target = target

    async def check(self) -> EnvPin:
        """M6 step 7: resolve the secret (cache or store), check the destination pin against
        `Target.destinations()` and return the effective environment. Raises `PinError`,
        `StoreError` or `SessionLocked`."""
        return self._grant(await self._service.current(self.ref))

    def _grant(self, fetched: Fetched) -> EnvPin:
        target = self._target
        if target is None:
            raise RuntimeError(f"target {self.name} has not been opened")
        if fetched.pin_error is not None:
            raise fetched.pin_error
        pins = fetched.pins if fetched.pins is not None else Pins()
        secret = str(self.ref)
        check_destinations(
            pins, target.destinations(), target.default_port, secret=secret, target=self.name
        )
        return env_pin(self._policy, self.declared_env, pins.env, secret=secret)

    async def login[T](self, connect: Callable[[ResolvedSecret], Awaitable[T]]) -> T:
        scope = _SCOPE.get()
        if scope is None:
            raise RuntimeError("Secrets.login runs only while a call executes")
        async with self._login:
            self._still_unlocked(scope)
            fetched = await self._latch_gate(await self._service.current(self.ref), scope)
            self._usable(fetched, scope)
            try:
                return await connect(fetched.secret)
            except AuthFailed as exc:
                failed = exc
            if failed.final:
                why = "the account is locked or expired, so the login is never retried"
                raise self._failed(failed, (fetched,), why)
            fresh = await self._service.refetch(self.ref, fetched)
            self._still_unlocked(scope)
            self._usable(fresh, scope)
            if fresh.digest == fetched.digest:
                why = "the secret in the store is unchanged, so the login was not retried"
                raise self._failed(failed, (fetched,), why)
            try:
                return await connect(fresh.secret)
            except AuthFailed as exc:
                why = "the store had a new value and it failed as well"
                raise self._failed(exc, (fetched, fresh), why) from None

    def _still_unlocked(self, scope: CallScope) -> None:
        if not self._service.session.is_current(scope.epoch):
            raise SessionLocked

    def _usable(self, fetched: Fetched, scope: CallScope) -> None:
        """The value's pins allow this target, in the environment the call was decided with."""
        pin = self._grant(fetched)
        if pin.env != scope.env:
            raise PinError(
                f"the environment pin of secret {self.ref} changed while the call ran (it now "
                f"gives {pin.env}; the call was decided for {scope.env}); run the call again",
                rule=RULE_ENV,
            )

    async def _latch_gate(self, fetched: Fetched, scope: CallScope) -> Fetched:
        """While the target is latched, only a value that has not failed may log in. The store,
        never the server, is asked whether the value changed; a changed value ends the latch."""
        latch = self._service.latch(self.name)
        if latch is None:
            return fetched
        if fetched.digest in latch.failed:
            fetched = await self._service.refetch(self.ref, fetched)
            self._still_unlocked(scope)
        if fetched.digest not in latch.failed:
            self._service.clear_latch(self.name)
            return fetched
        raise Latched(
            f"target {self.name} is latched after an authentication failure ({latch.reason}); "
            f"no login is tried until {_utc(latch.until)} UTC. {_CLEARS}"
        )

    def _failed(self, exc: AuthFailed, tried: Iterable[Fetched], why: str) -> LoginFailed:
        minutes = f"{LATCH_SECONDS / 60:g}"
        self._service.set_latch(self.name, (f.digest for f in tried), str(exc))
        return LoginFailed(
            f"authentication failed for target {self.name}: {exc}; {why}. The target is "
            f"latched for {minutes} minutes: calls fail at once without contacting it. {_CLEARS}"
        )
