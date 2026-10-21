"""The store session (M7, attended only): LOCKED and UNLOCKED, the timers and failed unlocks.

This module holds the state and the clock arithmetic, nothing else; the broker (`app.py`) runs
the lock side effects and writes the audit records.

- The session starts LOCKED. Only `unlock` on `human.sock` unlocks it, and every successful
  unlock resets both timers.
- **Idle** is the time since an executing call last started or finished. Denied calls and
  metadata ops do not reset it, and a call in flight holds it off.
- **Absolute** counts from the last successful unlock.
- Deadlines are wall-clock timestamps from an injectable clock, checked at every request entry
  and by a timer: a sleeping laptop stops monotonic clocks. A clock that moves backwards past
  the unlock time locks.
- **Failed unlocks:** at most 5 within 60 s; further attempts are refused untested.
- `epoch` changes on every lock, so a call can tell whether the session it passed the lock gate
  in is still the current one.
"""

from __future__ import annotations

import math
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

#: At most this many failed unlocks within `FAILED_UNLOCK_WINDOW` seconds.
FAILED_UNLOCK_LIMIT = 5
FAILED_UNLOCK_WINDOW = 60.0

BACKWARDS = "the clock moved backwards past the unlock time"


class SessionState(StrEnum):
    LOCKED = "locked"
    UNLOCKED = "unlocked"


class LockReason(StrEnum):
    MANUAL = "manual"
    IDLE = "idle"
    ABSOLUTE = "absolute"
    STORE_INVALID = "store-invalid"
    SHUTDOWN = "shutdown"


@dataclass(frozen=True)
class Expiry:
    """A deadline that has passed: the session must lock with `reason`."""

    reason: LockReason
    detail: str | None = None


class Session:
    def __init__(
        self,
        *,
        clock: Callable[[], datetime],
        idle_lock: float,
        absolute_lock: float,
    ) -> None:
        self._clock = clock
        self.idle_lock = idle_lock
        self.absolute_lock = absolute_lock
        self.state = SessionState.LOCKED
        #: Changes on every lock.
        self.epoch = 0
        #: Successful unlocks so far; a waiting `unlock` uses it to see that another one won.
        self.unlocks = 0
        #: Why the session last locked; None before the first lock.
        self.reason: LockReason | None = None
        self.unlocked_at: float | None = None
        self.last_activity: float | None = None
        #: Executing calls; while any runs, the idle timer is held off.
        self.in_flight = 0
        self._failures: deque[float] = deque()

    def now(self) -> float:
        return self._clock().timestamp()

    @property
    def unlocked(self) -> bool:
        return self.state is SessionState.UNLOCKED

    def is_current(self, epoch: int) -> bool:
        """Whether the session a call saw at the lock gate is still unlocked and unchanged."""
        return self.unlocked and self.epoch == epoch

    # --- deadlines ----------------------------------------------------------------------------

    def expiry(self) -> Expiry | None:
        """The deadline that has passed, if any. Checked at request entry and by the timer."""
        if not self.unlocked or self.unlocked_at is None or self.last_activity is None:
            return None
        now = self.now()
        if now < self.unlocked_at:
            return Expiry(LockReason.ABSOLUTE, BACKWARDS)
        if now >= self.unlocked_at + self.absolute_lock:
            return Expiry(LockReason.ABSOLUTE)
        if self.in_flight == 0 and now >= self.last_activity + self.idle_lock:
            return Expiry(LockReason.IDLE)
        return None

    def call_started(self) -> None:
        self.in_flight += 1
        self.last_activity = self.now()

    def call_finished(self) -> None:
        self.in_flight = max(0, self.in_flight - 1)
        self.last_activity = self.now()

    # --- unlock and lock ----------------------------------------------------------------------

    def unlock_retry_after(self) -> float | None:
        """Seconds until another unlock may be tried, or None when one may be tried now."""
        now = self.now()
        # Failures stamped after `now` come from a clock that moved backwards: dropped too.
        self._failures = deque(t for t in self._failures if now - FAILED_UNLOCK_WINDOW < t <= now)
        if len(self._failures) < FAILED_UNLOCK_LIMIT:
            return None
        return float(max(1, math.ceil(self._failures[0] + FAILED_UNLOCK_WINDOW - now)))

    def unlock_failed(self) -> None:
        self._failures.append(self.now())

    def unlocked_now(self) -> bool:
        """A successful unlock: UNLOCKED, both timers reset, the failure count cleared.

        Returns True when the session was unlocked already (a re-authentication)."""
        again = self.unlocked
        now = self.now()
        self.state = SessionState.UNLOCKED
        self.unlocked_at = now
        self.last_activity = now
        self.unlocks += 1
        self._failures.clear()
        return again

    def lock(self, reason: LockReason) -> bool:
        """LOCKED. Returns False when the session was locked already (`lock` is idempotent)."""
        if not self.unlocked:
            return False
        self.state = SessionState.LOCKED
        self.reason = reason
        self.epoch += 1
        self.unlocked_at = None
        return True
