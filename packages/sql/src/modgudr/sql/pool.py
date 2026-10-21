"""A small session pool per target (M15): idle 5 minutes, at most `maxConcurrent` sessions.

The broker's slots keep a target at `maxConcurrent` calls, and a new session opens only when no
idle one is free, so the pool never holds more sessions than that. It also knows the sessions
that are checked out, so a lock can abandon them (M7): closing is never waited for.
"""

from __future__ import annotations

import contextlib
import threading
import time
from collections.abc import Awaitable, Callable

from .driver import Session

IDLE_SECONDS = 300.0


class SessionPool:
    def __init__(
        self,
        *,
        idle_seconds: float = IDLE_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._idle_seconds = idle_seconds
        self._clock = clock
        self._idle: list[tuple[Session, float]] = []
        self._out: dict[int, tuple[Session, int]] = {}
        self._generation = 0

    @property
    def idle(self) -> int:
        return len(self._idle)

    @property
    def checked_out(self) -> int:
        return len(self._out)

    async def acquire(self, open_session: Callable[[], Awaitable[Session]]) -> Session:
        """An idle session younger than the idle limit, else a new one."""
        now = self._clock()
        while self._idle:
            session, since = self._idle.pop()
            if now - since < self._idle_seconds:
                self._out[id(session)] = (session, self._generation)
                return session
            dispose(session, abandon=False)
        generation = self._generation
        session = await open_session()
        if generation != self._generation:
            # A lock came while the login ran: the session is not kept.
            dispose(session, abandon=True)
            raise PoolClosed
        self._out[id(session)] = (session, generation)
        return session

    def release(self, session: Session) -> None:
        """Return a healthy session."""
        entry = self._out.pop(id(session), None)
        if entry is None or entry[1] != self._generation:
            dispose(session, abandon=False)
            return
        self._idle.append((session, self._clock()))

    def discard(self, session: Session) -> None:
        """Drop a session that failed or was cancelled."""
        self._out.pop(id(session), None)
        dispose(session, abandon=True)

    def close_all(self) -> None:
        """Lock (M7): abandon every session, idle or in use, without waiting."""
        self._generation += 1
        idle, self._idle = self._idle, []
        out, self._out = list(self._out.values()), {}
        for session, _ in idle:
            dispose(session, abandon=False)
        for session, _ in out:
            dispose(session, abandon=True)


class PoolClosed(Exception):
    """The pool closed (a lock) while a session was being opened."""


def dispose(session: Session, *, abandon: bool) -> None:
    """Close in a daemon thread: closing talks to the server and must not block the loop."""

    def run() -> None:
        with contextlib.suppress(Exception):  # disposal is best effort and never raises
            if abandon:
                session.abandon()
            else:
                session.close()

    threading.Thread(target=run, name="modgudr-sql-close", daemon=True).start()
