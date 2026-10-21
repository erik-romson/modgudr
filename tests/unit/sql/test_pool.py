"""The session pool (M15): idle expiry, reuse, and a lock that abandons everything."""

from __future__ import annotations

import time
from collections.abc import Sequence

import pytest

from modgudr.sql.driver import Session, Statement
from modgudr.sql.pool import PoolClosed, SessionPool


class FakeSession:
    def __init__(self) -> None:
        self.closed = 0
        self.abandoned = 0

    def run(self, sql: str, params: Sequence[object], *, timeout: float, tag: str) -> Statement:
        raise NotImplementedError

    def commit(self) -> None: ...

    def rollback(self) -> None: ...

    def close(self) -> None:
        self.closed += 1

    def abandon(self) -> None:
        self.abandoned += 1


class Clock:
    now = 1000.0

    def __call__(self) -> float:
        return self.now


async def opener_of(created: list[FakeSession]):  # noqa: ANN201
    session = FakeSession()
    created.append(session)
    return session


def wait(predicate: object, seconds: float = 2.0) -> None:
    deadline = time.monotonic() + seconds
    while not predicate() and time.monotonic() < deadline:  # type: ignore[operator]
        time.sleep(0.005)
    assert predicate()  # type: ignore[operator]


async def test_a_released_session_is_reused_until_it_idles_out() -> None:
    clock = Clock()
    pool = SessionPool(idle_seconds=300, clock=clock)
    created: list[FakeSession] = []

    async def open_session() -> Session:
        return await opener_of(created)

    first = await pool.acquire(open_session)
    pool.release(first)
    assert await pool.acquire(open_session) is first
    pool.release(first)
    clock.now += 301
    second = await pool.acquire(open_session)
    assert second is not first and len(created) == 2
    wait(lambda: first.closed == 1)


async def test_close_all_abandons_idle_and_checked_out_sessions() -> None:
    pool = SessionPool()
    created: list[FakeSession] = []

    async def open_session() -> Session:
        return await opener_of(created)

    busy = await pool.acquire(open_session)
    idle = await pool.acquire(open_session)
    pool.release(idle)
    pool.close_all()
    wait(lambda: busy.abandoned == 1 and idle.closed == 1)
    pool.release(busy)  # a late return after the lock is not pooled
    assert pool.idle == 0 and pool.checked_out == 0
    fresh = await pool.acquire(open_session)
    assert fresh is not busy and fresh is not idle


async def test_a_session_opened_while_the_pool_closed_is_dropped() -> None:
    pool = SessionPool()
    created: list[FakeSession] = []

    async def open_session() -> Session:
        session = await opener_of(created)
        pool.close_all()
        return session

    with pytest.raises(PoolClosed):
        await pool.acquire(open_session)
    wait(lambda: created[0].abandoned == 1)
