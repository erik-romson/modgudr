"""`OracleSession.abandon` against a stub connection: the drop waits for the running call.

`terminate()` under a call that is still inside the connection crashed the interpreter in CI
(`Fatal Python error: Segmentation fault` in `oracledb`); the session now holds a lock around
every blocking call and `abandon` takes it before it drops the connection.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from typing import cast

import oracledb
import pytest

from modgudr.sql.dialects.oracle import driver_oracle
from modgudr.sql.dialects.oracle.driver_oracle import OracleSession
from modgudr.sql.driver import SessionDead

WAIT = 5.0


class Stub:
    """A connection whose `execute` of `BLOCK` waits until `cancel()` or `release`."""

    def __init__(self, *, cancel_breaks: bool = True) -> None:
        self.events: list[str] = []
        self.inside = threading.Event()
        self.release = threading.Event()
        self.cancel_breaks = cancel_breaks
        self.call_timeout = 0
        self.module: str | None = None
        self.action: str | None = None
        self.client_identifier: str | None = None
        self.current_schema: str | None = None
        self._impl = self

    def cursor(self) -> StubCursor:
        return StubCursor(self)

    def cancel(self) -> None:
        self.events.append("cancel")
        if self.cancel_breaks:
            self.release.set()

    def terminate(self) -> None:
        self.events.append("terminate")

    def commit(self) -> None:
        self.events.append("commit")

    def rollback(self) -> None:
        self.events.append("rollback")

    def close(self) -> None:
        self.events.append("close")


class StubCursor:
    description = None
    rowcount = 0

    def __init__(self, conn: Stub) -> None:
        self.conn = conn

    def execute(self, sql: str, binds: Mapping[str, object] | None = None) -> None:
        if sql == "BLOCK":
            self.conn.inside.set()
            assert self.conn.release.wait(WAIT), "the stub call was never released"
            self.conn.events.append("execute returned")

    def fetchmany(self, size: int) -> list[object]:
        self.conn.events.append("fetch")
        return []

    def close(self) -> None:
        self.conn.events.append("cursor close")


def session(conn: Stub) -> OracleSession:
    return OracleSession(cast("oracledb.Connection", conn), "APP")


def run_blocking(target: OracleSession) -> threading.Thread:
    def work() -> None:
        target.run("BLOCK", {}, timeout=5, tag="a-1", op="read", schema=None)

    worker = threading.Thread(target=work, daemon=True)
    worker.start()
    return worker


def test_abandon_cancels_at_once_and_drops_only_after_the_call_returns() -> None:
    conn = Stub()
    target = session(conn)
    worker = run_blocking(target)
    assert conn.inside.wait(WAIT)
    target.abandon()
    worker.join(WAIT)
    assert conn.events.index("cancel") < conn.events.index("execute returned")
    assert conn.events.index("execute returned") < conn.events.index("terminate")


def test_a_call_that_ignores_the_cancel_is_waited_for_with_a_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(driver_oracle, "ABANDON_WARN", 0.05)
    conn = Stub(cancel_breaks=False)
    target = session(conn)
    worker = run_blocking(target)
    assert conn.inside.wait(WAIT)
    dropper = threading.Thread(target=target.abandon, daemon=True)
    dropper.start()
    dropper.join(0.3)
    assert dropper.is_alive() and conn.events == ["cancel"]  # no terminate under the call
    assert "has not returned" in caplog.text
    conn.release.set()
    worker.join(WAIT)
    dropper.join(WAIT)
    assert conn.events == ["cancel", "execute returned", "terminate"]


def test_an_abandoned_session_refuses_work_and_closes_quietly() -> None:
    conn = Stub()
    target = session(conn)
    statement = target.run("SELECT 1 FROM DUAL", {}, timeout=5, tag="a-1", op="read", schema=None)
    target.abandon()
    assert conn.events == ["cancel", "terminate"]
    with pytest.raises(SessionDead):
        target.run("SELECT 1 FROM DUAL", {}, timeout=5, tag="a-2", op="read", schema=None)
    with pytest.raises(SessionDead):
        statement.fetch(10, 1000)
    with pytest.raises(SessionDead):
        target.commit()
    with pytest.raises(SessionDead):
        target.rollback()
    statement.close()
    target.close()
    assert conn.events == ["cancel", "terminate"]  # nothing touched the dropped connection


def test_a_live_session_still_fetches_commits_and_closes() -> None:
    conn = Stub()
    target = session(conn)
    statement = target.run("SELECT 1 FROM DUAL", {}, timeout=5, tag="a-1", op="read", schema=None)
    assert statement.fetch(10, 1000) == []
    statement.close()
    target.commit()
    target.close()
    assert conn.events == ["fetch", "cursor close", "commit", "close"]
