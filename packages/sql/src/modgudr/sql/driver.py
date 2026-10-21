"""What a dialect's driver adapter provides to the `sql` connector.

A `Driver` opens `Session`s (blocking calls: the connector runs them in worker threads). A session
runs one statement at a time and hands back a `Statement` whose rows are already encoded as cells
(M4). Adapters translate their library's exceptions into the ones below, and never let a secret
into a message they choose.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from modgudr.spi import Cell, Column, Destination, UpstreamFailure


class SessionDead(UpstreamFailure):
    """The pooled connection died (Snowflake 390114, ORA-03113): a read may reconnect once."""


class StatementError(UpstreamFailure):
    """The server refused the statement; the session is still healthy."""


class Statement(Protocol):
    @property
    def columns(self) -> Sequence[Column]: ...

    @property
    def rowcount(self) -> int | None:
        """Rows a DML statement changed; None when the driver cannot say."""
        ...

    def fetch(self, size: int) -> Sequence[Sequence[Cell]]:
        """At most `size` encoded rows; empty at the end."""
        ...

    def close(self) -> None: ...


class Session(Protocol):
    def run(self, sql: str, params: Sequence[object], *, timeout: float, tag: str) -> Statement:
        """Run one statement with server-side binds, `tag` as the query tag and `timeout`
        seconds as the bound. Raises `TimeoutError`, `SessionDead`, `StatementError` or
        `UpstreamFailure`."""
        ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...

    def close(self) -> None: ...

    def abandon(self) -> None:
        """Cancel what runs and close the connection, best effort. Never raises."""
        ...


class Driver(Protocol):
    def destinations(self) -> frozenset[Destination]: ...

    def connect(self, secret: str, *, timeout: float) -> Session:
        """Open a session. Raises `AuthFailed` when the server refuses the credential (and only
        then), `UpstreamFailure` for everything else."""
        ...
