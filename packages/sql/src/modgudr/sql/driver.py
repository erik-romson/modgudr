"""What a dialect's driver adapter provides to the `sql` connector.

A `Driver` opens `Session`s (blocking calls: the connector runs them in worker threads). A session
runs one statement at a time and hands back a `Statement` whose rows are already encoded as cells
(M4). Adapters translate their library's exceptions into the ones below, and never let a secret
into a message they choose.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol

from modgudr.spi import Cell, Column, Destination, UpstreamFailure


class SessionDead(UpstreamFailure):
    """The pooled connection died (Snowflake 390114, ORA-03113): a read may reconnect once."""


class StatementError(UpstreamFailure):
    """The server refused the statement; the session is still healthy."""


class CellTooLarge(Exception):
    """One cell cannot be sent within the bytes left of `maxBytes`: the connector ends the call
    with `limit` naming `column`. Nothing of the cell was read, or the read stopped at the
    budget. `size` is the encoded size, or a lower bound of it."""

    def __init__(self, column: str, size: int) -> None:
        super().__init__(f"column {column!r} holds at least {size} bytes")
        self.column = column
        self.size = size


class Statement(Protocol):
    @property
    def columns(self) -> Sequence[Column]: ...

    @property
    def rowcount(self) -> int | None:
        """Rows a DML statement changed; None when the driver cannot say."""
        ...

    def fetch(self, size: int, budget: int) -> Sequence[Sequence[Cell]]:
        """At most `size` encoded rows; empty at the end. `budget` is the bytes of `maxBytes`
        still free: a driver that streams large objects stops at it with `CellTooLarge`."""
        ...

    def close(self) -> None: ...


class Session(Protocol):
    def run(
        self,
        sql: str,
        params: Sequence[object] | Mapping[str, object],
        *,
        timeout: float,
        tag: str,
        op: str,
        schema: str | None,
    ) -> Statement:
        """Run one statement with server-side binds (a sequence for `numeric` placeholders, a
        mapping for `named` ones), `tag` as the query tag, `op` as the operation that asked for it
        and `timeout` seconds as the bound. `schema` is the `--schema` of the call, or None.
        Raises `TimeoutError`, `SessionDead`, `StatementError` or `UpstreamFailure`."""
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
