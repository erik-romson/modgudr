"""Calls, operation descriptions and the result sink (§9.2, M4)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal, NoReturn, Protocol

from .rules import Constraint

#: How an argument is written on the command line and typed on the wire.
ArgKind = Literal["str", "int", "bool"]

#: Bind parameter types (M4): `int` is a JSON integer, everything else a string, `null` is None.
ParamType = Literal["str", "int", "decimal", "date", "timestamp", "bytes", "null"]

#: Column types of a `header` frame (M4).
ColumnType = Literal[
    "integer",
    "number",
    "string",
    "date",
    "timestamp",
    "timestamp_tz",
    "time",
    "binary",
    "boolean",
    "variant",
    "interval",
    "other",
]

#: An encoded cell (M4): numbers, dates, binary and VARIANT are strings; NULL is None.
Cell = str | bool | None


@dataclass(frozen=True)
class ArgSpec:
    """One argument of an operation. Its `name` is the key in the request's `args`."""

    name: str
    kind: ArgKind = "str"
    help: str = ""
    required: bool = True
    #: `None` for a positional argument, else the option that carries it (`--like`).
    flag: str | None = None
    #: The value may come from `-f FILE` or standard input instead (SQL text).
    from_file: bool = False


@dataclass(frozen=True)
class OperationSpec:
    """What callers invoke on a target (`query`, `write`, `kubectl`), so clients parse generically.

    A `passthrough` operation takes everything after its name verbatim as `args.argv`; client
    flags must then come before the operation name.
    """

    name: str
    help: str
    args: tuple[ArgSpec, ...] = ()
    #: Accepts `-p name[:type]=value` binds (`args.params`).
    params: bool = False
    #: Accepts `--dry-run` (`args.dryRun`).
    dry_run: bool = False
    #: Returns rows (`header`/`row` frames) rather than text.
    rows: bool = True
    passthrough: bool = False


@dataclass(frozen=True)
class TypedParam:
    """A bind parameter as it arrives on the wire (M4): `{"t": type, "v": value}`."""

    name: str
    type: ParamType
    value: str | int | None


@dataclass(frozen=True)
class Call:
    """One request to a target: what the plugin classifies and, once allowed, executes."""

    target: str
    op: str
    #: Op-specific arguments, validated against the op's `OperationSpec`.
    args: Mapping[str, object] = field(default_factory=dict[str, object])
    audit_id: str = ""
    #: The call deadline as a `time.monotonic()` value; set when the call executes.
    deadline: float | None = None
    #: The merged constraints of the decision, for the checks that run after execution.
    constraints: Mapping[str, Constraint] = field(default_factory=dict[str, Constraint])


@dataclass(frozen=True)
class Column:
    name: str
    type: ColumnType


class ResultSink(Protocol):
    """Where a plugin writes its result (§9.2). It enforces `maxRows`/`maxBytes` and scrubs.

    A plugin never writes to the socket itself, so it cannot forget a limit.
    """

    async def header(self, columns: Sequence[Column]) -> None: ...

    async def row(self, values: Sequence[Cell]) -> None: ...

    @property
    def room(self) -> int:
        """The bytes of `maxBytes` still free, for a plugin that must not read a cell it could
        not send (an Oracle LOB, M16)."""
        ...

    def cell_too_large(self, column: str, size: int) -> NoReturn:
        """End the call with `limit` because one cell, `size` encoded bytes at least, does not
        fit in `room`. Raises `LimitReached`."""
        ...

    async def text(self, stream: str, data: str) -> None:
        """A chunk of text output (`stream` is `stdout` or `stderr`), for kubectl."""
        ...

    def report(
        self,
        *,
        affected_rows: int | None = None,
        committed: bool | None = None,
        dry_run: bool | None = None,
        exit_code: int | None = None,
    ) -> None:
        """Facts for the trailer of a write or a process (M4)."""
        ...
