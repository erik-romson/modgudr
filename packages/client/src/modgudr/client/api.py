"""The Python API (§6.3, MVP subset): `modgudr.connect()` and what it returns.

    mg = modgudr.connect()
    result = mg.sql("prod-ro").query("select id from po where status = :s", s="OPEN")
    for row in result:          # named tuples, streamed as they arrive
        print(row.ID)

One request per connection, no shared state: a `Client` is safe across threads, and results from
different threads are independent. A `Result` owns its socket. Closing it, or abandoning its
iterator, closes the socket, and the broker cancels the call (M4).
"""

import collections
import contextlib
import os
import sys
from collections import deque
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any, Self

from modgudr.client import paths
from modgudr.client.errors import LimitExceeded, UsageError
from modgudr.client.params import map_python_params
from modgudr.client.protocol import Column, Frame, Header, Row, Text, Trailer
from modgudr.client.protocol import Result as ResultFrame
from modgudr.client.transport import Call, client_info, open_call

__all__ = ["Client", "Column", "Result", "Sql", "connect", "truncation_note"]


def truncation_note(trailer: Mapping[str, Any]) -> str:
    """What a truncated result says about its limit, for the CLI's stderr and the exception."""
    reason = trailer.get("reason")
    rows, size = trailer.get("rows"), trailer.get("bytes")
    if reason == "rows":
        return f"truncated: the maxRows limit was reached after {rows} rows"
    if reason == "bytes":
        return f"truncated: the maxBytes limit was reached after {size} bytes"
    return "truncated: a limit was reached"


class Result:
    """A streaming result. Iterating yields rows as named tuples; `columns` and the facts of
    the trailer are there when the stream has delivered them.

    Single-pass: rows are not kept once yielded. `fetchall()` reads the rest into a list. A
    result that hit `maxRows` or `maxBytes` raises `LimitExceeded` at its end (`.partial` holds
    the rows `fetchall()` had) unless the call passed `allow_truncated=True`.
    """

    def __init__(self, call: Call, *, allow_truncated: bool = False) -> None:
        self._call = call
        self._frames: Iterator[Frame] = call.frames()
        self._allow_truncated = allow_truncated
        self._buffer: deque[Frame] = deque()
        self._columns: list[Column] | None = None
        self._row_type: Any = None
        self._trailer: Mapping[str, Any] | None = None
        self._data: Any = None
        self._text: dict[str, list[str]] = {}
        self._done = False
        # Read the first frame now, so that a refusal raises from the call that caused it.
        first = self._read()
        if first is not None:
            self._buffer.append(first)

    # --- reading ---------------------------------------------------------------------------

    def _read(self) -> Frame | None:
        if self._done:
            return None
        try:
            frame = next(self._frames)
        except StopIteration:
            self._done = True
            self.close()
            return None
        except BaseException:
            self._done = True
            self.close()
            raise
        self._apply(frame)
        return frame

    def _apply(self, frame: Frame) -> None:
        if isinstance(frame, Header):
            self._columns = list(frame.columns)
            names: list[str] = [c.name for c in frame.columns]
            self._row_type = collections.namedtuple("Row", names, rename=True)  # pyright: ignore[reportUntypedNamedTuple]
        elif isinstance(frame, Text):
            self._text.setdefault(frame.stream, []).append(frame.data)
        elif isinstance(frame, ResultFrame):
            self._data = frame.data
        elif isinstance(frame, Trailer):
            self._trailer = frame.data
            self._done = True
            self.close()
            if frame.data.get("truncated") and not self._allow_truncated:
                raise LimitExceeded(truncation_note(frame.data), audit_id=_audit_id(frame.data))

    def _pull(self) -> Frame | None:
        if self._buffer:
            return self._buffer.popleft()
        return self._read()

    def _complete(self) -> None:
        """Read every remaining frame into the buffer (rows stay available to iteration)."""
        while (frame := self._read()) is not None:
            self._buffer.append(frame)

    def __iter__(self) -> Iterator[Any]:
        try:
            while (frame := self._pull()) is not None:
                if isinstance(frame, Row):
                    yield self._row_type(*frame.values)
        finally:
            self.close()

    def fetchall(self) -> list[Any]:
        rows: list[Any] = []
        try:
            rows.extend(self)
        except LimitExceeded as exc:
            exc.partial = rows
            raise
        return rows

    def wait(self) -> Self:
        """Read the whole response (keeping its rows for iteration) and return the result."""
        self._complete()
        return self

    # --- facts -----------------------------------------------------------------------------

    @property
    def columns(self) -> list[Column]:
        """The column names and types, once the header arrived (waits for it)."""
        while self._columns is None:
            frame = self._read()
            if frame is None:
                break
            self._buffer.append(frame)
        return list(self._columns or [])

    @property
    def trailer(self) -> Mapping[str, Any]:
        self._complete()
        return self._trailer or {}

    @property
    def data(self) -> Any:  # noqa: ANN401
        """The `result` frame of a metadata op."""
        self._complete()
        return self._data

    @property
    def stdout(self) -> str:
        return self._stream("stdout")

    @property
    def stderr(self) -> str:
        return self._stream("stderr")

    def _stream(self, name: str) -> str:
        self._complete()
        return "".join(self._text.get(name, ()))

    @property
    def affected_rows(self) -> int | None:
        value = self.trailer.get("affectedRows")
        return value if isinstance(value, int) else None

    @property
    def committed(self) -> bool | None:
        value = self.trailer.get("committed")
        return value if isinstance(value, bool) else None

    @property
    def dry_run(self) -> bool | None:
        value = self.trailer.get("dryRun")
        return value if isinstance(value, bool) else None

    @property
    def exit_code(self) -> int | None:
        value = self.trailer.get("exitCode")
        return value if isinstance(value, int) and not isinstance(value, bool) else None

    @property
    def truncated(self) -> bool:
        return bool(self.trailer.get("truncated"))

    @property
    def audit_id(self) -> str | None:
        return _audit_id(self.trailer)

    # --- closing ---------------------------------------------------------------------------

    def close(self) -> None:
        """Close the socket. If the call still runs, the broker cancels it."""
        self._call.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        with contextlib.suppress(Exception):  # interpreter shutdown
            self._call.close()


def _audit_id(trailer: Mapping[str, Any]) -> str | None:
    value = trailer.get("auditId")
    return value if isinstance(value, str) else None


def _merge_binds(
    params: Mapping[str, object] | None, binds: Mapping[str, object]
) -> dict[str, Any] | None:
    """`params=` and keyword binds are two spellings of the same thing: a name in both is an
    error, never last-wins."""
    if params is None and not binds:
        return None
    given = dict(params or {})
    folded = {name.lower() for name in given}
    for name in binds:
        if name.lower() in folded:
            raise UsageError(f"parameter {name!r} is given both in params= and as a keyword")
    given.update(binds)
    return map_python_params(given)


class Client:
    """A way to reach the broker. Holds a socket path and defaults; no connection."""

    def __init__(
        self, socket_path: Path, *, env: str | None = None, session: str | None = None
    ) -> None:
        self.socket_path = socket_path
        self.env = env
        self.session = session

    def _client_info(self) -> dict[str, Any]:
        script: str | None = None
        if sys.argv and sys.argv[0]:
            candidate = Path(sys.argv[0])
            if candidate.is_file():
                script = str(candidate.resolve())
        return client_info("python", session=self.session, script=script)

    def call(
        self,
        target: str,
        op: str,
        env: str | None = None,
        args: Mapping[str, Any] | Sequence[Any] | None = None,
        *,
        params: Mapping[str, object] | None = None,
        max_rows: int | None = None,
        dry_run: bool = False,
        allow_truncated: bool = False,
        **kw: Any,  # noqa: ANN401
    ) -> Result:
        """Any operation of any plugin. `args` is a dict of the op's arguments, or a list of
        words for a passthrough op (`args=["get", "pods"]`); keyword arguments are more op
        arguments."""
        wire: dict[str, Any] = {}
        if isinstance(args, str):
            raise UsageError("args must be a dict, or a list of words, not one string")
        if isinstance(args, Mapping):
            wire.update(args)
        elif args is not None:
            words = list(args)
            if not all(isinstance(word, str) for word in words):
                raise UsageError("args must be a list of strings")
            wire["argv"] = words
        for key, value in kw.items():
            if key in wire:
                raise UsageError(f"argument {key!r} is given twice")
            wire[key] = value
        mapped = _merge_binds(params, {})
        if mapped is not None:
            wire["params"] = mapped
        if max_rows is not None:
            wire["maxRows"] = max_rows
        if dry_run:
            wire["dryRun"] = True
        return self._run(target, op, env, wire, allow_truncated=allow_truncated)

    def _run(
        self,
        target: str,
        op: str,
        env: str | None,
        args: dict[str, Any],
        *,
        allow_truncated: bool = False,
    ) -> Result:
        call = open_call(
            self.socket_path,
            op,
            target=target,
            env=env or self.env,
            args=args,
            client=self._client_info(),
        )
        try:
            return Result(call, allow_truncated=allow_truncated)
        except BaseException:
            call.close()
            raise

    def sql(self, target: str, env: str | None = None) -> "Sql":
        return Sql(self, target, env)


class Sql:
    """Typed wrappers over `Client.call` for a `sql` target."""

    def __init__(self, client: Client, target: str, env: str | None) -> None:
        self._client = client
        self.target = target
        self.env = env

    def _run(self, op: str, args: dict[str, Any], *, allow_truncated: bool = False) -> Result:
        return self._client._run(  # pyright: ignore[reportPrivateUsage]
            self.target, op, self.env, args, allow_truncated=allow_truncated
        )

    def query(
        self,
        sql: str,
        *,
        params: Mapping[str, object] | None = None,
        max_rows: int | None = None,
        allow_truncated: bool = False,
        **binds: object,
    ) -> Result:
        args: dict[str, Any] = {"sql": sql}
        self._common(args, params, binds, max_rows)
        return self._run("query", args, allow_truncated=allow_truncated)

    def write(
        self,
        sql: str,
        *,
        dry_run: bool = False,
        params: Mapping[str, object] | None = None,
        **binds: object,
    ) -> Result:
        """Run one DML statement in a transaction. Returns when it ended: `.affected_rows`,
        `.committed` and `.dry_run` are set."""
        args: dict[str, Any] = {"sql": sql}
        self._common(args, params, binds, None)
        if dry_run:
            args["dryRun"] = True
        return self._run("write", args).wait()

    def tables(
        self, like: str | None = None, *, max_rows: int | None = None, allow_truncated: bool = False
    ) -> Result:
        args: dict[str, Any] = {} if like is None else {"like": like}
        self._common(args, None, {}, max_rows)
        return self._run("tables", args, allow_truncated=allow_truncated)

    def describe(self, table: str) -> Result:
        return self._run("describe", {"table": table})

    def count(
        self,
        table: str,
        where: str | None = None,
        *,
        params: Mapping[str, object] | None = None,
        **binds: object,
    ) -> Result:
        args: dict[str, Any] = {"table": table}
        if where is not None:
            args["where"] = where
        self._common(args, params, binds, None)
        return self._run("count", args)

    def sample(
        self,
        table: str,
        n: int | None = None,
        *,
        max_rows: int | None = None,
        allow_truncated: bool = False,
    ) -> Result:
        args: dict[str, Any] = {"table": table}
        if n is not None:
            args["n"] = n
        self._common(args, None, {}, max_rows)
        return self._run("sample", args, allow_truncated=allow_truncated)

    @staticmethod
    def _common(
        args: dict[str, Any],
        params: Mapping[str, object] | None,
        binds: Mapping[str, object],
        max_rows: int | None,
    ) -> None:
        mapped = _merge_binds(params, binds)
        if mapped is not None:
            args["params"] = mapped
        if max_rows is not None:
            args["maxRows"] = max_rows


def connect(
    path: str | os.PathLike[str] | None = None,
    *,
    env: str | None = None,
    session: str | None = None,
) -> Client:
    """A client for the broker's agent socket: `path`, else `$MODGUDR_SOCKET`, else the default
    location (M1). Nothing connects until the first call. `env` (else `$MODGUDR_ENV`) is the
    default environment of calls that name none; `session` (else `$MODGUDR_SESSION`) groups the
    audit."""
    socket_path = Path(path) if path is not None else paths.agent_socket()
    chosen_env = env if env is not None else (os.environ.get("MODGUDR_ENV") or None)
    return Client(socket_path, env=chosen_env, session=session)
