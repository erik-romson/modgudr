"""The result sink (§9.2, M4): limits and scrubbing between a plugin and the socket.

A plugin writes only through the sink, so it cannot forget a limit or skip the scrubber. The sink
counts rows and encoded bytes, truncates at row boundaries and raises `LimitReached` to the
connector, which ends the call. The caller builds the trailer from the sink's counters.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Sequence
from typing import Literal, NoReturn

from ..spi import Cell, Column
from .scrub import CallScrubber, TextStream

#: Receives one encoded frame: a JSON line ending in a newline.
Emit = Callable[[bytes], Awaitable[None]]

LimitReason = Literal["rows", "bytes"]


class LimitReached(Exception):
    """`maxRows` or `maxBytes` ended the call. Everything before it was emitted whole.

    A single row larger than `maxBytes` also ends here, with `column` and `size` naming the
    largest cell.
    """

    def __init__(
        self,
        reason: LimitReason,
        message: str,
        *,
        column: str | None = None,
        size: int | None = None,
    ) -> None:
        super().__init__(message)
        self.reason: LimitReason = reason
        self.column = column
        self.size = size


def _encode(frame: dict[str, object]) -> bytes:
    # ASCII-escaped, so a lone surrogate in a cell cannot break the encoding.
    return json.dumps(frame, separators=(",", ":")).encode("ascii") + b"\n"


class LimitedSink:
    """A `ResultSink` that enforces `maxRows` and `maxBytes` and scrubs every string it emits."""

    def __init__(
        self,
        emit: Emit,
        scrub: CallScrubber,
        *,
        max_rows: int,
        max_bytes: int,
    ) -> None:
        self._emit = emit
        self._scrub = scrub
        self._max_rows = max_rows
        self._max_bytes = max_bytes
        self._names: list[str] = []
        self._streams: dict[str, TextStream] = {}
        self.rows = 0
        self.bytes = 0
        self.truncated = False
        self.reason: LimitReason | None = None
        self.affected_rows: int | None = None
        self.committed: bool | None = None
        self.dry_run: bool | None = None
        self.exit_code: int | None = None

    @property
    def scrubbed(self) -> int:
        return self._scrub.count

    async def header(self, columns: Sequence[Column]) -> None:
        self._names = [self._scrub.data(c.name) for c in columns]
        cols = [{"name": n, "type": c.type} for n, c in zip(self._names, columns, strict=True)]
        await self._emit(_encode({"t": "header", "columns": cols}))

    async def row(self, values: Sequence[Cell]) -> None:
        if self.rows >= self._max_rows:
            self._stop("rows", f"row limit {self._max_rows} reached")
        cells = self._scrub.cells(values)
        line = _encode({"t": "row", "v": cells})
        if len(line) > self._max_bytes:
            self._row_too_large(cells)
        if self.bytes + len(line) > self._max_bytes:
            self._stop("bytes", f"byte limit {self._max_bytes} reached")
        await self._emit(line)
        self.rows += 1
        self.bytes += len(line)

    async def text(self, stream: str, data: str) -> None:
        scrubber = self._streams.get(stream)
        if scrubber is None:
            scrubber = self._streams[stream] = self._scrub.stream()
        await self._emit_text(stream, scrubber.feed(data))

    async def finish(self) -> None:
        """End of output: emit what the scrubbers' rolling tails still hold."""
        for stream, scrubber in self._streams.items():
            await self._emit_text(stream, scrubber.flush())

    def report(
        self,
        *,
        affected_rows: int | None = None,
        committed: bool | None = None,
        dry_run: bool | None = None,
        exit_code: int | None = None,
    ) -> None:
        if affected_rows is not None:
            self.affected_rows = affected_rows
        if committed is not None:
            self.committed = committed
        if dry_run is not None:
            self.dry_run = dry_run
        if exit_code is not None:
            self.exit_code = exit_code

    async def _emit_text(self, stream: str, data: str) -> None:
        if not data:
            return

        def frame(part: str) -> bytes:
            return _encode({"t": "text", "stream": stream, "data": part})

        line = frame(data)
        room = self._max_bytes - self.bytes
        if len(line) <= room:
            await self._emit(line)
            self.bytes += len(line)
            return
        # Cut the chunk at the largest prefix that fits, then end the call.
        lo, hi = 0, len(data)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if len(frame(data[:mid])) <= room:
                lo = mid
            else:
                hi = mid - 1
        if lo:
            part = frame(data[:lo])
            await self._emit(part)
            self.bytes += len(part)
        self._stop("bytes", f"byte limit {self._max_bytes} reached")

    def _stop(self, reason: LimitReason, message: str) -> NoReturn:
        self.truncated = True
        self.reason = reason
        raise LimitReached(reason, message)

    def _row_too_large(self, cells: Sequence[Cell]) -> NoReturn:
        sizes = [len(json.dumps(v)) for v in cells]
        index = max(range(len(sizes)), key=sizes.__getitem__)
        name = self._names[index] if index < len(self._names) else f"#{index + 1}"
        message = (
            f"a row exceeds maxBytes ({self._max_bytes}): column {name!r} is {sizes[index]} bytes"
        )
        self.truncated = True
        self.reason = "bytes"
        raise LimitReached("bytes", message, column=name, size=sizes[index])
