"""The result sink: row and byte limits at row boundaries, scrubbing of every string."""

from __future__ import annotations

import json
import time

import pytest

from modgudr.broker.scrub import REDACTED, Scrubber
from modgudr.broker.sink import LimitedSink, LimitReached
from modgudr.spi import Cell, Column, ResultSink


class Wire:
    def __init__(self) -> None:
        self.lines: list[bytes] = []

    async def __call__(self, line: bytes) -> None:
        self.lines.append(line)

    @property
    def frames(self) -> list[dict[str, object]]:
        return [json.loads(line) for line in self.lines]

    @property
    def size(self) -> int:
        return sum(len(line) for line in self.lines)


def make(
    wire: Wire, *, max_rows: int = 100, max_bytes: int = 10_000, secrets: tuple[str, ...] = ()
) -> LimitedSink:
    scrubber = Scrubber()
    for s in secrets:
        scrubber.add(s)
    return LimitedSink(wire, scrubber.call(), max_rows=max_rows, max_bytes=max_bytes)


COLS = [Column("id", "integer"), Column("note", "string")]


def test_implements_the_protocol() -> None:
    sink: ResultSink = make(Wire())
    assert sink is not None


async def test_exactly_max_rows_is_complete() -> None:
    wire = Wire()
    sink = make(wire, max_rows=3)
    await sink.header(COLS)
    for i in range(3):
        await sink.row([str(i), "x"])
    await sink.finish()
    assert (sink.rows, sink.truncated, sink.reason) == (3, False, None)
    assert [f["t"] for f in wire.frames] == ["header", "row", "row", "row"]
    assert wire.frames[0] == {
        "t": "header",
        "columns": [{"name": "id", "type": "integer"}, {"name": "note", "type": "string"}],
    }


async def test_one_more_than_max_rows_truncates_by_rows() -> None:
    wire = Wire()
    sink = make(wire, max_rows=3)
    await sink.header(COLS)
    for i in range(3):
        await sink.row([str(i), "x"])
    with pytest.raises(LimitReached) as exc:
        await sink.row(["3", "x"])
    assert exc.value.reason == "rows"
    assert (sink.rows, sink.truncated, sink.reason) == (3, True, "rows")
    assert len(wire.frames) == 4


async def test_bytes_reached_between_rows_truncates_at_a_row_boundary() -> None:
    wire = Wire()
    one = len(b'{"t":"row","v":["1","abcdefghij"]}\n')
    sink = make(wire, max_bytes=one * 2 + 5)
    await sink.header(COLS)
    await sink.row(["1", "abcdefghij"])
    await sink.row(["2", "abcdefghij"])
    with pytest.raises(LimitReached) as exc:
        await sink.row(["3", "abcdefghij"])
    assert exc.value.reason == "bytes"
    assert exc.value.column is None
    assert (sink.rows, sink.bytes, sink.truncated, sink.reason) == (2, one * 2, True, "bytes")
    assert [f["t"] for f in wire.frames] == ["header", "row", "row"]


async def test_one_row_larger_than_max_bytes_gives_header_only_and_names_the_column() -> None:
    wire = Wire()
    sink = make(wire, max_bytes=200)
    await sink.header(COLS)
    with pytest.raises(LimitReached) as exc:
        await sink.row(["1", "z" * 1000])
    assert exc.value.column == "note"
    assert exc.value.size is not None and exc.value.size >= 1000
    assert "note" in str(exc.value)
    assert [f["t"] for f in wire.frames] == ["header"]
    assert (sink.rows, sink.truncated) == (0, True)


async def test_cells_and_column_names_are_scrubbed() -> None:
    wire = Wire()
    sink = make(wire, secrets=("abcdefgh", "1234567"))
    await sink.header([Column("abcdefgh", "string"), Column("n", "string")])
    await sink.row(["pw=abcdefgh", "1234567"])
    frames = wire.frames
    assert frames[0]["columns"][0]["name"] == REDACTED  # pyright: ignore[reportIndexIssue]
    assert frames[1]["v"] == [f"pw={REDACTED}", "1234567"]
    assert sink.scrubbed == 2


async def test_secret_with_json_special_characters_is_replaced_before_encoding() -> None:
    wire = Wire()
    value = 'pa"ss\\word\tü'
    sink = make(wire, secrets=(value,))
    await sink.row([f"x{value}y"])
    assert b"pa" not in wire.lines[0]
    assert wire.frames[0]["v"] == [f"x{REDACTED}y"]


async def test_non_string_cells_pass() -> None:
    wire = Wire()
    sink = make(wire)
    cells: list[Cell] = [None, True, "1.50"]
    await sink.row(cells)
    assert wire.frames[0]["v"] == cells


async def test_lone_surrogate_in_a_cell_is_encoded() -> None:
    wire = Wire()
    sink = make(wire)
    await sink.row(["a\ud800b"])
    assert wire.frames[0]["v"] == ["a\ud800b"]


async def test_text_chunks_are_scrubbed_across_chunk_boundaries() -> None:
    wire = Wire()
    sink = make(wire, secrets=("topsecret-token",))
    for part in ("out topsec", "ret-to", "ken done\n"):
        await sink.text("stdout", part)
    await sink.text("stderr", "warning topsecret-token")
    await sink.finish()
    got = {"stdout": "", "stderr": ""}
    for f in wire.frames:
        got[str(f["stream"])] += str(f["data"])
    assert got == {"stdout": f"out {REDACTED} done\n", "stderr": f"warning {REDACTED}"}
    assert sink.scrubbed == 2


async def test_text_over_max_bytes_is_cut_and_ends_the_call() -> None:
    wire = Wire()
    sink = make(wire, max_bytes=120)
    with pytest.raises(LimitReached) as exc:
        for _ in range(10):
            await sink.text("stdout", "line of output " * 4 + "\n")
    assert exc.value.reason == "bytes"
    assert wire.size <= 120
    assert sink.bytes == wire.size
    assert sink.truncated


async def test_report_collects_trailer_facts() -> None:
    sink = make(Wire())
    sink.report(affected_rows=3, committed=False)
    sink.report(dry_run=True, exit_code=1)
    assert (sink.affected_rows, sink.committed, sink.dry_run, sink.exit_code) == (3, False, True, 1)


async def test_large_result_under_five_seconds() -> None:
    secrets = tuple(f"secret-{i}-value" for i in range(5))
    sent = 0

    async def drop(line: bytes) -> None:
        nonlocal sent
        sent += 1

    scrubber = Scrubber()
    for s in secrets:
        scrubber.add(s)
    sink = LimitedSink(drop, scrubber.call(), max_rows=1_000_000, max_bytes=10**9)
    row: list[Cell] = [f"col{j}-plain" for j in range(20)]
    for i, s in enumerate(secrets):
        row[i * 3] = f"x {s} y"
    start = time.monotonic()
    for _ in range(100_000):
        await sink.row(row)
    assert time.monotonic() - start < 5
    assert sink.rows == sent == 100_000
    assert sink.scrubbed == 500_000
