"""Rendering of row results (§6.1 output contract): `tsv`, `csv`, `json`, `ndjson`, `table`.

Renderers take the cells as they are on the wire (M4): strings, booleans and None. They write
text to a `Writer`; the CLI's writer flushes to stdout.

- `tsv` (default): header line; tab, newline, CR and backslash escaped as `\\t \\n \\r \\\\`;
  NULL is `\\N`, so the text `\\N` becomes `\\\\N`.
- `csv`: RFC 4180, CRLF line ends, NULL as an empty field.
- `json`: one document `{"columns": [...], "rows": [...]}`, with `"truncated": true` when the
  result was cut. `ndjson`: one object per row. Duplicate column names get `_2`, `_3` suffixes.
- `table`: for humans; it may change.
"""

import csv
import json
from collections.abc import Sequence
from typing import Protocol

from modgudr.client.protocol import Column

FORMATS = ("tsv", "csv", "json", "ndjson", "table")

Cell = str | bool | None


class Writer(Protocol):
    def write(self, text: str, /) -> object: ...


class Renderer(Protocol):
    def begin(self, columns: Sequence[Column]) -> None:
        """The header frame arrived: always called once, also for an empty result."""
        ...

    def row(self, values: Sequence[object]) -> None: ...

    def end(self, *, truncated: bool = False) -> None: ...


def cell_text(value: object) -> str | None:
    """A wire cell as text; None stays None."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value
    return json.dumps(value)


def unique_names(names: Sequence[str]) -> list[str]:
    """Column names for `json`/`ndjson`: a repeated name gets `_2`, `_3`, … (never a clash)."""
    used: set[str] = set(names)
    seen: set[str] = set()
    out: list[str] = []
    for name in names:
        if name not in seen:
            seen.add(name)
            out.append(name)
            continue
        number = 2
        while f"{name}_{number}" in used:
            number += 1
        unique = f"{name}_{number}"
        used.add(unique)
        seen.add(unique)
        out.append(unique)
    return out


def tsv_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r")


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


class TsvRenderer:
    def __init__(self, out: Writer, *, header: bool) -> None:
        self._out = out
        self._header = header

    def begin(self, columns: Sequence[Column]) -> None:
        if self._header:
            self._out.write("\t".join(tsv_escape(c.name) for c in columns) + "\n")

    def row(self, values: Sequence[object]) -> None:
        cells = (cell_text(v) for v in values)
        self._out.write("\t".join("\\N" if c is None else tsv_escape(c) for c in cells) + "\n")

    def end(self, *, truncated: bool = False) -> None:
        return None


class CsvRenderer:
    def __init__(self, out: Writer, *, header: bool) -> None:
        self._writer = csv.writer(out, lineterminator="\r\n")
        self._header = header

    def begin(self, columns: Sequence[Column]) -> None:
        if self._header:
            self._writer.writerow([c.name for c in columns])

    def row(self, values: Sequence[object]) -> None:
        self._writer.writerow(["" if (t := cell_text(v)) is None else t for v in values])

    def end(self, *, truncated: bool = False) -> None:
        return None


class JsonRenderer:
    def __init__(self, out: Writer) -> None:
        self._out = out
        self._names: list[str] = []
        self._started = False
        self._first = True

    def begin(self, columns: Sequence[Column]) -> None:
        self._names = unique_names([c.name for c in columns])
        described = [{"name": n, "type": c.type} for n, c in zip(self._names, columns, strict=True)]
        self._out.write('{"columns":' + _json(described) + ',"rows":[')
        self._started = True

    def row(self, values: Sequence[object]) -> None:
        prefix = "" if self._first else ","
        self._first = False
        self._out.write(prefix + _json(dict(zip(self._names, values, strict=True))))

    def end(self, *, truncated: bool = False) -> None:
        if self._started:
            self._out.write("]" + (',"truncated":true' if truncated else "") + "}\n")


class NdjsonRenderer:
    def __init__(self, out: Writer) -> None:
        self._out = out
        self._names: list[str] = []

    def begin(self, columns: Sequence[Column]) -> None:
        self._names = unique_names([c.name for c in columns])

    def row(self, values: Sequence[object]) -> None:
        self._out.write(_json(dict(zip(self._names, values, strict=True))) + "\n")

    def end(self, *, truncated: bool = False) -> None:
        return None


class TableRenderer:
    """Aligned columns. It holds the rows until the end, to size the columns."""

    def __init__(self, out: Writer, *, header: bool) -> None:
        self._out = out
        self._header = header
        self._names: list[str] = []
        self._rows: list[list[str]] = []
        self._started = False

    def begin(self, columns: Sequence[Column]) -> None:
        self._names = [_table_text(c.name) for c in columns]
        self._started = True

    def row(self, values: Sequence[object]) -> None:
        self._rows.append(
            ["NULL" if (t := cell_text(v)) is None else _table_text(t) for v in values]
        )

    def end(self, *, truncated: bool = False) -> None:
        if not self._started:
            return
        widths = [len(n) for n in self._names]
        for row in self._rows:
            widths = [max(w, len(c)) for w, c in zip(widths, row, strict=True)]
        lines: list[list[str]] = []
        if self._header:
            lines.append(self._names)
        lines.extend(self._rows)
        for index, cells in enumerate(lines):
            text = " | ".join(c.ljust(w) for c, w in zip(cells, widths, strict=True)).rstrip()
            self._out.write(text + "\n")
            if self._header and index == 0:
                self._out.write("-+-".join("-" * w for w in widths) + "\n")


def _table_text(text: str) -> str:
    return text.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")


def make_renderer(fmt: str, out: Writer, *, header: bool = True) -> Renderer:
    """The renderer of one `--format`. An unknown format is an error naming the valid ones."""
    if fmt == "tsv":
        return TsvRenderer(out, header=header)
    if fmt == "csv":
        return CsvRenderer(out, header=header)
    if fmt == "json":
        return JsonRenderer(out)
    if fmt == "ndjson":
        return NdjsonRenderer(out)
    if fmt == "table":
        return TableRenderer(out, header=header)
    raise ValueError(f"unknown format {fmt!r}; valid formats: {', '.join(FORMATS)}")
