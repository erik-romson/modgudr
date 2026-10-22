"""Oracle column types and cell encoding as the wire knows them (M4, M16).

Nothing here imports `oracledb`: a column's type is named by `DbType.name` (`DB_TYPE_NUMBER`) and
a LOB is any object with `size()` and `read(offset, amount)`, so the logic is testable without a
database. The driver adapter supplies the real objects.
"""

from __future__ import annotations

import base64
import json
import math
from collections.abc import Sequence
from typing import Protocol, cast

from modgudr.spi import Cell, ColumnType
from modgudr.sql.driver import CellTooLarge
from modgudr.sql.encode import encode_value

#: `DbType.name` to wire type. A name this table does not know is `other`.
_BY_NAME: dict[str, ColumnType] = {
    "DB_TYPE_BINARY_INTEGER": "integer",
    "DB_TYPE_BINARY_DOUBLE": "number",
    "DB_TYPE_BINARY_FLOAT": "number",
    "DB_TYPE_VARCHAR": "string",
    "DB_TYPE_NVARCHAR": "string",
    "DB_TYPE_CHAR": "string",
    "DB_TYPE_NCHAR": "string",
    "DB_TYPE_LONG": "string",
    "DB_TYPE_LONG_NVARCHAR": "string",
    "DB_TYPE_CLOB": "string",
    "DB_TYPE_NCLOB": "string",
    "DB_TYPE_ROWID": "string",
    "DB_TYPE_UROWID": "string",
    "DB_TYPE_JSON": "variant",
    # DATE has a time part, so it is a timestamp on the wire.
    "DB_TYPE_DATE": "timestamp",
    "DB_TYPE_TIMESTAMP": "timestamp",
    # The thin driver delivers a zoned value as a wall clock without its offset (a deviation from
    # M16, see the run report), so it is a plain `timestamp` on the wire, never `timestamp_tz`.
    "DB_TYPE_TIMESTAMP_TZ": "timestamp",
    "DB_TYPE_TIMESTAMP_LTZ": "timestamp",
    "DB_TYPE_RAW": "binary",
    "DB_TYPE_LONG_RAW": "binary",
    "DB_TYPE_BLOB": "binary",
    "DB_TYPE_BFILE": "binary",
    "DB_TYPE_BOOLEAN": "boolean",
    "DB_TYPE_INTERVAL_DS": "interval",
    "DB_TYPE_INTERVAL_YM": "interval",
}

#: Columns that arrive as LOB locators (`fetch_lobs=True`) and are streamed within the budget.
TEXT_LOBS = frozenset({"DB_TYPE_CLOB", "DB_TYPE_NCLOB"})
BINARY_LOBS = frozenset({"DB_TYPE_BLOB", "DB_TYPE_BFILE"})
#: A LOB is read in chunks of at most 1 MiB of encoded data: 256 Ki characters of a CLOB, or
#: 768 KiB of a BLOB (1 MiB in base64).
CLOB_CHUNK = 256 * 1024
BLOB_CHUNK = 768 * 1024

#: `{"t":"row","v":[]}` and its newline, and a comma per cell: what a row costs besides its cells.
ROW_OVERHEAD = len('{"t":"row","v":[]}\n')


class Lob(Protocol):
    def size(self) -> int: ...

    def read(self, offset: int = 1, amount: int | None = None) -> str | bytes: ...


def column_type(name: str, precision: int | None, scale: int | None) -> ColumnType:
    """The wire type of a column. NUMBER is `integer` when it declares a precision and scale 0,
    else `number`."""
    if name == "DB_TYPE_NUMBER":
        return "integer" if precision and scale == 0 else "number"
    return _BY_NAME.get(name, "other")


def cell_size(cell: Cell) -> int:
    """The bytes a cell takes in a row frame (ASCII-escaped JSON, as the sink writes it)."""
    return len(json.dumps(cell))


def read_clob(lob: Lob, column: str, room: int) -> str:
    """The text of a CLOB, if it fits `room` encoded bytes (quotes included), else
    `CellTooLarge`.

    The character count is a lower bound of the encoded size, so a LOB that cannot fit is refused
    before any read. One that might fit is read in chunks and counted as it arrives (escapes and
    non-ASCII text cost more than one byte a character); the read stops at the first chunk that
    passes the budget.
    """
    size = lob.size()
    if size + 2 > room:
        raise CellTooLarge(column, size + 2)
    used = 2
    offset = 1
    parts: list[str] = []
    while offset <= size:
        chunk = lob.read(offset, min(CLOB_CHUNK, size - offset + 1))
        if not isinstance(chunk, str) or not chunk:
            raise ValueError(f"column {column}: the CLOB read returned no text at offset {offset}")
        offset += len(chunk)
        used += len(json.dumps(chunk)) - 2
        if used > room:
            raise CellTooLarge(column, used)
        parts.append(chunk)
    return "".join(parts)


def base64_size(count: int) -> int:
    """The length of `count` bytes in base64, plus the two quotes of the JSON string."""
    return 4 * math.ceil(count / 3) + 2


def read_blob(lob: Lob, column: str, room: int) -> str:
    """The base64 of a BLOB, if it fits `room` encoded bytes, else `CellTooLarge`. The size is
    exact, so the check before the first read is final; the count after each chunk is a guard
    against a LOB that grows while it is read."""
    size = lob.size()
    if base64_size(size) > room:
        raise CellTooLarge(column, base64_size(size))
    offset = 1
    parts: list[bytes] = []
    while offset <= size:
        chunk = lob.read(offset, min(BLOB_CHUNK, size - offset + 1))
        if not isinstance(chunk, bytes) or not chunk:
            raise ValueError(f"column {column}: the BLOB read returned no data at offset {offset}")
        offset += len(chunk)
        parts.append(chunk)
        if base64_size(offset - 1) > room:
            raise CellTooLarge(column, base64_size(offset - 1))
    return base64.b64encode(b"".join(parts)).decode("ascii")


def encode_row(
    values: Sequence[object],
    kinds: Sequence[ColumnType],
    type_names: Sequence[str],
    names: Sequence[str],
    room: int,
) -> list[Cell]:
    """One fetched row as cells. Its LOB cells are read here, one after the other, each within
    what is left of `room` after the row's other cells and the LOBs before it (M16). Raises
    `CellTooLarge` naming the column."""
    left = room - ROW_OVERHEAD - len(values)
    cells: list[Cell] = [None] * len(values)
    lobs: list[int] = []
    for i, value in enumerate(values):
        if value is not None and type_names[i] in TEXT_LOBS | BINARY_LOBS:
            lobs.append(i)
        else:
            cells[i] = encode_value(value, kinds[i])
            left -= cell_size(cells[i])
    for i in lobs:
        lob = cast("Lob", values[i])
        reader = read_clob if type_names[i] in TEXT_LOBS else read_blob
        cells[i] = reader(lob, names[i], left)
        left -= cell_size(cells[i])
    return cells
