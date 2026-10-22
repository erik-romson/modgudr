"""Oracle type mapping and LOB budgets (M16), against fake LOBs: no database needed."""

from __future__ import annotations

import base64

import pytest

from modgudr.sql.dialects.oracle.types import (
    BLOB_CHUNK,
    CLOB_CHUNK,
    ROW_OVERHEAD,
    base64_size,
    column_type,
    encode_row,
    read_blob,
    read_clob,
)
from modgudr.sql.driver import CellTooLarge


class FakeLob:
    def __init__(self, data: str | bytes) -> None:
        self.data = data
        self.reads: list[tuple[int, int]] = []

    def size(self) -> int:
        return len(self.data)

    def read(self, offset: int = 1, amount: int | None = None) -> str | bytes:
        assert amount is not None
        self.reads.append((offset, amount))
        return self.data[offset - 1 : offset - 1 + amount]


@pytest.mark.parametrize(
    ("name", "precision", "scale", "expected"),
    [
        ("DB_TYPE_NUMBER", 10, 0, "integer"),
        ("DB_TYPE_NUMBER", 0, -127, "number"),
        ("DB_TYPE_NUMBER", None, None, "number"),
        ("DB_TYPE_NUMBER", 10, 2, "number"),
        ("DB_TYPE_BINARY_DOUBLE", None, None, "number"),
        ("DB_TYPE_DATE", None, None, "timestamp"),
        ("DB_TYPE_TIMESTAMP", 0, 6, "timestamp"),
        ("DB_TYPE_RAW", None, None, "binary"),
        ("DB_TYPE_BLOB", None, None, "binary"),
        ("DB_TYPE_LONG", None, None, "string"),
        ("DB_TYPE_CLOB", None, None, "string"),
        ("DB_TYPE_VARCHAR", None, None, "string"),
        ("DB_TYPE_BOOLEAN", None, None, "boolean"),
        ("DB_TYPE_OBJECT", None, None, "other"),
    ],
)
def test_column_types(name: str, precision: int | None, scale: int | None, expected: str) -> None:
    assert column_type(name, precision, scale) == expected


def test_a_clob_that_cannot_fit_by_characters_is_refused_before_any_read() -> None:
    lob = FakeLob("x" * 1000)
    with pytest.raises(CellTooLarge) as caught:
        read_clob(lob, "C", 500)
    assert caught.value.column == "C" and caught.value.size == 1002
    assert lob.reads == []


def test_a_clob_is_read_in_chunks_and_whole_when_it_fits() -> None:
    text = "a" * (CLOB_CHUNK * 2 + 5)
    lob = FakeLob(text)
    assert read_clob(lob, "C", len(text) + 2) == text
    assert [amount for _, amount in lob.reads] == [CLOB_CHUNK, CLOB_CHUNK, 5]
    assert [offset for offset, _ in lob.reads] == [1, CLOB_CHUNK + 1, 2 * CLOB_CHUNK + 1]


def test_a_clob_stops_at_the_first_chunk_that_passes_the_budget() -> None:
    lob = FakeLob("€" * (CLOB_CHUNK * 4))  # each sign is 6 bytes once escaped
    room = CLOB_CHUNK * 7
    with pytest.raises(CellTooLarge):
        read_clob(lob, "C", room)
    assert len(lob.reads) == 2  # one chunk fits (6 x 256 Ki), the second passes the budget


def test_escapes_count_as_encoded_bytes() -> None:
    lob = FakeLob('"' * 100)
    with pytest.raises(CellTooLarge):
        read_clob(lob, "C", 150)  # 100 characters fit, 200 escaped bytes do not
    assert len(lob.reads) == 1
    assert read_clob(FakeLob('"' * 100), "C", 202) == '"' * 100


def test_a_blob_is_refused_by_its_exact_encoded_size() -> None:
    lob = FakeLob(b"\x01" * 3000)
    assert base64_size(3000) == 4002
    with pytest.raises(CellTooLarge) as caught:
        read_blob(lob, "B", 4001)
    assert caught.value.size == 4002 and lob.reads == []
    assert read_blob(lob, "B", 4002) == base64.b64encode(b"\x01" * 3000).decode()


def test_a_blob_is_read_in_chunks_of_one_mebibyte_encoded() -> None:
    data = b"\x07" * (BLOB_CHUNK + 10)
    lob = FakeLob(data)
    assert read_blob(lob, "B", base64_size(len(data))) == base64.b64encode(data).decode()
    assert [amount for _, amount in lob.reads] == [BLOB_CHUNK, 10]
    assert base64_size(BLOB_CHUNK) - 2 == 1024 * 1024


def test_a_row_spends_the_budget_on_its_other_cells_first() -> None:
    kinds = ["string", "string", "binary"]
    names = ["CLOB_COL", "ID", "BLOB_COL"]
    types = ["DB_TYPE_CLOB", "DB_TYPE_VARCHAR", "DB_TYPE_BLOB"]
    clob, blob = FakeLob("t" * 100), FakeLob(b"b" * 30)
    # 102 for the CLOB, 42 for the BLOB, 7 for "row-id", plus the frame and the commas.
    needed = ROW_OVERHEAD + 3 + 102 + 8 + base64_size(30)
    cells = encode_row([clob, "row-id", blob], kinds, types, names, needed)  # type: ignore[arg-type]
    assert cells == ["t" * 100, "row-id", base64.b64encode(b"b" * 30).decode()]
    with pytest.raises(CellTooLarge) as caught:
        encode_row(
            [FakeLob("t" * 100), "row-id", FakeLob(b"b" * 30)], kinds, types, names, needed - 1
        )  # type: ignore[list-item]
    assert caught.value.column == "BLOB_COL"


def test_null_lobs_and_plain_cells() -> None:
    types = ["DB_TYPE_CLOB", "DB_TYPE_NUMBER", "DB_TYPE_BLOB"]
    cells = encode_row(
        [None, 5, None], ["string", "integer", "binary"], types, ["A", "B", "C"], 100
    )
    assert cells == [None, "5", None]
