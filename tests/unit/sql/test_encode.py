"""Result values on the wire (M4)."""

from __future__ import annotations

from datetime import UTC, date, datetime, time, timedelta, timezone
from decimal import Decimal

import pytest

from modgudr.sql.dialects.snowflake.types import column_type
from modgudr.sql.encode import encode_value


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        (True, True),
        (12, "12"),
        (10**30, "1000000000000000000000000000000"),
        (Decimal("1.50"), "1.50"),
        (Decimal("1E+3"), "1000"),
        (Decimal("0.00000001"), "0.00000001"),
        (Decimal("-0.5"), "-0.5"),
        (1e20, "100000000000000000000"),
        (1.5e-7, "0.00000015"),
        (float("nan"), "NaN"),
        (float("-inf"), "-Infinity"),
        ("text", "text"),
        (b"\xca\xfe", "yv4="),
        (bytearray(b"hi"), "aGk="),
        (date(2026, 10, 2), "2026-10-02"),
        (time(8, 30, 5), "08:30:05"),
        (datetime(2026, 10, 1, 8, 0), "2026-10-01T08:00:00"),
        (
            datetime(2026, 10, 1, 8, 0, tzinfo=timezone(timedelta(hours=2))),
            "2026-10-01T08:00:00+02:00",
        ),
        (datetime(2026, 10, 1, 8, 0, tzinfo=UTC), "2026-10-01T08:00:00+00:00"),
    ],
)
def test_values(value: object, expected: object) -> None:
    assert encode_value(value, "other") == expected


def test_variant_python_objects_become_json_text() -> None:
    assert encode_value({"a": [1, 2]}, "variant") == '{"a":[1,2]}'
    assert encode_value('{"a": 1}', "variant") == '{"a": 1}'


@pytest.mark.parametrize(
    ("code", "scale", "expected"),
    [
        (0, 0, "integer"),
        (0, None, "integer"),
        (0, 2, "number"),
        (1, None, "number"),
        (2, None, "string"),
        (3, None, "date"),
        (5, None, "variant"),
        (6, None, "timestamp_tz"),
        (7, None, "timestamp_tz"),
        (8, None, "timestamp"),
        (9, None, "variant"),
        (10, None, "variant"),
        (11, None, "binary"),
        (12, None, "time"),
        (13, None, "boolean"),
        (14, None, "other"),
        (99, None, "other"),
    ],
)
def test_snowflake_column_types(code: int, scale: int | None, expected: str) -> None:
    assert column_type(code, scale) == expected
