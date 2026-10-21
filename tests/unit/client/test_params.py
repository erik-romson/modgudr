from datetime import UTC, date, datetime
from decimal import Decimal

import pytest

from modgudr.client.errors import UsageError
from modgudr.client.params import (
    PARAM_TYPES,
    map_python_params,
    parse_cli_param,
    parse_cli_params,
    to_wire,
)


@pytest.mark.parametrize(
    ("item", "name", "wire"),
    [
        ("id:int=42", "id", {"t": "int", "v": 42}),
        ("id:int=+7", "id", {"t": "int", "v": 7}),
        ("note=a=b=c", "note", {"t": "str", "v": "a=b=c"}),
        ("a:str=x:y", "a", {"t": "str", "v": "x:y"}),
        ("a:INT=1", "a", {"t": "int", "v": 1}),
        ("x:null", "x", {"t": "null", "v": None}),
        ("x=", "x", {"t": "str", "v": ""}),
    ],
)
def test_accepted(item: str, name: str, wire: dict[str, object]) -> None:
    assert parse_cli_param(item) == (name, wire)


@pytest.mark.parametrize(
    ("item", "needle"),
    [
        ("id:int=x", "id"),
        ("id:int=", "id"),
        ("id:int=1_000", "id"),
        ("id:int=٣", "id"),
        ("id:int=" + "1" * 39, "id"),
        ("x:float=1", "valid types: " + ", ".join(PARAM_TYPES)),
        ("x:null=1", "x"),
        ("x:int", "x"),
        ("=1", "name"),
        ("1x=1", "1x"),
    ],
)
def test_refused(item: str, needle: str) -> None:
    with pytest.raises(UsageError) as info:
        parse_cli_param(item)
    assert info.value.exit_code == 64
    assert needle in str(info.value)


def test_38_digits_accepted() -> None:
    assert parse_cli_param("n:int=-" + "9" * 38)[1]["v"] == -int("9" * 38)


@pytest.mark.parametrize("items", [["a=1", "a=2"], ["a=1", "A=2"], ["a=1", "A:null"]])
def test_duplicates(items: list[str]) -> None:
    with pytest.raises(UsageError, match="duplicate"):
        parse_cli_params(items)


def test_parse_many() -> None:
    assert parse_cli_params(["a=1", "b:int=2"]) == {
        "a": {"t": "str", "v": "1"},
        "b": {"t": "int", "v": 2},
    }


@pytest.mark.parametrize(
    "item",
    [
        "d:date=2026-10-01",
        "t:timestamp=2026-10-01T12:30:00Z",
        "t:timestamp=2026-10-01T12:30:00+02:00",
        "t:timestamp=2026-10-01T12:30:00.123456",
        "t:timestamp=2026-10-01 12:30",
        "m:decimal=-1.50",
        "m:decimal=.5",
        "b:bytes=AAEC",
        "b:bytes=",
    ],
)
def test_typed_accepted(item: str) -> None:
    parse_cli_param(item)


@pytest.mark.parametrize(
    "item",
    [
        "d:date=2026-02-30",
        "d:date=20261001",
        "d:date=2026-W41-1",
        "t:timestamp=2026-10-01T12:30:00.1234567",
        "t:timestamp=2026-10-01T25:30:00",
        "t:timestamp=20261001T123000",
        "m:decimal=1e3",
        "m:decimal=NaN",
        "m:decimal=1,5",
        "m:decimal=1.",
        "b:bytes=@@@@",
        "b:bytes=AAE",
        "b:bytes=ÄÄÄÄ",
    ],
)
def test_typed_refused(item: str) -> None:
    with pytest.raises(UsageError) as info:
        parse_cli_param(item)
    assert info.value.exit_code == 64


def test_timestamp_zone_kept() -> None:
    assert parse_cli_param("t:timestamp=2026-10-01T12:30:00+02:00")[1]["v"].endswith("+02:00")
    assert parse_cli_param("t:timestamp=2026-10-01T12:30:00")[1]["v"] == "2026-10-01T12:30:00"
    assert parse_cli_param("t:timestamp=2026-10-01T12:30:00Z")[1]["v"].endswith("+00:00")


def test_bytes_value() -> None:
    assert parse_cli_param("b:bytes=AAEC")[1] == {"t": "bytes", "v": "AAEC"}


def test_python_values() -> None:
    assert to_wire("a", Decimal("1.10")) == {"t": "decimal", "v": "1.10"}
    assert to_wire("a", Decimal("1E+3")) == {"t": "decimal", "v": "1000"}
    assert to_wire("a", 5) == {"t": "int", "v": 5}
    assert to_wire("a", "s") == {"t": "str", "v": "s"}
    assert to_wire("a", date(2026, 10, 1)) == {"t": "date", "v": "2026-10-01"}
    assert to_wire("a", datetime(2026, 10, 1, 12, 0)) == {
        "t": "timestamp",
        "v": "2026-10-01T12:00:00",
    }
    assert to_wire("a", datetime(2026, 10, 1, 12, 0, tzinfo=UTC)) == {
        "t": "timestamp",
        "v": "2026-10-01T12:00:00+00:00",
    }
    assert to_wire("a", b"\x00") == {"t": "bytes", "v": "AA=="}
    assert to_wire("a", None) == {"t": "null", "v": None}


@pytest.mark.parametrize("value", [1.5, True, False, [1], object()])
def test_python_type_errors(value: object) -> None:
    with pytest.raises(TypeError, match="'a'"):
        to_wire("a", value)


def test_nonfinite_decimal() -> None:
    with pytest.raises(UsageError):
        to_wire("a", Decimal("NaN"))


def test_map_python_params() -> None:
    assert map_python_params({"id": 1, "n": None}) == {
        "id": {"t": "int", "v": 1},
        "n": {"t": "null", "v": None},
    }
    with pytest.raises(UsageError, match="duplicate"):
        map_python_params({"a": 1, "A": 2})
    with pytest.raises(UsageError):
        map_python_params({"1": 1})
