"""The Snowflake `SqlDialect`: its properties, catalogues and bind values (M12, M13)."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta, timezone
from decimal import Decimal

import pytest

from modgudr.broker.registry import PluginRegistry
from modgudr.spi import Risk, TypedParam
from modgudr.sql.binds import BindError
from modgudr.sql.dialects.snowflake import SnowflakeDialect

DIALECT = SnowflakeDialect()


def test_properties_and_registration() -> None:
    assert (DIALECT.name, DIALECT.sqlglot_dialect, DIALECT.default_port) == (
        "snowflake",
        "snowflake",
        443,
    )
    assert DIALECT.bind_style == "numeric"
    registry = PluginRegistry()
    registry.register_dialect(DIALECT)
    assert registry.dialect("snowflake") is DIALECT


def test_function_catalogue() -> None:
    catalogue = DIALECT.function_catalogue()
    assert catalogue["SYSTEM$*"] is Risk.ADMIN
    assert catalogue["SYSTEM$GET_*"] is Risk.SECRET
    assert catalogue["SYSTEM$TYPEOF"] is Risk.READ
    assert DIALECT.object_catalogue() == {}


@pytest.mark.parametrize(
    ("param", "expected"),
    [
        (TypedParam("p", "str", "x"), "x"),
        (TypedParam("p", "str", ""), ""),
        (TypedParam("p", "int", 12), 12),
        (TypedParam("p", "decimal", "1.50"), Decimal("1.50")),
        (TypedParam("p", "date", "2026-10-21"), date(2026, 10, 21)),
        (TypedParam("p", "timestamp", "2026-10-21T08:00:00"), datetime(2026, 10, 21, 8)),
        (TypedParam("p", "bytes", "aGk="), b"hi"),
        (TypedParam("p", "null", None), None),
    ],
)
def test_bind_values(param: TypedParam, expected: object) -> None:
    value = DIALECT.bind_value(param)
    assert value == expected
    assert type(value) is type(expected)


def test_a_timestamp_with_a_zone_binds_as_timestamp_tz() -> None:
    plus_two = DIALECT.bind_value(TypedParam("p", "timestamp", "2026-10-21T08:00:00+02:00"))
    assert plus_two == (
        "TIMESTAMP_TZ",
        datetime(2026, 10, 21, 8, tzinfo=timezone(timedelta(hours=2))),
    )
    utc = DIALECT.bind_value(TypedParam("p", "timestamp", "2026-10-21T08:00:00Z"))
    assert utc == ("TIMESTAMP_TZ", datetime(2026, 10, 21, 8, tzinfo=UTC))


def test_a_bad_value_is_a_bind_error() -> None:
    with pytest.raises(BindError, match="parameter p"):
        DIALECT.bind_value(TypedParam("p", "decimal", "1e5"))
