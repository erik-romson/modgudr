"""The Oracle `SqlDialect`: its properties, catalogues and bind values (M12, M13)."""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal

import pytest

from modgudr.broker.registry import PluginRegistry
from modgudr.spi import Risk, TypedParam
from modgudr.sql.binds import BindError, bind, find_placeholders
from modgudr.sql.dialects.oracle import OracleDialect

DIALECT = OracleDialect()


def test_properties_and_registration() -> None:
    assert (DIALECT.name, DIALECT.sqlglot_dialect, DIALECT.default_port) == (
        "oracle",
        "oracle",
        1521,
    )
    assert DIALECT.bind_style == "named"
    registry = PluginRegistry()
    registry.register_dialect(DIALECT)
    assert registry.dialect("oracle") is DIALECT


def test_the_entry_point_group_provides_both_dialects() -> None:
    registry = PluginRegistry.discover()
    assert {d.name for d in registry.dialects()} == {"snowflake", "oracle"}


def test_catalogues() -> None:
    functions = DIALECT.function_catalogue()
    assert functions["UTL_*"] is Risk.ADMIN
    assert functions["DBMS_XPLAN.*"] is Risk.READ
    objects = DIALECT.object_catalogue()
    assert objects["DBA_USERS"] is Risk.SECRET
    assert objects["V$*"] is Risk.READ


@pytest.mark.parametrize(
    ("param", "expected"),
    [
        (TypedParam("a", "str", "x"), "x"),
        (TypedParam("a", "int", 3), 3),
        (TypedParam("a", "decimal", "1.50"), Decimal("1.50")),
        (TypedParam("a", "date", "2026-01-02"), date(2026, 1, 2)),
        (TypedParam("a", "timestamp", "2026-01-02T03:04:05"), datetime(2026, 1, 2, 3, 4, 5)),
        (TypedParam("a", "null", None), None),
    ],
)
def test_bind_value(param: TypedParam, expected: object) -> None:
    assert DIALECT.bind_value(param) == expected


@pytest.mark.parametrize("value", ["2026-01-02T03:04:05Z", "2026-01-02T03:04:05+02:00"])
def test_a_timestamp_with_a_zone_is_refused(value: str) -> None:
    with pytest.raises(BindError, match="FROM_TZ"):
        DIALECT.bind_value(TypedParam("ts", "timestamp", value))


def test_binds_are_native_and_by_name() -> None:
    sql = "select '12:30', q'[:x]' from dual where username = :ID"
    names = [p.name for p in find_placeholders(sql, "oracle")]
    assert names == ["ID"]
    bound = bind(sql, [TypedParam("id", "int", 1)], dialect="oracle", style="named")
    assert bound.sql == sql


def test_a_positional_bind_is_refused() -> None:
    with pytest.raises(BindError, match="positional"):
        find_placeholders("select * from t where id = :1", "oracle")
