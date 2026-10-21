"""The `sql` target keys (M10) and the plugin registration (M24)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from modgudr.broker.registry import CONNECTORS, SQL_DIALECTS, PluginRegistry
from modgudr.sql.config import SqlConfig

BASE = {
    "dialect": "snowflake",
    "account": "acme-example",
    "user": "APP_RO",
    "role": "R",
    "warehouse": "W",
}


def test_a_snowflake_target() -> None:
    config = SqlConfig.model_validate({**BASE, "database": "D", "schema": "S"})
    assert (config.account, config.database, config.schema_) == ("acme-example", "D", "S")
    assert config.value("schema") == "S" and config.value("role") == "R"


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"dialect": "oracle"}, "unknown sql dialect 'oracle'; available: snowflake"),
        ({"account": None}, "needs account"),
        ({"user": None, "role": None}, "needs role, user"),
        ({"host": "x.example.net"}, "unknown key|Extra inputs"),
        ({"account": "evil.com/x"}, "not a Snowflake account identifier"),
    ],
)
def test_bad_targets_are_refused(change: dict[str, object], message: str) -> None:
    data = {**BASE, **change}
    data = {k: v for k, v in data.items() if v is not None}
    with pytest.raises(ValidationError, match=message):
        SqlConfig.model_validate(data)


def test_the_connector_and_dialect_register_through_entry_points() -> None:
    registry = PluginRegistry.discover()
    connector = registry.connector_plugin("sql")
    assert connector is not None and connector.type == "sql"
    dialect = registry.dialect("snowflake")
    assert dialect is not None and dialect.default_port == 443
    origins = {(o.group, o.name): o.distribution for o in registry.origins()}
    assert origins[(CONNECTORS, "sql")] == "modgudr-sql"
    assert origins[(SQL_DIALECTS, "snowflake")] == "modgudr-sql"
    policy = registry.connector("sql")
    assert policy is not None
    assert policy.supports("requireWhere", "delete") and policy.supports(
        "maxAffectedRows", "update"
    )
    assert not policy.supports("requireWhere", "insert")
