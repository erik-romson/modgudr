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
        ({"dialect": "db2"}, "unknown sql dialect 'db2'; available: oracle, snowflake"),
        ({"account": None}, "needs account"),
        ({"user": None, "role": None}, "needs role, user"),
        ({"host": "x.example.net"}, "dialect snowflake takes no host"),
        ({"account": "evil.com/x"}, "not a Snowflake account identifier"),
    ],
)
def test_bad_targets_are_refused(change: dict[str, object], message: str) -> None:
    data = {**BASE, **change}
    data = {k: v for k, v in data.items() if v is not None}
    with pytest.raises(ValidationError, match=message):
        SqlConfig.model_validate(data)


ORACLE = {"dialect": "oracle", "host": "db.example.net", "user": "APP_RO", "service": "SVC"}


def test_an_oracle_target() -> None:
    config = SqlConfig.model_validate(ORACLE)
    assert (config.host, config.port, config.service, config.sid) == (
        "db.example.net",
        None,
        "SVC",
        None,
    )
    sid = SqlConfig.model_validate({**ORACLE, "service": None, "sid": "FREE", "port": 1522})
    assert (sid.sid, sid.service, sid.port) == ("FREE", None, 1522)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"service": None}, "exactly one of service and sid"),
        ({"sid": "FREE"}, "exactly one of service and sid"),
        ({"host": None}, "needs host"),
        ({"user": None}, "needs user"),
        ({"host": "(DESCRIPTION=(ADDRESS=(HOST=x)))"}, "not a host name"),
        ({"host": "db.example.net:1521/SVC"}, "not a host name"),
        ({"host": "//db.example.net"}, "not a host name"),
        ({"service": "SVC)(X"}, "not a service name"),
        ({"port": 0}, "greater than or equal to 1"),
        ({"port": 70000}, "less than or equal to 65535"),
        ({"account": "acme"}, "dialect oracle takes no account"),
        ({"schema": "APP"}, "dialect oracle takes no schema"),
    ],
)
def test_bad_oracle_targets_are_refused(change: dict[str, object], message: str) -> None:
    data = {k: v for k, v in {**ORACLE, **change}.items() if v is not None}
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
