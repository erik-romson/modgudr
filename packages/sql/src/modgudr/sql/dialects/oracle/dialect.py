"""The Oracle `SqlDialect` (§8.1 "Oracle specifics", M12, M13).

Oracle binds natively by name: the statement keeps its `:name` placeholders and the driver gets a
dict. A timestamp with a zone is refused, because python-oracledb drops the zone silently.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import TYPE_CHECKING

from modgudr.spi import Action, BindStyle, Risk, TypedParam
from modgudr.sql.binds import BindError, parse_value
from modgudr.sql.classify import classify

from .catalogue import FUNCTIONS, OBJECTS, RULES, SQLGLOT_DIALECT

if TYPE_CHECKING:
    from modgudr.sql.config import SqlConfig
    from modgudr.sql.driver import Driver


class OracleDialect:
    """The Oracle dialect: its classifier, catalogues and binding."""

    @property
    def name(self) -> str:
        return "oracle"

    @property
    def sqlglot_dialect(self) -> str:
        return SQLGLOT_DIALECT

    @property
    def default_port(self) -> int:
        return 1521

    @property
    def bind_style(self) -> BindStyle:
        return "named"

    def classify(self, sql: str) -> Action:
        """Name, risk and facts of one statement (M12). Never raises."""
        return classify(sql, RULES)

    def function_catalogue(self) -> Mapping[str, Risk]:
        return dict(FUNCTIONS)

    def object_catalogue(self) -> Mapping[str, Risk]:
        return dict(OBJECTS)

    def bind_value(self, param: TypedParam) -> object:
        """A typed parameter as python-oracledb binds it. Raises `BindError`."""
        value = parse_value(param)
        if isinstance(value, datetime) and value.tzinfo is not None:
            raise BindError(
                f"parameter {param.name}: Oracle does not take a timestamp with a zone; give a "
                "wall-clock timestamp or use FROM_TZ in the statement"
            )
        return value

    def tables_query(self, *, in_schema: bool = False) -> str:
        # `--schema` only sets CURRENT_SCHEMA, which all_objects ignores, so filter on it here.
        owner = "and owner = sys_context('USERENV', 'CURRENT_SCHEMA') " if in_schema else ""
        return (
            "select owner as table_schema, object_name as table_name, object_type as table_type "
            f"from all_objects where object_type in ('TABLE', 'VIEW') {owner}"
            "and upper(object_name) like upper(:pattern) order by owner, object_name"
        )

    def describe_query(self) -> str:
        return "select * from {table} where 1 = 0"

    def sample_query(self) -> str:
        return "select * from {table} fetch first {n} rows only"

    def driver(self, config: SqlConfig) -> Driver:
        """The driver adapter of a target. `oracledb` is imported here, not at start, so
        classifying works without the `oracle` extra."""
        from .driver_oracle import OracleDriver

        return OracleDriver(config)
