"""The Snowflake `SqlDialect` (§8.1 "Snowflake specifics", M12, M13).

Binds are server-side only: the driver's `numeric` style (`:1`, `:2`), so values never enter the
SQL text. A timestamp with a zone binds as `TIMESTAMP_TZ`; the driver's default for `datetime` is
`TIMESTAMP_NTZ`, which the naive form keeps.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime

from modgudr.spi import Action, BindStyle, Risk, TypedParam
from modgudr.sql.binds import parse_value
from modgudr.sql.classify import classify

from .catalogue import FUNCTIONS, OBJECTS, RULES, SQLGLOT_DIALECT


class SnowflakeDialect:
    """The Snowflake dialect: its classifier, catalogues and binding."""

    @property
    def name(self) -> str:
        return "snowflake"

    @property
    def sqlglot_dialect(self) -> str:
        return SQLGLOT_DIALECT

    @property
    def default_port(self) -> int:
        return 443

    @property
    def bind_style(self) -> BindStyle:
        return "numeric"

    def classify(self, sql: str) -> Action:
        """Name, risk and facts of one statement (M12). Never raises."""
        return classify(sql, RULES)

    def function_catalogue(self) -> Mapping[str, Risk]:
        return dict(FUNCTIONS)

    def object_catalogue(self) -> Mapping[str, Risk]:
        return dict(OBJECTS)

    def bind_value(self, param: TypedParam) -> object:
        """A typed parameter as the Snowflake connector binds it. Raises `BindError`."""
        value = parse_value(param)
        if isinstance(value, datetime) and value.tzinfo is not None:
            return ("TIMESTAMP_TZ", value)
        return value

    def tables_query(self) -> str | None:
        return None

    def describe_query(self) -> str | None:
        return None
