"""The target keys of a `sql` target (M10): `dialect` and the connection keys of that dialect."""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


@dataclass(frozen=True)
class DialectKeys:
    """The connection keys a dialect takes (YAML names)."""

    required: frozenset[str]
    optional: frozenset[str] = frozenset()


#: The dialects this build can open. A dialect that is not here is a policy error.
DIALECT_KEYS: dict[str, DialectKeys] = {
    "snowflake": DialectKeys(
        required=frozenset({"account", "user", "role", "warehouse"}),
        optional=frozenset({"database", "schema"}),
    ),
}

_KEYS = ("account", "user", "role", "warehouse", "database", "schema")


class SqlConfig(BaseModel):
    """`type: sql` target keys. Which of the connection keys are required depends on the
    dialect; keys of another dialect are refused."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    dialect: str
    account: str | None = None
    user: str | None = None
    role: str | None = None
    warehouse: str | None = None
    database: str | None = None
    schema_: str | None = Field(default=None, alias="schema")

    @field_validator("account")
    @classmethod
    def _account(cls, value: str | None) -> str | None:
        if value is not None:
            from .dialects.snowflake.connect import snowflake_host

            snowflake_host(value)
        return value

    @model_validator(mode="after")
    def _dialect_keys(self) -> SqlConfig:
        keys = DIALECT_KEYS.get(self.dialect)
        if keys is None:
            known = ", ".join(sorted(DIALECT_KEYS))
            raise ValueError(f"unknown sql dialect {self.dialect!r}; available: {known}")
        given = {key for key in _KEYS if self.value(key) is not None}
        missing = sorted(keys.required - given)
        if missing:
            raise ValueError(f"dialect {self.dialect} needs {', '.join(missing)}")
        extra = sorted(given - keys.required - keys.optional)
        if extra:
            raise ValueError(f"dialect {self.dialect} takes no {', '.join(extra)}")
        return self

    def value(self, key: str) -> str | None:
        """A connection key by its YAML name."""
        return self.schema_ if key == "schema" else getattr(self, key)
