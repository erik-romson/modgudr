"""Snowflake column types as the wire knows them (M4, M15)."""

from __future__ import annotations

from modgudr.spi import ColumnType

#: `ResultMetadata.type_code` of the connector (python-connector-api, "Type codes").
_BY_CODE: dict[int, ColumnType] = {
    1: "number",  # REAL
    2: "string",  # TEXT
    3: "date",
    4: "timestamp",
    5: "variant",
    6: "timestamp_tz",  # TIMESTAMP_LTZ: the value carries the session's offset
    7: "timestamp_tz",
    8: "timestamp",  # TIMESTAMP_NTZ
    9: "variant",  # OBJECT
    10: "variant",  # ARRAY
    11: "binary",
    12: "time",
    13: "boolean",
    17: "variant",  # MAP
    19: "interval",
    20: "interval",
}


def column_type(type_code: int, scale: int | None) -> ColumnType:
    """The wire type of a column. NUMBER is `integer` at scale 0 and `number` otherwise; a type
    this table does not know is `other`."""
    if type_code == 0:
        return "integer" if not scale else "number"
    return _BY_CODE.get(type_code, "other")
