"""Result values on the wire (M4): numbers in plain notation, ISO dates, base64 binary, JSON text.

`encode_value` turns what a driver returns into a `Cell`. It never loses precision (no float
round trip for a `Decimal`) and never produces an exponent.
"""

from __future__ import annotations

import base64
import json
import math
from datetime import date, datetime, time, timedelta
from decimal import Decimal

from modgudr.spi import Cell, ColumnType


def plain_decimal(value: Decimal) -> str:
    """A decimal in plain notation: `1E+3` becomes `1000`, `0.00001` stays as written."""
    if not value.is_finite():
        return "NaN" if value.is_nan() else ("Infinity" if value > 0 else "-Infinity")
    return format(value, "f")


def plain_float(value: float) -> str:
    if math.isnan(value):
        return "NaN"
    if math.isinf(value):
        return "Infinity" if value > 0 else "-Infinity"
    return plain_decimal(Decimal(repr(value)))


def encode_value(value: object, column: ColumnType) -> Cell:
    """One driver value as a cell of a column of type `column`."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return str(value)
    if isinstance(value, Decimal):
        return plain_decimal(value)
    if isinstance(value, float):
        return plain_float(value)
    if isinstance(value, bytes | bytearray):
        return base64.b64encode(bytes(value)).decode("ascii")
    if isinstance(value, memoryview):
        return base64.b64encode(value.tobytes()).decode("ascii")
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date | time):
        return value.isoformat()
    if isinstance(value, timedelta):
        return str(value)
    if isinstance(value, str):
        return value
    if column == "variant" and isinstance(value, dict | list | tuple):
        return json.dumps(value, separators=(",", ":"), default=str)
    return str(value)
