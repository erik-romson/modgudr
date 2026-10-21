"""Bind parameters on the client side (M13): the CLI `-p` parser and the Python value mapper."""

import base64
import binascii
import re
from collections.abc import Iterable, Mapping
from datetime import date, datetime
from decimal import Decimal
from typing import Any

from modgudr.client.errors import UsageError

PARAM_TYPES = ("str", "int", "decimal", "date", "timestamp", "bytes", "null")

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_INT = re.compile(r"[+-]?[0-9]{1,38}")
_DECIMAL = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}"
    r"(?::[0-9]{2}(?:\.[0-9]{1,6})?)?(?:Z|[+-][0-9]{2}:[0-9]{2})?"
)

WireParam = dict[str, Any]


def _valid_types() -> str:
    return ", ".join(PARAM_TYPES)


def _check_name(name: str) -> None:
    if not _NAME.fullmatch(name):
        raise UsageError(
            f"parameter {name!r}: the name must be an ASCII identifier "
            "(letters, digits, underscore; not starting with a digit)"
        )


def _int_value(name: str, text: str) -> int:
    if not _INT.fullmatch(text):
        raise UsageError(f"parameter {name!r}: {text!r} is not an integer of at most 38 digits")
    return int(text)


def _decimal_value(name: str, text: str) -> str:
    if not _DECIMAL.fullmatch(text):
        raise UsageError(f"parameter {name!r}: {text!r} is not a plain decimal literal")
    return text


def _date_value(name: str, text: str) -> str:
    if not _DATE.fullmatch(text):
        raise UsageError(f"parameter {name!r}: {text!r} is not a date (YYYY-MM-DD)")
    try:
        return date.fromisoformat(text).isoformat()
    except ValueError as exc:
        raise UsageError(f"parameter {name!r}: {text!r} is not a valid date") from exc


def _timestamp_value(name: str, text: str) -> str:
    if not _TIMESTAMP.fullmatch(text):
        raise UsageError(
            f"parameter {name!r}: {text!r} is not an ISO timestamp "
            "(YYYY-MM-DDTHH:MM[:SS[.ffffff]][Z|+HH:MM], at most 6 fractional digits)"
        )
    try:
        return datetime.fromisoformat(text).isoformat()
    except ValueError as exc:
        raise UsageError(f"parameter {name!r}: {text!r} is not a valid timestamp") from exc


def _bytes_value(name: str, text: str) -> str:
    try:
        raw = base64.b64decode(text.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise UsageError(f"parameter {name!r}: the value is not strict base64") from exc
    return base64.b64encode(raw).decode("ascii")


def parse_cli_param(item: str) -> tuple[str, WireParam]:
    """Parse one `-p name[:type]=value` argument into `(name, {"t": ..., "v": ...})`."""
    left, sep, text = item.partition("=")
    name, _, type_name = left.partition(":")
    has_type = ":" in left
    kind = type_name.lower() if has_type else "str"
    _check_name(name)
    if kind not in PARAM_TYPES:
        raise UsageError(
            f"parameter {name!r}: unknown type {type_name!r}; valid types: {_valid_types()}"
        )
    if kind == "null":
        if sep:
            raise UsageError(f"parameter {name!r}: type null takes no value (use -p {name}:null)")
        return name, {"t": "null", "v": None}
    if not sep:
        raise UsageError(f"parameter {name!r}: expected name[:type]=value, got {item!r}")
    value: Any
    if kind == "str":
        value = text
    elif kind == "int":
        value = _int_value(name, text)
    elif kind == "decimal":
        value = _decimal_value(name, text)
    elif kind == "date":
        value = _date_value(name, text)
    elif kind == "timestamp":
        value = _timestamp_value(name, text)
    else:
        value = _bytes_value(name, text)
    return name, {"t": kind, "v": value}


def _add(params: dict[str, WireParam], seen: dict[str, str], name: str, wire: WireParam) -> None:
    folded = name.lower()
    if folded in seen:
        raise UsageError(
            f"duplicate parameter {name!r} (already given as {seen[folded]!r}; "
            "names are case-insensitive)"
        )
    seen[folded] = name
    params[name] = wire


def parse_cli_params(items: Iterable[str]) -> dict[str, WireParam]:
    """Parse every `-p` argument. A duplicate name, also by case, is an error (never last-wins)."""
    params: dict[str, WireParam] = {}
    seen: dict[str, str] = {}
    for item in items:
        name, wire = parse_cli_param(item)
        _add(params, seen, name, wire)
    return params


def to_wire(name: str, value: object) -> WireParam:
    """Map a Python value to `{"t": ..., "v": ...}`. `float` and `bool` raise `TypeError`."""
    if value is None:
        return {"t": "null", "v": None}
    if isinstance(value, bool):
        raise TypeError(f"parameter {name!r}: bool is not supported; use int 0/1 or a str")
    if isinstance(value, float):
        raise TypeError(f"parameter {name!r}: float is not supported; use decimal.Decimal")
    if isinstance(value, int):
        return {"t": "int", "v": value}
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise UsageError(f"parameter {name!r}: {value} is not a finite decimal")
        return {"t": "decimal", "v": format(value, "f")}
    if isinstance(value, str):
        return {"t": "str", "v": value}
    if isinstance(value, datetime):
        return {"t": "timestamp", "v": value.isoformat()}
    if isinstance(value, date):
        return {"t": "date", "v": value.isoformat()}
    if isinstance(value, bytes):
        return {"t": "bytes", "v": base64.b64encode(value).decode("ascii")}
    raise TypeError(
        f"parameter {name!r}: unsupported type {type(value).__name__}; supported: "
        "int, Decimal, str, date, datetime, bytes, None"
    )


def map_python_params(values: Mapping[str, object]) -> dict[str, WireParam]:
    """Map a Python `{name: value}` mapping to `args.params`; names are checked like the CLI's."""
    params: dict[str, WireParam] = {}
    seen: dict[str, str] = {}
    for name, value in values.items():
        _check_name(name)
        _add(params, seen, name, to_wire(name, value))
    return params
