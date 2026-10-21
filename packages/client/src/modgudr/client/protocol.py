"""Wire protocol v1, client side (M4): request encoding and the response frame decoder."""

import base64
import binascii
import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import date, datetime, time
from decimal import Decimal, InvalidOperation
from typing import Any, BinaryIO, cast

from modgudr.client.errors import BrokerUnavailable, Error, error_from_frame

PROTOCOL_VERSION = 1
SUPPORTED_VERSIONS = (1,)


@dataclass(frozen=True)
class Column:
    name: str
    type: str


@dataclass(frozen=True)
class Header:
    columns: tuple[Column, ...]


@dataclass(frozen=True)
class Row:
    values: tuple[object, ...]


@dataclass(frozen=True)
class Text:
    stream: str
    data: str


@dataclass(frozen=True)
class Result:
    data: Any


@dataclass(frozen=True)
class Trailer:
    data: Mapping[str, Any]


Frame = Header | Row | Text | Result | Trailer


def encode_request(
    op: str,
    *,
    target: str | None = None,
    env: str | None = None,
    args: Mapping[str, Any] | None = None,
    client: Mapping[str, Any] | None = None,
) -> bytes:
    """One request as a single JSON line (with the trailing newline)."""
    request: dict[str, Any] = {"v": PROTOCOL_VERSION, "op": op}
    if target is not None:
        request["target"] = target
    if env is not None:
        request["env"] = env
    request["args"] = dict(args) if args is not None else {}
    if client is not None:
        request["client"] = dict(client)
    return json.dumps(request, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"


def decode_value(type_name: str, value: object) -> object:
    """Decode one cell by its column type. NULL is `None` for every type."""
    if value is None:
        return None
    try:
        if type_name == "boolean":
            if not isinstance(value, bool):
                raise ValueError("expected a JSON boolean")
            return value
        if type_name in ("integer", "number", "date", "timestamp", "timestamp_tz", "time"):
            if isinstance(value, bool) or not isinstance(value, (str, int)):
                raise ValueError(f"expected a string for {type_name}")
            if type_name == "integer":
                return int(value)
            if type_name == "number":
                return Decimal(value)
            if not isinstance(value, str):
                raise ValueError(f"expected a string for {type_name}")
            if type_name == "date":
                return date.fromisoformat(value)
            if type_name == "time":
                return time.fromisoformat(value)
            return datetime.fromisoformat(value)
        if type_name == "binary":
            if not isinstance(value, str):
                raise ValueError("expected a base64 string")
            return base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, InvalidOperation, binascii.Error) as exc:
        raise Error(f"malformed {type_name} value from the broker: {exc}") from exc
    return value


def _frame_from(obj: Mapping[str, Any], columns: tuple[Column, ...] | None) -> Frame:
    kind = obj.get("t")
    if kind == "header":
        raw = obj.get("columns")
        if not isinstance(raw, list):
            raise Error("malformed header frame from the broker")
        cols: list[Column] = []
        for entry in cast(list[object], raw):
            if not isinstance(entry, dict):
                raise Error("malformed header frame from the broker")
            fields = cast(dict[str, Any], entry)
            cols.append(Column(str(fields.get("name", "")), str(fields.get("type", "other"))))
        return Header(tuple(cols))
    if kind == "row":
        cells = obj.get("v")
        if not isinstance(cells, list) or columns is None:
            raise Error("malformed row frame from the broker")
        values = cast(list[object], cells)
        if len(values) != len(columns):
            raise Error("row frame does not match the header")
        return Row(tuple(decode_value(c.type, v) for c, v in zip(columns, values, strict=True)))
    if kind == "text":
        return Text(str(obj.get("stream", "")), str(obj.get("data", "")))
    if kind == "result":
        return Result(obj.get("data"))
    if kind == "trailer":
        return Trailer({k: v for k, v in obj.items() if k != "t"})
    raise Error(f"unknown frame type {kind!r} from the broker")


def read_frames(stream: BinaryIO) -> Iterator[Frame]:
    """Decode response frames from a socket file object, up to and including the trailer.

    An `error` frame raises the M5 exception. A stream that ends with neither trailer nor
    error raises `BrokerUnavailable`.
    """
    columns: tuple[Column, ...] | None = None
    while True:
        line = stream.readline()
        if not line.endswith(b"\n"):
            raise BrokerUnavailable("connection lost; outcome unknown")
        try:
            obj = json.loads(line)
        except ValueError as exc:
            raise Error("malformed frame from the broker (not JSON)") from exc
        if not isinstance(obj, dict):
            raise Error("malformed frame from the broker (not an object)")
        frame_obj: dict[str, Any] = obj  # pyright: ignore[reportUnknownVariableType]
        if frame_obj.get("t") == "error":
            raise error_from_frame(frame_obj)
        frame = _frame_from(frame_obj, columns)
        if isinstance(frame, Header):
            columns = frame.columns
        yield frame
        if isinstance(frame, Trailer):
            return
