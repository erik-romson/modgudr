import io
import json
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

import pytest

from modgudr.client.errors import BrokerUnavailable, Denied, Error, Throttled
from modgudr.client.protocol import (
    Header,
    Result,
    Row,
    Text,
    Trailer,
    decode_value,
    encode_request,
    read_frames,
)


def stream(*frames: dict[str, Any], tail: bytes = b"") -> io.BytesIO:
    return io.BytesIO(b"".join(json.dumps(f).encode() + b"\n" for f in frames) + tail)


def test_encode_request() -> None:
    raw = encode_request(
        "query",
        target="sf@prod",
        env="dev",
        args={"sql": "select 1", "params": {"a": {"t": "int", "v": 1}}},
        client={"name": "cli", "version": "0.1.0"},
    )
    assert raw.endswith(b"\n") and raw.count(b"\n") == 1
    assert json.loads(raw) == {
        "v": 1,
        "op": "query",
        "target": "sf@prod",
        "env": "dev",
        "args": {"sql": "select 1", "params": {"a": {"t": "int", "v": 1}}},
        "client": {"name": "cli", "version": "0.1.0"},
    }


def test_encode_minimal_and_non_ascii() -> None:
    assert json.loads(encode_request("status")) == {"v": 1, "op": "status", "args": {}}
    raw = encode_request("query", args={"sql": "select 'ä'"})
    assert raw.isascii()
    assert json.loads(raw)["args"]["sql"] == "select 'ä'"


def test_decode_rows_by_header() -> None:
    cols = [
        {"name": "i", "type": "integer"},
        {"name": "n", "type": "number"},
        {"name": "s", "type": "string"},
        {"name": "d", "type": "date"},
        {"name": "t", "type": "timestamp"},
        {"name": "z", "type": "timestamp_tz"},
        {"name": "b", "type": "binary"},
        {"name": "f", "type": "boolean"},
        {"name": "v", "type": "variant"},
    ]
    row = [
        "42",
        "1.10",
        "x",
        "2026-10-01",
        "2026-10-01T12:00:00.5",
        "2026-10-01T12:00:00+02:00",
        "AAE=",
        True,
        '{"a":1}',
    ]
    frames = list(
        read_frames(
            stream(
                {"t": "header", "columns": cols},
                {"t": "row", "v": row},
                {"t": "row", "v": [None] * 9},
                {"t": "trailer", "rows": 2, "truncated": False},
            )
        )
    )
    assert isinstance(frames[0], Header) and frames[0].columns[1].type == "number"
    assert isinstance(frames[1], Row)
    assert frames[1].values == (
        42,
        Decimal("1.10"),
        "x",
        date(2026, 10, 1),
        datetime(2026, 10, 1, 12, 0, 0, 500000),
        datetime(2026, 10, 1, 12, 0, tzinfo=timezone(timedelta(hours=2))),
        b"\x00\x01",
        True,
        '{"a":1}',
    )
    assert isinstance(frames[2], Row) and frames[2].values == (None,) * 9
    assert isinstance(frames[3], Trailer) and frames[3].data["rows"] == 2


def test_text_and_result_frames() -> None:
    frames = list(
        read_frames(
            stream(
                {"t": "text", "stream": "stdout", "data": "hi"},
                {"t": "result", "data": {"a": 1}},
                {"t": "trailer"},
            )
        )
    )
    assert frames == [Text("stdout", "hi"), Result({"a": 1}), Trailer({})]


def test_trailer_ends_the_stream() -> None:
    s = stream({"t": "trailer"}, {"t": "row", "v": []})
    assert list(read_frames(s)) == [Trailer({})]


def test_error_frame_raises_denied() -> None:
    with pytest.raises(Denied) as info:
        list(
            read_frames(
                stream({"t": "error", "code": "denied", "message": "nope", "layer": "company"})
            )
        )
    assert info.value.exit_code == 2
    assert info.value.layer == "company"


def test_error_after_data_lines() -> None:
    s = stream(
        {"t": "header", "columns": [{"name": "i", "type": "integer"}]},
        {"t": "row", "v": ["1"]},
        {"t": "error", "code": "throttled", "message": "busy", "retryAfter": 2.5},
    )
    seen: list[object] = []
    with pytest.raises(Throttled) as info:
        for frame in read_frames(s):
            seen.append(frame)
    assert len(seen) == 2 and info.value.retry_after == 2.5


@pytest.mark.parametrize(
    "s",
    [
        stream(),
        stream({"t": "header", "columns": []}),
        stream({"t": "header", "columns": []}, tail=b'{"t":"trailer"}'),
    ],
)
def test_stream_without_trailer(s: io.BytesIO) -> None:
    with pytest.raises(BrokerUnavailable, match="connection lost; outcome unknown") as info:
        list(read_frames(s))
    assert info.value.exit_code == 6


@pytest.mark.parametrize(
    "tail",
    [
        b"not json\n",
        b"[1]\n",
        b'{"t":"mystery"}\n',
        b'{"t":"row","v":[1]}\n',
        b'{"t":"header","columns":[{"name":"i","type":"integer"}]}\n{"t":"row","v":[]}\n',
        b'{"t":"header","columns":[{"name":"i","type":"integer"}]}\n{"t":"row","v":["x"]}\n',
    ],
)
def test_malformed_frames_are_internal_errors(tail: bytes) -> None:
    with pytest.raises(Error) as info:
        list(read_frames(io.BytesIO(tail)))
    assert info.value.exit_code == 70


def test_decode_value() -> None:
    assert decode_value("integer", "7") == 7
    assert decode_value("integer", 7) == 7
    assert decode_value("date", None) is None
    assert decode_value("interval", "1 day") == "1 day"
    assert decode_value("time", "12:30:00") is not None
    assert decode_value("binary", "") == b""
    with pytest.raises(Error):
        decode_value("binary", "@@")
    with pytest.raises(Error):
        decode_value("boolean", "true")
