"""Oracle result types, LOB budgets and memory (M16, M4)."""

from __future__ import annotations

import base64
import tracemalloc

import pytest

from modgudr.broker.app import Broker
from tests.support.brokerfx import BrokerEnv
from tests.support.oraclefx import OracleDb, Spy, completion, rows, run, trailer

pytestmark = pytest.mark.oracle

MAX_BYTES = 2 * 1024**2


async def test_numbers_are_exact_plain_strings(broker: Broker, env: BrokerEnv) -> None:
    sql = (
        "select 12345678901234567890.123456789 as n1, "
        "99999999999999999999999999999999999999 as n2, 0.5 as n3, "
        "to_binary_double('NaN') as nan, cast(7 as number(10)) as i, "
        "0.00001 as tiny from dual"
    )
    frames = await run(env, "query", sql=sql)
    assert rows(frames) == [
        [
            "12345678901234567890.123456789",
            "99999999999999999999999999999999999999",
            "0.5",
            "NaN",
            "7",
            "0.00001",
        ]
    ]
    types = {c["name"]: c["type"] for c in frames[0]["columns"]}
    assert types == {
        "N1": "number",
        "N2": "number",
        "N3": "number",
        "NAN": "number",
        "I": "integer",
        "TINY": "number",
    }


async def test_dates_timestamps_raw_and_long(broker: Broker, env: BrokerEnv) -> None:
    sql = (
        "select to_date('2026-10-22 13:14:15', 'YYYY-MM-DD HH24:MI:SS') as d, "
        "timestamp '2026-10-22 13:14:15.5' as ts, "
        "timestamp '2026-10-01 10:00:00 +02:00' as tz, "
        "timestamp '2026-10-01 10:00:00.25 -05:30' as tz_frac, "
        "hextoraw('CAFE') as r "
        "from dual"
    )
    frames = await run(env, "query", sql=sql)
    ((d, ts, tz, tz_frac, raw),) = rows(frames)
    assert d == "2026-10-22T13:14:15"
    assert ts == "2026-10-22T13:14:15.500000"
    # The thin driver hands over the wall clock of a zoned value without its offset (see the
    # run report): the wire says `timestamp`, never an offset it does not have.
    assert tz == "2026-10-01T10:00:00"
    assert tz_frac == "2026-10-01T10:00:00.250000"
    assert raw == base64.b64encode(bytes.fromhex("CAFE")).decode()
    assert {c["name"]: c["type"] for c in frames[0]["columns"]} == {
        "D": "timestamp",
        "TS": "timestamp",
        "TZ": "timestamp",
        "TZ_FRAC": "timestamp",
        "R": "binary",
    }


async def test_a_long_column_is_text(broker: Broker, env: BrokerEnv) -> None:
    frames = await run(
        env,
        "query",
        sql="select text from all_views where owner = 'APP' and view_name = 'V_PO'",
    )
    assert frames[0]["columns"] == [{"name": "TEXT", "type": "string"}]
    ((text,),) = rows(frames)
    assert text.lower().startswith("select id, status from app.po")


async def test_small_lobs_arrive_whole(broker: Broker, env: BrokerEnv, spy: Spy) -> None:
    frames = await run(env, "query", sql="select c, b from app.lobs where id = 3")
    ((clob, blob),) = rows(frames)
    assert clob == "y" * 1024
    assert base64.b64decode(blob) == bytes.fromhex("CD") * 1024
    assert [c["type"] for c in frames[0]["columns"]] == ["string", "binary"]
    assert trailer(frames)["truncated"] is False


@pytest.mark.parametrize("column", ["c", "b"])
async def test_a_huge_lob_ends_with_limit_before_any_read(
    broker: Broker, env: BrokerEnv, spy: Spy, column: str
) -> None:
    tracemalloc.start()
    try:
        frames = await run(env, "query", sql=f"select id, {column} from app.lobs where id = 1")
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    done = trailer(frames)
    assert (done["truncated"], done["reason"], done["rows"]) == (True, "bytes", 0)
    assert spy.reads == []  # the size check ended it
    assert f"column '{column.upper()}'" in completion(env)["limit"]
    assert peak < 4 * MAX_BYTES, peak


async def test_a_clob_that_fits_by_characters_but_not_by_bytes_stops_in_chunks(
    broker: Broker, env: BrokerEnv, spy: Spy
) -> None:
    tracemalloc.start()
    try:
        frames = await run(env, "query", sql="select c from app.lobs where id = 2")
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    done = trailer(frames)
    assert (done["truncated"], done["reason"], done["rows"]) == (True, "bytes", 0)
    chunk = 256 * 1024
    assert len(spy.reads) >= 2
    assert all(amount <= chunk for _, amount in spy.reads)
    # Each chunk is 256 Ki euro signs, 6 bytes each once escaped: the budget passes in the
    # second chunk, and nothing past that is read.
    assert sum(amount for _, amount in spy.reads) <= MAX_BYTES + chunk
    assert sum(amount for _, amount in spy.reads) < 1024 * 1024
    assert "column 'C'" in completion(env)["limit"]
    assert peak < 4 * MAX_BYTES, peak


async def test_a_lob_row_counts_against_the_bytes_already_sent(
    broker: Broker, env: BrokerEnv, spy: Spy
) -> None:
    """Three 1 KiB LOBs are fine; the same row after 2 MiB of other rows is not."""
    sql = "select c from app.lobs where id = 3 connect by level <= 3000"
    frames = await run(env, "query", sql=sql, maxRows=3000)
    done = trailer(frames)
    assert done["truncated"] is True and done["reason"] == "bytes"
    assert 0 < done["rows"] < 3000
    assert "column 'C'" in completion(env)["limit"]
    assert done["bytes"] <= MAX_BYTES


async def test_lob_reads_leave_no_session_state(
    broker: Broker, env: BrokerEnv, db: OracleDb
) -> None:
    await run(env, "query", sql="select c from app.lobs where id = 1")
    frames = await run(env, "query", sql="select c, b from app.lobs where id = 3")
    assert trailer(frames)["rows"] == 1
