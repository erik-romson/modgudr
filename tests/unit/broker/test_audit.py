"""The audit writer (M9): files, modes, escaping, ordering, failure handling."""

from __future__ import annotations

import asyncio
import hashlib
import json
import stat
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from modgudr.broker.audit import (
    FIELD_LIMIT,
    STATEMENT_LIMIT,
    AuditUnavailable,
    AuditWriter,
    new_audit_id,
)
from modgudr.broker.scrub import REDACTED, Scrubber


class Clock:
    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


NOON = datetime(2026, 10, 21, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
async def audit(shortdir: Path) -> AsyncIterator[AuditWriter]:
    writer = AuditWriter(
        shortdir / "audit",
        Scrubber(),
        clock=Clock(NOON),
        stamp={"isolation": "none", "store": "file", "dev": True},
    )
    await writer.start()
    yield writer
    await writer.close()


def read(directory: Path) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for path in sorted(directory.glob("audit-*.jsonl")):
        for line in path.read_text().splitlines():
            out.append(json.loads(line))
    return out


async def test_decision_and_completion_share_an_audit_id(
    audit: AuditWriter, shortdir: Path
) -> None:
    audit_id = new_audit_id()
    await audit.decision(audit_id, target="t", op="query", statement="select 1")
    assert await audit.completion(audit_id, rows=1, scrubbed=0)
    records = read(shortdir / "audit")
    assert [r["type"] for r in records] == ["decision", "completion"]
    assert {r["auditId"] for r in records} == {audit_id}
    assert records[0]["ts"] == "2026-10-21T12:00:00.000Z"
    assert records[0]["statement"] == "select 1"
    assert (records[0]["isolation"], records[0]["store"], records[0]["dev"]) == (
        "none",
        "file",
        True,
    )


async def test_single_and_lifecycle_records(audit: AuditWriter, shortdir: Path) -> None:
    assert await audit.event("denied", "a-1", layer="global", rule="x")
    assert await audit.event("broker.start", dev=True, plugins=[{"name": "sql", "version": "1"}])
    assert await audit.event("lock", reason="manual")
    records = read(shortdir / "audit")
    assert [r["type"] for r in records] == ["denied", "broker.start", "lock"]
    assert "auditId" not in records[1]
    with pytest.raises(ValueError):
        await audit.event("decision")
    with pytest.raises(ValueError):
        await audit.event("nonsense")


async def test_reserved_fields_cannot_be_overridden(audit: AuditWriter) -> None:
    with pytest.raises(AuditUnavailable):
        await audit.decision("a-1", ts="yesterday")


async def test_statement_over_4kib_is_prefix_hash_and_size(
    audit: AuditWriter, shortdir: Path
) -> None:
    statement = "select '" + "x" * 6000 + "' from dual"
    await audit.decision("a-1", statement=statement)
    stored = read(shortdir / "audit")[0]["statement"]
    assert isinstance(stored, dict)
    assert stored["sha256"] == hashlib.sha256(statement.encode()).hexdigest()
    assert stored["size"] == len(statement.encode())
    assert statement.startswith(stored["prefix"])
    assert len(stored["prefix"]) < STATEMENT_LIMIT


async def test_statement_at_the_limit_is_stored_whole(audit: AuditWriter, shortdir: Path) -> None:
    statement = "s" * STATEMENT_LIMIT
    await audit.decision("a-1", statement=statement)
    assert read(shortdir / "audit")[0]["statement"] == statement


async def test_password_literal_in_a_statement_is_replaced(shortdir: Path) -> None:
    scrubber = Scrubber()
    scrubber.add("hunter2")  # shorter than 8: still replaced in audit text
    scrubber.add("correct-horse-battery")
    writer = AuditWriter(shortdir / "audit", scrubber)
    await writer.start()
    await writer.decision("a-1", statement="alter user a identified by 'hunter2'", error=None)
    long_statement = "x" * 5000 + " correct-horse-battery"
    await writer.decision("a-2", statement="correct-horse-battery " + long_statement)
    await writer.completion("a-1", error={"message": "bad correct-horse-battery"})
    await writer.close()
    text = "".join(p.read_text() for p in (shortdir / "audit").glob("audit-*"))
    assert "hunter2" not in text and "correct-horse-battery" not in text
    assert REDACTED in text


async def test_lone_surrogate_in_cwd_is_written_escaped(audit: AuditWriter, shortdir: Path) -> None:
    await audit.decision("a-1", client={"cwd": "/tmp/a\ud800b", "script": "tab\there\nnl"})
    client = read(shortdir / "audit")[0]["client"]
    assert client == {"cwd": "/tmp/a\ud800b", "script": "tab\there\nnl"}


async def test_client_fields_are_length_capped(audit: AuditWriter, shortdir: Path) -> None:
    await audit.decision("a-1", client={"cwd": "/" + "d" * 100_000})
    cwd = read(shortdir / "audit")[0]["client"]["cwd"]  # pyright: ignore[reportIndexIssue]
    assert FIELD_LIMIT < len(cwd) < FIELD_LIMIT + 10


async def test_fifty_concurrent_writers_never_interleave(
    audit: AuditWriter, shortdir: Path
) -> None:
    async def one(i: int) -> None:
        await audit.decision(f"a-{i}", statement="q" * 3000 + str(i), client={"cwd": "c" * 900})
        await audit.completion(f"a-{i}", rows=i)

    await asyncio.gather(*(one(i) for i in range(50)))
    records = read(shortdir / "audit")  # every line parses
    assert len(records) == 100
    for i in range(50):
        kinds = [r["type"] for r in records if r["auditId"] == f"a-{i}"]
        assert kinds == ["decision", "completion"]


async def test_unwritable_directory_refuses_the_decision(shortdir: Path) -> None:
    clock = Clock(NOON)
    writer = AuditWriter(shortdir / "audit", Scrubber(), clock=clock)
    await writer.start()
    (shortdir / "audit").chmod(0o500)
    clock.now += timedelta(days=1)  # today's file exists; the next day's cannot be created
    try:
        with pytest.raises(AuditUnavailable):
            await writer.decision("a-1", op="query")
        assert await writer.completion("a-1") is False
        assert writer.degraded
        with pytest.raises(AuditUnavailable):
            await writer.recover()
        assert writer.degraded
    finally:
        (shortdir / "audit").chmod(0o700)
    await writer.recover()
    assert not writer.degraded
    await writer.decision("a-2", op="query")
    await writer.close()


async def test_failed_completion_sets_degraded_until_a_test_write_succeeds(
    shortdir: Path,
) -> None:
    clock = Clock(NOON)
    writer = AuditWriter(shortdir / "audit", Scrubber(), clock=clock)
    await writer.start()
    day = shortdir / "audit" / "audit-2026-10-21.jsonl"
    day.unlink()
    day.mkdir()  # a directory in the file's place: the append fails
    assert await writer.completion("a-1") is False
    assert writer.degraded
    day.rmdir()
    await writer.recover()
    assert not writer.degraded
    await writer.close()


async def test_start_refuses_an_unwritable_directory(shortdir: Path) -> None:
    (shortdir / "ro").mkdir(mode=0o500)
    writer = AuditWriter(shortdir / "ro" / "audit", Scrubber())
    with pytest.raises(AuditUnavailable):
        await writer.start()
    (shortdir / "ro").chmod(0o700)


async def test_writes_before_start_are_refused(shortdir: Path) -> None:
    writer = AuditWriter(shortdir / "audit", Scrubber())
    with pytest.raises(AuditUnavailable):
        await writer.decision("a-1")


async def test_call_spanning_utc_midnight(shortdir: Path) -> None:
    clock = Clock(datetime(2026, 10, 21, 23, 59, 59, 500_000, tzinfo=UTC))
    writer = AuditWriter(shortdir / "audit", Scrubber(), clock=clock)
    await writer.start()
    await writer.decision("a-1", op="query")
    clock.now += timedelta(seconds=1)
    await writer.completion("a-1", rows=1)
    await writer.close()
    first = (shortdir / "audit" / "audit-2026-10-21.jsonl").read_text()
    second = (shortdir / "audit" / "audit-2026-10-22.jsonl").read_text()
    assert json.loads(first)["type"] == "decision"
    assert json.loads(second)["type"] == "completion"


async def test_a_local_time_zone_clock_is_converted_to_utc(shortdir: Path) -> None:
    from datetime import timezone

    clock = Clock(datetime(2026, 10, 22, 1, 30, tzinfo=timezone(timedelta(hours=2))))
    writer = AuditWriter(shortdir / "audit", Scrubber(), clock=clock)
    await writer.start()
    await writer.decision("a-1")
    await writer.close()
    assert (shortdir / "audit" / "audit-2026-10-21.jsonl").exists()


async def test_modes(audit: AuditWriter, shortdir: Path) -> None:
    await audit.decision("a-1")
    directory = shortdir / "audit"
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    files = list(directory.glob("audit-*.jsonl"))
    assert files
    assert all(stat.S_IMODE(f.stat().st_mode) == 0o600 for f in files)


async def test_a_wider_directory_is_tightened(shortdir: Path) -> None:
    directory = shortdir / "audit"
    directory.mkdir(mode=0o755)
    directory.chmod(0o755)
    writer = AuditWriter(directory, Scrubber())
    await writer.start()
    await writer.close()
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700


async def test_unencodable_field_is_not_written(audit: AuditWriter, shortdir: Path) -> None:
    with pytest.raises(AuditUnavailable):
        await audit.decision("a-1", thing=object())
    assert read(shortdir / "audit") == []
