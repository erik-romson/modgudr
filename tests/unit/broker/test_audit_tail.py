"""The `audit tail` reader (M9): backwards block reads, partial and malformed lines."""

import json
from pathlib import Path

import pytest

from modgudr.broker import audit_tail
from modgudr.broker.audit_tail import AuditReadError, TailFilter, read_tail


def record(i: int, **fields: object) -> bytes:
    return json.dumps({"i": i, **fields}, separators=(",", ":")).encode() + b"\n"


def indices(lines: tuple[str, ...]) -> list[int]:
    return [json.loads(line)["i"] for line in lines]


def test_lines_across_block_boundaries_come_back_whole_and_in_order(
    shortdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(audit_tail, "BLOCK", 64)
    (shortdir / "audit-2026-10-22.jsonl").write_bytes(
        b"".join(record(i, pad="x" * (i * 7 % 50)) for i in range(40))
    )
    result = read_tail(shortdir, TailFilter(), 1000)
    assert indices(result.lines) == list(range(40))
    assert (result.malformed, result.truncated) == (0, False)
    assert indices(read_tail(shortdir, TailFilter(), 3).lines) == [37, 38, 39]


def test_a_partial_last_line_is_skipped_and_a_garbage_line_is_counted(shortdir: Path) -> None:
    (shortdir / "audit-2026-10-22.jsonl").write_bytes(
        record(1) + b"not json\n" + record(2) + b'{"i":3,"half'
    )
    result = read_tail(shortdir, TailFilter(), 10)
    assert indices(result.lines) == [1, 2] and result.malformed == 1


def test_only_a_partial_line_and_empty_files_give_nothing(shortdir: Path) -> None:
    (shortdir / "audit-2026-10-22.jsonl").write_bytes(b'{"i":1')
    (shortdir / "audit-2026-10-21.jsonl").write_bytes(b"")
    result = read_tail(shortdir, TailFilter(), 10)
    assert (result.lines, result.malformed) == ((), 0)


def test_a_json_line_that_is_not_an_object_is_malformed(shortdir: Path) -> None:
    (shortdir / "audit-2026-10-22.jsonl").write_bytes(b"[1]\n\n" + record(1))
    result = read_tail(shortdir, TailFilter(), 10)
    assert indices(result.lines) == [1] and result.malformed == 2


def test_it_continues_in_older_files_in_order(shortdir: Path) -> None:
    (shortdir / "audit-2026-10-20.jsonl").write_bytes(record(1) + record(2))
    (shortdir / "audit-2026-10-21.jsonl").write_bytes(record(3))
    (shortdir / "audit-2026-10-22.jsonl").write_bytes(record(4) + record(5))
    (shortdir / "other.jsonl").write_bytes(record(99))
    assert indices(read_tail(shortdir, TailFilter(), 4).lines) == [2, 3, 4, 5]
    assert indices(read_tail(shortdir, TailFilter(), 50).lines) == [1, 2, 3, 4, 5]


def test_it_reads_at_most_31_daily_files(shortdir: Path) -> None:
    for day in range(1, 32):
        (shortdir / f"audit-2026-08-{day:02d}.jsonl").write_bytes(record(day))
    (shortdir / "audit-2026-07-31.jsonl").write_bytes(record(0))
    assert indices(read_tail(shortdir, TailFilter(), 100).lines) == list(range(1, 32))


def test_filters_match_the_parsed_fields_exactly(shortdir: Path) -> None:
    (shortdir / "audit-2026-10-22.jsonl").write_bytes(
        record(1, target="a", session="s-1", client={"name": "cli"})
        + record(2, target="a", session="s-2", client={"name": "python"})
        + record(3, target="ab", session="s-1", client={"name": "python"})
        + record(4, client="python")
        + record(5)
    )

    def pick(**kwargs: str) -> list[int]:
        return indices(read_tail(shortdir, TailFilter(**kwargs), 10).lines)

    assert pick(target="a") == [1, 2]
    assert pick(session="s-1") == [1, 3]
    assert pick(client="python") == [2, 3]
    assert pick(target="a", client="python") == [2]
    assert pick(target="x") == []


def test_output_stops_at_the_byte_limit_keeping_the_newest(
    shortdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(audit_tail, "MAX_BYTES", 400)
    (shortdir / "audit-2026-10-22.jsonl").write_bytes(
        b"".join(record(i, pad="x" * 100) for i in range(10))
    )
    result = read_tail(shortdir, TailFilter(), 10)
    assert result.truncated is True
    assert indices(result.lines) == [7, 8, 9]  # oldest first; the newest records that fit


def test_a_symlinked_file_is_refused(shortdir: Path) -> None:
    target = shortdir / "elsewhere"
    target.write_bytes(record(1))
    (shortdir / "audit-2026-10-22.jsonl").symlink_to(target)
    with pytest.raises(AuditReadError, match=r"audit-2026-10-22\.jsonl"):
        read_tail(shortdir, TailFilter(), 10)


def test_a_missing_directory_is_an_error(shortdir: Path) -> None:
    with pytest.raises(AuditReadError):
        read_tail(shortdir / "nope", TailFilter(), 10)
