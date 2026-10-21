"""The reader behind `audit tail` (M9, A28).

It runs in a worker thread and takes no lock the writer waits on: the writer appends whole lines
with one `write`, so a reader sees at most one partial line, the last, and skips it. Each daily
file is opened read-only with `O_NOFOLLOW` and read backwards in 64 KiB blocks, newest day first,
until `n` records match, 31 daily files were read, or the output would pass 4 MiB.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

BLOCK = 64 * 1024
MAX_FILES = 31
MAX_BYTES = 4 * 1024 * 1024
MAX_N = 1000
DEFAULT_N = 50

_NAME = re.compile(r"audit-\d{4}-\d{2}-\d{2}\.jsonl")


class AuditReadError(Exception):
    """An audit file could not be read."""


@dataclass(frozen=True)
class TailFilter:
    """Exact matches on the parsed record, combined with AND."""

    target: str | None = None
    session: str | None = None
    client: str | None = None

    def matches(self, record: dict[str, Any]) -> bool:
        if self.target is not None and record.get("target") != self.target:
            return False
        if self.session is not None and record.get("session") != self.session:
            return False
        if self.client is not None:
            client = record.get("client")
            if not isinstance(client, dict):
                return False
            if cast("dict[str, Any]", client).get("name") != self.client:
                return False
        return True


@dataclass(frozen=True)
class TailResult:
    #: The matching stored lines, oldest first.
    lines: tuple[str, ...]
    #: Lines that were not a JSON object (skipped).
    malformed: int
    #: The 4 MiB limit stopped the read: older matching records may exist.
    truncated: bool


def _complete_end(fd: int, size: int) -> int:
    """The offset after the last newline: a tail without one is the writer mid-line."""
    pos = size
    while pos > 0:
        start = max(0, pos - BLOCK)
        chunk = os.pread(fd, pos - start, start)
        index = chunk.rfind(b"\n")
        if index >= 0:
            return start + index + 1
        pos = start
    return 0


def _backwards_lines(fd: int, size: int) -> Iterator[bytes]:
    """The complete lines of a file, last first, reading 64 KiB blocks from the end."""
    pos = _complete_end(fd, size)
    if pos == 0:
        return
    buf = b""
    first = True
    while pos > 0:
        start = max(0, pos - BLOCK)
        buf = os.pread(fd, pos - start, start) + buf
        pos = start
        parts = buf.split(b"\n")
        buf = parts[0]
        complete = parts[1:-1] if first else parts[1:]
        first = False
        yield from reversed(complete)
    yield buf


def _parse(raw: bytes) -> dict[str, Any] | None:
    try:
        record = json.loads(raw)
    except (ValueError, RecursionError):
        return None
    return cast("dict[str, Any]", record) if isinstance(record, dict) else None


def _day_files(directory: Path) -> list[str]:
    try:
        names = [name for name in os.listdir(directory) if _NAME.fullmatch(name)]  # noqa: PTH208
    except OSError as exc:
        raise AuditReadError(f"cannot list the audit directory {directory}: {exc}") from exc
    return sorted(names, reverse=True)[:MAX_FILES]


def read_tail(directory: Path, flt: TailFilter, n: int) -> TailResult:
    """The last `n` records that match, oldest first."""
    found: list[bytes] = []
    total = 0
    malformed = 0
    truncated = False
    for name in _day_files(directory):
        try:
            fd = os.open(directory / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as exc:
            raise AuditReadError(f"cannot read the audit file {name}: {exc}") from exc
        try:
            for raw in _backwards_lines(fd, os.fstat(fd).st_size):
                record = _parse(raw)
                if record is None:
                    malformed += 1
                    continue
                if not flt.matches(record):
                    continue
                if total + len(raw) + 1 > MAX_BYTES:
                    truncated = True
                    break
                found.append(raw)
                total += len(raw) + 1
                if len(found) >= n:
                    break
            else:
                continue
            break
        except OSError as exc:
            raise AuditReadError(f"cannot read the audit file {name}: {exc}") from exc
        finally:
            os.close(fd)
    lines = tuple(raw.decode("utf-8") for raw in reversed(found))
    return TailResult(lines, malformed, truncated)
