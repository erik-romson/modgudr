"""The audit writer (M9).

Daily files `audit-YYYY-MM-DD.jsonl` (UTC date of each line's `ts`) in a 0700 directory, files 0600.
One writer task serialises all lines, and each line is one `write` in append mode, so a reader sees
at most one partial line, the last.

Never written: bind values, secret values, result data. The pipeline passes none of them; the
writer also scrubs every string (error context, so short secrets go too), caps its length, and
stores a statement over 4 KiB as prefix, SHA-256 and size.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from .scrub import Scrubber

#: Record types: the call records, the single records of refused calls, and the lifecycle records.
#: `failed` is a call that ended before its decision record: a store error at M6 step 7.
CALL_TYPES = frozenset({"decision", "completion"})
SINGLE_TYPES = frozenset({"denied", "throttled", "locked", "bad_request", "failed"})
LIFECYCLE_TYPES = frozenset(
    {
        "broker.start",
        "broker.stop",
        "unlock",
        "unlock.failed",
        "unlock.throttled",
        "lock",
        "isolation.changed",
        "audit.probe",
    }
)

#: A statement over this many bytes is stored as prefix, SHA-256 and size.
STATEMENT_LIMIT = 4096
STATEMENT_PREFIX = 1024
#: Every other string is cut to this many characters.
FIELD_LIMIT = 1024

_RESERVED = frozenset({"ts", "type", "auditId"})

Clock = Callable[[], datetime]


class AuditUnavailable(Exception):
    """A decision record could not be written: the call must not execute (`internal`)."""


def new_audit_id() -> str:
    return "a-" + secrets.token_hex(8)


def _utcnow() -> datetime:
    return datetime.now(UTC)


class AuditWriter:
    def __init__(
        self,
        directory: Path,
        scrubber: Scrubber,
        *,
        clock: Clock = _utcnow,
        stamp: Mapping[str, object] | None = None,
    ) -> None:
        self._dir = directory
        self._scrubber = scrubber
        self._clock = clock
        self._stamp: dict[str, object] = dict(stamp or {})
        self._queue: asyncio.Queue[tuple[str, bytes, asyncio.Future[None]] | None] = asyncio.Queue()
        self._task: asyncio.Task[None] | None = None
        self.degraded = False

    def set_stamp(self, **fields: object) -> None:
        """Fields on every line: `isolation`, `store`, `dev`."""
        self._stamp.update(fields)

    async def start(self) -> None:
        """Create the directory (0700) and start the writer task. Raises when it is not writable."""
        try:
            self._dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            if (self._dir.stat().st_mode & 0o777) != 0o700:
                self._dir.chmod(0o700)
            self._append(self._clock().astimezone(UTC).strftime("%Y-%m-%d"), b"")
        except OSError as exc:
            raise AuditUnavailable(f"audit directory {self._dir} is not writable: {exc}") from exc
        if self._task is None:
            self._task = asyncio.get_running_loop().create_task(self._run())

    async def close(self) -> None:
        """Write what is queued, then stop the writer task."""
        task, self._task = self._task, None
        if task is not None:
            await self._queue.put(None)
            await task

    async def decision(self, audit_id: str, **fields: object) -> None:
        """The record before execution. Raises `AuditUnavailable` when it cannot be written."""
        try:
            await self._write("decision", audit_id, fields)
        except OSError as exc:
            raise AuditUnavailable(f"decision record not written: {exc}") from exc
        except (TypeError, ValueError) as exc:
            raise AuditUnavailable(f"decision record not encodable: {exc}") from exc

    async def completion(self, audit_id: str, **fields: object) -> bool:
        """The record after execution. A failure sets `degraded`; it is not raised."""
        return await self._soft("completion", audit_id, fields)

    async def event(self, record_type: str, audit_id: str | None = None, **fields: object) -> bool:
        """A single record: a denial, throttle or bad request, or a lifecycle record."""
        if record_type not in SINGLE_TYPES and record_type not in LIFECYCLE_TYPES:
            raise ValueError(f"unknown audit record type {record_type!r}")
        return await self._soft(record_type, audit_id, fields)

    async def recover(self) -> None:
        """While `degraded`, new executing calls are refused until a test write succeeds."""
        if not self.degraded:
            return
        await self._probe()
        self.degraded = False

    async def _probe(self) -> None:
        try:
            await self._write("audit.probe", None, {})
        except OSError as exc:
            raise AuditUnavailable(f"audit directory {self._dir} is not writable: {exc}") from exc

    async def _soft(
        self, record_type: str, audit_id: str | None, fields: Mapping[str, object]
    ) -> bool:
        try:
            await self._write(record_type, audit_id, fields)
        except (OSError, TypeError, ValueError):
            self.degraded = True
            return False
        return True

    async def _write(
        self, record_type: str, audit_id: str | None, fields: Mapping[str, object]
    ) -> None:
        if self._task is None:
            raise OSError("audit writer is not running")
        if _RESERVED & fields.keys():
            raise ValueError(f"audit fields may not set {sorted(_RESERVED & fields.keys())}")
        now = self._clock().astimezone(UTC)
        record: dict[str, object] = {
            "ts": now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z",
            "type": record_type,
        }
        if audit_id is not None:
            record["auditId"] = self._clean(audit_id)
        for key, value in {**self._stamp, **fields}.items():
            record[self._clean(key)] = self._field(key, value)
        # ASCII-escaped, so a lone surrogate cannot crash the encoding.
        line = json.dumps(record, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"
        done: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        await self._queue.put((now.strftime("%Y-%m-%d"), line, done))
        await done

    def _field(self, key: str, value: object) -> object:
        if key == "statement" and isinstance(value, str):
            return self._statement(value)
        return self._clean_value(value)

    def _statement(self, text: str) -> object:
        size = len(text.encode("utf-8", "surrogatepass"))
        if size <= STATEMENT_LIMIT:
            return self._scrubber.error(text)
        digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
        prefix = self._scrubber.error(text)[:STATEMENT_PREFIX]
        return {"prefix": prefix, "sha256": digest, "size": size}

    def _clean(self, text: str) -> str:
        text = self._scrubber.error(text)
        return text if len(text) <= FIELD_LIMIT else text[:FIELD_LIMIT] + "…"

    def _clean_value(self, value: object) -> object:
        if value is None or isinstance(value, bool | int | float):
            return value
        if isinstance(value, str):
            return self._clean(value)
        if isinstance(value, Mapping):
            mapping = cast("Mapping[object, object]", value)
            return {self._clean(str(k)): self._clean_value(v) for k, v in mapping.items()}
        if isinstance(value, list | tuple):
            return [self._clean_value(v) for v in cast("Sequence[object]", value)]
        raise TypeError(f"cannot audit a {type(value).__name__}")

    async def _run(self) -> None:
        while (item := await self._queue.get()) is not None:
            day, line, done = item
            try:
                await asyncio.to_thread(self._append, day, line)
            except BaseException as exc:  # reported to the caller, never kills the writer
                if not done.cancelled():
                    done.set_exception(exc)
            else:
                if not done.cancelled():
                    done.set_result(None)

    def _append(self, day: str, line: bytes) -> None:
        path = self._dir / f"audit-{day}.jsonl"
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)
            if os.write(fd, line) != len(line):
                raise OSError("short write")
        finally:
            os.close(fd)
