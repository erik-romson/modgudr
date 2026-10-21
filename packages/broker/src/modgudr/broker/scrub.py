"""The secret scrubber (§5.3, D21).

It replaces **known values** (registered when a secret or minted token enters memory, dropped on
lock) and **prefixed token formats** (`ghp_`, `github_pat_`, `gho_`, `ATATT`, `AKIA`, `xoxb-`,
`xoxp-`), JWTs and PEM private key blocks. Never generic hex or base64: a GitHub response is full of
40-hex SHAs that must survive.

Known values of at least 8 characters are replaced everywhere. Shorter ones are replaced only in
error, log and audit text, never in rows, because a short password would corrupt data.

Results stream in chunks, so a `TextStream` keeps a rolling tail before it emits, or a secret split
across two chunks would escape. Memory stays flat: only the tail and the current chunk are held.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Literal

from ..spi import Cell

REDACTED = "[modgudr:redacted]"

#: Known values shorter than this are replaced in error, log and audit text only (D21).
MIN_DATA_LENGTH = 8

Context = Literal["data", "error"]

_TOKEN_PREFIXES = ("ghp_", "gho_", "github_pat_", "ATATT", "AKIA", "xoxb-", "xoxp-")

_TOKEN_PATTERNS = (
    r"ghp_[A-Za-z0-9]{16,}",
    r"gho_[A-Za-z0-9]{16,}",
    r"github_pat_[A-Za-z0-9_]{16,}",
    r"ATATT[A-Za-z0-9_\-=]{16,}",
    r"AKIA[0-9A-Z]{16}",
    r"xox[bp]-[A-Za-z0-9\-]{10,}",
)
_JWT_PATTERN = r"eyJ[A-Za-z0-9_\-]{4,}\.eyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]*"
_PEM_PATTERN = r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----"
_PATTERNS = "|".join((_PEM_PATTERN, _JWT_PATTERN, *_TOKEN_PATTERNS))

_PEM = re.compile(_PEM_PATTERN, re.DOTALL)
_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_PEM_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")
_PEM_BEGIN_MARK = "-----BEGIN "

#: Characters a token body can hold; a trailing run of them may be an unfinished token.
_TOKEN_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-=."
_OPEN_PREFIX = re.compile("|".join(re.escape(p) for p in (*_TOKEN_PREFIXES, "eyJ")))

#: The longest unfinished token held back, and the longest unfinished PEM block held back.
_OPEN_MAX = 8192
_PEM_MAX = 65536

#: At least the longest literal that must be seen whole: `-----BEGIN ENCRYPTED PRIVATE KEY-----`.
_MIN_TAIL = 40

_NEVER = re.compile(r"(?!)")


class Scrubber:
    """The registered secret values, shared by every call. One event loop uses it."""

    def __init__(self) -> None:
        self._values: set[str] = set()
        self._dirty = True
        self._data_rx: re.Pattern[str] = _NEVER
        self._error_rx: re.Pattern[str] = _NEVER
        self._max_data = 0

    def add(self, value: str) -> None:
        if not value:
            raise ValueError("cannot register an empty secret")
        if value not in self._values:
            self._values.add(value)
            self._dirty = True

    def remove(self, value: str) -> None:
        if value in self._values:
            self._values.discard(value)
            self._dirty = True

    def clear(self) -> None:
        """Lock drops every registered value (M7)."""
        if self._values:
            self._values.clear()
            self._dirty = True

    def __len__(self) -> int:
        return len(self._values)

    def data(self, text: str) -> str:
        """Scrub a whole string from result data: the 8-character rule applies."""
        return self.compiled()[0].sub(REDACTED, text)

    def error(self, text: str) -> str:
        """Scrub error, log or audit text: every registered value is replaced."""
        return self.compiled()[1].sub(REDACTED, text)

    def call(self) -> CallScrubber:
        return CallScrubber(self)

    def _effective(self) -> set[str]:
        values = set(self._values)
        for value in self._values:
            if _PEM_BEGIN_MARK in value:
                for line in value.splitlines():
                    line = line.strip()
                    if len(line) >= MIN_DATA_LENGTH and not line.startswith("-----"):
                        values.add(line)
        return values

    def compiled(self) -> tuple[re.Pattern[str], re.Pattern[str], int]:
        if self._dirty:
            values = self._effective()
            data = [v for v in values if len(v) >= MIN_DATA_LENGTH]
            self._data_rx = _build(data)
            self._error_rx = _build(list(values))
            self._max_data = max((len(v) for v in data), default=0)
            self._dirty = False
        return self._data_rx, self._error_rx, self._max_data


def _build(values: Sequence[str]) -> re.Pattern[str]:
    known = "|".join(re.escape(v) for v in sorted(values, key=len, reverse=True))
    pattern = f"{known}|{_PATTERNS}" if known else _PATTERNS
    return re.compile(pattern, re.DOTALL)


class CallScrubber:
    """One call's view of the scrubber, with its `scrubbed` count."""

    def __init__(self, scrubber: Scrubber) -> None:
        self.scrubber = scrubber
        self.count = 0

    def data(self, text: str) -> str:
        rx = self.scrubber.compiled()[0]
        out, n = rx.subn(REDACTED, text)
        self.count += n
        return out

    def error(self, text: str) -> str:
        rx = self.scrubber.compiled()[1]
        out, n = rx.subn(REDACTED, text)
        self.count += n
        return out

    def cells(self, values: Sequence[Cell]) -> list[Cell]:
        """Scrub the string cells of one row; a row without a match costs one search."""
        strings = [v for v in values if isinstance(v, str)]
        if not strings:
            return list(values)
        rx = self.scrubber.compiled()[0]
        joined = "\x1f".join(strings)
        if rx.search(joined) is None:
            return list(values)
        # One pass over the whole row. A match that swallowed a separator spanned two cells: then
        # each cell is scrubbed on its own.
        out_joined, n = rx.subn(REDACTED, joined)
        parts: list[str] = out_joined.split("\x1f")
        if len(parts) != len(strings):
            parts = []
            n = 0
            for text in strings:
                part, k = rx.subn(REDACTED, text)
                parts.append(part)
                n += k
        self.count += n
        it = iter(parts)
        return [next(it) if isinstance(v, str) else v for v in values]

    def stream(self) -> TextStream:
        return TextStream(self)


class TextStream:
    """Scrubs a stream of text chunks, holding back a rolling tail until the next chunk."""

    def __init__(self, call: CallScrubber) -> None:
        self._call = call
        self._buf: str = ""
        self._in_pem = False

    def feed(self, chunk: str) -> str:
        """Return the text that is safe to emit. The rest waits for the next chunk."""
        rx, _, max_len = self._call.scrubber.compiled()
        buf = self._buf + chunk
        self._buf = ""
        if self._in_pem:
            end = _PEM_END.search(buf)
            if end is None:
                self._buf = buf[-_MIN_TAIL:]
                return ""
            buf = buf[end.end() :]
            self._in_pem = False

        hold = max(0, len(buf) - max(max_len - 1, _MIN_TAIL))
        hold = min(hold, _open_token_start(buf))
        pem = _open_pem_start(buf)
        if pem is not None:
            if len(buf) - pem > _PEM_MAX:
                # An unterminated key block this long: redact it and drop its body.
                head = self._scrub(rx, buf[:pem])
                self._call.count += 1
                self._in_pem = True
                self._buf = buf[-_MIN_TAIL:]
                return head + REDACTED
            hold = min(hold, pem)

        out: list[str] = []
        pos = 0
        for m in rx.finditer(buf):
            if m.start() >= hold:
                break
            out.append(buf[pos : m.start()])
            out.append(REDACTED)
            self._call.count += 1
            pos = m.end()
        end_at = max(pos, hold)
        out.append(buf[pos:end_at])
        self._buf = buf[end_at:]
        return "".join(out)

    def flush(self) -> str:
        """End of stream: scrub and return what the tail still holds."""
        rx = self._call.scrubber.compiled()[0]
        buf, self._buf = self._buf, ""
        if self._in_pem:
            self._in_pem = False
            return ""
        pem = _open_pem_start(buf)
        if pem is not None:
            self._call.count += 1
            return self._scrub(rx, buf[:pem]) + REDACTED
        return self._scrub(rx, buf)

    def _scrub(self, rx: re.Pattern[str], text: str) -> str:
        out, n = rx.subn(REDACTED, text)
        self._call.count += n
        return out


def _open_token_start(buf: str) -> int:
    """Where an unfinished token may begin: the first prefix in the trailing run of token chars."""
    run = len(buf.rstrip(_TOKEN_CHARS))
    run = max(run, len(buf) - _OPEN_MAX)
    m = _OPEN_PREFIX.search(buf, run)
    return len(buf) if m is None else m.start()


def _open_pem_start(buf: str) -> int | None:
    """Where an unfinished PEM private key block begins, if the last `BEGIN` has no end yet."""
    i = buf.rfind(_PEM_BEGIN_MARK)
    if i < 0 or _PEM_BEGIN.match(buf, i) is None or _PEM.match(buf, i) is not None:
        return None
    return i
