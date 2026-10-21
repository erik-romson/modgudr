"""Effective limits (§7.6, M5): the policy defaults, overridden per target where the policy allows.

`maxRowsHard` and `maxRequestBytes` come from the company defaults only. A requested `maxRows`
above `maxRowsHard` is refused (`denied`, exit 2), never clamped (A24).
"""

from __future__ import annotations

from dataclasses import dataclass

from .policy.model import Defaults, TargetConfig


class MaxRowsRefused(Exception):
    """A requested `maxRows` above `maxRowsHard`: `denied`, naming the limit."""


@dataclass(frozen=True)
class Limits:
    #: The call deadline in seconds.
    timeout: float
    max_rows: int
    max_rows_hard: int
    max_bytes: int
    max_request_bytes: int
    max_concurrent: int

    def to_json(self) -> dict[str, object]:
        return {
            "timeout": self.timeout,
            "maxRows": self.max_rows,
            "maxRowsHard": self.max_rows_hard,
            "maxBytes": self.max_bytes,
            "maxRequestBytes": self.max_request_bytes,
            "maxConcurrent": self.max_concurrent,
        }

    def with_max_rows(self, requested: int | None) -> Limits:
        """The limits of one call with its own `maxRows` (`--max-rows`), validated already."""
        if requested is None:
            return self
        if requested > self.max_rows_hard:
            raise MaxRowsRefused(
                f"maxRows {requested} is above maxRowsHard {self.max_rows_hard}; "
                f"ask for at most {self.max_rows_hard} rows"
            )
        return Limits(
            timeout=self.timeout,
            max_rows=requested,
            max_rows_hard=self.max_rows_hard,
            max_bytes=self.max_bytes,
            max_request_bytes=self.max_request_bytes,
            max_concurrent=self.max_concurrent,
        )


def defaults_limits(defaults: Defaults) -> Limits:
    return Limits(
        timeout=defaults.timeout,
        max_rows=defaults.maxRows,
        max_rows_hard=defaults.maxRowsHard,
        max_bytes=defaults.maxBytes,
        max_request_bytes=defaults.maxRequestBytes,
        max_concurrent=defaults.maxConcurrent,
    )


def effective_limits(defaults: Defaults, target: TargetConfig) -> Limits:
    """The limits of a target: its own `timeout`, `maxRows`, `maxBytes` and `maxConcurrent`
    where it sets them, else the company defaults."""
    return Limits(
        timeout=target.timeout if target.timeout is not None else defaults.timeout,
        max_rows=target.maxRows if target.maxRows is not None else defaults.maxRows,
        max_rows_hard=defaults.maxRowsHard,
        max_bytes=target.maxBytes if target.maxBytes is not None else defaults.maxBytes,
        max_request_bytes=defaults.maxRequestBytes,
        max_concurrent=(
            target.maxConcurrent if target.maxConcurrent is not None else defaults.maxConcurrent
        ),
    )


class Slots:
    """A target's `maxConcurrent` slots. Taking one never blocks (A23: no queueing)."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.used = 0

    def try_acquire(self) -> bool:
        if self.used >= self.limit:
            return False
        self.used += 1
        return True

    def release(self) -> None:
        if self.used <= 0:
            raise RuntimeError("slot released twice")
        self.used -= 1
