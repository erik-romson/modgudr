"""Exceptions of the modgudr client, with the exit codes of M5 and the wire-code mapping."""

from collections.abc import Mapping
from typing import Any


class Error(Exception):
    """Base class of every modgudr error. Wire code `internal`, exit code 70."""

    code: str = "internal"
    exit_code: int = 70

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        audit_id: str | None = None,
        layer: str | None = None,
        rule: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code
        self.audit_id = audit_id
        self.layer = layer
        self.rule = rule


class Denied(Error):
    code = "denied"
    exit_code = 2


class Locked(Error):
    code = "locked"
    exit_code = 3


class LimitExceeded(Error):
    """Truncated by a limit (`limit`) or timed out (`timeout`). `.partial` holds what arrived."""

    code = "limit"
    exit_code = 4

    def __init__(self, message: str, *, partial: object = None, **details: str | None) -> None:
        super().__init__(message, **details)
        self.partial = partial


class UpstreamError(Error):
    code = "upstream"
    exit_code = 5


class BrokerUnavailable(Error):
    code = "unavailable"
    exit_code = 6


class Throttled(Error):
    code = "throttled"
    exit_code = 7

    def __init__(
        self, message: str, *, retry_after: float | None = None, **details: str | None
    ) -> None:
        super().__init__(message, **details)
        self.retry_after = retry_after


class UsageError(Error):
    code = "bad_request"
    exit_code = 64


class CannotRun(Error):
    """`agent run` or `doctor --agent` cannot run or reach a verdict (`claude` missing, not
    logged in, inconclusive). Exit 69 (M5)."""

    code = "cannot_run"
    exit_code = 69


ERROR_CLASSES: Mapping[str, type[Error]] = {
    "denied": Denied,
    "locked": Locked,
    "limit": LimitExceeded,
    "timeout": LimitExceeded,
    "upstream": UpstreamError,
    "unavailable": BrokerUnavailable,
    "throttled": Throttled,
    "bad_request": UsageError,
    "not_found": UsageError,
    "internal": Error,
}


def exit_code_for(code: str) -> int:
    """The exit code of a wire error code. An unknown code is `internal` (70)."""
    return ERROR_CLASSES.get(code, Error).exit_code


def error_from_frame(frame: Mapping[str, Any]) -> Error:
    """Build the exception for an `error` frame (M4). An unknown code becomes `Error`."""
    code = frame.get("code")
    code = code if isinstance(code, str) else "internal"
    message = frame.get("message")
    text = message if isinstance(message, str) else f"broker error ({code})"
    audit_id = frame.get("auditId")
    layer = frame.get("layer")
    rule = frame.get("rule")
    details: dict[str, str | None] = {
        "code": code,
        "audit_id": audit_id if isinstance(audit_id, str) else None,
        "layer": layer if isinstance(layer, str) else None,
        "rule": rule if isinstance(rule, str) else None,
    }
    cls = ERROR_CLASSES.get(code, Error)
    if cls is Throttled:
        retry = frame.get("retryAfter")
        seconds = (
            float(retry)
            if isinstance(retry, (int, float)) and not isinstance(retry, bool)
            else None
        )
        return Throttled(text, retry_after=seconds, **details)  # pyright: ignore[reportArgumentType]
    return cls(text, **details)
