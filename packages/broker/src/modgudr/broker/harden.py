"""Start-up hardening (M23, §5.3). Only the daemon runs it; the factory never does (M3).

`apply` replaces the process environment, so it is never called inside a test process: tests run
it in a child and probe the child from the parent.

The re-exec under `python -I` lives in `reexec`; the rest are one function per M23 item.
"""

from __future__ import annotations

import ctypes
import faulthandler
import logging
import os
import resource
import sys
import traceback
from collections.abc import MutableMapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .scrub import Scrubber

#: The only variables the daemon keeps (and so the only ones any child could inherit).
KEPT_VARIABLES = ("PATH", "HOME", "LANG")
KEPT_PREFIX = "LC_"
TELEMETRY_VARIABLE = "SF_TELEMETRY_DISABLE_CONNECTION_SHAPE"

PT_DENY_ATTACH = 31
PR_SET_DUMPABLE = 4

#: Driver loggers that must not log at INFO/DEBUG (they can carry statements and parameters).
QUIET_LOGGERS = ("snowflake.connector", "oracledb", "sqlglot")


class Libc(Protocol):
    """What the anti-debug calls need of the C library (tests inject a fake)."""

    ptrace: Any
    prctl: Any


class HardeningError(Exception):
    """A hardening call failed: the broker refuses to start (exit 78)."""


@dataclass(frozen=True)
class Hardening:
    """The hardening facts reported by `status --json`."""

    isolated: bool
    environment_kept: tuple[str, ...]
    anti_debug: str
    anti_debug_result: int
    core_limit: tuple[int, int]
    faulthandler_enabled: bool
    log_filter: bool
    quiet_loggers: tuple[str, ...]
    warnings: tuple[str, ...]

    def to_json(self) -> dict[str, object]:
        return {
            "applied": True,
            "isolated": self.isolated,
            "environmentKept": list(self.environment_kept),
            "antiDebug": {"mechanism": self.anti_debug, "result": self.anti_debug_result},
            "coreLimit": list(self.core_limit),
            "faulthandler": self.faulthandler_enabled,
            "logFilter": self.log_filter,
            "quietLoggers": list(self.quiet_loggers),
            "warnings": list(self.warnings),
        }


NOT_APPLIED: dict[str, object] = {"applied": False}


def reexec(args: list[str]) -> None:
    """Replace this process with `sys.executable -I -m modgudr.broker <args>` unless it already
    runs isolated. Raises `HardeningError` when the exec fails."""
    if sys.flags.isolated:
        return
    argv = [sys.executable, "-I", "-m", "modgudr.broker", *args]
    try:
        os.execv(sys.executable, argv)
    except OSError as exc:
        raise HardeningError(f"cannot re-execute under -I: {exc}") from exc


def reset_environment(environ: MutableMapping[str, str]) -> tuple[str, ...]:
    """Keep `PATH`, `HOME`, `LANG` and `LC_*`; set the Snowflake telemetry switch."""
    kept = {
        key: value
        for key, value in environ.items()
        if key in KEPT_VARIABLES or key.startswith(KEPT_PREFIX)
    }
    environ.clear()
    environ.update(kept)
    environ[TELEMETRY_VARIABLE] = "true"
    return tuple(sorted(environ))


def deny_attach(platform: str, libc: Libc | None = None) -> tuple[str, int]:
    """macOS: `ptrace(PT_DENY_ATTACH)`; Linux: `prctl(PR_SET_DUMPABLE, 0)`.

    Returns (mechanism, result). Any other platform, or a non-zero result, is an error."""
    try:
        if platform == "darwin":
            lib = libc if libc is not None else ctypes.CDLL(None, use_errno=True)
            lib.ptrace.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
            lib.ptrace.restype = ctypes.c_int
            result = int(lib.ptrace(PT_DENY_ATTACH, 0, None, 0))
            mechanism = "ptrace(PT_DENY_ATTACH)"
        elif platform.startswith("linux"):
            lib = libc if libc is not None else ctypes.CDLL(None, use_errno=True)
            lib.prctl.argtypes = [ctypes.c_int, *([ctypes.c_ulong] * 4)]
            lib.prctl.restype = ctypes.c_int
            result = int(lib.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0))
            mechanism = "prctl(PR_SET_DUMPABLE)"
        else:
            raise HardeningError(f"no anti-debug mechanism for the platform {platform!r}")
    except (OSError, AttributeError, TypeError) as exc:
        raise HardeningError(f"the anti-debug call failed: {exc}") from exc
    if result != 0:
        raise HardeningError(f"{mechanism} returned {result} (errno {ctypes.get_errno()})")
    return mechanism, result


def disable_core_dumps() -> tuple[int, int]:
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        return resource.getrlimit(resource.RLIMIT_CORE)
    except (OSError, ValueError) as exc:
        raise HardeningError(f"cannot set RLIMIT_CORE to 0: {exc}") from exc


class ScrubbingFilter(logging.Filter):
    """Replaces every registered secret in a record's message and exception text."""

    def __init__(self, scrubber: Scrubber) -> None:
        super().__init__()
        self._scrubber = scrubber

    def filter(self, record: logging.LogRecord) -> bool:
        scrubber = self._scrubber
        record.msg = scrubber.error(record.getMessage())
        record.args = None
        if record.exc_info and record.exc_info[1] is not None:
            text = "".join(traceback.format_exception(*record.exc_info)).rstrip("\n")
            record.exc_text = scrubber.error(text)
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = scrubber.error(record.exc_text)
        if record.stack_info:
            record.stack_info = scrubber.error(record.stack_info)
        return True


def install_log_filter(scrubber: Scrubber) -> tuple[str, ...]:
    """Put the scrubbing filter on the root logger and on every root handler (a logger's filter
    does not see records from its children), and set the driver loggers to WARNING. Returns the
    quiet logger names."""
    root = logging.getLogger()
    if not root.handlers:
        root.addHandler(logging.StreamHandler(sys.stderr))
    scrubbing = ScrubbingFilter(scrubber)
    root.addFilter(scrubbing)
    for handler in root.handlers:
        handler.addFilter(scrubbing)
    for name in QUIET_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)
    return QUIET_LOGGERS


def permission_warnings(policy_dir: Path, venv: Path) -> tuple[str, ...]:
    """A warning for the policy directory or the venv when group- or world-writable."""
    found: list[str] = []
    for label, path in (("the policy directory", policy_dir), ("the virtual environment", venv)):
        try:
            mode = path.stat().st_mode
        except FileNotFoundError:
            continue
        except OSError as exc:
            found.append(f"cannot check the permissions of {label} {path}: {exc}")
            continue
        if mode & 0o022:
            found.append(f"{label} {path} is group- or world-writable ({mode & 0o777:04o})")
    return tuple(found)


def apply(
    scrubber: Scrubber,
    policy_dir: Path,
    *,
    platform: str = sys.platform,
    libc: Libc | None = None,
    environ: MutableMapping[str, str] | None = None,
    venv: Path | None = None,
) -> Hardening:
    """Run every M23 item in order and return the facts. Raises `HardeningError`.

    The caller reads `MODGUDR_HOME` and `MODGUDR_SOCKET` before this replaces the environment."""
    env = os.environ if environ is None else environ
    kept = reset_environment(env)
    mechanism, result = deny_attach(platform, libc)
    core = disable_core_dumps()
    faulthandler.disable()
    quiet = install_log_filter(scrubber)
    warnings = permission_warnings(policy_dir, venv if venv is not None else Path(sys.prefix))
    return Hardening(
        isolated=bool(sys.flags.isolated),
        environment_kept=kept,
        anti_debug=mechanism,
        anti_debug_result=result,
        core_limit=core,
        faulthandler_enabled=faulthandler.is_enabled(),
        log_filter=True,
        quiet_loggers=quiet,
        warnings=warnings,
    )
