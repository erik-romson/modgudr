"""Report tests the agent sandbox cannot run as skipped, only when a probe shows it is blocking."""

import errno
import shutil
import socket
import traceback
from collections.abc import Generator

import pytest

from tests.support.shortdir import make_shortdir

DOCKER_MISSING = "Docker or the Oracle Free image is not available"
REASON = "the sandbox blocks this; run scripts/check.sh outside it"


def _probe() -> bool:
    """Whether a bind in our own directory is refused. A directory we cannot create proves nothing:
    it counts as not blocked, and the tests then fail with the real error."""
    try:
        path = make_shortdir()
    except PermissionError:
        return False
    probe = socket.socket(socket.AF_UNIX)
    try:
        probe.bind(str(path / "p.sock"))
    except PermissionError:
        return True
    else:
        return False
    finally:
        probe.close()
        shutil.rmtree(path, ignore_errors=True)


BIND_BLOCKED = _probe()


def _blocked(info: pytest.ExceptionInfo[BaseException]) -> bool:
    value = info.value
    text = str(value)
    if isinstance(value, pytest.fail.Exception):
        return text.startswith(DOCKER_MISSING)
    if isinstance(value, AssertionError):
        return False
    if "cannot bind" in text and "not permitted" in text:
        return True
    if isinstance(value, PermissionError) and value.errno == errno.EPERM:
        return any("bind(" in line for line in traceback.format_tb(info.tb))
    return False


def pytest_report_header() -> str | None:
    if not BIND_BLOCKED:
        return None
    return f"agent sandbox: socket and Docker tests are skipped ({REASON})"


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(
    item: pytest.Item, call: pytest.CallInfo[None]
) -> Generator[None, pytest.TestReport, pytest.TestReport]:
    report = yield
    if (
        BIND_BLOCKED
        and report.failed
        and report.when in ("setup", "call")
        and call.excinfo is not None
        and _blocked(call.excinfo)
    ):
        report.outcome = "skipped"
        report.longrepr = (str(item.path), item.location[1] or 0, f"Skipped: {REASON}")
    return report
