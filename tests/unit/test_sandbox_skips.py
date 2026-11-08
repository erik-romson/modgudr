# pyright: reportPrivateUsage=false
"""The sandbox skip hook: what it recognises and when it acts. `BIND_BLOCKED` is set per test, so
the results do not depend on where the suite runs."""

from __future__ import annotations

import errno
import socket
from collections.abc import Callable, Generator
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from modgudr.broker.server import StartError
from tests.support import sandbox
from tests.support.sandbox import DOCKER_MISSING, REASON

BIND_TEXT = "cannot bind /x: Operation not permitted"


def capture(raiser: Callable[[], object]) -> pytest.ExceptionInfo[BaseException]:
    with pytest.raises(BaseException) as info:
        raiser()
    return info


def raise_eperm_in_bind() -> None:
    class Sock:
        def bind(self, path: str) -> None:
            raise PermissionError(errno.EPERM, "Operation not permitted")

    Sock().bind("/x")


def raise_eperm_elsewhere() -> None:
    raise PermissionError(errno.EPERM, "Operation not permitted")


def raise_eacces_in_bind() -> None:
    class Sock:
        def bind(self, path: str) -> None:
            raise PermissionError(errno.EACCES, "Permission denied")

    Sock().bind("/x")


def raise_start_error() -> None:
    raise StartError(BIND_TEXT)


def raise_assertion(text: str) -> Callable[[], None]:
    def raiser() -> None:
        raise AssertionError(text)

    return raiser


def raise_fail(text: str) -> Callable[[], None]:
    def raiser() -> None:
        pytest.fail(text, pytrace=False)

    return raiser


def raise_runtime(text: str) -> Callable[[], None]:
    def raiser() -> None:
        raise RuntimeError(text)

    return raiser


def raise_value_error() -> None:
    raise ValueError("boom")


# --- _blocked ----------------------------------------------------------------------------------


def test_start_error_with_the_bind_text_is_blocked() -> None:
    assert sandbox._blocked(capture(raise_start_error))


def test_eperm_under_a_bind_line_is_blocked() -> None:
    assert sandbox._blocked(capture(raise_eperm_in_bind))


def test_eperm_elsewhere_is_not_blocked() -> None:
    assert not sandbox._blocked(capture(raise_eperm_elsewhere))


def test_eacces_under_a_bind_line_is_not_blocked() -> None:
    assert not sandbox._blocked(capture(raise_eacces_in_bind))


def test_assertion_quoting_the_bind_text_is_not_blocked() -> None:
    assert not sandbox._blocked(capture(raise_assertion(BIND_TEXT)))


def test_pytest_fail_quoting_the_bind_text_is_not_blocked() -> None:
    assert not sandbox._blocked(capture(raise_fail(BIND_TEXT)))


def test_the_oracle_fixture_failure_with_a_cause_is_blocked() -> None:
    from tests.support import oraclefx

    assert sandbox._blocked(capture(raise_fail(f"{oraclefx.NOT_AVAILABLE}: FileNotFoundError")))


def test_the_oracle_fixture_failure_without_a_cause_is_blocked() -> None:
    from tests.support import oraclefx

    assert sandbox._blocked(capture(raise_fail(oraclefx.NOT_AVAILABLE)))


def test_the_docker_text_after_other_text_is_not_blocked() -> None:
    assert not sandbox._blocked(capture(raise_fail(f"other: {DOCKER_MISSING}")))


def test_a_runtime_error_with_the_docker_text_is_not_blocked() -> None:
    assert not sandbox._blocked(capture(raise_runtime(DOCKER_MISSING)))


def test_an_assertion_with_the_docker_text_is_not_blocked() -> None:
    assert not sandbox._blocked(capture(raise_assertion(DOCKER_MISSING)))


def test_the_docker_text_matches_the_oracle_fixture() -> None:
    from tests.support import oraclefx

    assert oraclefx.NOT_AVAILABLE.startswith(DOCKER_MISSING)


def test_an_unrelated_error_is_not_blocked() -> None:
    assert not sandbox._blocked(capture(raise_value_error))


# --- the hook ----------------------------------------------------------------------------------


class FakeItem:
    path = Path("/x/test_a.py")
    location = ("test_a.py", 6, "test_a")


class FakeReport:
    def __init__(self, when: str, outcome: str) -> None:
        self.when = when
        self.outcome = outcome
        self.longrepr: object = "original"

    @property
    def failed(self) -> bool:
        return self.outcome == "failed"


def run_hook(
    when: str, outcome: str, info: pytest.ExceptionInfo[BaseException] | None
) -> FakeReport:
    report = FakeReport(when, outcome)
    call = cast(Any, type("Call", (), {"excinfo": info})())
    hook: Generator[None, Any, Any] = sandbox.pytest_runtest_makereport(cast(Any, FakeItem()), call)
    next(hook)
    try:
        hook.send(report)
    except StopIteration as done:
        assert done.value is report
        return report
    raise AssertionError("the hook did not return")


def test_a_docker_setup_failure_is_skipped_in_the_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sandbox, "BIND_BLOCKED", True)
    report = run_hook("setup", "failed", capture(raise_fail(DOCKER_MISSING)))
    assert report.outcome == "skipped"


def test_a_docker_setup_failure_stays_failed_outside_the_sandbox(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sandbox, "BIND_BLOCKED", False)
    report = run_hook("setup", "failed", capture(raise_fail(DOCKER_MISSING)))
    assert report.outcome == "failed"


def test_a_call_failure_stays_failed_outside_the_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sandbox, "BIND_BLOCKED", False)
    report = run_hook("call", "failed", capture(raise_start_error))
    assert report.outcome == "failed"
    assert report.longrepr == "original"


def test_a_call_failure_is_skipped_in_the_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sandbox, "BIND_BLOCKED", True)
    report = run_hook("call", "failed", capture(raise_start_error))
    assert report.outcome == "skipped"
    longrepr = cast(tuple[str, int, str], report.longrepr)
    assert isinstance(longrepr, tuple)
    path, line, reason = longrepr
    assert (path, line) == ("/x/test_a.py", 6)
    assert reason.startswith("Skipped: ")
    assert REASON in reason


def test_a_setup_failure_is_skipped_in_the_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sandbox, "BIND_BLOCKED", True)
    report = run_hook("setup", "failed", capture(raise_start_error))
    assert report.outcome == "skipped"


def test_a_teardown_failure_stays_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sandbox, "BIND_BLOCKED", True)
    report = run_hook("teardown", "failed", capture(raise_start_error))
    assert report.outcome == "failed"


def test_an_unrelated_failure_stays_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sandbox, "BIND_BLOCKED", True)
    report = run_hook("call", "failed", capture(raise_value_error))
    assert report.outcome == "failed"


def test_a_passed_report_is_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sandbox, "BIND_BLOCKED", True)
    report = run_hook("call", "passed", None)
    assert report.outcome == "passed"
    assert report.longrepr == "original"


# --- _probe ------------------------------------------------------------------------------------


class FakeSocket:
    def __init__(self, error: OSError | None) -> None:
        self.error = error
        self.closed = False

    def bind(self, path: str) -> None:
        if self.error is not None:
            raise self.error

    def close(self) -> None:
        self.closed = True


def fake_socket(monkeypatch: pytest.MonkeyPatch, error: OSError | None) -> FakeSocket:
    fake = FakeSocket(error)
    namespace = SimpleNamespace(AF_UNIX=socket.AF_UNIX, socket=lambda *args, **kwargs: fake)  # pyright: ignore[reportUnknownLambdaType]
    monkeypatch.setattr(sandbox, "socket", namespace)
    return fake


def test_probe_is_true_when_bind_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = fake_socket(monkeypatch, PermissionError(errno.EPERM, "Operation not permitted"))
    assert sandbox._probe() is True
    assert fake.closed


def test_probe_is_false_when_bind_works(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = fake_socket(monkeypatch, None)
    assert sandbox._probe() is False
    assert fake.closed


def test_probe_is_false_when_the_directory_cannot_be_made(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse() -> Path:
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(sandbox, "make_shortdir", refuse)
    assert sandbox._probe() is False


def test_probe_lets_other_errors_propagate(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_socket(monkeypatch, OSError(errno.ENAMETOOLONG, "File name too long"))
    with pytest.raises(OSError) as raised:
        sandbox._probe()
    assert raised.value.errno == errno.ENAMETOOLONG


# --- header ------------------------------------------------------------------------------------


def test_header_names_the_reason_only_when_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sandbox, "BIND_BLOCKED", True)
    header = sandbox.pytest_report_header()
    assert header is not None
    assert REASON in header
    monkeypatch.setattr(sandbox, "BIND_BLOCKED", False)
    assert sandbox.pytest_report_header() is None
