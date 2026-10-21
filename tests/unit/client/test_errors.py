import pytest

import modgudr
from modgudr.client.errors import (
    ERROR_CLASSES,
    BrokerUnavailable,
    Denied,
    Error,
    LimitExceeded,
    Locked,
    Throttled,
    UpstreamError,
    UsageError,
    error_from_frame,
    exit_code_for,
)

TABLE = [
    ("denied", Denied, 2),
    ("locked", Locked, 3),
    ("limit", LimitExceeded, 4),
    ("timeout", LimitExceeded, 4),
    ("upstream", UpstreamError, 5),
    ("unavailable", BrokerUnavailable, 6),
    ("throttled", Throttled, 7),
    ("bad_request", UsageError, 64),
    ("not_found", UsageError, 64),
    ("internal", Error, 70),
]


@pytest.mark.parametrize(("code", "cls", "exit_code"), TABLE)
def test_every_code_maps_to_class_and_exit_code(
    code: str, cls: type[Error], exit_code: int
) -> None:
    exc = error_from_frame({"t": "error", "code": code, "message": "m"})
    assert type(exc) is cls
    assert exc.exit_code == exit_code
    assert exc.code == code
    assert exit_code_for(code) == exit_code


def test_table_is_complete() -> None:
    assert set(ERROR_CLASSES) == {code for code, _, _ in TABLE}


def test_usage_error_is_a_modgudr_error() -> None:
    assert issubclass(UsageError, modgudr.Error)
    assert all(issubclass(cls, Error) for _, cls, _ in TABLE)


def test_details_travel_on_the_exception() -> None:
    exc = error_from_frame(
        {
            "t": "error",
            "code": "denied",
            "message": "no",
            "auditId": "a1",
            "layer": "company",
            "rule": "r7",
        }
    )
    assert isinstance(exc, Denied)
    assert (str(exc), exc.audit_id, exc.layer, exc.rule) == ("no", "a1", "company", "r7")


def test_throttled_carries_retry_after() -> None:
    exc = error_from_frame({"code": "throttled", "message": "busy", "retryAfter": 3})
    assert isinstance(exc, Throttled)
    assert exc.retry_after == 3.0


def test_limit_carries_partial() -> None:
    assert LimitExceeded("x", partial=[1]).partial == [1]


def test_unknown_code_is_internal() -> None:
    exc = error_from_frame({"code": "weird", "message": "m"})
    assert type(exc) is Error
    assert exc.exit_code == 70


def test_package_reexports_errors() -> None:
    for name in (
        "Error",
        "Denied",
        "Locked",
        "LimitExceeded",
        "UpstreamError",
        "BrokerUnavailable",
        "Throttled",
        "UsageError",
    ):
        assert getattr(modgudr, name).__name__ == name
