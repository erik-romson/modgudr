"""The Oracle driver's error mapping (M8, M16), with errors built by hand: no database needed."""

from __future__ import annotations

from types import SimpleNamespace

import oracledb
import pytest

from modgudr.spi import AuthFailed, UpstreamFailure
from modgudr.sql.config import SqlConfig
from modgudr.sql.dialects.oracle.driver_oracle import OracleDriver, _translate  # pyright: ignore[reportPrivateUsage]
from modgudr.sql.driver import SessionDead, StatementError


def error(kind: type[oracledb.Error], code: str, message: str = "") -> oracledb.Error:
    return kind(
        SimpleNamespace(full_code=code, message=message or f"{code}: text\nHelp: https://x")
    )


def driver(**change: object) -> OracleDriver:
    data = {
        "dialect": "oracle",
        "host": "db.example.net",
        "port": 1522,
        "user": "APP_RO",
        "service": "SVC",
        **change,
    }
    return OracleDriver(SqlConfig.model_validate({k: v for k, v in data.items() if v is not None}))


def test_destinations_use_the_configured_port_or_1521() -> None:
    assert [str(d) for d in driver().destinations()] == ["db.example.net:1522"]
    assert [str(d) for d in driver(port=None).destinations()] == ["db.example.net:1521"]


def test_a_wrong_password_is_an_authentication_failure() -> None:
    result = driver()._login_error(error(oracledb.DatabaseError, "ORA-01017"))  # pyright: ignore[reportPrivateUsage]
    assert isinstance(result, AuthFailed) and not result.final
    assert "Help:" not in str(result)


@pytest.mark.parametrize("code", ["ORA-28000", "ORA-28001"])
def test_a_locked_or_expired_account_is_final(code: str) -> None:
    result = driver()._login_error(error(oracledb.DatabaseError, code))  # pyright: ignore[reportPrivateUsage]
    assert isinstance(result, AuthFailed) and result.final


@pytest.mark.parametrize("code", ["DPY-6005", "ORA-12541"])
def test_an_unreachable_host_says_to_check_the_vpn(code: str) -> None:
    result = driver()._login_error(error(oracledb.OperationalError, code))  # pyright: ignore[reportPrivateUsage]
    assert isinstance(result, UpstreamFailure)
    assert str(result) == "cannot reach db.example.net:1522; check that your VPN is up"


def test_the_listener_not_knowing_the_name_says_service_or_sid() -> None:
    wrapped = 'DPY-6005: cannot connect\nDPY-6001: Service "X" is not registered'
    service = driver()._login_error(error(oracledb.OperationalError, "DPY-6005", wrapped))  # pyright: ignore[reportPrivateUsage]
    assert "`service`" in str(service) and "VPN" not in str(service)
    sid_wrapped = 'DPY-6005: cannot connect\nDPY-6003: SID "X" is not registered'
    sid = driver(service=None, sid="FREE")._login_error(  # pyright: ignore[reportPrivateUsage]
        error(oracledb.OperationalError, "DPY-6005", sid_wrapped)
    )
    assert "`sid`" in str(sid) and "'FREE'" in str(sid)
    assert "`service`" in str(driver()._login_error(error(oracledb.DatabaseError, "ORA-12514")))  # pyright: ignore[reportPrivateUsage]
    assert "`sid`" in str(driver()._login_error(error(oracledb.DatabaseError, "ORA-12505")))  # pyright: ignore[reportPrivateUsage]


def test_native_network_encryption_needs_thick_mode() -> None:
    result = driver()._login_error(error(oracledb.NotSupportedError, "DPY-3001"))  # pyright: ignore[reportPrivateUsage]
    assert isinstance(result, UpstreamFailure) and "thick mode" in str(result)


def test_any_other_login_failure_names_the_code() -> None:
    result = driver()._login_error(error(oracledb.DatabaseError, "ORA-12637", "ORA-12637: x"))  # pyright: ignore[reportPrivateUsage]
    assert isinstance(result, UpstreamFailure) and "ORA-12637" in str(result)


@pytest.mark.parametrize("code", ["ORA-03113", "ORA-03114", "DPY-4011", "ORA-00028"])
def test_a_dead_connection_may_reconnect(code: str) -> None:
    assert isinstance(_translate(error(oracledb.OperationalError, code)), SessionDead)


@pytest.mark.parametrize("code", ["DPY-4024", "ORA-01013"])
def test_a_call_timeout_is_a_timeout(code: str) -> None:
    assert isinstance(_translate(error(oracledb.OperationalError, code)), TimeoutError)


def test_a_server_refusal_keeps_the_session() -> None:
    result = _translate(error(oracledb.DatabaseError, "ORA-00942", "ORA-00942: no table\nHelp: x"))
    assert isinstance(result, StatementError) and str(result) == "ORA-00942: no table"
