"""The explicit `connect()` arguments of the Snowflake driver (M15)."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from modgudr.sql.config import SqlConfig
from modgudr.sql.dialects.snowflake.connect import (
    FORBIDDEN_ARGUMENTS,
    KeyUnusable,
    connect_kwargs,
    normalize_pem,
    private_key_der,
    snowflake_host,
)
from tests.support.snowflakefx import private_key_pem

CONFIG = SqlConfig.model_validate(
    {
        "dialect": "snowflake",
        "account": "Acme_Example",
        "user": "APP_RO",
        "role": "R",
        "warehouse": "W",
        "database": "D",
        "schema": "S",
    }
)


def test_host_is_derived_from_the_account() -> None:
    assert snowflake_host("Acme_Example") == "acme-example.snowflakecomputing.com"
    assert snowflake_host("xy12345.us-east-2.aws") == "xy12345.us-east-2.aws.snowflakecomputing.com"


@pytest.mark.parametrize("account", ["", "a/b", "a b", "evil.com:443@x", "-lead", "a..b", "x#y"])
def test_a_bad_account_is_refused(account: str) -> None:
    with pytest.raises(ValueError, match="account identifier"):
        snowflake_host(account)


def test_connect_arguments_from_a_pem_key() -> None:
    der = private_key_der(private_key_pem())
    assert isinstance(der, bytes)
    kwargs = connect_kwargs(CONFIG, der, 29.2)
    assert kwargs["authenticator"] == "SNOWFLAKE_JWT"
    assert kwargs["private_key"] == der
    assert kwargs["paramstyle"] == "numeric"
    assert kwargs["autocommit"] is False
    assert kwargs["host"] == "acme-example.snowflakecomputing.com"
    assert kwargs["session_parameters"] == {"STATEMENT_TIMEOUT_IN_SECONDS": 30}
    assert kwargs["login_timeout"] == kwargs["network_timeout"] == 30
    assert kwargs["client_store_temporary_credential"] is False
    assert (kwargs["role"], kwargs["warehouse"], kwargs["database"], kwargs["schema"]) == (
        "R",
        "W",
        "D",
        "S",
    )
    assert not FORBIDDEN_ARGUMENTS & kwargs.keys()
    assert "password" not in kwargs and "token" not in kwargs


def test_the_der_is_pkcs8_of_the_same_key() -> None:
    key = serialization.load_der_private_key(private_key_der(private_key_pem()), password=None)
    assert isinstance(key, rsa.RSAPrivateKey)


def test_building_the_arguments_writes_no_file(
    monkeypatch: pytest.MonkeyPatch, shortdir: Path
) -> None:
    home, tmp = shortdir / "home", shortdir / "tmp"
    home.mkdir()
    tmp.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("TMPDIR", str(tmp))
    monkeypatch.setattr(tempfile, "tempdir", str(tmp))
    connect_kwargs(CONFIG, private_key_der(private_key_pem()), 5)
    assert list(home.rglob("*")) == [] and list(tmp.rglob("*")) == []


def test_pkcs1_and_crlf_and_literal_newlines_work() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pkcs1 = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    expected = private_key_der(pkcs1)
    assert private_key_der(pkcs1.replace("\n", "\r\n")) == expected
    assert private_key_der(pkcs1.strip().replace("\n", "\\n")) == expected
    assert "\\n" not in normalize_pem(pkcs1.replace("\n", "\\n"))


def test_an_encrypted_key_is_refused_without_echoing_it() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"pw"),
    ).decode()
    with pytest.raises(KeyUnusable, match="encrypted keys are not supported in the MVP") as info:
        private_key_der(pem)
    assert pem.splitlines()[1] not in str(info.value)


def test_garbage_is_refused_without_echoing_it() -> None:
    with pytest.raises(KeyUnusable, match="not a PEM private key") as info:
        private_key_der(
            "-----BEGIN PRIVATE KEY-----\nZ2FyYmFnZS1nYXJiYWdl\n-----END PRIVATE KEY-----"
        )
    assert "Z2FyYmFnZS1nYXJiYWdl" not in str(info.value)
    with pytest.raises(KeyUnusable):
        private_key_der("hunter2")


def test_the_driver_never_names_a_forbidden_argument() -> None:
    source = (
        Path("packages/sql/src/modgudr/sql/dialects/snowflake/driver_snowflake.py").read_text()
        + Path("packages/sql/src/modgudr/sql/dialects/snowflake/connect.py").read_text()
    )
    code = [ln for ln in source.splitlines() if not ln.lstrip().startswith(("#", '"'))]
    for name in ("insecure_mode", "disable_ocsp_checks", "private_key_file"):
        assert not any(name in ln and "FORBIDDEN" not in ln for ln in code), name
