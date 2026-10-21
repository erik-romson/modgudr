"""The connect arguments of the Snowflake driver (M15): host, key, session.

Everything the connector is told is explicit; nothing is read from `~/.snowflake` or the
environment. The private key stays in memory: PEM text from the store in, DER bytes out.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from modgudr.sql.config import SqlConfig

HOST_SUFFIX = ".snowflakecomputing.com"
PORT = 443

_ACCOUNT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*(\.[A-Za-z0-9][A-Za-z0-9_-]*)*")

#: Arguments the broker never passes (M15): they weaken the TLS check or read a key from disk.
FORBIDDEN_ARGUMENTS = frozenset({"insecure_mode", "disable_ocsp_checks", "private_key_file"})


class KeyUnusable(Exception):
    """The secret is not an unencrypted PEM private key. The message never holds key text."""


def snowflake_host(account: str) -> str:
    """`<account>.snowflakecomputing.com`, lowercased with `_` turned into `-`.

    Raises `ValueError` for an account that is not made of plain labels, so that a policy file
    cannot point the broker at another endpoint.
    """
    if not _ACCOUNT.fullmatch(account):
        raise ValueError(
            f"{account!r} is not a Snowflake account identifier (letters, digits, '_' and '-', "
            "with '.' between the parts of a locator)"
        )
    host = account.lower().replace("_", "-") + HOST_SUFFIX
    if not host.endswith(HOST_SUFFIX) or "/" in host or ":" in host:
        raise ValueError(f"the host {host!r} derived from account {account!r} is not valid")
    return host


def normalize_pem(text: str) -> str:
    """CRLF and a literal `\\n` (a key pasted on one line) become real newlines."""
    return text.strip().replace("\r\n", "\n").replace("\r", "\n").replace("\\n", "\n")


def private_key_der(pem: str) -> bytes:
    """The PKCS#8 DER of an unencrypted PEM private key (PKCS#8 or PKCS#1), in memory only.

    Raises `KeyUnusable` for an encrypted key (A19) or anything that is not a private key.
    """
    from cryptography.hazmat.primitives import serialization

    text = normalize_pem(pem)
    if "ENCRYPTED" in text.split("\n", 2)[0] or "Proc-Type: 4,ENCRYPTED" in text:
        raise KeyUnusable("encrypted keys are not supported in the MVP; store an unencrypted key")
    try:
        key = serialization.load_pem_private_key(text.encode("ascii"), password=None)
    except (ValueError, TypeError, UnicodeEncodeError):
        raise KeyUnusable("the secret is not a PEM private key (PKCS#8 or PKCS#1)") from None
    return key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def connect_kwargs(config: SqlConfig, der: bytes, timeout: float) -> dict[str, object]:
    """The explicit arguments of `snowflake.connector.connect` for one target (M15).

    `timeout` (seconds) bounds a statement on the server and the login and network waits.
    """
    assert config.account is not None
    seconds = max(1, int(timeout + 0.999))
    kwargs: dict[str, object] = {
        "account": config.account,
        "user": config.user,
        "role": config.role,
        "warehouse": config.warehouse,
        "host": snowflake_host(config.account),
        "authenticator": "SNOWFLAKE_JWT",
        "private_key": der,
        "paramstyle": "numeric",
        "autocommit": False,
        "session_parameters": {"STATEMENT_TIMEOUT_IN_SECONDS": seconds},
        "login_timeout": seconds,
        "network_timeout": seconds,
        "client_store_temporary_credential": False,
    }
    if config.database is not None:
        kwargs["database"] = config.database
    if config.schema_ is not None:
        kwargs["schema"] = config.schema_
    return kwargs
