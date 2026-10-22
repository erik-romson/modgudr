"""The connect parameters of the Oracle driver (M16): host, port, service or SID.

Everything is explicit and discrete: the broker never builds a DSN string, never reads
`tnsnames.ora` and never calls `init_oracle_client` (thin mode only). The password is not part of
the parameters; the driver passes it to `oracledb.connect` when it logs in.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import oracledb

    from modgudr.sql.config import SqlConfig

PORT = 1521

_HOST = re.compile(r"[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?")
_SERVICE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.$#-]{0,127}")


def check_host(host: str) -> None:
    """A host name or address, nothing else. Raises `ValueError` for a connect descriptor
    (`(DESCRIPTION=`), an Easy Connect string, a URL or anything that needs a TNS lookup."""
    if not _HOST.fullmatch(host):
        raise ValueError(
            f"{host!r} is not a host name or address: give only the host, with the port in "
            "'port', not a TNS alias, a connect descriptor or an Easy Connect string"
        )


def check_service(name: str) -> None:
    """A service name or SID in plain letters, digits and `_ . $ # -`. Raises `ValueError`."""
    if not _SERVICE.fullmatch(name):
        raise ValueError(f"{name!r} is not a service name or SID (letters, digits, _ . $ # -)")


def oracle_port(config: SqlConfig) -> int:
    return config.port if config.port is not None else PORT


def connect_params(config: SqlConfig, timeout: float) -> oracledb.ConnectParams:
    """`oracledb.ConnectParams(host, port, service_name | sid)` for one target (M16).

    `timeout` (seconds) bounds the TCP connect. No retries: a refused login is one attempt.
    """
    import oracledb

    assert config.host is not None
    seconds = max(1.0, float(timeout))
    if config.service is not None:
        return oracledb.ConnectParams(
            host=config.host,
            port=oracle_port(config),
            service_name=config.service,
            user=config.user,
            tcp_connect_timeout=seconds,
            retry_count=0,
        )
    assert config.sid is not None
    return oracledb.ConnectParams(
        host=config.host,
        port=oracle_port(config),
        sid=config.sid,
        user=config.user,
        tcp_connect_timeout=seconds,
        retry_count=0,
    )
