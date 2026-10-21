"""modgudr: a local secret broker for coding agents and scripts."""

from pkgutil import extend_path

__path__ = extend_path(__path__, __name__)

from modgudr.client.api import Client, Result, Sql, connect
from modgudr.client.errors import (
    BrokerUnavailable,
    Denied,
    Error,
    LimitExceeded,
    Locked,
    Throttled,
    UpstreamError,
    UsageError,
)

__all__ = [
    "BrokerUnavailable",
    "Client",
    "Denied",
    "Error",
    "LimitExceeded",
    "Locked",
    "Result",
    "Sql",
    "Throttled",
    "UpstreamError",
    "UsageError",
    "connect",
]
