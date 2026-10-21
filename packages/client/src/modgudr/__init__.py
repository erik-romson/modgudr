"""modgudr: a local secret broker for coding agents and scripts."""

from pkgutil import extend_path
from typing import Any

__path__ = extend_path(__path__, __name__)

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
    "Denied",
    "Error",
    "LimitExceeded",
    "Locked",
    "Throttled",
    "UpstreamError",
    "UsageError",
    "connect",
]


def connect(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
    """Open a connection to the broker. Implemented in step 08."""
    raise NotImplementedError("modgudr.connect() is implemented in step 08")
