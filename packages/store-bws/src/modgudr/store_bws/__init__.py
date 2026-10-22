"""modgudr-store-bws: the attended Bitwarden Secrets Manager store, driven through the `bws` CLI.

modgudr never imports, vendors, locks, downloads or ships `bws` or the Bitwarden SDK (M19, Q5).
"""

from .settings import BwsSettings
from .store import BwsStore

__all__ = ["BwsSettings", "BwsStore"]
