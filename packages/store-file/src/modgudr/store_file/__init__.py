"""modgudr-store-file: the `file` secret store, for development and tests only (§10.3)."""

from .store import Entry, FileStore, FileStoreError, read_secrets_file

__all__ = ["Entry", "FileStore", "FileStoreError", "read_secrets_file"]
