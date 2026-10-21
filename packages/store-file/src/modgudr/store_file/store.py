"""The `file` secret store (§10.3): a YAML file of secrets, for development and tests only.

It is enabled only with `modgudr-broker --dev` (M3). The file must be a regular file owned by the
current user with mode 0600 (no group or other access), and it is read again on every resolve, so
a test can change a value under a running broker. The store starts LOCKED (M7); its `unlock`
accepts any input, which lets tests drive the state machine.

    cbsl-test:
      value: "the password or PEM key"
      hosts: [db-test.example.net:1521]
      env: test

Each entry has `value` (required), `hosts` (the destination pins, M8) and `env` (the environment
pin). Any other key, a duplicate key or a malformed entry refuses the whole file.
"""

from __future__ import annotations

import errno
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from modgudr.broker.policy.yaml_strict import StrictYamlError, load_strict
from modgudr.spi import ResolvedSecret, SecretRef, StoreConfigError, StoreContext, StoreError

SCHEME = "file"
_ENTRY_KEYS = frozenset({"value", "hosts", "env"})


class FileStoreError(Exception):
    """The secrets file cannot be used."""


@dataclass(frozen=True)
class Entry:
    value: str = field(repr=False)
    hosts: tuple[str, ...] = ()
    env: str | None = None


def read_secrets_file(path: Path, *, uid: int | None = None) -> dict[str, Entry]:
    """Read and validate the secrets file. Raises `FileStoreError` naming the problem."""
    me = os.getuid() if uid is None else uid
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise FileStoreError(f"{path} is a symlink") from None
        raise FileStoreError(f"{path} cannot be opened: {exc.strerror}") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise FileStoreError(f"{path} is not a regular file")
        if st.st_uid != me:
            raise FileStoreError(f"{path} is owned by uid {st.st_uid}, not by this user")
        mode = stat.S_IMODE(st.st_mode)
        if mode & 0o077:
            raise FileStoreError(f"{path} has mode {mode:04o}; it must be 0600")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            raw = handle.read()
    finally:
        os.close(fd)
    try:
        data = load_strict(raw.decode("utf-8"), path.name)
    except UnicodeDecodeError:
        raise FileStoreError(f"{path} is not valid UTF-8") from None
    except StrictYamlError as exc:
        raise FileStoreError(str(exc)) from None
    if data is None:
        return {}
    if not isinstance(data, Mapping):
        raise FileStoreError(f"{path} must hold a mapping of secret names to entries")
    entries: dict[str, Entry] = {}
    for name, raw_entry in cast("Mapping[object, object]", data).items():
        if not isinstance(name, str) or not name:
            raise FileStoreError(f"{path}: secret names must be non-empty strings")
        entries[name] = _entry(path, name, raw_entry)
    return entries


def _entry(path: Path, name: str, raw: object) -> Entry:
    where = f"{path}: {name}"
    if not isinstance(raw, Mapping):
        raise FileStoreError(f"{where}: an entry must be a mapping with value, hosts and env")
    entry = cast("Mapping[object, object]", raw)
    unknown = sorted(str(k) for k in entry if k not in _ENTRY_KEYS)
    if unknown:
        raise FileStoreError(f"{where}: unknown key {unknown[0]!r}; keys: env, hosts, value")
    value = entry.get("value")
    if not isinstance(value, str) or not value:
        raise FileStoreError(f"{where}: 'value' must be a non-empty string")
    hosts = entry.get("hosts", [])
    if not isinstance(hosts, list) or not all(
        isinstance(h, str) and h for h in cast("list[object]", hosts)
    ):
        raise FileStoreError(f"{where}: 'hosts' must be a list of host[:port] strings")
    env = entry.get("env")
    if env is not None and (not isinstance(env, str) or not env):
        raise FileStoreError(f"{where}: 'env' must be an environment name")
    return Entry(value, tuple(cast("list[str]", hosts)), env)


class FileStore:
    """The `SecretStore` for scheme `file`."""

    scheme = SCHEME

    def __init__(self, context: StoreContext) -> None:
        if not context.dev:
            raise StoreConfigError("the file store is for development only; start with --dev")
        if context.settings:
            keys = ", ".join(sorted(context.settings))
            raise StoreConfigError(f"store.file takes no settings (found: {keys})")
        if context.secrets_file is None:
            raise StoreConfigError("the file store needs --secrets-file")
        self._path = context.secrets_file
        try:
            read_secrets_file(self._path)
        except FileStoreError as exc:
            raise StoreConfigError(str(exc)) from exc
        self._unlocked = False

    @property
    def path(self) -> Path:
        return self._path

    async def unlock(self, credential: str) -> None:
        """Any input unlocks the file store (M7)."""
        self._unlocked = True

    async def lock(self) -> None:
        self._unlocked = False

    def is_unlocked(self) -> bool:
        return self._unlocked

    async def resolve(self, ref: SecretRef) -> ResolvedSecret:
        if not self._unlocked:
            raise StoreError("the file store is locked")
        if ref.store != SCHEME:
            raise StoreError(f"the file store cannot resolve {ref}")
        try:
            entries = read_secrets_file(self._path)
        except FileStoreError as exc:
            raise StoreError(str(exc)) from None
        entry = entries.get(ref.item)
        if entry is None:
            raise StoreError(f"secret {ref} is not in {self._path}")
        env = (entry.env,) if entry.env is not None else ()
        return ResolvedSecret(ref=ref, value=entry.value, hosts=entry.hosts, env=env)
