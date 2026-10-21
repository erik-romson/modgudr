"""The `file` secret store: the file's rules, LOCKED at start, resolve, and the entry point."""

from __future__ import annotations

import importlib.metadata
from pathlib import Path

import pytest

from modgudr.spi import SecretRef, StoreConfigError, StoreContext, StoreError
from modgudr.store_file import FileStore, FileStoreError, read_secrets_file
from tests.support.brokerfx import write_file, write_secrets

ENTRY = {"value": "pa55word-long", "hosts": ["db1.example.net:1521"], "env": "test"}


def context(
    path: Path | None, *, dev: bool = True, settings: dict[str, object] | None = None
) -> StoreContext:
    return StoreContext(
        scheme="file",
        home=path.parent if path else Path("/nonexistent"),
        dev=dev,
        settings=settings or {},
        secrets_file=path,
    )


@pytest.fixture
def secrets(shortdir: Path) -> Path:
    path = shortdir / "secrets.yaml"
    write_secrets(path, {"db1": ENTRY, "bare": {"value": "only-a-value"}})
    return path


async def test_it_starts_locked_and_any_input_unlocks(secrets: Path) -> None:
    store = FileStore(context(secrets))
    assert store.scheme == "file"
    assert not store.is_unlocked()
    with pytest.raises(StoreError, match="locked"):
        await store.resolve(SecretRef("file", "db1"))
    await store.unlock("")
    assert store.is_unlocked()
    await store.lock()
    assert not store.is_unlocked()


async def test_resolve_returns_value_and_pins(secrets: Path) -> None:
    store = FileStore(context(secrets))
    await store.unlock("anything")
    secret = await store.resolve(SecretRef("file", "db1"))
    assert (secret.value, secret.hosts, secret.env) == (
        "pa55word-long",
        ("db1.example.net:1521",),
        ("test",),
    )
    assert "pa55word-long" not in repr(secret)
    bare = await store.resolve(SecretRef("file", "bare"))
    assert (bare.hosts, bare.env) == ((), ())
    with pytest.raises(StoreError, match="file:nosuch is not in"):
        await store.resolve(SecretRef("file", "nosuch"))
    with pytest.raises(StoreError, match="cannot resolve bws:x"):
        await store.resolve(SecretRef("bws", "x"))


async def test_the_file_is_read_again_on_every_resolve(secrets: Path) -> None:
    store = FileStore(context(secrets))
    await store.unlock("x")
    write_secrets(secrets, {"db1": {**ENTRY, "value": "changed-value"}})
    assert (await store.resolve(SecretRef("file", "db1"))).value == "changed-value"


def test_only_with_dev(secrets: Path) -> None:
    with pytest.raises(StoreConfigError, match="start with --dev"):
        FileStore(context(secrets, dev=False))


def test_settings_and_a_missing_path_are_refused(secrets: Path) -> None:
    with pytest.raises(StoreConfigError, match="takes no settings"):
        FileStore(context(secrets, settings={"path": "x"}))
    with pytest.raises(StoreConfigError, match="needs --secrets-file"):
        FileStore(context(None))


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604])
def test_the_file_must_be_0600(secrets: Path, mode: int) -> None:
    secrets.chmod(mode)
    with pytest.raises(StoreConfigError, match="it must be 0600"):
        FileStore(context(secrets))


def test_a_symlink_is_refused(secrets: Path) -> None:
    link = secrets.parent / "link.yaml"
    link.symlink_to(secrets)
    with pytest.raises(FileStoreError, match="is a symlink"):
        read_secrets_file(link)


def test_another_owner_is_refused(secrets: Path) -> None:
    with pytest.raises(FileStoreError, match="not by this user"):
        read_secrets_file(secrets, uid=12345)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("db1: {value: x, colour: red}\n", "unknown key 'colour'"),
        ("db1: {hosts: [a]}\n", "'value' must be a non-empty string"),
        ("db1: {value: x, hosts: a}\n", "'hosts' must be a list"),
        ("db1: {value: x, env: [a, b]}\n", "'env' must be an environment name"),
        ("db1: {value: x}\ndb1: {value: y}\n", "duplicate key"),
        ("- a\n- b\n", "must hold a mapping"),
        ("db1: [unclosed\n", "YAML syntax error"),
        ("db1: plain\n", "an entry must be a mapping"),
    ],
)
def test_malformed_files_are_refused(shortdir: Path, text: str, message: str) -> None:
    path = shortdir / "s.yaml"
    write_file(path, text, 0o600)
    with pytest.raises(FileStoreError, match=message):
        read_secrets_file(path)


def test_an_empty_file_holds_no_secrets(shortdir: Path) -> None:
    path = shortdir / "s.yaml"
    write_file(path, "", 0o600)
    assert read_secrets_file(path) == {}


def test_the_entry_point_names_the_store() -> None:
    (ep,) = importlib.metadata.entry_points(group="modgudr.secret_stores", name="file")
    assert ep.load() is FileStore
    assert ep.dist is not None and ep.dist.metadata["Name"] == "modgudr-store-file"
