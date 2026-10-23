"""The `bws` store on its own against the fake `bws`: settings, the generated config, the child
environment, unlock, resolve, notes, lock and the state guard (M19, M8)."""

from __future__ import annotations

import stat
from collections.abc import Iterator
from pathlib import Path

import pytest

from modgudr.broker.pins import PinError, pins_of
from modgudr.spi import (
    ReportingStore,
    SecretRef,
    StoreConfigError,
    StoreContext,
    StoreError,
    StoreSessionInvalid,
    UnlockRefused,
)
from modgudr.store_bws import BwsStore
from tests.support.bwsfx import (
    CHILD_KEYS,
    FREE_TEXT,
    NO_NOTE,
    OK,
    OK_VALUE,
    OTHER_PROJECT,
    OTHER_PROJECT_SECRET,
    PROJECT,
    SCHEME_NOTE,
    TOKEN,
    TWO_ENVS,
    TWO_HOSTS,
    UNKNOWN,
    bws_runs,
    child_keys,
    set_bws,
    update_bws,
)
from tests.support.fakebin import FakeBin
from tests.support.shortdir import make_shortdir


@pytest.fixture
def home() -> Iterator[Path]:
    import shutil

    root = make_shortdir()
    (root / "h").mkdir()
    try:
        yield root / "h"
    finally:
        shutil.rmtree(root, ignore_errors=True)


def context(
    home: Path,
    fake: FakeBin,
    settings: dict[str, object] | None = None,
    *,
    dev: bool = False,
    path: str | None = None,
) -> StoreContext:
    return StoreContext(
        scheme="bws",
        home=home,
        dev=dev,
        settings={"project": PROJECT} if settings is None else settings,
        path=fake.path_env() if path is None else path,
    )


def ref(item: str) -> SecretRef:
    return SecretRef("bws", item)


@pytest.fixture
def fake(fakebin: FakeBin) -> FakeBin:
    set_bws(fakebin)
    return fakebin


async def unlocked(home: Path, fake: FakeBin) -> BwsStore:
    store = BwsStore(context(home, fake))
    await store.unlock(TOKEN)
    return store


# --- settings -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("settings", "message"),
    [
        ({}, "store.bws.project"),
        ({"project": "not-a-uuid"}, "store.bws.project"),
        ({"project": PROJECT, "mode": "unattended"}, "store.bws.mode"),
        ({"project": PROJECT, "tokenFile": "/etc/x"}, "store.bws.tokenFile"),
        ({"project": PROJECT, "serverUrl": "http://vault.example.net"}, "store.bws.serverUrl"),
        ({"project": PROJECT, "serverUrl": "https://u:p@vault.example.net"}, "serverUrl"),
        ({"project": PROJECT, "serverUrl": 'https://vault.example.net/"x'}, "serverUrl"),
    ],
)
def test_a_bad_store_block_refuses_the_start(
    home: Path, fake: FakeBin, settings: dict[str, object], message: str
) -> None:
    with pytest.raises(StoreConfigError, match=message):
        BwsStore(context(home, fake, settings))


def test_dev_mode_refuses_the_store(home: Path, fake: FakeBin) -> None:
    with pytest.raises(StoreConfigError, match="dev mode refuses the bws store"):
        BwsStore(context(home, fake, dev=True))


def test_the_store_starts_locked_and_warns_about_the_token_in_the_environment(
    home: Path, fake: FakeBin
) -> None:
    store = BwsStore(context(home, fake))
    assert store.scheme == "bws"
    assert not store.is_unlocked()
    assert isinstance(store, ReportingStore)
    (warning,) = store.warnings()
    assert "handed to each `bws` child through its environment" in warning
    assert "any process running as you can read it while the child runs" in warning
    assert bws_runs(fake) == []


# --- the generated config -------------------------------------------------------------------


def test_the_config_opts_state_out_and_names_the_state_dir(home: Path, fake: FakeBin) -> None:
    BwsStore(context(home, fake))
    config = home / "bws" / "config"
    assert config.read_text() == (
        f'[profiles.default]\nstate_opt_out = "true"\nstate_dir = "{home / "bws" / "state"}"\n'
    )
    assert stat.S_IMODE(config.stat().st_mode) == 0o600
    assert stat.S_IMODE((home / "bws").stat().st_mode) == 0o700


def test_the_config_carries_server_base_when_the_server_url_is_set(
    home: Path, fake: FakeBin
) -> None:
    server = "https://vault.bitwarden.eu"
    BwsStore(context(home, fake, {"project": PROJECT, "serverUrl": server}))
    assert f'server_base = "{server}"\n' in (home / "bws" / "config").read_text()


def test_a_symlinked_bws_directory_is_refused(home: Path, fake: FakeBin) -> None:
    elsewhere = home.parent / "elsewhere"
    elsewhere.mkdir()
    (home / "bws").symlink_to(elsewhere)
    with pytest.raises(StoreConfigError, match="not a directory"):
        BwsStore(context(home, fake))
    assert list(elsewhere.iterdir()) == []


# --- unlock ---------------------------------------------------------------------------------


async def test_unlock_checks_the_project_with_an_allowlisted_environment(
    home: Path, fake: FakeBin
) -> None:
    store = await unlocked(home, fake)
    assert store.is_unlocked()
    (run,) = bws_runs(fake)
    assert run["argv"] == ["project", "list", "--output", "json"]
    assert TOKEN not in " ".join(run["argv"])
    assert child_keys(run) == CHILD_KEYS
    env = run["env"]
    assert env["BWS_ACCESS_TOKEN"] == TOKEN
    assert env["HOME"] == str(home / "bws")
    assert env["BWS_CONFIG_FILE"] == str(home / "bws" / "config")
    assert env["PATH"] == fake.path_env()
    assert not (home / "bws" / "state").exists() or not list((home / "bws" / "state").iterdir())


async def test_bws_is_resolved_to_an_absolute_path_at_start(home: Path, fake: FakeBin) -> None:
    store = BwsStore(context(home, fake))
    assert store.facts()["bws"] == str(fake.bin / "bws")
    await store.unlock(TOKEN)


@pytest.mark.parametrize("attempt", [1, 2])
async def test_a_wrong_token_is_refused_without_echoing_what_bws_printed(
    home: Path, fake: FakeBin, attempt: int
) -> None:
    store = BwsStore(context(home, fake))
    with pytest.raises(UnlockRefused) as raised:
        await store.unlock("0.wrong.token:abc")
    assert not store.is_unlocked()
    text = str(raised.value)
    assert "revoked" not in text and "wrong.token" not in text and "Invalid" not in text


async def test_a_token_that_cannot_see_the_project_is_refused_naming_the_project(
    home: Path, fake: FakeBin
) -> None:
    set_bws(fake, projects=[{"id": OTHER_PROJECT, "name": "other"}])
    store = BwsStore(context(home, fake))
    with pytest.raises(UnlockRefused, match=PROJECT):
        await store.unlock(TOKEN)
    assert not store.is_unlocked()


async def test_unlock_without_bws_is_an_upstream_error(home: Path, fake: FakeBin) -> None:
    store = BwsStore(context(home, fake, path="/usr/bin:/bin"))
    facts = store.facts()
    assert facts["bws"] is None
    assert "bws not found" in str(facts["problem"])
    with pytest.raises(StoreError, match="bws not found"):
        await store.unlock(TOKEN)
    assert bws_runs(fake) == []


async def test_a_bws_failure_at_unlock_names_the_cause_bws_printed(
    home: Path, fake: FakeBin
) -> None:
    store = BwsStore(context(home, fake))
    (home / "bws" / "config").write_text("[profiles.default]\nstate_opt_out = true\n")
    with pytest.raises(StoreError) as raised:
        await store.unlock(TOKEN)
    assert str(raised.value) == (
        "bws could not check the access token: TOML parse error at line 2, column 17"
    )
    assert not store.is_unlocked()


async def test_an_empty_token_is_refused_without_running_bws(home: Path, fake: FakeBin) -> None:
    store = BwsStore(context(home, fake))
    with pytest.raises(UnlockRefused):
        await store.unlock("")
    assert bws_runs(fake) == []


# --- resolve --------------------------------------------------------------------------------


async def test_resolve_returns_the_value_and_the_note(home: Path, fake: FakeBin) -> None:
    store = await unlocked(home, fake)
    secret = await store.resolve(ref(OK))
    assert secret.value == OK_VALUE
    assert secret.note == "modgudr-hosts: db1.example.net:1521"
    assert pins_of(secret).hosts[0].host == "db1.example.net"
    run = bws_runs(fake)[-1]
    assert run["argv"] == ["secret", "get", OK, "--output", "json"]
    assert child_keys(run) == CHILD_KEYS
    assert OK_VALUE not in repr(secret)


async def test_a_secret_of_another_project_is_refused(home: Path, fake: FakeBin) -> None:
    store = await unlocked(home, fake)
    with pytest.raises(StoreError, match="not in the configured project"):
        await store.resolve(ref(OTHER_PROJECT_SECRET))


async def test_an_unknown_id_is_an_error_naming_the_reference(home: Path, fake: FakeBin) -> None:
    store = await unlocked(home, fake)
    with pytest.raises(StoreError) as raised:
        await store.resolve(ref(UNKNOWN))
    assert f"bws:{UNKNOWN}" in str(raised.value)
    assert TOKEN not in str(raised.value)


async def test_an_item_that_is_not_a_uuid_never_reaches_argv(home: Path, fake: FakeBin) -> None:
    store = await unlocked(home, fake)
    before = len(bws_runs(fake))
    with pytest.raises(StoreError, match="not a bws secret uuid"):
        await store.resolve(ref("--output"))
    assert len(bws_runs(fake)) == before


@pytest.mark.parametrize(("fmt", "ok"), [("object", True), ("array", True), ("array2", False)])
async def test_one_object_or_a_one_element_array_is_accepted(
    home: Path, fake: FakeBin, fmt: str, ok: bool
) -> None:
    set_bws(fake, get_format=fmt)
    store = await unlocked(home, fake)
    if ok:
        assert (await store.resolve(ref(OK))).value == OK_VALUE
    else:
        with pytest.raises(StoreError, match="exactly one"):
            await store.resolve(ref(OK))


async def test_resolve_while_locked_is_an_error(home: Path, fake: FakeBin) -> None:
    store = BwsStore(context(home, fake))
    with pytest.raises(StoreError, match="locked"):
        await store.resolve(ref(OK))
    assert bws_runs(fake) == []


async def test_a_revoked_token_invalidates_the_session(home: Path, fake: FakeBin) -> None:
    store = await unlocked(home, fake)
    update_bws(fake, revoke=True)
    with pytest.raises(StoreSessionInvalid):
        await store.resolve(ref(OK))


# --- notes (M8) -----------------------------------------------------------------------------


async def test_a_note_without_pins_gives_a_secret_without_hosts(home: Path, fake: FakeBin) -> None:
    store = await unlocked(home, fake)
    pins = pins_of(await store.resolve(ref(NO_NOTE)))
    assert pins.hosts == () and pins.env == ()


async def test_several_hosts_lines_are_unioned(home: Path, fake: FakeBin) -> None:
    store = await unlocked(home, fake)
    pins = pins_of(await store.resolve(ref(TWO_HOSTS)))
    assert [(p.host, p.port) for p in pins.hosts] == [
        ("db1.example.net", 1521),
        ("db2.example.net", 1521),
        ("db3.example.net", None),
    ]


async def test_a_hosts_line_with_a_scheme_is_rejected(home: Path, fake: FakeBin) -> None:
    store = await unlocked(home, fake)
    with pytest.raises(PinError, match="scheme"):
        pins_of(await store.resolve(ref(SCHEME_NOTE)))


async def test_free_text_around_the_lines_is_ignored_with_a_warning(
    home: Path, fake: FakeBin
) -> None:
    store = await unlocked(home, fake)
    pins = pins_of(await store.resolve(ref(FREE_TEXT)))
    assert [(p.host, p.port) for p in pins.hosts] == [("db1.example.net", 1521)]
    assert len(pins.warnings) == 2 and all("ignored" in w for w in pins.warnings)


async def test_a_note_with_two_environment_lines_gives_two_pins(home: Path, fake: FakeBin) -> None:
    # The broker refuses the secret for more than one `modgudr-env` line (pins.env_pin).
    store = await unlocked(home, fake)
    assert pins_of(await store.resolve(ref(TWO_ENVS))).env == ("test", "prod")


# --- lock and the state guard ---------------------------------------------------------------


async def test_lock_drops_the_token_and_no_child_runs_after_it(home: Path, fake: FakeBin) -> None:
    store = await unlocked(home, fake)
    await store.resolve(ref(OK))
    runs = len(bws_runs(fake))
    await store.lock()
    assert not store.is_unlocked()
    assert store._token is None  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(StoreError, match="locked"):
        await store.resolve(ref(OK))
    assert len(bws_runs(fake)) == runs


def state_files(home: Path) -> list[str]:
    found: list[str] = []
    for path in (home / "bws" / "state", home / "bws" / ".config" / "bws" / "state"):
        if path.is_dir():
            found.extend(str(p) for p in path.rglob("*"))
    return sorted(found)


async def test_no_state_is_written_when_bws_honours_the_opt_out(home: Path, fake: FakeBin) -> None:
    store = await unlocked(home, fake)
    await store.resolve(ref(OK))
    assert state_files(home) == []


async def test_lock_empties_both_state_paths(home: Path, fake: FakeBin) -> None:
    set_bws(fake, force_state=True)
    store = await unlocked(home, fake)
    await store.resolve(ref(OK))
    token_id = TOKEN.split(".")[1]
    assert state_files(home) == sorted(
        [
            str(home / "bws" / "state" / token_id),
            str(home / "bws" / ".config" / "bws" / "state" / token_id),
        ]
    )
    await store.lock()
    assert state_files(home) == []


async def test_start_empties_leftovers_and_removes_symlinks_without_following(
    home: Path, fake: FakeBin
) -> None:
    set_bws(fake, force_state=True)
    store = await unlocked(home, fake)
    assert state_files(home)
    del store  # a killed broker leaves its state behind
    target = home.parent / "precious"
    target.mkdir()
    (target / "keep").write_text("keep")
    (home / "bws" / "state" / "planted").symlink_to(target)
    (home / "bws" / ".config" / "bws" / "state" / "planted-file").symlink_to(target / "keep")
    BwsStore(context(home, fake))
    assert state_files(home) == []
    assert (target / "keep").read_text() == "keep"
    assert [p.name for p in target.iterdir()] == ["keep"]


def test_a_state_directory_that_is_a_symlink_is_removed_not_followed(
    home: Path, fake: FakeBin
) -> None:
    target = home.parent / "precious"
    target.mkdir()
    (target / "keep").write_text("keep")
    (home / "bws").mkdir(mode=0o700)
    (home / "bws" / "state").symlink_to(target)
    BwsStore(context(home, fake))
    assert not (home / "bws" / "state").exists()
    assert (target / "keep").read_text() == "keep"
