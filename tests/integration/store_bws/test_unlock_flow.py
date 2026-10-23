"""The `bws` store through the whole broker: `modgudr unlock` in a pty, wrong tokens, pins, lock,
a revoked token and the state guard (M19, M7, M8). `bws` is the fake in `tests/fixtures/bin`."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from modgudr.broker.app import Broker, build
from modgudr.broker.server import StartError
from tests.support.brokerfx import (
    BrokerEnv,
    call,
    error,
    lock,
    read_audit,
    result_data,
    running,
    wait_for,
)
from tests.support.brokerthread import BrokerThread, cli_environ
from tests.support.bwsfx import (
    CHILD_KEYS,
    FREE_TEXT,
    NO_NOTE,
    OK,
    OTHER_PROJECT,
    OTHER_PROJECT_SECRET,
    PROD_PINNED,
    PROJECT,
    SCHEME_NOTE,
    TOKEN,
    TWO_ENVS,
    TWO_HOSTS,
    UNKNOWN,
    bws_env,
    bws_runs,
    child_keys,
    company,
    echo_targets,
    fixture_secrets,
    run_in_pty,
    set_bws,
    update_bws,
)
from tests.support.fakebin import FakeBin
from tests.support.snowflakefx import COMPANY as SF_COMPANY
from tests.support.snowflakefx import HOST, fake_snowflake, private_key_pem
from tests.support.snowflakefx import TARGETS as SF_TARGETS

Frames = list[dict[str, Any]]


async def unlock_with(env: BrokerEnv, token: str) -> Frames:
    return await call(env.human_socket, "unlock", args={"credential": token})  # type: ignore[return-value]


async def echo(env: BrokerEnv, target: str = "echo-ok") -> Frames:
    return await call(env.agent_socket, "echo", target, args={"text": "x"})  # type: ignore[return-value]


def records(env: BrokerEnv, record_type: str) -> list[dict[str, Any]]:
    return [r for r in read_audit(env.audit_dir) if r["type"] == record_type]


async def state_of(env: BrokerEnv) -> dict[str, Any]:
    return result_data(await call(env.agent_socket, "status"))


@pytest.fixture
def fake(fakebin: FakeBin) -> FakeBin:
    set_bws(fakebin)
    return fakebin


def all_targets() -> str:
    return echo_targets(
        **{
            "echo-ok": OK,
            "echo-none": NO_NOTE,
            "echo-two": TWO_HOSTS,
            "echo-scheme": SCHEME_NOTE,
            "echo-free": FREE_TEXT,
            "echo-envs": TWO_ENVS,
            "echo-prod": PROD_PINNED,
            "echo-other": OTHER_PROJECT_SECRET,
            "echo-unknown": UNKNOWN,
        }
    )


@pytest.fixture
def env(shortdir: Path, fake: FakeBin) -> BrokerEnv:
    return bws_env(shortdir, fake, targets=all_targets())


@pytest.fixture
async def broker(env: BrokerEnv) -> AsyncIterator[Broker]:
    async with running(env) as b:
        yield b


# --- unlock ---------------------------------------------------------------------------------


def test_modgudr_unlock_in_a_pty_unlocks_with_the_typed_token(
    shortdir: Path, fake: FakeBin
) -> None:
    env = bws_env(shortdir, fake)
    with BrokerThread(env):
        environ = cli_environ(env)
        code, shown = run_in_pty(environ, ["unlock"], TOKEN)
        assert code == 0, shown
        assert TOKEN not in shown
        assert asyncio.run(state_of(env))["state"] == "unlocked"
        runs = bws_runs(fake)
        (run,) = runs
        assert run["argv"] == ["project", "list", "--output", "json"]
        assert not any(TOKEN in arg for r in runs for arg in r["argv"])
        assert child_keys(run) == CHILD_KEYS
        home = env.home.resolve()
        assert run["env"]["HOME"] == str(home / "bws")
        config = Path(run["env"]["BWS_CONFIG_FILE"])
        assert config == home / "bws" / "config"
        text = config.read_text()
        assert 'state_opt_out = "true"' in text
        assert f'state_dir = "{home / "bws" / "state"}"' in text
        assert not list((env.home / "bws" / "state").rglob("*"))
    assert TOKEN not in "".join(p.read_text() for p in env.audit_dir.glob("*.jsonl"))


def test_a_wrong_token_in_a_pty_is_refused_with_exit_2(shortdir: Path, fake: FakeBin) -> None:
    env = bws_env(shortdir, fake)
    with BrokerThread(env):
        code, shown = run_in_pty(cli_environ(env), ["unlock"], "0.wrong.token:abc")
        assert code == 2, shown
        assert asyncio.run(state_of(env))["state"] == "locked"
        assert "revoked" not in shown and "Invalid" not in shown


async def test_a_wrong_token_twice_stays_locked_and_audits_both_without_input(
    broker: Broker, env: BrokerEnv
) -> None:
    for _ in range(2):
        err = error(await unlock_with(env, "0.wrong.token:abc"))
        assert err["code"] == "denied"
        text = str(err["message"])
        assert "wrong.token" not in text and "revoked" not in text and "Invalid" not in text
    assert (await state_of(env))["state"] == "locked"
    failed = records(env, "unlock.failed")
    assert len(failed) == 2
    assert "wrong.token" not in json.dumps(read_audit(env.audit_dir))
    assert (await echo(env))[-1]["code"] == "locked"


async def test_a_valid_token_without_the_configured_project_is_refused(
    broker: Broker, env: BrokerEnv, fake: FakeBin
) -> None:
    set_bws(fake, projects=[{"id": OTHER_PROJECT, "name": "other"}])
    err = error(await unlock_with(env, TOKEN))
    assert err["code"] == "denied" and PROJECT in str(err["message"])
    assert (await state_of(env))["state"] == "locked"


async def test_without_bws_status_says_so_and_unlock_is_an_upstream_error(
    shortdir: Path, fake: FakeBin
) -> None:
    env = bws_env(shortdir, fake, path="/usr/bin:/bin")
    async with running(env):
        status = await state_of(env)
        assert status["storeInfo"]["bws"] is None
        assert "bws not found" in status["storeInfo"]["problem"]
        err = error(await unlock_with(env, TOKEN))
        assert err["code"] == "upstream" and "bws not found" in str(err["message"])
    assert bws_runs(fake) == []


async def test_status_reports_the_resolved_bws_path(broker: Broker, env: BrokerEnv) -> None:
    info = (await state_of(env))["storeInfo"]
    assert info["bws"].endswith("/bin/bws") and "problem" not in info


async def test_the_start_prints_the_l0_warning(env: BrokerEnv, broker: Broker) -> None:
    text = env.stderr.getvalue()
    assert "handed to each `bws` child through its environment" in text


# --- resolve and pins -----------------------------------------------------------------------


async def test_a_secret_with_a_hosts_note_resolves_with_its_pins(
    broker: Broker, env: BrokerEnv, fake: FakeBin
) -> None:
    assert (await unlock_with(env, TOKEN))[0]["t"] == "result"
    frames = await echo(env)
    assert frames[-1]["t"] == "trailer"
    gets = [r for r in bws_runs(fake) if r["argv"][:2] == ["secret", "get"]]
    assert [r["argv"] for r in gets] == [["secret", "get", OK, "--output", "json"]]
    assert child_keys(gets[0]) == CHILD_KEYS
    assert not any(TOKEN in arg for r in bws_runs(fake) for arg in r["argv"])


async def test_a_secret_of_another_project_is_refused_with_exit_5(
    broker: Broker, env: BrokerEnv
) -> None:
    await unlock_with(env, TOKEN)
    err = error(await echo(env, "echo-other"))
    assert err["code"] == "upstream"
    assert f"bws:{OTHER_PROJECT_SECRET}" in str(err["message"])
    assert "not in the configured project" in str(err["message"])


async def test_an_unknown_id_is_exit_5_naming_the_reference(broker: Broker, env: BrokerEnv) -> None:
    await unlock_with(env, TOKEN)
    err = error(await echo(env, "echo-unknown"))
    assert err["code"] == "upstream" and f"bws:{UNKNOWN}" in str(err["message"])
    assert TOKEN not in str(err["message"])
    assert (await state_of(env))["state"] == "unlocked"


@pytest.mark.parametrize(
    ("target", "code", "text"),
    [
        ("echo-none", "denied", "no destination pins"),
        ("echo-two", None, ""),
        ("echo-scheme", "denied", "scheme"),
        ("echo-free", None, ""),
        ("echo-envs", "denied", "modgudr-env"),
    ],
    ids=["no-note", "union", "scheme", "free-text", "two-env-lines"],
)
async def test_notes_give_pins_or_refuse_the_secret(
    broker: Broker, env: BrokerEnv, target: str, code: str | None, text: str
) -> None:
    await unlock_with(env, TOKEN)
    frames = await echo(env, target)
    if code is None:
        assert frames[-1]["t"] == "trailer"
    else:
        err = error(frames)
        assert (err["code"], err["layer"]) == (code, "pinning")
        assert text in str(err["message"])


async def test_an_environment_pin_to_prod_holds_a_test_target_to_prod(
    broker: Broker, env: BrokerEnv
) -> None:
    await unlock_with(env, TOKEN)
    frames = await echo(env, "echo-prod")
    assert frames[-1]["t"] == "trailer"
    assert records(env, "decision")[0]["effectiveEnv"] == "prod"
    denied = error(await call(env.agent_socket, "put", "echo-prod", args={"value": "v"}))
    assert (denied["code"], denied["layer"]) == ("denied", "ceiling")


@pytest.mark.parametrize("fmt", ["array", "array2"])
async def test_a_one_element_array_is_accepted_and_a_two_element_array_refused(
    broker: Broker, env: BrokerEnv, fake: FakeBin, fmt: str
) -> None:
    update_bws(fake, get_format=fmt)
    await unlock_with(env, TOKEN)
    frames = await echo(env)
    if fmt == "array":
        assert frames[-1]["t"] == "trailer"
    else:
        err = error(frames)
        assert err["code"] == "upstream" and "exactly one" in str(err["message"])


async def test_a_snowflake_key_comes_from_the_bws_store(shortdir: Path, fake: FakeBin) -> None:
    key_id = "2f1c0a9e-5b7d-4c3a-9e11-0a1b2c3d4e10"
    set_bws(
        fake,
        secrets=[
            *fixture_secrets(),
            {
                "id": key_id,
                "projectId": PROJECT,
                "value": private_key_pem(),
                "note": f"modgudr-hosts: {HOST}:443",
            },
        ],
    )
    sf_company = SF_COMPANY.replace(
        "  default: file\n", f"  default: bws\n  bws:\n    project: {PROJECT}\n"
    )
    sf_targets = SF_TARGETS.replace("file:sf-key", f"bws:{key_id}")
    env = bws_env(shortdir, fake, company_text=sf_company, targets=sf_targets)
    with fake_snowflake() as spy:
        async with running(env):
            assert (await unlock_with(env, TOKEN))[0]["t"] == "result"
            frames = await call(
                env.agent_socket, "query", "sf-test", args={"sql": "select 1 as one"}
            )
    assert [f["v"] for f in frames if f["t"] == "row"] == [["1"]]
    assert frames[-1]["t"] == "trailer"
    assert spy.logins(), "the driver was never asked to log in"
    assert private_key_pem() not in json.dumps(read_audit(env.audit_dir))


# --- lock, expiry and the state guard -------------------------------------------------------


async def test_lock_drops_the_session_and_no_bws_child_runs_after_it(
    broker: Broker, env: BrokerEnv, fake: FakeBin
) -> None:
    await unlock_with(env, TOKEN)
    assert (await echo(env))[-1]["t"] == "trailer"
    runs = len(bws_runs(fake))
    assert runs == 2
    await lock(env)
    assert (await state_of(env))["state"] == "locked"
    err = error(await echo(env))
    assert err["code"] == "locked"
    assert len(bws_runs(fake)) == runs
    # The cache went with the lock: the next unlock fetches again.
    await unlock_with(env, TOKEN)
    assert (await echo(env))[-1]["t"] == "trailer"
    assert len(bws_runs(fake)) == runs + 2


async def test_a_revoked_token_locks_the_broker_with_reason_store_invalid(
    broker: Broker, env: BrokerEnv, fake: FakeBin
) -> None:
    await unlock_with(env, TOKEN)
    update_bws(fake, revoke=True)
    err = error(await echo(env))
    assert err["code"] == "locked"
    assert "store session expired" in str(err["message"])
    assert "modgudr unlock" in str(err["message"])
    assert (await state_of(env))["state"] == "locked"
    await wait_for(lambda: records(env, "lock"))
    assert [r["reason"] for r in records(env, "lock")] == ["store-invalid"]
    assert TOKEN not in json.dumps(read_audit(env.audit_dir))
    # And the unlock with the same revoked token is refused.
    assert error(await unlock_with(env, TOKEN))["code"] == "denied"


def state_files(env: BrokerEnv) -> list[Path]:
    found: list[Path] = []
    for path in (env.home / "bws" / "state", env.home / "bws" / ".config" / "bws" / "state"):
        if path.is_dir():
            found.extend(path.rglob("*"))
    return sorted(found)


async def test_state_written_despite_the_opt_out_is_emptied_at_lock_and_at_start(
    env: BrokerEnv, fake: FakeBin, shortdir: Path
) -> None:
    set_bws(fake, force_state=True)
    token_id = TOKEN.split(".")[1]
    async with running(env):
        await unlock_with(env, TOKEN)
        assert (await echo(env))[-1]["t"] == "trailer"
        assert state_files(env) == [
            env.home / "bws" / ".config" / "bws" / "state" / token_id,
            env.home / "bws" / "state" / token_id,
        ]
        await lock(env)
        assert state_files(env) == []
    # State left behind by a killed broker, and symlinks that must not be followed.
    precious = shortdir / "precious"
    precious.mkdir()
    (precious / "keep").write_text("keep")
    (env.home / "bws" / "state" / token_id).write_text("left behind")
    (env.home / "bws" / ".config" / "bws" / "state" / "planted").symlink_to(precious)
    assert len(state_files(env)) == 2
    async with running(env):
        assert state_files(env) == []
    assert [p.name for p in precious.iterdir()] == ["keep"]


# --- start-up refusals ----------------------------------------------------------------------


def test_dev_mode_with_the_bws_store_is_refused(shortdir: Path, fake: FakeBin) -> None:
    env = bws_env(shortdir, fake)
    from dataclasses import replace

    with pytest.raises(StartError, match="dev mode refuses the bws store"):
        build(replace(env.config, dev=True))


@pytest.mark.parametrize(
    ("extra", "key"),
    [("    mode: unattended\n", "store.bws.mode"), ("    tokenFile: /etc/x\n", "tokenFile")],
)
def test_attended_only_keys_are_refused_at_load(
    shortdir: Path, fake: FakeBin, extra: str, key: str
) -> None:
    env = bws_env(shortdir, fake, company_text=company(extra))
    with pytest.raises(StartError, match=key):
        build(env.config)


def test_a_store_block_without_a_project_refuses_the_start(shortdir: Path, fake: FakeBin) -> None:
    text = company().replace(
        f"    project: {PROJECT}\n", "    serverUrl: https://vault.example.net\n"
    )
    env = bws_env(shortdir, fake, company_text=text)
    with pytest.raises(StartError, match=r"store\.bws\.project"):
        asyncio.run(_start(env))


async def _start(env: BrokerEnv) -> None:
    async with running(env):
        pass
