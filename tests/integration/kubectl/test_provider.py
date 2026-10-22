"""The `azure-cli` provider (M18) against the fake `az`: endpoint discovery and token minting after
the decision record, the stages of their failures, the login messages, the token cache and its
margin, single-flight, and `login-info`."""

from __future__ import annotations

import asyncio
import stat
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from modgudr.broker.app import Broker
from tests.support.brokerfx import (
    BrokerEnv,
    call,
    error,
    read_audit,
    result_data,
    running,
    unlock,
)
from tests.support.fakebin import FakeBin
from tests.support.kubectlfx import (
    AKS_SERVER_APP,
    CREDENTIAL_URL,
    SERVER,
    custody_dir,
    kube_env,
    kubeconfig_of,
    records,
    set_scenario,
)


@pytest.fixture
async def env(shortdir: Path, fakebin: FakeBin) -> BrokerEnv:
    set_scenario(fakebin)
    return kube_env(shortdir, fakebin)


@pytest.fixture
async def broker(env: BrokerEnv) -> AsyncIterator[Broker]:
    async with running(env) as b:
        yield b


async def kubectl(env: BrokerEnv, target: str, *argv: str) -> list[dict[str, object]]:
    return await call(env.agent_socket, "kubectl", target, args={"argv": list(argv)})


def az_commands(fakebin: FakeBin) -> list[str]:
    return [" ".join(r["argv"][:2]) for r in fakebin.entries("az")]


# --- what az is asked -------------------------------------------------------------------------


async def test_the_endpoint_comes_from_list_cluster_user_credential(
    env: BrokerEnv, broker: Broker, fakebin: FakeBin
) -> None:
    await unlock(env)
    assert (await kubectl(env, "aks-test", "get", "pods"))[-1]["t"] == "trailer"
    rest, token = fakebin.entries("az")
    assert rest["argv"] == ["rest", "--method", "post", "--url", CREDENTIAL_URL, "-o", "json"]
    assert token["argv"] == [
        "account",
        "get-access-token",
        "--resource",
        AKS_SERVER_APP,
        "-o",
        "json",
    ]
    (run,) = fakebin.entries("kubectl")
    assert kubeconfig_of(run)["clusters"][0]["cluster"]["server"] == SERVER


async def test_a_policy_server_key_is_refused_at_load(shortdir: Path, fakebin: FakeBin) -> None:
    from modgudr.broker.app import build
    from modgudr.broker.server import StartError
    from tests.support.kubectlfx import targets

    text = targets().replace(
        "    defaultNamespace: app-test\n  aks-prod:",
        "    defaultNamespace: app-test\n    server: https://evil.example.net\n  aks-prod:",
        1,
    )
    env = kube_env(shortdir, fakebin, targets_text=text)
    with pytest.raises(StartError, match=r"targets\.aks-test\.server: unknown key"):
        build(env.config)


# --- failures name their stage ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("key", "stage", "commands"),
    [
        ("fail_rest", "provider.endpoint", ["rest --method"]),
        ("fail_token", "provider.token", ["rest --method", "account get-access-token"]),
    ],
)
async def test_an_az_failure_is_upstream_after_the_decision_record(
    env: BrokerEnv, broker: Broker, fakebin: FakeBin, key: str, stage: str, commands: list[str]
) -> None:
    line = "ERROR: (AuthorizationFailed) eyJhbGciOiJSUzI1.eyJzdWIiOiJ4.c2lnbmF0dXJl was denied"
    set_scenario(fakebin, az={key: line + "\nmore detail\n"})
    await unlock(env)
    err = error(await kubectl(env, "aks-test", "get", "pods"))
    assert err["code"] == "upstream"
    message = str(err["message"])
    assert message.startswith("az ")
    assert "(AuthorizationFailed) [modgudr:redacted] was denied" in message
    assert "eyJ" not in message and "more detail" not in message
    assert az_commands(fakebin) == commands
    assert fakebin.entries("kubectl") == []
    decision, completion = (
        r for r in read_audit(env.audit_dir) if r.get("auditId") == err["auditId"]
    )
    assert (decision["type"], completion["type"]) == ("decision", "completion")
    assert completion["stage"] == stage
    assert completion["outcome"] == "failed"


async def test_not_logged_in_borrowed_says_az_login(
    env: BrokerEnv, broker: Broker, fakebin: FakeBin
) -> None:
    set_scenario(fakebin, az={"logged_in": []})
    await unlock(env)
    err = error(await kubectl(env, "aks-test", "get", "pods"))
    assert err["code"] == "upstream"
    message = str(err["message"])
    assert "run `az login` in your own terminal" in message
    assert str(env.config.user_home / ".azure") in message
    (completion,) = records(env, "completion")
    assert completion["stage"] == "provider.endpoint"


async def test_not_logged_in_custody_says_modgudr_login(shortdir: Path, fakebin: FakeBin) -> None:
    env = kube_env(shortdir, fakebin, tier="custody")
    set_scenario(fakebin, az={"logged_in": ["borrowed"]})
    async with running(env):
        await unlock(env)
        err = error(await kubectl(env, "aks-test", "get", "pods"))
    assert err["code"] == "upstream"
    assert "run `modgudr login azure aks-test` in your own terminal" in str(err["message"])


async def test_an_aadsts_error_asks_for_a_new_login(
    env: BrokerEnv, broker: Broker, fakebin: FakeBin
) -> None:
    error_line = "ERROR: AADSTS70043: The refresh token has expired due to inactivity."
    set_scenario(fakebin, az={"fail_token": error_line})
    await unlock(env)
    err = error(await kubectl(env, "aks-test", "get", "pods"))
    assert "run `az login` in your own terminal" in str(err["message"])
    (completion,) = records(env, "completion")
    assert completion["stage"] == "provider.token"


# --- caching ----------------------------------------------------------------------------------


async def test_the_token_and_endpoint_are_cached_across_calls(
    env: BrokerEnv, broker: Broker, fakebin: FakeBin
) -> None:
    await unlock(env)
    for _ in range(2):
        assert (await kubectl(env, "aks-test", "get", "pods"))[-1]["t"] == "trailer"
    assert (await kubectl(env, "aks-prod", "get", "pods", "-n", "app"))[-1]["t"] == "trailer"
    assert az_commands(fakebin) == ["rest --method", "account get-access-token"]
    assert len(fakebin.entries("kubectl")) == 3


async def test_a_token_inside_the_five_minute_margin_is_minted_again(
    env: BrokerEnv, broker: Broker, fakebin: FakeBin
) -> None:
    set_scenario(fakebin, az={"expires_in": 200})
    await unlock(env)
    for _ in range(2):
        assert (await kubectl(env, "aks-test", "get", "pods"))[-1]["t"] == "trailer"
    assert az_commands(fakebin) == [
        "rest --method",
        "account get-access-token",
        "account get-access-token",
    ]


async def test_concurrent_calls_share_one_endpoint_and_one_token(
    env: BrokerEnv, broker: Broker, fakebin: FakeBin
) -> None:
    await unlock(env)
    results = await asyncio.gather(*(kubectl(env, "aks-test", "get", "pods") for _ in range(3)))
    assert all(frames[-1]["t"] == "trailer" for frames in results)
    assert az_commands(fakebin) == ["rest --method", "account get-access-token"]


# --- login-info -------------------------------------------------------------------------------


async def test_login_info_gives_the_custody_directory(shortdir: Path, fakebin: FakeBin) -> None:
    env = kube_env(shortdir, fakebin, tier="custody")
    async with running(env):
        data = result_data(await call(env.human_socket, "login-info", args={"target": "aks-test"}))
        refused = error(await call(env.agent_socket, "login-info", args={"target": "aks-test"}))
        borrowed = error(await call(env.human_socket, "login-info", args={"target": "aks-prod"}))
    assert data == {
        "target": "aks-test",
        "system": "aks",
        "provider": "azure-cli",
        "tier": "custody",
        "stateDir": custody_dir(env),
    }
    assert stat.S_IMODE(Path(custody_dir(env)).stat().st_mode) == 0o700
    assert refused["code"] == "bad_request"
    assert "not available on this channel" in str(refused["message"])
    assert borrowed["code"] == "bad_request"
    assert "uses the borrowed tier" in str(borrowed["message"])
    assert fakebin.entries("az") == []


async def test_a_tier_the_provider_does_not_serve_refuses_the_start(
    shortdir: Path, fakebin: FakeBin
) -> None:
    from modgudr.broker.app import build
    from modgudr.broker.server import StartError

    env = kube_env(shortdir, fakebin, tier="dedicated")
    broker = build(env.config)
    with pytest.raises(StartError, match="serves the tiers borrowed, custody, not dedicated"):
        await broker.start()
    assert not env.agent_socket.exists() and not env.human_socket.exists()
