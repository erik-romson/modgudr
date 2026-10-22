"""kubectl execution through the broker-owned kubeconfig (M18), against the fake `az` and
`kubectl`: the per-call directory, the child environments, denials before anything runs, exit
codes, timeouts, locks and a missing `kubectl`."""

from __future__ import annotations

import asyncio
import os
import stat
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from modgudr.broker.app import Broker
from tests.support.brokerfx import (
    BrokerEnv,
    audit_text,
    call,
    error,
    lock,
    read_audit,
    result_data,
    running,
    unlock,
    wait_for,
)
from tests.support.fakebin import FakeBin
from tests.support.kubectlfx import (
    AZ_KEYS,
    GET_PODS,
    KUBECTL_KEYS,
    LOCALE,
    SERVER,
    SERVER_HOST,
    TOKEN,
    call_dir,
    child_keys,
    custody_dir,
    kube_env,
    kubeconfig_of,
    pid_gone,
    records,
    set_scenario,
    targets,
)


@pytest.fixture
async def env(shortdir: Path, fakebin: FakeBin) -> BrokerEnv:
    set_scenario(fakebin)
    return kube_env(shortdir, fakebin)


@pytest.fixture
async def broker(env: BrokerEnv) -> AsyncIterator[Broker]:
    async with running(env) as b:
        yield b


def text_of(frames: list[dict[str, object]], stream: str = "stdout") -> str:
    return "".join(str(f["data"]) for f in frames if f["t"] == "text" and f["stream"] == stream)


async def kubectl(env: BrokerEnv, target: str, *argv: str) -> list[dict[str, object]]:
    return await call(env.agent_socket, "kubectl", target, args={"argv": list(argv)})


# --- the call ---------------------------------------------------------------------------------


async def test_get_pods_runs_kubectl_with_the_broker_kubeconfig(
    env: BrokerEnv, broker: Broker, fakebin: FakeBin
) -> None:
    await unlock(env)
    frames = await kubectl(env, "aks@test", "get", "pods", "-n", "app-test")
    assert frames[-1]["t"] == "trailer", frames
    assert text_of(frames) == GET_PODS
    assert frames[-1]["exitCode"] == 0
    (run,) = fakebin.entries("kubectl")
    workdir = call_dir(run)
    assert run["argv"] == [
        "--kubeconfig",
        str(workdir / "kubeconfig"),
        "--cache-dir",
        str(workdir / "cache"),
        "get",
        "pods",
        "-n",
        "app-test",
    ]
    assert workdir.parent == Path(os.path.realpath(env.home)) / "run"
    assert workdir.name.startswith("k-") and len(workdir.name) == 18
    assert child_keys(run) == KUBECTL_KEYS
    assert run["env"]["HOME"] == str(workdir)
    assert run["env"]["KUBECONFIG"] == str(workdir / "kubeconfig")
    assert run["env"]["PATH"] == fakebin.path_env()
    assert not workdir.exists()
    config = kubeconfig_of(run)
    assert config["clusters"][0]["cluster"]["server"] == SERVER
    assert config["contexts"][0]["context"]["namespace"] == "app-test"
    user = config["users"][0]["user"]["exec"]
    assert user["interactiveMode"] == "Never"
    assert user["args"][:3] == ["-I", "-m", "modgudr.kubectl.exec_credential"]
    assert user["args"][3] == str(workdir / "cred.sock")


async def test_az_runs_with_the_allowlisted_environment_borrowed(
    env: BrokerEnv, broker: Broker, fakebin: FakeBin
) -> None:
    await unlock(env)
    assert (await kubectl(env, "aks-test", "get", "pods"))[-1]["t"] == "trailer"
    runs = fakebin.entries("az")
    assert [r["argv"][:2] for r in runs] == [["rest", "--method"], ["account", "get-access-token"]]
    for run in runs:
        assert child_keys(run) == AZ_KEYS
        assert run["env"]["HOME"] == str(env.config.user_home)
        assert run["env"]["PATH"] == fakebin.path_env()
        assert {k: run["env"][k] for k in LOCALE} == LOCALE
        assert "AZURE_CONFIG_DIR" not in run["env"]


async def test_the_audit_names_the_action_decision_and_destination(
    env: BrokerEnv, broker: Broker
) -> None:
    await unlock(env)
    frames = await kubectl(env, "aks@test", "get", "pods", "-n", "app-test")
    audit_id = frames[-1]["auditId"]
    (decision,) = records(env, "decision")
    (completion,) = records(env, "completion")
    assert decision["auditId"] == completion["auditId"] == audit_id
    assert (decision["action"], decision["risk"], decision["decision"]) == (
        "kubectl:get/pods",
        "read",
        "allow",
    )
    assert decision["args"] == {"argv": ["get", "pods", "-n", "app-test"]}
    assert completion["destination"] == f"{SERVER_HOST}:443"
    assert completion["outcome"] == "completed" and completion["exitCode"] == 0


async def test_a_custody_target_gives_az_its_own_config_dir(
    shortdir: Path, fakebin: FakeBin
) -> None:
    env = kube_env(shortdir, fakebin, tier="custody")
    directory = custody_dir(env)
    set_scenario(fakebin, az={"logged_in": [directory]})
    async with running(env):
        await unlock(env)
        assert (await kubectl(env, "aks-test", "get", "pods"))[-1]["t"] == "trailer"
    runs = fakebin.entries("az")
    assert len(runs) == 2
    for run in runs:
        assert child_keys(run) == {*AZ_KEYS, "AZURE_CONFIG_DIR"}
        assert run["env"]["AZURE_CONFIG_DIR"] == directory
        assert run["env"]["HOME"] == str(env.config.user_home)
    assert stat.S_IMODE(Path(directory).stat().st_mode) == 0o700
    assert stat.S_IMODE(Path(directory).parent.stat().st_mode) == 0o700


# --- refused before anything runs ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("argv", "layer", "rule"),
    [
        (["delete", "pods", "--all", "-n", "app-test"], "constraint", "requireName"),
        (["--as=admin", "get", "pods"], "plugin-invariant", "--as"),
        (["get", "secrets", "-n", "app-test"], "plugin-invariant", "secret"),
    ],
)
async def test_denied_calls_contact_neither_azure_nor_the_cluster(
    env: BrokerEnv, broker: Broker, fakebin: FakeBin, argv: list[str], layer: str, rule: str
) -> None:
    await unlock(env)
    err = error(await kubectl(env, "aks@test", *argv))
    assert (err["code"], err["layer"], err["rule"]) == ("denied", layer, rule)
    assert fakebin.entries("kubectl") == [] and fakebin.entries("az") == []
    (record,) = records(env, "denied")
    assert record["auditId"] == err["auditId"]


async def test_an_unwritable_audit_contacts_nothing(
    env: BrokerEnv, broker: Broker, fakebin: FakeBin
) -> None:
    await unlock(env)
    (day,) = env.audit_dir.glob("audit-*.jsonl")
    day.chmod(0o400)
    try:
        err = error(await kubectl(env, "aks-test", "get", "pods"))
    finally:
        day.chmod(0o600)
    assert err["code"] == "internal"
    assert "nothing was executed" in str(err["message"])
    assert fakebin.entries("az") == [] and fakebin.entries("kubectl") == []


async def test_the_lock_gate_holds_for_provider_targets(
    env: BrokerEnv, broker: Broker, fakebin: FakeBin
) -> None:
    err = error(await kubectl(env, "aks-test", "get", "pods"))
    assert err["code"] == "locked"
    assert fakebin.entries("az") == [] and fakebin.entries("kubectl") == []


# --- kubectl's exit, stderr and the VPN hint ----------------------------------------------------


async def test_a_failing_kubectl_is_upstream_with_its_raw_code_and_scrubbed_stderr(
    env: BrokerEnv, broker: Broker, fakebin: FakeBin
) -> None:
    stderr = f"error: the server rejected token {TOKEN}\n"
    set_scenario(fakebin, kubectl={"exit_code": 1, "stderr": stderr})
    await unlock(env)
    frames = await kubectl(env, "aks-test", "get", "pods")
    err = error(frames)
    assert (err["code"], err["exitCode"]) == ("upstream", 1)
    assert str(err["message"]).startswith("kubectl exited with code 1: error: the server")
    assert "[modgudr:redacted]" in text_of(frames, "stderr")
    assert TOKEN not in repr(frames)
    (completion,) = records(env, "completion")
    assert (completion["exitCode"], completion["stage"]) == (1, "exec")
    assert completion["auditId"] == err["auditId"]
    assert TOKEN not in audit_text(env.audit_dir)


async def test_unable_to_connect_asks_whether_the_vpn_is_up(
    env: BrokerEnv, broker: Broker, fakebin: FakeBin
) -> None:
    stderr = f"Unable to connect to the server: dial tcp: lookup {SERVER_HOST}: no such host\n"
    set_scenario(fakebin, kubectl={"exit_code": 1, "stderr": stderr})
    await unlock(env)
    err = error(await kubectl(env, "aks-test", "get", "pods"))
    assert err["code"] == "upstream"
    assert str(err["message"]).endswith("is your VPN up?")


# --- timeouts, limits, locks --------------------------------------------------------------------


async def test_a_timeout_kills_the_process_group(
    env: BrokerEnv, broker: Broker, fakebin: FakeBin
) -> None:
    set_scenario(fakebin, kubectl={"sleep": 10})
    await unlock(env)
    err = error(await kubectl(env, "aks-fast", "get", "pods"))
    assert err["code"] == "timeout"
    (run,) = fakebin.entries("kubectl")
    await wait_for(lambda: pid_gone(run["pid"]))
    assert not call_dir(run).exists()
    (completion,) = records(env, "completion")
    assert (completion["outcome"], completion["cancelled"]) == ("cancelled", "timeout")
    assert completion["destination"] == f"{SERVER_HOST}:443"


async def test_logs_follow_streams_until_the_timeout(
    env: BrokerEnv, broker: Broker, fakebin: FakeBin
) -> None:
    await unlock(env)
    frames = await kubectl(env, "aks-fast", "logs", "-f", "pod/x")
    err = error(frames)
    assert err["code"] == "timeout"
    # The scrubber holds back a short tail, so only the head is certain to arrive in time.
    assert text_of(frames).startswith("log line a\n")
    (run,) = fakebin.entries("kubectl")
    await wait_for(lambda: pid_gone(run["pid"]))


async def test_max_bytes_ends_a_stream_and_its_process(shortdir: Path, fakebin: FakeBin) -> None:
    small = (
        "  aks-small:\n"
        "    type: kubectl\n"
        "    env: test\n"
        "    maxBytes: 400B\n"
        "    provider: azure-cli\n"
        "    credential: { tier: borrowed }\n"
        "    cluster: { subscription: 0b1f6471-1bf0-4dda-aec3-111122223333, "
        "resourceGroup: rg-aks-test, name: aks-test }\n"
        "    defaultNamespace: app-test\n"
    )
    set_scenario(fakebin)
    env = kube_env(shortdir, fakebin, targets_text=targets(extra=small))
    async with running(env):
        await unlock(env)
        frames = await kubectl(env, "aks-small", "logs", "-f", "pod/x")
        trailer = frames[-1]
        assert trailer["t"] == "trailer", frames
        assert (trailer["truncated"], trailer["reason"]) == (True, "bytes")
        assert int(str(trailer["bytes"])) <= 400
        (run,) = fakebin.entries("kubectl")
        await wait_for(lambda: pid_gone(run["pid"]))


async def test_lock_kills_the_call_and_drops_the_token(
    env: BrokerEnv, broker: Broker, fakebin: FakeBin
) -> None:
    set_scenario(fakebin, kubectl={"sleep": 10})
    await unlock(env)
    task = asyncio.create_task(kubectl(env, "aks-test", "get", "pods"))
    await wait_for(lambda: bool(fakebin.entries("kubectl")), timeout=10)
    (run,) = fakebin.entries("kubectl")
    assert (await lock(env))["cancelled"] == 1
    err = error(await task)
    assert err["code"] == "locked"
    await wait_for(lambda: pid_gone(run["pid"]))
    assert not call_dir(run).exists()
    (completion,) = records(env, "completion")
    assert completion["cancelled"] == "lock"
    # The token and the endpoint went with the lock: the next session asks Azure again.
    set_scenario(fakebin)
    await unlock(env)
    assert (await kubectl(env, "aks-test", "get", "pods"))[-1]["t"] == "trailer"
    commands = [r["argv"][0] for r in fakebin.entries("az")]
    assert commands == ["rest", "account", "rest", "account"]


# --- executables and metadata -------------------------------------------------------------------


async def test_a_missing_kubectl_shows_in_status_and_fails_upstream(
    shortdir: Path, fakebin: FakeBin
) -> None:
    (fakebin.bin / "kubectl").unlink()
    set_scenario(fakebin)
    env = kube_env(shortdir, fakebin)
    async with running(env):
        status = result_data(await call(env.agent_socket, "status"))
        problems = status["problems"]
        assert isinstance(problems, list)
        assert "target aks-test: kubectl is not on the broker's PATH; calls fail" in problems
        summary = result_data(await call(env.agent_socket, "targets"))["targets"]
        assert isinstance(summary, list)
        first = summary[0]
        assert first["facts"]["kubectl"] is None
        assert first["problems"] == ["kubectl is not on the broker's PATH; calls fail"]
        await unlock(env)
        err = error(await kubectl(env, "aks-test", "get", "pods"))
    assert err["code"] == "upstream"
    assert "kubectl is not on the broker's PATH" in str(err["message"])
    assert fakebin.entries("az") == []


async def test_a_missing_az_shows_in_status_and_fails_at_the_endpoint(
    shortdir: Path, fakebin: FakeBin
) -> None:
    (fakebin.bin / "az").unlink()
    set_scenario(fakebin)
    env = kube_env(shortdir, fakebin)
    async with running(env):
        status = result_data(await call(env.agent_socket, "status"))
        providers = status["providers"]
        assert isinstance(providers, dict)
        assert providers["azure-cli"]["az"] is None
        assert any(
            "az (the Azure CLI) is not on the broker's PATH" in p for p in status["problems"]
        )
        await unlock(env)
        err = error(await kubectl(env, "aks-test", "get", "pods"))
    assert err["code"] == "upstream"
    (completion,) = records(env, "completion")
    assert completion["stage"] == "provider.endpoint"
    assert fakebin.entries("kubectl") == []


async def test_metadata_ops_never_run_az_and_show_the_endpoint_once_fetched(
    env: BrokerEnv, broker: Broker, fakebin: FakeBin
) -> None:
    sock = env.agent_socket

    async def endpoints() -> list[Any]:
        summary: Any = result_data(await call(sock, "targets"))["targets"]
        described: Any = result_data(await call(sock, "describe", args={"target": "aks-test"}))
        explained: Any = result_data(
            await call(
                sock,
                "explain",
                args={"target": "aks-test", "op": "kubectl", "args": {"argv": ["get", "pods"]}},
            )
        )
        return [
            summary[0]["facts"]["endpoint"],
            described["facts"]["endpoint"],
            explained["facts"]["endpoint"],
            summary[0]["destinations"],
        ]

    assert await endpoints() == ["not fetched"] * 3 + [[]]
    await unlock(env)
    assert await endpoints() == ["not fetched"] * 3 + [[]]
    assert fakebin.entries("az") == []
    assert [r["type"] for r in read_audit(env.audit_dir)] == ["broker.start", "unlock"]
    assert (await kubectl(env, "aks-test", "get", "pods"))[-1]["t"] == "trailer"
    runs = len(fakebin.entries("az"))
    assert await endpoints() == [SERVER] * 3 + [[f"{SERVER_HOST}:443"]]
    assert len(fakebin.entries("az")) == runs
    await lock(env)
    assert await endpoints() == ["not fetched"] * 3 + [[]]
