"""Where the AKS token may be, and where it never is (M18): never in kubectl's argv or
environment, never in the kubeconfig file, never in stdout, stderr or the audit; `cred.sock` is
gone after the call. The developer's own `~/.kube/config` is never read, and a static token in
Azure's kubeconfig is discarded."""

from __future__ import annotations

import json
import os
import socket
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from modgudr.broker.app import Broker
from tests.support.brokerfx import BrokerEnv, audit_text, call, error, running, unlock
from tests.support.fakebin import FakeBin
from tests.support.kubectlfx import (
    DECOY,
    TOKEN,
    call_dir,
    kube_env,
    kubeconfig_of,
    set_scenario,
)


@pytest.fixture
async def env(shortdir: Path, fakebin: FakeBin) -> BrokerEnv:
    return kube_env(shortdir, fakebin)


@pytest.fixture
async def broker(env: BrokerEnv) -> AsyncIterator[Broker]:
    async with running(env) as b:
        yield b


async def kubectl(env: BrokerEnv, target: str, *argv: str) -> list[dict[str, object]]:
    return await call(env.agent_socket, "kubectl", target, args={"argv": list(argv)})


async def test_the_token_reaches_kubectl_only_through_the_exec_plugin(
    env: BrokerEnv, broker: Broker, fakebin: FakeBin
) -> None:
    # The fake echoes the token it got from the exec plugin back on stdout and stderr; the
    # broker registered it at mint time, so both come back scrubbed.
    set_scenario(
        fakebin,
        kubectl={
            "output": {"get": f"token on stdout: {TOKEN}\n"},
            "stderr": f"Warning: token on stderr: {TOKEN}\n",
        },
    )
    await unlock(env)
    frames = await kubectl(env, "aks-test", "get", "pods")
    assert frames[-1]["t"] == "trailer", frames
    assert TOKEN not in json.dumps(frames)
    texts: dict[str, str] = {}
    for frame in frames:
        if frame["t"] == "text":
            texts[str(frame["stream"])] = texts.get(str(frame["stream"]), "") + str(frame["data"])
    assert texts == {
        "stdout": "token on stdout: [modgudr:redacted]\n",
        "stderr": "Warning: token on stderr: [modgudr:redacted]\n",
    }
    assert frames[-1]["scrubbed"] == 2
    (run,) = fakebin.entries("kubectl")
    assert TOKEN not in json.dumps(run["argv"])
    assert TOKEN not in json.dumps(run["env"])
    assert TOKEN not in run["kubeconfig"] and '"token"' not in run["kubeconfig"]
    assert TOKEN not in audit_text(env.audit_dir)
    for entry in fakebin.entries("az"):
        assert TOKEN not in json.dumps(entry["argv"]) + json.dumps(entry["env"])


async def test_cred_sock_is_gone_after_the_call(
    env: BrokerEnv, broker: Broker, fakebin: FakeBin
) -> None:
    set_scenario(fakebin)
    await unlock(env)
    assert (await kubectl(env, "aks-test", "get", "pods"))[-1]["t"] == "trailer"
    (run,) = fakebin.entries("kubectl")
    workdir = call_dir(run)
    socket_path = workdir / "cred.sock"
    assert kubeconfig_of(run)["users"][0]["user"]["exec"]["args"][-1] == str(socket_path)
    assert not workdir.exists()
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        with pytest.raises(OSError):
            probe.connect(os.fspath(socket_path))
    finally:
        probe.close()
    run_dir = Path(os.path.realpath(env.home)) / "run"
    assert sorted(p.name for p in run_dir.iterdir()) == ["broker.lock", "human.sock"]


async def test_the_developers_kubeconfig_is_never_read(
    env: BrokerEnv, broker: Broker, fakebin: FakeBin
) -> None:
    set_scenario(fakebin)
    await unlock(env)
    frames = await kubectl(env, "aks-test", "get", "pods")
    assert frames[-1]["t"] == "trailer", frames
    (run,) = fakebin.entries("kubectl")
    workdir = call_dir(run)
    assert run["env"]["KUBECONFIG"] == str(workdir / "kubeconfig")
    assert run["env"]["HOME"] == str(workdir)
    assert str(env.config.user_home) not in json.dumps(run)
    assert DECOY not in json.dumps(frames)
    assert (env.config.user_home / ".kube" / "config").read_text() == DECOY


async def test_a_static_token_in_azures_kubeconfig_is_discarded(
    env: BrokerEnv, broker: Broker, fakebin: FakeBin
) -> None:
    static = "static-cluster-admin-token-0123456789"
    set_scenario(fakebin, az={"user_token": static})
    await unlock(env)
    assert (await kubectl(env, "aks-test", "get", "pods"))[-1]["t"] == "trailer"
    (run,) = fakebin.entries("kubectl")
    assert static not in run["kubeconfig"]
    assert "client-key-data" not in run["kubeconfig"]
    assert static not in audit_text(env.audit_dir)


async def test_a_kubectl_error_echoing_the_token_is_scrubbed_everywhere(
    env: BrokerEnv, broker: Broker, fakebin: FakeBin
) -> None:
    set_scenario(fakebin, kubectl={"exit_code": 1, "stderr": f"error: bad token {TOKEN}\n"})
    await unlock(env)
    frames = await kubectl(env, "aks-test", "get", "pods")
    err = error(frames)
    assert err["exitCode"] == 1
    assert TOKEN not in json.dumps(frames)
    assert "[modgudr:redacted]" in str(err["message"])
    assert TOKEN not in audit_text(env.audit_dir)
