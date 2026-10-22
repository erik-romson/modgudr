"""The kubectl connector against a real kind cluster (opt-in: `MODGUDR_TEST_KIND=1`, CI only).

The real `kubectl` on the CI runner's `PATH` runs with the broker's own kubeconfig and exec
plugin. In place of `azure-cli`, a test provider gives the endpoint from the kind kubeconfig and a
service-account token, both handed over by the CI job:

- `MODGUDR_KIND_KUBECONFIG`: the kubeconfig `kind create cluster` wrote (server and CA only are
  read);
- `MODGUDR_KIND_TOKEN`: a token from `kubectl create token` for a service account that may list
  pods in the namespace `app-test`.

It never runs on a developer's machine: nothing here reads `~/.kube` or `~/.azure`.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from modgudr.broker.policy.yaml_strict import load_strict
from modgudr.kubectl.provider_azure_cli import server_destination
from modgudr.spi import (
    Endpoint,
    EndpointRequest,
    MintedToken,
    ProviderContext,
    ProviderTarget,
    TokenRequest,
)
from tests.support.brokerfx import BrokerEnv, call, error, make_env, running, unlock
from tests.support.kubectlfx import COMPANY, SUBSCRIPTION

pytestmark = pytest.mark.kind

TARGETS = f"""\
targets:
  kind-test:
    type: kubectl
    system: kind
    env: test
    provider: kind-sa
    credential: {{ tier: borrowed }}
    cluster: {{ subscription: {SUBSCRIPTION}, resourceGroup: rg-kind, name: kind }}
    defaultNamespace: app-test
"""


class KindProvider:
    """The kind cluster's endpoint and the CI job's service-account token."""

    def __init__(self, context: ProviderContext) -> None:
        self.context = context

    @property
    def name(self) -> str:
        return "kind-sa"

    @property
    def tiers(self) -> frozenset[str]:
        return frozenset({"borrowed"})

    def facts(self) -> Mapping[str, object]:
        return {}

    def state_dir(self, target: ProviderTarget) -> Path | None:
        return None

    async def endpoint(self, request: EndpointRequest) -> Endpoint:
        text = Path(os.environ["MODGUDR_KIND_KUBECONFIG"]).read_text("utf-8")
        document: Any = load_strict(text, "kind kubeconfig")
        cluster = document["clusters"][0]["cluster"]
        server = str(cluster["server"])
        return Endpoint(
            server, str(cluster["certificate-authority-data"]), server_destination(server)
        )

    async def mint(self, request: TokenRequest) -> MintedToken:
        return MintedToken(os.environ["MODGUDR_KIND_TOKEN"], time.time() + 3600)

    async def lock(self) -> None:
        return None


def kind_env(root: Path) -> BrokerEnv:
    kubectl = shutil.which("kubectl")
    assert kubectl is not None, "the kind job puts kubectl on PATH"
    env = make_env(
        root,
        company=COMPANY,
        targets=TARGETS,
        secrets={},
        path=f"{Path(kubectl).parent}:/usr/bin:/bin",
    )
    assert env.config.registry is not None
    env.config.registry.register_provider("kind-sa", KindProvider)
    return env


async def kubectl(env: BrokerEnv, *argv: str) -> list[dict[str, object]]:
    return await call(env.agent_socket, "kubectl", "kind-test", args={"argv": list(argv)})


async def test_get_pods_runs_real_kubectl_with_the_broker_kubeconfig(shortdir: Path) -> None:
    env = kind_env(shortdir)
    token = os.environ["MODGUDR_KIND_TOKEN"]
    async with running(env):
        await unlock(env)
        frames = await kubectl(env, "get", "pods", "-n", "app-test")
        refused = error(await kubectl(env, "delete", "pods", "--all", "-n", "app-test"))
        secrets = error(await kubectl(env, "get", "secrets", "-n", "app-test"))
    assert frames[-1]["t"] == "trailer", frames
    assert frames[-1]["exitCode"] == 0
    assert token not in json.dumps(frames)
    assert (refused["code"], refused["rule"]) == ("denied", "requireName")
    assert (secrets["code"], secrets["layer"]) == ("denied", "plugin-invariant")
    run_dir = Path(os.path.realpath(env.home)) / "run"
    assert not [p for p in run_dir.iterdir() if p.name.startswith("k-")]
