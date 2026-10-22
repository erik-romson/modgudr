"""The `kubectl` connector's config, operation and action catalogue (M17, M18)."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from modgudr.broker.policy.lint import lint_policy
from modgudr.broker.registry import PluginRegistry
from modgudr.kubectl.connector import ACTIONS, KubectlConfig, KubectlConnector
from modgudr.kubectl.kubeconfig import kubeconfig
from modgudr.spi import Call, Destination, Endpoint, Risk, TargetContext
from tests.support.brokerfx import write_file
from tests.support.kubectlfx import COMPANY, SUBSCRIPTION, targets

CLUSTER = {"subscription": SUBSCRIPTION, "resourceGroup": "rg-aks-test", "name": "aks-test"}


def test_the_config_takes_a_cluster_and_a_default_namespace() -> None:
    config = KubectlConfig.model_validate({"cluster": CLUSTER, "defaultNamespace": "app-test"})
    assert config.cluster_keys() == CLUSTER
    assert KubectlConfig.model_validate({"cluster": CLUSTER}).defaultNamespace is None


@pytest.mark.parametrize(
    "data",
    [
        {"cluster": CLUSTER, "server": "https://aks.example.net"},
        {"cluster": {**CLUSTER, "server": "https://aks.example.net"}},
        {"cluster": {**CLUSTER, "subscription": "not-a-guid"}},
        {"cluster": {**CLUSTER, "resourceGroup": "rg/../x"}},
        {"cluster": {**CLUSTER, "resourceGroup": "rg."}},
        {"cluster": {**CLUSTER, "name": "-aks"}},
        {"cluster": {**CLUSTER, "name": 7}},
        {"cluster": CLUSTER, "defaultNamespace": "App_Test"},
        {"defaultNamespace": "app"},
    ],
)
def test_the_config_refuses_everything_else(data: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        KubectlConfig.model_validate(data)


def test_the_kubectl_op_is_a_passthrough() -> None:
    (spec,) = KubectlConnector().operations()
    assert (spec.name, spec.passthrough, spec.rows, spec.params, spec.dry_run) == (
        "kubectl",
        True,
        False,
        False,
        False,
    )


def test_classification_uses_the_default_namespace() -> None:
    config = KubectlConfig.model_validate({"cluster": CLUSTER, "defaultNamespace": "app-test"})
    action = KubectlConnector().classify(
        Call("aks-test", "kubectl", {"argv": ["get", "pods"]}), config
    )
    assert (action.name, action.facts["namespace"]) == ("kubectl:get/pods", "app-test")
    unknown = KubectlConnector().classify(Call("aks-test", "kubectl", {"argv": "get"}), config)
    assert unknown.risk is Risk.UNKNOWN


def test_the_catalogue_names_what_the_classifier_returns() -> None:
    names = {spec.name for spec in ACTIONS}
    for name in (
        "get/pods",
        "get/multiple",
        "delete/pods",
        "delete/namespaces",
        "rollout/restart",
        "scale/deployments",
        "logs/pods",
        "exec/pods",
        "cp/pods",
        "top/nodes",
        "create/configmaps",
        "create/token",
        "auth/can-i",
        "config/view",
        "apply",
    ):
        assert name in names, name
    risks = {spec.name: spec.risk for spec in ACTIONS}
    assert risks["get/secrets"] is Risk.SECRET and risks["create/secrets"] is Risk.SECRET
    assert all(spec.constraints == {"namespaces", "requireName"} for spec in ACTIONS)


def test_the_7_8_policy_lints_clean_with_the_installed_connector(shortdir: Path) -> None:
    policy_dir = shortdir / "policy.d"
    write_file(policy_dir / "00-company.yaml", COMPANY)
    write_file(policy_dir / "50-targets.yaml", targets())
    report = lint_policy(policy_dir, PluginRegistry.discover(), dev=True)
    assert [f for f in report.findings if f.severity == "error"] == []


async def test_open_refuses_a_secret_target(shortdir: Path) -> None:
    config = KubectlConfig.model_validate({"cluster": CLUSTER})
    with pytest.raises(ValueError, match="takes a credential provider"):
        await KubectlConnector().open("aks", config, None, context=TargetContext(home=shortdir))


def test_the_kubeconfig_holds_no_token() -> None:
    endpoint = Endpoint("https://h.example.net:443", "Q0E=", Destination("h.example.net", 443))
    document = kubeconfig(endpoint, Path("/run/k-0/cred.sock"), "app-test")
    user = document["users"][0]["user"]  # type: ignore[index]
    assert set(user) == {"exec"}
    assert user["exec"]["interactiveMode"] == "Never"
    assert user["exec"]["apiVersion"] == "client.authentication.k8s.io/v1"
    assert user["exec"]["args"][-1] == "/run/k-0/cred.sock"


def test_discovery_finds_the_connector_and_the_provider() -> None:
    from modgudr.broker.registry import CONNECTORS, CREDENTIAL_PROVIDERS
    from modgudr.kubectl.provider_azure_cli import AzureCliProvider

    registry = PluginRegistry.discover()
    assert isinstance(registry.connector_plugin("kubectl"), KubectlConnector)
    assert registry.provider_factory("azure-cli") is AzureCliProvider
    origins = {(o.group, o.name): o.distribution for o in registry.origins()}
    assert origins[(CONNECTORS, "kubectl")] == "modgudr-kubectl"
    assert origins[(CREDENTIAL_PROVIDERS, "azure-cli")] == "modgudr-kubectl"
