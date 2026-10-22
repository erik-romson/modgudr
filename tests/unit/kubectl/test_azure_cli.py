"""Parsing what `az` prints (M18): only the server URL and CA of the one cluster are taken, and
anything unexpected is refused, never guessed at."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from modgudr.kubectl.provider_azure_cli import (
    AzureCliProvider,
    credential_url,
    parse_access_token,
    parse_cluster_credential,
    server_destination,
)
from modgudr.spi import Destination, ProviderContext, ProviderTarget, UpstreamFailure

CA = base64.b64encode(b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n").decode()
SERVER = "https://aks-test-dns-1.hcp.westeurope.azmk8s.io:443"


def kubeconfig(clusters: str) -> str:
    return f"apiVersion: v1\nkind: Config\nclusters:\n{clusters}users: []\n"


def cluster(server: str = SERVER, ca: str = CA) -> str:
    return f"- name: c\n  cluster:\n    server: {server}\n    certificate-authority-data: {ca}\n"


def output(text: str, *, entries: int = 1) -> str:
    value = base64.b64encode(text.encode()).decode()
    return json.dumps({"kubeconfigs": [{"name": "clusterUser", "value": value}] * entries})


def test_only_the_server_and_ca_are_taken() -> None:
    found = parse_cluster_credential(output(kubeconfig(cluster())))
    assert (found.server, found.ca_data) == (SERVER, CA)
    assert found.destination == Destination("aks-test-dns-1.hcp.westeurope.azmk8s.io", 443)
    assert CA not in repr(found)


@pytest.mark.parametrize(
    ("text", "why"),
    [
        ("not json", "not JSON"),
        (json.dumps([]), "not a JSON object"),
        (json.dumps({"kubeconfigs": []}), "exactly one kubeconfig"),
        (output(kubeconfig(cluster()), entries=2), "exactly one kubeconfig"),
        (json.dumps({"kubeconfigs": [{"value": "%%%"}]}), "not base64"),
        (output(kubeconfig(cluster() + cluster())), "exactly one cluster"),
        (output(kubeconfig(cluster(ca="'not base64!'"))), "certificate-authority-data"),
        (output(kubeconfig(cluster(server="http://h.example.net"))), "not https"),
        (output(kubeconfig(cluster(server="https://u:p@h.example.net"))), "userinfo"),
        (output(kubeconfig(cluster(server="https://h.example.net/api"))), "path or query"),
        (output("clusters: [\n"), "cannot be read"),
        (output("clusters: []\nclusters: []\n"), "cannot be read"),
    ],
)
def test_anything_else_is_refused(text: str, why: str) -> None:
    with pytest.raises(UpstreamFailure, match=why):
        parse_cluster_credential(text)


def test_server_destination_defaults_to_443() -> None:
    assert server_destination("https://Host.Example.NET.") == Destination("host.example.net", 443)
    assert server_destination("https://h.example.net:6443/") == Destination("h.example.net", 6443)


def test_the_access_token() -> None:
    token = parse_access_token(json.dumps({"accessToken": "t0k", "expires_on": 1800000000}))
    assert (token.value, token.expires_at) == ("t0k", 1800000000.0)
    assert parse_access_token(json.dumps({"accessToken": "t", "expires_on": "17"})).expires_at == 17
    for bad in (
        "nope",
        json.dumps({"accessToken": "", "expires_on": 1}),
        json.dumps({"accessToken": "t", "expiresOn": "2026-10-22 10:00:00.000000"}),
        json.dumps({"accessToken": "t", "expires_on": True}),
        json.dumps({"accessToken": "t", "expires_on": "\uff11\uff17"}),  # full-width digits
    ):
        with pytest.raises(UpstreamFailure):
            parse_access_token(bad)


def test_the_credential_url() -> None:
    url = credential_url({"subscription": "s", "resourceGroup": "rg (x)", "name": "n"})
    assert url == (
        "https://management.azure.com/subscriptions/s/resourceGroups/rg%20%28x%29/providers/"
        "Microsoft.ContainerService/managedClusters/n/listClusterUserCredential"
        "?api-version=2025-10-01"
    )
    with pytest.raises(UpstreamFailure, match="no resourceGroup"):
        credential_url({"subscription": "s", "name": "n"})


def test_custody_lives_under_modgudr_home_and_borrowed_has_none(shortdir: Path) -> None:
    provider = AzureCliProvider(ProviderContext(home=shortdir / "h", user_home=shortdir / "u"))
    assert provider.state_dir(ProviderTarget("aks-test", "aks", "borrowed")) is None
    directory = provider.state_dir(ProviderTarget("aks-test", "aks", "custody"))
    assert directory == shortdir / "h" / "azure" / "aks"
    assert directory.stat().st_mode & 0o777 == 0o700
    assert provider.facts()["az"] is None
    assert "not on the broker's PATH" in str(provider.facts()["problem"])
    assert provider.tiers == frozenset({"borrowed", "custody"})
