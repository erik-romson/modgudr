"""Helpers for the kubectl tests (step 18): the §7.8 policy with AKS targets, the scenario of the
fake `az` and `kubectl`, and a broker config whose `PATH` is the fake `bin/` only.

The broker's `user_home` is a temporary home that holds a decoy `~/.kube/config`; nothing may read
it. `PATH` for the broker and its children is `<fake bin>:/usr/bin:/bin`, so the developer's real
`kubectl` (prod AKS contexts) and `az` are unreachable.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from tests.support.brokerfx import BrokerEnv, make_env, read_audit
from tests.support.fakebin import FakeBin

#: The token the fake `az` mints. Not JWT-shaped: only its registration as a known value can
#: scrub it.
TOKEN = "aks-token-7f3e9a1c5d2b4e6f8a0c-fake"
SERVER_HOST = "aks-test-dns-1a2b3c4d.hcp.westeurope.azmk8s.io"
SERVER = f"https://{SERVER_HOST}:443"
SUBSCRIPTION = "0b1f6471-1bf0-4dda-aec3-111122223333"
AKS_SERVER_APP = "6dae42f8-4368-4678-94ff-3960e28e3630"
CREDENTIAL_URL = (
    f"https://management.azure.com/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-aks-test/"
    "providers/Microsoft.ContainerService/managedClusters/aks-test/listClusterUserCredential"
    "?api-version=2025-10-01"
)
DECOY = "apiVersion: v1\nkind: Config\n# the developer's own kubeconfig: never read\n"

GET_PODS = "NAME    READY   STATUS    RESTARTS   AGE\nweb-1   1/1     Running   0          3d\n"
LOGS = "log line a\nlog line b\n"

#: The locale the broker passes on to `az` (M18).
LOCALE = {"LANG": "en_US.UTF-8", "LC_MESSAGES": "en_US.UTF-8"}
#: Keys a fake's own interpreter adds: the coerced C locale, and macOS's text encoding.
INTERPRETER_KEYS = {"LC_CTYPE", "__CF_USER_TEXT_ENCODING"}
KUBECTL_KEYS = {"PATH", "HOME", "KUBECONFIG"}
AZ_KEYS = {"PATH", "HOME", *LOCALE}

COMPANY = """\
store:
  default: file
defaults:
  env: test
  timeout: 30s
  maxRows: 500
  maxRowsHard: 50000
  maxBytes: 2MiB
  maxRequestBytes: 1MiB
  maxConcurrent: 4
environments:
  test:
    ceiling: destructive
    kubectl:
      allow: [read, rollout/restart, scale/*, delete/pods, delete/jobs]
      deny: [delete/namespaces, delete/persistentvolumeclaims]
      constraints:
        "*": { namespaces: [app-test, app-test-2] }
        "delete/*": { requireName: true }
  prod:
    ceiling: read
    kubectl:
      constraints:
        "*": { namespaces: [app] }
"""


def targets(tier: str = "borrowed", *, extra: str = "") -> str:
    """`aks-test` (system `aks`, env test, the given tier), `aks-prod` and `aks-fast` (timeout
    1 s), all on the same cluster."""
    cluster = (
        f"    cluster: {{ subscription: {SUBSCRIPTION}, resourceGroup: rg-aks-test, "
        "name: aks-test }\n"
    )
    return (
        "targets:\n"
        "  aks-test:\n"
        "    type: kubectl\n"
        "    system: aks\n"
        "    env: test\n"
        "    provider: azure-cli\n"
        f"    credential: {{ tier: {tier} }}\n" + cluster + "    defaultNamespace: app-test\n"
        "  aks-prod:\n"
        "    type: kubectl\n"
        "    system: aks\n"
        "    env: prod\n"
        "    provider: azure-cli\n"
        "    credential: { tier: borrowed }\n" + cluster + "    defaultNamespace: app\n"
        "  aks-fast:\n"
        "    type: kubectl\n"
        "    env: test\n"
        "    timeout: 1s\n"
        "    provider: azure-cli\n"
        "    credential: { tier: borrowed }\n"
        + cluster
        + "    defaultNamespace: app-test\n"
        + extra
    )


def scenario(
    *,
    az: Mapping[str, Any] | None = None,
    kubectl: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """The fakes' scenario: a borrowed login, `TOKEN`, `SERVER`, and canned `get`/`logs`."""
    plan_az: dict[str, Any] = {"token": TOKEN, "server": SERVER, "logged_in": ["borrowed"]}
    plan_az.update(az or {})
    plan_kubectl: dict[str, Any] = {
        "expect_token": TOKEN,
        "output": {"get": GET_PODS, "logs": LOGS},
    }
    plan_kubectl.update(kubectl or {})
    return {"az": plan_az, "kubectl": plan_kubectl}


def set_scenario(
    fake: FakeBin,
    *,
    az: Mapping[str, Any] | None = None,
    kubectl: Mapping[str, Any] | None = None,
) -> None:
    fake.set_scenario(scenario(az=az, kubectl=kubectl))


def kube_env(
    root: Path,
    fake: FakeBin,
    *,
    tier: str = "borrowed",
    targets_text: str | None = None,
    path: str | None = None,
    **overrides: object,
) -> BrokerEnv:
    """A dev broker config with the AKS targets, the fakes' `PATH`, a fixed locale and a
    temporary home with a decoy `~/.kube/config`."""
    env = make_env(
        root,
        company=COMPANY,
        targets=targets_text if targets_text is not None else targets(tier),
        secrets={},
        path=path if path is not None else fake.path_env(),
        locale=dict(LOCALE),
        **overrides,
    )
    decoy = env.config.user_home / ".kube" / "config"
    decoy.parent.mkdir(parents=True, exist_ok=True)
    decoy.write_text(DECOY)
    return env


def child_keys(entry: Mapping[str, Any]) -> set[str]:
    """The environment keys a fake was given, without those its interpreter adds."""
    return set(entry["env"]) - INTERPRETER_KEYS


def custody_dir(env: BrokerEnv, system: str = "aks") -> str:
    """`$MODGUDR_HOME/azure/<system>`, canonical, as the broker hands it to `az`."""
    return str(Path(os.path.realpath(env.home)) / "azure" / system)


def call_dir(entry: Mapping[str, Any]) -> Path:
    """The per-call directory of a `kubectl` run, from its `--kubeconfig`."""
    argv = list(entry["argv"])
    return Path(argv[argv.index("--kubeconfig") + 1]).parent


def records(env: BrokerEnv, record_type: str) -> list[dict[str, object]]:
    return [r for r in read_audit(env.audit_dir) if r["type"] == record_type]


def kubeconfig_of(entry: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(entry["kubeconfig"])


def pid_gone(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False
