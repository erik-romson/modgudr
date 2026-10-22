"""The static resource catalogue (M17, assumption A12): the core kinds the classifier knows.

There is no `kubectl api-resources` discovery in the MVP. A name the table does not hold, such as
a custom resource, is `kubectl:unknown`. Lookups follow kubectl's own resolution, case-insensitive:

- a plural, singular or short name, or the kind (`pods`, `pod`, `po`, `Pod`);
- `<name>.<group>` and `<name>.<version>.<group>` (`deployments.apps`, `deploy.v1.apps`,
  `Secret.v1.` for the core group, whose name is empty).

A qualified name must carry the kind's own group, so a custom resource that shares a plural with a
core kind (`certificates.cert-manager.io`, `events.events.k8s.io`) never resolves to it.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class Kind:
    """One resource kind: its names, API group and scope."""

    plural: str
    singular: str
    short: tuple[str, ...]
    kind: str
    #: The API group; the core group is `""`.
    group: str
    namespaced: bool

    @property
    def names(self) -> tuple[str, ...]:
        """Every name it is looked up by, lower case."""
        return (self.plural, self.singular, *self.short, self.kind.lower())


_CORE = ""
_APPS = "apps"
_BATCH = "batch"
_NETWORKING = "networking.k8s.io"
_RBAC = "rbac.authorization.k8s.io"

#: The core kinds of M17, as `kubectl api-resources` lists them.
KINDS: tuple[Kind, ...] = (
    Kind("pods", "pod", ("po",), "Pod", _CORE, True),
    Kind("deployments", "deployment", ("deploy",), "Deployment", _APPS, True),
    Kind("replicasets", "replicaset", ("rs",), "ReplicaSet", _APPS, True),
    Kind("statefulsets", "statefulset", ("sts",), "StatefulSet", _APPS, True),
    Kind("daemonsets", "daemonset", ("ds",), "DaemonSet", _APPS, True),
    Kind("jobs", "job", (), "Job", _BATCH, True),
    Kind("cronjobs", "cronjob", ("cj",), "CronJob", _BATCH, True),
    Kind("services", "service", ("svc",), "Service", _CORE, True),
    Kind("endpoints", "endpoints", ("ep",), "Endpoints", _CORE, True),
    Kind("configmaps", "configmap", ("cm",), "ConfigMap", _CORE, True),
    Kind("secrets", "secret", (), "Secret", _CORE, True),
    Kind("namespaces", "namespace", ("ns",), "Namespace", _CORE, False),
    Kind("nodes", "node", ("no",), "Node", _CORE, False),
    Kind("events", "event", ("ev",), "Event", _CORE, True),
    Kind("ingresses", "ingress", ("ing",), "Ingress", _NETWORKING, True),
    Kind(
        "persistentvolumeclaims",
        "persistentvolumeclaim",
        ("pvc",),
        "PersistentVolumeClaim",
        _CORE,
        True,
    ),
    Kind("persistentvolumes", "persistentvolume", ("pv",), "PersistentVolume", _CORE, False),
    Kind("serviceaccounts", "serviceaccount", ("sa",), "ServiceAccount", _CORE, True),
    Kind("roles", "role", (), "Role", _RBAC, True),
    Kind("rolebindings", "rolebinding", (), "RoleBinding", _RBAC, True),
    Kind("clusterroles", "clusterrole", (), "ClusterRole", _RBAC, False),
    Kind("clusterrolebindings", "clusterrolebinding", (), "ClusterRoleBinding", _RBAC, False),
    Kind(
        "horizontalpodautoscalers",
        "horizontalpodautoscaler",
        ("hpa",),
        "HorizontalPodAutoscaler",
        "autoscaling",
        True,
    ),
    Kind("networkpolicies", "networkpolicy", ("netpol",), "NetworkPolicy", _NETWORKING, True),
    Kind(
        "poddisruptionbudgets",
        "poddisruptionbudget",
        ("pdb",),
        "PodDisruptionBudget",
        "policy",
        True,
    ),
    Kind("limitranges", "limitrange", ("limits",), "LimitRange", _CORE, True),
    Kind("resourcequotas", "resourcequota", ("quota",), "ResourceQuota", _CORE, True),
    Kind("storageclasses", "storageclass", ("sc",), "StorageClass", "storage.k8s.io", False),
    Kind(
        "customresourcedefinitions",
        "customresourcedefinition",
        ("crd", "crds"),
        "CustomResourceDefinition",
        "apiextensions.k8s.io",
        False,
    ),
)

#: The kind whose every mention makes a call `secret` (M17).
SECRETS = "secrets"


def _index(kinds: tuple[Kind, ...]) -> dict[str, Kind]:
    index: dict[str, Kind] = {}
    for kind in kinds:
        for name in kind.names:
            other = index.setdefault(name, kind)
            if other is not kind:
                raise ValueError(f"{name!r} names both {other.plural} and {kind.plural}")
    return index


_BY_NAME: Mapping[str, Kind] = _index(KINDS)
_BY_PLURAL: Mapping[str, Kind] = {kind.plural: kind for kind in KINDS}

#: An API version as Kubernetes writes it: `v1`, `v2`, `v1beta1`, `v2alpha3`.
_VERSION = re.compile(r"v[1-9][0-9]*(?:(?:alpha|beta)[1-9][0-9]*)?")


def lookup(name: str) -> Kind | None:
    """The kind `name` resolves to, or None when the catalogue does not hold it."""
    lower = name.lower()
    found = _BY_NAME.get(lower)
    if found is not None:
        return found
    if lower.count(".") >= 2:
        # `resource.version.group`, as kubectl tries first; the group may hold dots.
        resource, version, group = lower.split(".", 2)
        found = _BY_NAME.get(resource)
        if found is not None and found.group == group and _VERSION.fullmatch(version):
            return found
    if "." in lower:
        resource, group = lower.split(".", 1)
        found = _BY_NAME.get(resource)
        if found is not None and found.group == group:
            return found
    return None


def by_plural(plural: str) -> Kind:
    """The kind with this plural; a `KeyError` for a name outside the catalogue."""
    return _BY_PLURAL[plural]
