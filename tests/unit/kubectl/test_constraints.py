"""The step 04 engine with the kubectl classifier, its invariants and its constraint checks.

The policy is pre-plan §7.8: `aks-test` in `test` (ceiling destructive) and `aks-prod` in `prod`
(ceiling read). The first rows are the four kubectl examples of §7.7.
"""

from __future__ import annotations

import shlex
from collections.abc import Mapping

import pytest

from modgudr.broker.engine.decide import Scope, build_scope, decide
from modgudr.broker.engine.explain import explain
from modgudr.broker.policy.model import EnvironmentConfig
from modgudr.kubectl.classify import CHECKS, INVARIANTS, TYPE, Namespaces, RequireName, classify
from modgudr.spi import Action, ConstraintValue, Fact, Layer, Risk, Rule, RuleSet
from tests.support.enginefx import FakePlugin

#: Pre-plan §7.8, as the company file writes it.
ENVIRONMENTS: Mapping[str, EnvironmentConfig] = {
    "test": EnvironmentConfig.model_validate(
        {
            "ceiling": "destructive",
            "kubectl": {
                "allow": ["read", "rollout/restart", "scale/*", "delete/pods", "delete/jobs"],
                "deny": ["delete/namespaces", "delete/persistentvolumeclaims"],
                "constraints": {
                    "*": {"namespaces": ["app-test", "app-test-2"]},
                    "delete/*": {"requireName": True},
                },
            },
        }
    ),
    "prod": EnvironmentConfig.model_validate(
        {"ceiling": "read", "kubectl": {"constraints": {"*": {"namespaces": ["app"]}}}}
    ),
    "stage": EnvironmentConfig.model_validate({"ceiling": "write"}),
}
TARGETS = {"aks-test": "test", "aks-prod": "prod", "aks-stage": "stage"}

#: The engine's view of the kubectl connector: its invariants, defaults (reads) and checks.
PLUGIN = FakePlugin(TYPE, INVARIANTS, RuleSet(allow=(Rule("read"),)), CHECKS)


def scope(target: str) -> Scope:
    env = TARGETS[target]
    return build_scope(
        target=target,
        env=env,
        environment=ENVIRONMENTS[env],
        target_rules={},
        guard=(),
        plugin=PLUGIN,
    )


def decided(target: str, argv: str, default_namespace: str | None = None) -> tuple[str, str, str]:
    decision = decide(classify(shlex.split(argv), default_namespace), scope(target))
    return decision.verdict, str(decision.layer), decision.rule


def test_the_7_7_rows_for_aks_test() -> None:
    assert decided("aks-test", "-n app-test delete pod web-1") == (
        "allow",
        "environment",
        "delete/pods",
    )
    assert decided("aks-test", "-n app-test delete pods --all") == (
        "deny",
        "constraint",
        "requireName",
    )
    assert decided("aks-test", "get secrets -n app-test") == ("deny", "plugin-invariant", "secret")
    assert decided("aks-test", "--as=admin get pods") == ("deny", "plugin-invariant", "--as")


def test_the_7_7_explanations() -> None:
    allowed = decide(classify(shlex.split("-n app-test delete pod web-1")), scope("aks-test"))
    assert explain(allowed) == (
        "allowed: kubectl:delete/pods (destructive) on aks-test. Environment test allows "
        "delete/pods (environment); subject to requireName true, namespaces [app-test, "
        "app-test-2]."
    )
    denied = decide(classify(shlex.split("-n app-test delete pods --all")), scope("aks-test"))
    assert explain(denied) == (
        "denied: kubectl:delete/pods (destructive) on aks-test. Constraint requireName from "
        "environment test is not met: --all is refused; name the objects (constraint)."
    )
    identity = decide(classify(shlex.split("--as=admin get pods")), scope("aks-test"))
    assert explain(identity) == (
        "denied: kubectl:get/pods (read) on aks-test. The kubectl plugin never allows --as: the "
        "broker sets the cluster, the user and the kubeconfig itself (plugin-invariant)."
    )


@pytest.mark.parametrize(
    ("argv", "want"),
    [
        # requireName (KC-03)
        ("delete pod/web-1 pod/web-2 -n app-test", ("allow", "environment", "delete/pods")),
        ("delete pods -l app=x -n app-test", ("deny", "constraint", "requireName")),
        ("delete pods -n app-test", ("deny", "constraint", "requireName")),
        ("delete job j -n app-test-2", ("allow", "environment", "delete/jobs")),
        # namespaces (KC-02)
        ("get pods -n app-test", ("allow", "environment", "read")),
        ("get pods -napp-test-2", ("allow", "environment", "read")),
        ("get pods", ("deny", "constraint", "namespaces")),
        ("get pods -n kube-system", ("deny", "constraint", "namespaces")),
        ("get pods -A", ("deny", "constraint", "namespaces")),
        ("get pods -A -n app-test", ("deny", "constraint", "namespaces")),
        ("get nodes -n app-test", ("deny", "constraint", "namespaces")),
        ("top node", ("deny", "constraint", "namespaces")),
        ("get pods,secrets -n app-test", ("deny", "plugin-invariant", "secret")),
        # what §7.8 allows and denies by name
        ("rollout restart deploy/po -n app-test", ("allow", "environment", "rollout/restart")),
        ("scale --replicas=0 deploy/po -n app-test", ("allow", "environment", "scale/*")),
        ("scale --replicas=0 deploy -l app=x -n app-test", ("allow", "environment", "scale/*")),
        ("delete ns app-test", ("deny", "environment", "delete/namespaces")),
        ("delete pvc data -n app-test", ("deny", "environment", "delete/persistentvolumeclaims")),
        ("delete deploy web -n app-test", ("deny", "no-rule", "none")),
        ("delete pods,jobs x -n app-test", ("deny", "no-rule", "none")),
        ("label pods x a=b -n app-test", ("deny", "no-rule", "none")),
        # follow and watch are reads (A13)
        ("logs -f web-1 -n app-test", ("allow", "environment", "read")),
        ("get pods -w -n app-test", ("allow", "environment", "read")),
        # the ceiling, the invariants and unknown
        ("exec -it p -n app-test -- sh", ("deny", "ceiling", "destructive")),
        ("cp p:/x . -n app-test", ("deny", "plugin-invariant", "kubectl:cp/*")),
        ("apply -f x.yaml -n app-test", ("deny", "plugin-invariant", "--filename")),
        ("replace --force -f x -n app-test", ("deny", "plugin-invariant", "--filename")),
        ("get pods -v=9 -n app-test", ("deny", "plugin-invariant", "--v")),
        ("--kubeconfig f get pods", ("deny", "plugin-invariant", "--kubeconfig")),
        ("get certificates.cert-manager.io -n app-test", ("deny", "plugin-invariant", "unknown")),
        ("proxy", ("deny", "plugin-invariant", "unknown")),
    ],
)
def test_aks_test(argv: str, want: tuple[str, str, str]) -> None:
    assert decided("aks-test", argv) == want


def test_the_targets_default_namespace_is_checked_like_a_flag() -> None:
    assert decided("aks-test", "get pods", "app-test") == ("allow", "environment", "read")
    assert decided("aks-test", "get pods", "kube-system") == ("deny", "constraint", "namespaces")


@pytest.mark.parametrize(
    ("argv", "want"),
    [
        ("get pods -n app", ("allow", "plugin-default", "read")),
        ("get pods", ("deny", "constraint", "namespaces")),
        ("get pods -A", ("deny", "constraint", "namespaces")),
        ("delete pod web-1 -n app", ("deny", "ceiling", "read")),
        ("rollout restart deploy/po -n app", ("deny", "ceiling", "read")),
    ],
)
def test_aks_prod(argv: str, want: tuple[str, str, str]) -> None:
    assert decided("aks-prod", argv) == want


def test_without_a_namespaces_constraint_all_namespaces_is_allowed() -> None:
    assert decided("aks-stage", "get pods -A") == ("allow", "plugin-default", "read")
    assert decided("aks-stage", "get nodes") == ("allow", "plugin-default", "read")


def test_the_namespaces_message_says_what_to_add() -> None:
    decision = decide(classify(["get", "pods"]), scope("aks-test"))
    assert decision.message.endswith(
        "namespace 'default' is not allowed; allowed: app-test, app-test-2; add -n app-test"
    )
    every = decide(classify(["get", "pods", "-A"]), scope("aks-test"))
    assert "-A (all namespaces) never matches namespaces" in every.message


def kubectl_action(**facts: Fact) -> Action:
    return Action("kubectl:delete/pods", Risk.DESTRUCTIVE, facts)


@pytest.mark.parametrize(
    ("facts", "reason"),
    [
        ({"names": ("x",), "all": False}, None),
        ({"names": ("x",), "all": True}, "--all is refused; name the objects"),
        ({"names": (), "all": False, "selector": "a=b"}, "a selector is refused; name the objects"),
        ({"names": (), "all": False, "selector": None}, "name the objects to act on"),
        ({"names": ("x",)}, "the call does not say whether it acts on --all"),
    ],
)
def test_require_name(facts: dict[str, Fact], reason: str | None) -> None:
    assert RequireName().before(kubectl_action(**facts), True) == reason


def test_require_name_false_is_met_and_other_values_are_not() -> None:
    nameless = kubectl_action(names=(), all=True)
    assert RequireName().before(nameless, False) is None
    assert RequireName().before(nameless, "yes") is not None
    assert RequireName().before(nameless, 1) is not None


@pytest.mark.parametrize(
    ("facts", "met"),
    [
        ({"namespace": "app", "allNamespaces": False, "clusterScoped": False}, True),
        ({"namespace": "x", "allNamespaces": False, "clusterScoped": False}, False),
        ({"namespace": "app", "allNamespaces": True, "clusterScoped": False}, False),
        ({"namespace": "app", "allNamespaces": False, "clusterScoped": True}, False),
        ({"namespace": "app", "allNamespaces": False}, False),
        ({"namespace": "app", "clusterScoped": False}, False),
        ({"allNamespaces": False, "clusterScoped": False}, False),
    ],
)
def test_namespaces_fails_closed(facts: dict[str, Fact], met: bool) -> None:
    assert (Namespaces().before(kubectl_action(**facts), ("app",)) is None) is met


@pytest.mark.parametrize("value", [(), "app", True, 3])
def test_namespaces_needs_a_list(value: ConstraintValue) -> None:
    ok = kubectl_action(namespace="app", allNamespaces=False, clusterScoped=False)
    assert Namespaces().before(ok, value) is not None


def test_the_checks_run_nothing_after_the_call() -> None:
    action = classify(["delete", "pod", "x"])
    assert RequireName().after(action, True, {}) is None
    assert Namespaces().after(action, ("default",), {}) is None
    assert set(CHECKS) == {"namespaces", "requireName"}
    assert decide(action, scope("aks-test")).layer is Layer.CONSTRAINT
