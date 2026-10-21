"""Constraint merging (§7.5: per key, the most specific layer winning) and evaluation (§7.6)."""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from modgudr.broker.engine.constraints import merge, unmet
from modgudr.broker.engine.decide import Scope, decide
from modgudr.broker.engine.explain import explain, format_value
from modgudr.spi import Action, ConstraintValue, Layer, Risk, Rule, RuleSet
from tests.support.enginefx import FakePlugin, kubectl_plugin, sql_plugin

DELETE = Action("sql:delete", Risk.DESTRUCTIVE, {"where": "column"})

Constraints = Mapping[str, Mapping[str, ConstraintValue]]


def allow(*patterns: str, constraints: Constraints | None = None) -> RuleSet:
    return RuleSet(tuple(Rule(p) for p in patterns), (), {} if constraints is None else constraints)


def scope(
    *,
    target_rules: Mapping[str, RuleSet] | None = None,
    env_rules: Mapping[str, RuleSet] | None = None,
    plugin: FakePlugin | None = None,
    target: str = "pg-sol",
) -> Scope:
    plugin = sql_plugin() if plugin is None else plugin
    return Scope(
        target=target,
        type=plugin.type,
        env="test",
        ceiling=Risk.DESTRUCTIVE,
        invariants=tuple(plugin.invariants()),
        target_rules={} if target_rules is None else target_rules,
        env_rules={} if env_rules is None else env_rules,
        defaults=plugin.default_rules(),
        checks=plugin.constraint_checks(),
    )


def merged(s: Scope, action: Action = DELETE) -> dict[str, tuple[ConstraintValue, Layer]]:
    return {name: (c.value, c.layer) for name, c in merge(action, s.layers()).items()}


def test_merge_per_key_the_most_specific_layer_wins() -> None:
    s = scope(
        env_rules={"sql": allow("delete", constraints={"delete": {"maxAffectedRows": 1000}})},
        target_rules={"sql": RuleSet(constraints={"delete": {"maxAffectedRows": 100}})},
    )
    want = {
        "maxAffectedRows": (100, Layer.TARGET),
        "requireWhere": (True, Layer.PLUGIN_DEFAULT),
    }
    assert merged(s) == want
    decision = decide(DELETE, s)
    assert decision.allowed and decision.layer is Layer.ENVIRONMENT
    assert {n: (c.value, c.layer) for n, c in decision.constraints.items()} == want


def test_a_layer_keeps_the_keys_a_more_specific_one_does_not_set() -> None:
    env = {"delete": {"requireWhere": True, "maxAffectedRows": 1000}}
    s = scope(
        env_rules={"sql": allow("delete", constraints=env)},
        target_rules={"sql": RuleSet(constraints={"delete": {"maxAffectedRows": 100}})},
    )
    assert merged(s) == {
        "maxAffectedRows": (100, Layer.TARGET),
        "requireWhere": (True, Layer.ENVIRONMENT),
    }


def test_constraints_apply_whichever_layer_allowed() -> None:
    s = scope(
        target_rules={"sql": allow("delete")},
        env_rules={"sql": RuleSet(constraints={"delete": {"maxAffectedRows": 7}})},
    )
    decision = decide(DELETE, s)
    assert decision.layer is Layer.TARGET
    assert decision.constraints["maxAffectedRows"].value == 7


def test_the_connector_block_beats_all_in_one_layer() -> None:
    s = scope(
        env_rules={
            "all": RuleSet(constraints={"delete": {"maxAffectedRows": 20}}),
            "sql": RuleSet(constraints={"delete": {"maxAffectedRows": 10}}),
        }
    )
    assert merged(s)["maxAffectedRows"] == (10, Layer.ENVIRONMENT)


@pytest.mark.parametrize(
    ("patterns", "winner"),
    [
        (["destructive", "*", "del*", "delete"], "delete"),
        (["destructive", "*", "del*"], "del*"),
        (["destructive", "*"], "*"),
        (["destructive"], "destructive"),
    ],
)
def test_inside_a_block_the_most_specific_pattern_wins(patterns: list[str], winner: str) -> None:
    block = RuleSet(constraints={p: {"maxAffectedRows": i} for i, p in enumerate(patterns)})
    constraint = merge(DELETE, scope(env_rules={"sql": block}).layers())["maxAffectedRows"]
    assert constraint.pattern == winner


def test_constraints_of_other_actions_do_not_apply() -> None:
    s = scope(env_rules={"sql": RuleSet(constraints={"update": {"maxAffectedRows": 1}})})
    assert "maxAffectedRows" not in merged(s)


def test_a_constraint_without_a_check_is_never_met() -> None:
    plugin = FakePlugin("sql", (), allow("read"))
    s = scope(
        plugin=plugin,
        env_rules={"sql": allow("delete", constraints={"delete": {"requireWhere": True}})},
    )
    decision = decide(DELETE, s)
    assert (decision.allowed, decision.layer, decision.rule) == (
        False,
        Layer.CONSTRAINT,
        "requireWhere",
    )
    assert decision.message.endswith("the sql connector has no check for requireWhere")


def test_checks_run_before_and_after_the_run() -> None:
    s = scope(env_rules={"sql": allow("delete", constraints={"delete": {"maxAffectedRows": 3}})})
    constraints = merge(DELETE, s.layers())
    assert unmet(DELETE, constraints, s.checks) is None
    after = unmet(DELETE, constraints, s.checks, {"affectedRows": 5})
    assert after is not None
    assert (after.constraint.name, after.reason) == ("maxAffectedRows", "5 rows, limit 3")
    assert unmet(DELETE, constraints, s.checks, {"affectedRows": 3}) is None
    missing = unmet(DELETE, constraints, s.checks, {"affectedRows": None})
    assert missing is not None and missing.reason == "row count unavailable"


def test_the_first_unmet_constraint_in_merged_order_decides() -> None:
    env = RuleSet(
        (Rule("delete/pods"),),
        (),
        {"*": {"namespaces": ("app-test",)}, "delete/*": {"requireName": True}},
    )
    s = scope(plugin=kubectl_plugin(), env_rules={"kubectl": env}, target="aks-test")
    action = Action("kubectl:delete/pods", Risk.DESTRUCTIVE, {"all": True, "namespace": "kube"})
    decision = decide(action, s)
    assert (decision.layer, decision.rule) == (Layer.CONSTRAINT, "requireName")
    named = Action("kubectl:delete/pods", Risk.DESTRUCTIVE, {"names": ("x",), "namespace": "kube"})
    assert decide(named, s).rule == "namespaces"


def test_a_constraint_denial_names_the_source_layer() -> None:
    s = scope(
        target="qa-small",
        env_rules={"sql": allow("delete")},
        target_rules={"sql": RuleSet(constraints={"delete": {"requireWhere": True}})},
    )
    decision = decide(Action("sql:delete", Risk.DESTRUCTIVE, {"where": "none"}), s)
    assert explain(decision) == (
        "denied: sql:delete (destructive) on qa-small. Constraint requireWhere from target "
        "qa-small is not met: the statement has no WHERE clause (constraint)."
    )


def test_explain_lists_the_constraints_of_an_allowed_action() -> None:
    s = scope(env_rules={"sql": allow("delete", constraints={"delete": {"maxAffectedRows": 100}})})
    assert explain(decide(DELETE, s)) == (
        "allowed: sql:delete (destructive) on pg-sol. Environment test allows delete "
        "(environment); subject to maxAffectedRows 100, requireWhere true."
    )


@pytest.mark.parametrize(
    ("value", "text"),
    [(True, "true"), (False, "false"), (1000, "1000"), ("x", "x"), (("a", "b"), "[a, b]")],
)
def test_format_value(value: ConstraintValue, text: str) -> None:
    assert format_value(value) == text
