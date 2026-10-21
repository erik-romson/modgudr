"""The rule engine (§7.5, M11): one decision for one classified action.

The order is fixed: `unknown`, `secret`, plugin invariants, the global guard and the environment
ceiling; then the target, environment and plugin-default layers, each with its `all:` block. Inside
one layer deny beats allow, the first layer that mentions the action decides, and an action no
layer allows is denied. An allowed action is then held to its merged constraints.

Throttling is the broker's job (M6 step 5), not the engine's. The broker calls `decide` twice:
with the declared environment (phase 1) and with the effective one once the secret's pins are
known (phase 2).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Literal, Protocol

from ...spi import (
    Action,
    ConstraintCheck,
    Decision,
    Layer,
    Measured,
    Risk,
    Rule,
    RuleSet,
)
from ..policy.load import Policy
from ..policy.model import EnvironmentConfig, RuleBlock, TargetConfig
from .constraints import LayerRules, Unmet, merge, unmet

#: The rule block that applies to every connector type.
ALL = "all"


@dataclass(frozen=True)
class Scope:
    """One target in one environment: everything `decide` needs besides the action."""

    target: str
    #: The target's connector type; selects the rule blocks.
    type: str
    env: str
    ceiling: Risk
    guard: tuple[Rule, ...] = ()
    invariants: tuple[Rule, ...] = ()
    #: Rule sets by connector type and `all`.
    target_rules: Mapping[str, RuleSet] = field(default_factory=dict[str, RuleSet])
    env_rules: Mapping[str, RuleSet] = field(default_factory=dict[str, RuleSet])
    defaults: RuleSet = field(default_factory=RuleSet)
    checks: Mapping[str, ConstraintCheck] = field(default_factory=dict[str, ConstraintCheck])

    def layers(self) -> tuple[LayerRules, ...]:
        """The overridable layers, most specific first (§7.3 layers 4 to 6)."""
        return (
            LayerRules(Layer.TARGET, f"target {self.target}", self._blocks(self.target_rules)),
            LayerRules(Layer.ENVIRONMENT, f"environment {self.env}", self._blocks(self.env_rules)),
            LayerRules(Layer.PLUGIN_DEFAULT, f"the {self.type} plugin defaults", (self.defaults,)),
        )

    def _blocks(self, rules: Mapping[str, RuleSet]) -> tuple[RuleSet, ...]:
        return tuple(rules[key] for key in (self.type, ALL) if key in rules)


def decide(action: Action, scope: Scope) -> Decision:
    """Decide one classified action (§7.5)."""

    def deny(layer: Layer, rule: str, message: str) -> Decision:
        return Decision(False, action, scope.target, scope.env, layer, rule, message)

    if action.risk is Risk.UNKNOWN:
        detail = action.detail.rstrip(". ")
        return deny(
            Layer.INVARIANT,
            Risk.UNKNOWN.value,
            f"Cannot classify this call: {detail}" if detail else "Cannot classify this call",
        )
    if action.risk is Risk.SECRET:
        return deny(
            Layer.INVARIANT,
            Risk.SECRET.value,
            "This call would reveal a secret, which no rule can allow",
        )
    if action.invariant_hits:
        hit = action.invariant_hits[0]
        why = f": {action.detail.rstrip('. ')}" if action.detail else ""
        return deny(Layer.INVARIANT, hit, f"The {scope.type} plugin never allows {hit}{why}")
    for rule in scope.invariants:
        if rule.matches(action):
            why = f": {rule.reason}" if rule.reason else ""
            return deny(
                Layer.INVARIANT,
                rule.pattern,
                f"The {scope.type} plugin never allows {action.name}{why}",
            )
    for rule in scope.guard:
        if rule.matches(action):
            return deny(Layer.GUARD, rule.pattern, f"The global guard forbids {rule.pattern}")
    if action.risk > scope.ceiling:
        return deny(Layer.CEILING, scope.ceiling.value, _ceiling_message(scope))

    layers = scope.layers()
    for layer in layers:
        denied = _first_match(layer, "deny", action)
        if denied is not None:
            return deny(layer.layer, denied.pattern, _says(layer, "deny", denied.pattern))
        allowed = _first_match(layer, "allow", action)
        if allowed is not None:
            constraints = merge(action, layers)
            decision = Decision(
                True,
                action,
                scope.target,
                scope.env,
                layer.layer,
                allowed.pattern,
                _says(layer, "allow", allowed.pattern),
                constraints,
            )
            failed = unmet(action, constraints, scope.checks)
            return decision if failed is None else _refuse(decision, failed)
    return deny(
        Layer.NO_RULE,
        "none",
        f"No rule allows this: target {scope.target}, environment {scope.env} and the "
        f"{scope.type} plugin defaults do not allow {action.name}",
    )


def after_run(
    decision: Decision, checks: Mapping[str, ConstraintCheck], measured: Measured
) -> Decision:
    """Hold an allowed call to its constraints once it has run and before it commits.

    Returns the decision unchanged when every constraint is met, else a denial at layer
    `constraint` (the caller rolls back).
    """
    if not decision.allowed:
        return decision
    failed = unmet(decision.action, decision.constraints, checks, measured)
    return decision if failed is None else _refuse(decision, failed)


def _refuse(decision: Decision, failed: Unmet) -> Decision:
    constraint = failed.constraint
    return replace(
        decision,
        allowed=False,
        layer=Layer.CONSTRAINT,
        rule=constraint.name,
        message=f"Constraint {constraint.name} from {constraint.source} is not met: "
        f"{failed.reason}",
    )


def _first_match(layer: LayerRules, kind: Literal["allow", "deny"], action: Action) -> Rule | None:
    for block in layer.blocks:
        for rule in block.allow if kind == "allow" else block.deny:
            if rule.matches(action):
                return rule
    return None


def _says(layer: LayerRules, verb: Literal["allow", "deny"], pattern: str) -> str:
    """`Target pg-sol denies destructive`, `The sql plugin defaults allow read`."""
    source = layer.source[:1].upper() + layer.source[1:]
    if layer.layer is not Layer.PLUGIN_DEFAULT:
        verb_form = "allows" if verb == "allow" else "denies"
    else:
        verb_form = verb
    return f"{source} {verb_form} {pattern}"


def _ceiling_message(scope: Scope) -> str:
    if scope.ceiling is Risk.READ:
        return f"Environment {scope.env} allows read only"
    return f"Environment {scope.env} allows up to {scope.ceiling.value}"


class RuleProvider(Protocol):
    """The part of a connector the engine needs. Every `modgudr.spi.Connector` provides it."""

    @property
    def type(self) -> str: ...

    def invariants(self) -> Sequence[Rule]: ...

    def default_rules(self) -> RuleSet: ...

    def constraint_checks(self) -> Mapping[str, ConstraintCheck]: ...


def rule_set(block: RuleBlock) -> RuleSet:
    """A policy rule block as the engine's rule set."""
    return RuleSet(
        allow=tuple(Rule(p) for p in block.allow),
        deny=tuple(Rule(p) for p in block.deny),
        constraints={pattern: dict(values) for pattern, values in block.constraints.items()},
    )


def build_scope(
    *,
    target: str,
    env: str,
    environment: EnvironmentConfig,
    target_rules: Mapping[str, RuleBlock],
    guard: Sequence[str],
    plugin: RuleProvider,
) -> Scope:
    """A scope from policy pieces: one target's rule blocks in one environment."""
    return Scope(
        target=target,
        type=plugin.type,
        env=env,
        ceiling=Risk(environment.ceiling),
        guard=tuple(Rule(p) for p in guard),
        invariants=tuple(plugin.invariants()),
        target_rules={key: rule_set(block) for key, block in target_rules.items()},
        env_rules={key: rule_set(block) for key, block in environment.rules.items()},
        defaults=plugin.default_rules(),
        checks=dict(plugin.constraint_checks()),
    )


def scope_for(policy: Policy, target: TargetConfig, env: str, plugin: RuleProvider) -> Scope:
    """The scope of a policy target in `env` (canonical): its declared or its effective one."""
    return build_scope(
        target=target.name,
        env=env,
        environment=policy.company.environments[env],
        target_rules=target.rules,
        guard=policy.company.guard.forbid,
        plugin=plugin,
    )
