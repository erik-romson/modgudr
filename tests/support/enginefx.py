"""Helpers for the engine tests: constraint checks and plugins as connectors will provide them.

The checks read the facts a classifier records (`where`, `names`, `all`, `namespace`, …) and the
row count a write measures. The real ones arrive with the sql and kubectl connectors.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from modgudr.spi import Action, ConstraintCheck, ConstraintValue, Measured, Rule, RuleSet


class RequireWhere:
    """`requireWhere`: the `where` fact is `column`, `constant` or `none`."""

    def before(self, action: Action, value: ConstraintValue) -> str | None:
        if value is not True:
            return None
        where = action.facts.get("where")
        if where == "column":
            return None
        if where == "constant":
            return "the WHERE clause is constant"
        return "the statement has no WHERE clause"

    def after(self, action: Action, value: ConstraintValue, measured: Measured) -> str | None:
        return None


class MaxAffectedRows:
    """`maxAffectedRows`: checked after the run against the measured `affectedRows`."""

    def before(self, action: Action, value: ConstraintValue) -> str | None:
        return None

    def after(self, action: Action, value: ConstraintValue, measured: Measured) -> str | None:
        if isinstance(value, bool) or not isinstance(value, int):
            return f"maxAffectedRows needs a number, not {value!r}"
        count = measured.get("affectedRows")
        if count is None:
            return "row count unavailable"
        if count > value:
            return f"{count} rows, limit {value}"
        return None


class RequireName:
    """`requireName`: refuses `--all`, selector-only and nameless forms."""

    def before(self, action: Action, value: ConstraintValue) -> str | None:
        if value is not True:
            return None
        if action.facts.get("all"):
            return "--all is refused; name the objects"
        if not action.facts.get("names"):
            return "name the objects to act on"
        return None

    def after(self, action: Action, value: ConstraintValue, measured: Measured) -> str | None:
        return None


class Namespaces:
    """`namespaces`: the resolved namespace must be listed; `-A` never matches."""

    def before(self, action: Action, value: ConstraintValue) -> str | None:
        allowed = value if isinstance(value, tuple) else ()
        if action.facts.get("allNamespaces"):
            return "-A never matches namespaces"
        if action.facts.get("clusterScoped"):
            return "a cluster-scoped resource is denied under namespaces"
        namespace = action.facts.get("namespace")
        if namespace not in allowed:
            return f"namespace {namespace} is not one of {', '.join(allowed)}"
        return None

    def after(self, action: Action, value: ConstraintValue, measured: Measured) -> str | None:
        return None


SQL_CHECKS: Mapping[str, ConstraintCheck] = {
    "requireWhere": RequireWhere(),
    "maxAffectedRows": MaxAffectedRows(),
}
KUBECTL_CHECKS: Mapping[str, ConstraintCheck] = {
    "requireName": RequireName(),
    "namespaces": Namespaces(),
}


@dataclass(frozen=True)
class FakePlugin:
    """The engine's view of a connector: invariants, defaults and constraint checks."""

    type: str
    invariant_rules: tuple[Rule, ...] = ()
    defaults: RuleSet = field(default_factory=RuleSet)
    checks: Mapping[str, ConstraintCheck] = field(default_factory=dict[str, ConstraintCheck])

    def invariants(self) -> Sequence[Rule]:
        return self.invariant_rules

    def default_rules(self) -> RuleSet:
        return self.defaults

    def constraint_checks(self) -> Mapping[str, ConstraintCheck]:
        return self.checks


SQL_INVARIANTS = (
    Rule("session", "session state belongs to the broker's pooled connection"),
    Rule("transaction", "the broker owns the transaction"),
    Rule("use", "the target fixes database, schema, role and warehouse"),
    Rule("multi", "one statement per call"),
)


def sql_plugin() -> FakePlugin:
    """The sql defaults of §7.5: reads allowed, `requireWhere` on delete."""
    return FakePlugin(
        "sql",
        SQL_INVARIANTS,
        RuleSet(allow=(Rule("read"),), constraints={"delete": {"requireWhere": True}}),
        SQL_CHECKS,
    )


def kubectl_plugin() -> FakePlugin:
    return FakePlugin("kubectl", (), RuleSet(allow=(Rule("read"),)), KUBECTL_CHECKS)
