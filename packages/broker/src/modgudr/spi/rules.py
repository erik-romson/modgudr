"""Actions, rules, constraints and decisions (§7.1 to §7.6, M11)."""

from __future__ import annotations

import fnmatch
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from .risk import RISK_NAMES, Risk

#: A fact the classifier records about a call: tables, functions, namespace, names, ….
Fact = str | int | bool | None | tuple[str, ...]

#: A constraint value as the policy writes it: `requireWhere: true`, `maxAffectedRows: 1000`,
#: `namespaces: [app-test]`.
ConstraintValue = bool | int | str | tuple[str, ...]

#: What a call measured while it ran, for the constraints checked after the run
#: (`{"affectedRows": 4200}`; `None` when the driver could not say).
Measured = Mapping[str, int | None]


@dataclass(frozen=True)
class Action:
    """A classified call: a name, a risk class and the facts the rules check (§7.1).

    `name` carries the connector type as prefix (`sql:delete`, `kubectl:delete/pods`).
    `invariant_hits` are invariants the classifier found the call breaks without a name of its own,
    such as kubectl's `--as` flag; any hit refuses the call at layer `plugin-invariant`.
    `detail` says why a call is `unknown` ("resource 'x' is not in the catalogue").
    """

    name: str
    risk: Risk
    facts: Mapping[str, Fact] = field(default_factory=dict[str, Fact])
    invariant_hits: tuple[str, ...] = ()
    detail: str = ""

    @property
    def type(self) -> str:
        """The connector type: the part of the name before the colon."""
        return self.name.partition(":")[0]

    @property
    def local_name(self) -> str:
        """The name without the connector prefix: `delete`, `delete/pods`."""
        type_name, sep, rest = self.name.partition(":")
        return rest if sep else type_name

    @classmethod
    def unknown(cls, type_name: str, detail: str) -> Action:
        """What a classifier returns when it cannot classify: it never raises."""
        return cls(f"{type_name}:unknown", Risk.UNKNOWN, detail=detail)


@dataclass(frozen=True)
class ActionSpec:
    """One entry of a connector's action catalogue (`modgudr actions <type>`)."""

    #: The name without the connector prefix: `select`, `ddl.drop`, `delete/pods`.
    name: str
    risk: Risk
    #: The constraints this action supports (`requireWhere`, `maxAffectedRows`, …).
    constraints: frozenset[str] = frozenset()
    summary: str = ""


def pattern_matches(pattern: str, action: Action) -> bool:
    """Whether a rule pattern names an action (§7.1).

    A pattern is a risk class (`write`: exactly that class), a pattern with a connector prefix
    (`kubectl:delete/*`, `sql:user.*`: matched against the full name), or a pattern without one
    (`delete/*`, `ddl.*`, `truncate`: matched against the name without the prefix, inside the
    connector's own rule block or an `all:` block). `*` matches any run of characters.
    """
    if pattern in RISK_NAMES:
        return action.risk.value == pattern
    if ":" in pattern:
        return fnmatch.fnmatchcase(action.name, pattern)
    return fnmatch.fnmatchcase(action.local_name, pattern)


@dataclass(frozen=True)
class Rule:
    """A rule names an action, a wildcard or a risk class. `reason` explains an invariant."""

    pattern: str
    reason: str = ""

    def matches(self, action: Action) -> bool:
        return pattern_matches(self.pattern, action)


@dataclass(frozen=True)
class RuleSet:
    """`allow`, `deny` and `constraints` of one layer for one connector type (or `all`).

    `constraints` maps an action pattern to the constraint values it sets.
    """

    allow: tuple[Rule, ...] = ()
    deny: tuple[Rule, ...] = ()
    constraints: Mapping[str, Mapping[str, ConstraintValue]] = field(
        default_factory=dict[str, Mapping[str, ConstraintValue]]
    )


class Layer(StrEnum):
    """Where a decision was made (§7.3), as the audit records it."""

    INVARIANT = "plugin-invariant"
    GUARD = "guard"
    CEILING = "ceiling"
    TARGET = "target"
    ENVIRONMENT = "environment"
    PLUGIN_DEFAULT = "plugin-default"
    CONSTRAINT = "constraint"
    #: No layer allowed the action: the allowlist denies it.
    NO_RULE = "no-rule"


@dataclass(frozen=True)
class Constraint:
    """One merged constraint, with the layer it came from (`policy show`, explanations)."""

    name: str
    value: ConstraintValue
    layer: Layer
    #: Who set it, in words: `environment test`, `target pg-sol`, `the sql plugin defaults`.
    source: str
    #: The action pattern it was declared under.
    pattern: str


class ConstraintCheck(Protocol):
    """Evaluates one named constraint (§7.6, §9.2). Connectors provide one per constraint.

    Each method returns `None` when the constraint is met and otherwise the reason it is not, in
    words an agent acts on ("the statement has no WHERE clause", "4200 rows, limit 1000").
    """

    def before(self, action: Action, value: ConstraintValue) -> str | None:
        """Checked by the engine on the classified action, before anything runs."""
        ...

    def after(self, action: Action, value: ConstraintValue, measured: Measured) -> str | None:
        """Checked once the call has run and before it commits (`maxAffectedRows`)."""
        ...


@dataclass(frozen=True)
class Decision:
    """The outcome of `decide`: allowed or not, and the layer and rule that decided (§7.9)."""

    allowed: bool
    action: Action
    target: str
    #: The environment the decision used: the declared one (phase 1) or the effective one.
    env: str
    layer: Layer
    #: The deciding rule: a pattern, the ceiling class, a constraint name, `unknown`, `secret`.
    rule: str
    #: The reason as a clause of the explanation ("Environment prod allows read only").
    message: str
    #: The merged constraints of an allowed action, by name.
    constraints: Mapping[str, Constraint] = field(default_factory=dict[str, Constraint])

    @property
    def verdict(self) -> str:
        return "allow" if self.allowed else "deny"
