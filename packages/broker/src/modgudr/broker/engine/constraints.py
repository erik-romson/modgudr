"""Constraints (§7.5, §7.6): merged per key, the most specific layer winning.

Evaluation goes through each connector's `ConstraintCheck`s: `before` runs in the engine on the
classified action, `after` once the call has measured what it did (`maxAffectedRows`). A constraint
without a check is never met: the call is refused, not run unchecked.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from ...spi import (
    RISK_NAMES,
    Action,
    Constraint,
    ConstraintCheck,
    Layer,
    Measured,
    RuleSet,
    pattern_matches,
)


@dataclass(frozen=True)
class LayerRules:
    """One overridable rule layer as `decide` walks it."""

    layer: Layer
    #: Who wrote it, in words: `target pg-sol`, `environment test`, `the sql plugin defaults`.
    source: str
    #: The connector's own block first, then the `all:` block.
    blocks: tuple[RuleSet, ...]


@dataclass(frozen=True)
class Unmet:
    """A constraint that is not met, and why."""

    constraint: Constraint
    reason: str


def merge(action: Action, layers: Sequence[LayerRules]) -> dict[str, Constraint]:
    """The constraints that apply to `action`, by name.

    `layers` run from the most specific (target) to the least (plugin defaults). Per key, the first
    layer that sets it wins. Inside a layer the connector's block beats `all:`, and inside a block
    the most specific pattern beats a wider one.
    """
    merged: dict[str, Constraint] = {}
    for layer in layers:
        for block in layer.blocks:
            for pattern in _matching_patterns(block, action):
                for name, value in block.constraints[pattern].items():
                    if name not in merged:
                        merged[name] = Constraint(name, value, layer.layer, layer.source, pattern)
    return merged


def unmet(
    action: Action,
    constraints: Mapping[str, Constraint],
    checks: Mapping[str, ConstraintCheck],
    measured: Measured | None = None,
) -> Unmet | None:
    """The first constraint that is not met, or None.

    Without `measured` this is the check before execution; with it, the check after the run.
    """
    for constraint in constraints.values():
        check = checks.get(constraint.name)
        if check is None:
            return Unmet(
                constraint, f"the {action.type} connector has no check for {constraint.name}"
            )
        if measured is None:
            reason = check.before(action, constraint.value)
        else:
            reason = check.after(action, constraint.value, measured)
        if reason is not None:
            return Unmet(constraint, reason)
    return None


def _matching_patterns(block: RuleSet, action: Action) -> list[str]:
    matching = [p for p in block.constraints if pattern_matches(p, action)]
    # Stable: among equally specific patterns, the one written first wins.
    return sorted(matching, key=_specificity, reverse=True)


def _specificity(pattern: str) -> tuple[int, int]:
    """An exact action beats a wildcard (the longer literal part first), which beats a class."""
    if pattern in RISK_NAMES:
        return (0, 0)
    if "*" in pattern:
        return (1, len(pattern.replace("*", "")))
    return (2, len(pattern))
