"""Explanations (§7.9): one sentence naming action, class, layer and rule, that an agent acts on.

"denied: sql:delete (destructive) on prod-ro. Environment prod allows read only (ceiling)."
"""

from __future__ import annotations

from collections.abc import Mapping

from ...spi import Constraint, ConstraintValue, Decision


def explain(decision: Decision) -> str:
    action = decision.action
    verdict = "allowed" if decision.allowed else "denied"
    text = (
        f"{verdict}: {action.name} ({action.risk.value}) on {decision.target}. "
        f"{decision.message} ({decision.layer})"
    )
    if decision.allowed and decision.constraints:
        text += f"; subject to {format_constraints(decision.constraints)}"
    return text + "."


def format_constraints(constraints: Mapping[str, Constraint]) -> str:
    """`requireWhere true, maxAffectedRows 1000`."""
    return ", ".join(f"{c.name} {format_value(c.value)}" for c in constraints.values())


def format_value(value: ConstraintValue) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, tuple):
        return "[" + ", ".join(value) + "]"
    return str(value)
