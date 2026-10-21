"""The constraints the `sql` connector checks (§7.6): `requireWhere` and `maxAffectedRows`."""

from __future__ import annotations

from modgudr.spi import Action, ConstraintValue, Measured

from .classify import RequireWhere

__all__ = ["MaxAffectedRows", "RequireWhere"]


class MaxAffectedRows:
    """`maxAffectedRows` (§7.6): checked after the statement ran and before it commits.

    A driver that cannot say how many rows it changed fails the constraint: the check fails
    closed (M14).
    """

    def before(self, action: Action, value: ConstraintValue) -> str | None:
        return None

    def after(self, action: Action, value: ConstraintValue, measured: Measured) -> str | None:
        if isinstance(value, bool) or not isinstance(value, int):
            return f"the limit {value!r} is not a number"
        affected = measured.get("affectedRows")
        if affected is None:
            return "the driver did not report how many rows the statement changed"
        if affected > value:
            return f"{affected} rows, limit {value}"
        return None
