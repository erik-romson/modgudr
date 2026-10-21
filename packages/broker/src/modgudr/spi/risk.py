"""Risk classes (§7.2): an ordered enum, with `secret` and `unknown` above every ceiling."""

from __future__ import annotations

from enum import Enum


class Risk(Enum):
    """The risk class of an action. The order is `read < write < destructive < admin`.

    `secret` and `unknown` rank above every ceiling: no ordinary rule can allow them (M11). A
    statement's class is the maximum over everything in it, so `max(risks)` gives it.
    """

    READ = "read"
    WRITE = "write"
    DESTRUCTIVE = "destructive"
    ADMIN = "admin"
    SECRET = "secret"
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        return _ORDER.index(self)

    @property
    def is_ceiling(self) -> bool:
        """Whether an environment may use this class as its ceiling."""
        return self in CEILINGS

    def __lt__(self, other: Risk) -> bool:
        return self.rank < other.rank

    def __le__(self, other: Risk) -> bool:
        return self.rank <= other.rank

    def __gt__(self, other: Risk) -> bool:
        return self.rank > other.rank

    def __ge__(self, other: Risk) -> bool:
        return self.rank >= other.rank


_ORDER: tuple[Risk, ...] = tuple(Risk)

#: The classes an environment ceiling may name, lowest first.
CEILINGS: tuple[Risk, ...] = (Risk.READ, Risk.WRITE, Risk.DESTRUCTIVE, Risk.ADMIN)

#: Every class name, for telling a class pattern from an action pattern.
RISK_NAMES: frozenset[str] = frozenset(r.value for r in Risk)
