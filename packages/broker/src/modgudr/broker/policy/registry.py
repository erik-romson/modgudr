"""The interface through which a connector type registers with the policy layer.

The loader and lint take a `PolicyRegistry`. Tests register fake connectors with `StaticRegistry`;
`modgudr.broker.registry` implements the same protocol with entry-point discovery.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol

from pydantic import BaseModel


def action_matches(pattern: str, action: str) -> bool:
    """Whether a rule pattern (an action name, or a wildcard such as `delete/*`) names an action."""
    return fnmatch.fnmatchcase(action, pattern)


@dataclass(frozen=True)
class ConnectorPolicy:
    """What the policy layer needs to know about one connector type.

    `config_model` validates the target keys the core does not know (`extra="forbid"` is required).
    `actions` is the action catalogue (names without the connector prefix, for example `select`,
    `ddl.drop`, `delete/pods`). `constraints` maps each supported constraint name to the action
    patterns it supports.
    """

    type: str
    config_model: type[BaseModel]
    actions: frozenset[str] = frozenset()
    constraints: Mapping[str, frozenset[str]] = field(default_factory=dict[str, frozenset[str]])

    def __post_init__(self) -> None:
        if self.config_model.model_config.get("extra") != "forbid":
            raise ValueError(f"config model of connector {self.type!r} must set extra='forbid'")

    def has_action(self, pattern: str) -> bool:
        return any(action_matches(pattern, action) for action in self.actions)

    def supports(self, constraint: str, action: str) -> bool:
        patterns = self.constraints.get(constraint)
        return patterns is not None and any(action_matches(p, action) for p in patterns)


class PolicyRegistry(Protocol):
    def connector(self, type_name: str) -> ConnectorPolicy | None: ...

    def connectors(self) -> Sequence[ConnectorPolicy]: ...


class StaticRegistry:
    """A registry filled by hand: tests, and anything that registers programmatically."""

    def __init__(self, *connectors: ConnectorPolicy) -> None:
        self._connectors: dict[str, ConnectorPolicy] = {}
        for connector in connectors:
            self.register(connector)

    def register(self, connector: ConnectorPolicy) -> None:
        if connector.type in self._connectors:
            raise ValueError(f"connector type {connector.type!r} is already registered")
        self._connectors[connector.type] = connector

    def connector(self, type_name: str) -> ConnectorPolicy | None:
        return self._connectors.get(type_name)

    def connectors(self) -> Sequence[ConnectorPolicy]:
        return tuple(self._connectors.values())
