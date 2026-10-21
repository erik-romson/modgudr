"""Plugin discovery (§9.3, M24): the four entry-point groups, plus programmatic registration.

The built-in connectors and stores register through the same entry points as third-party plugins.
`PluginRegistry` implements the policy layer's `PolicyRegistry`, so the loader and lint see every
registered connector type. Tests register test-only plugins (the echo connector) by hand.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import cast

from ..spi import Connector, CredentialProvider, SqlDialect, StoreFactory
from .policy.registry import ConnectorPolicy

CONNECTORS = "modgudr.connectors"
SQL_DIALECTS = "modgudr.sql_dialects"
SECRET_STORES = "modgudr.secret_stores"
CREDENTIAL_PROVIDERS = "modgudr.credential_providers"
GROUPS = (CONNECTORS, SQL_DIALECTS, SECRET_STORES, CREDENTIAL_PROVIDERS)


class PluginError(Exception):
    """A plugin cannot be loaded or registered: the broker refuses to start."""


@dataclass(frozen=True)
class PluginOrigin:
    """Where a plugin came from, for the `broker.start` record (M9)."""

    group: str
    name: str
    #: The distribution that declares the entry point; None when registered programmatically.
    distribution: str | None = None
    version: str | None = None
    #: SHA-256 of the distribution's `RECORD` file, when it has one.
    record_sha256: str | None = None

    def to_json(self) -> dict[str, object]:
        return {
            "group": self.group,
            "name": self.name,
            "distribution": self.distribution,
            "version": self.version,
            "recordSha256": self.record_sha256,
        }


def connector_policy(connector: Connector) -> ConnectorPolicy:
    """What the policy layer needs from a connector: its config model, actions and constraints."""
    actions = tuple(connector.actions())
    constraints: dict[str, set[str]] = {}
    for spec in actions:
        for constraint in spec.constraints:
            constraints.setdefault(constraint, set()).add(spec.name)
    return ConnectorPolicy(
        type=connector.type,
        config_model=connector.config_model,
        actions=frozenset(spec.name for spec in actions),
        constraints={name: frozenset(names) for name, names in constraints.items()},
    )


EntryPoints = Callable[[str], Iterable[importlib.metadata.EntryPoint]]


def _entry_points(group: str) -> Iterable[importlib.metadata.EntryPoint]:
    return importlib.metadata.entry_points(group=group)


class PluginRegistry:
    """Every plugin the broker knows, by group and name."""

    def __init__(self) -> None:
        self._connectors: dict[str, Connector] = {}
        self._policies: dict[str, ConnectorPolicy] = {}
        self._dialects: dict[str, SqlDialect] = {}
        self._stores: dict[str, StoreFactory] = {}
        self._providers: dict[str, CredentialProvider] = {}
        self._origins: list[PluginOrigin] = []

    @classmethod
    def discover(cls, entry_points: EntryPoints = _entry_points) -> PluginRegistry:
        """Load every plugin from the four entry-point groups. A plugin that fails to load
        raises `PluginError`: nothing is skipped."""
        registry = cls()
        for group in GROUPS:
            for ep in sorted(entry_points(group), key=lambda e: e.name):
                try:
                    loaded: object = ep.load()
                except Exception as exc:
                    raise PluginError(
                        f"entry point {group}:{ep.name} ({ep.value}) cannot be loaded: {exc}"
                    ) from exc
                registry._register_loaded(group, ep.name, loaded, _origin(group, ep))
        return registry

    def _register_loaded(self, group: str, name: str, loaded: object, origin: PluginOrigin) -> None:
        if not callable(loaded):
            raise PluginError(f"entry point {group}:{name} is not callable")
        if group == SECRET_STORES:
            self.register_store(name, _as_store_factory(loaded), origin=origin)
            return
        try:
            instance: object = loaded()
        except Exception as exc:
            raise PluginError(f"plugin {group}:{name} cannot be created: {exc}") from exc
        if group == CONNECTORS:
            connector = _as_connector(instance)
            if connector.type != name:
                raise PluginError(
                    f"entry point {group}:{name} provides connector type {connector.type!r}"
                )
            self.register_connector(connector, origin=origin)
        elif group == SQL_DIALECTS:
            self.register_dialect(_as_dialect(instance), origin=origin)
        else:
            self.register_provider(_as_provider(instance), origin=origin)

    # --- programmatic registration ---------------------------------------------------------

    def register_connector(
        self, connector: Connector, *, origin: PluginOrigin | None = None
    ) -> None:
        name = connector.type
        if name in self._connectors:
            raise PluginError(f"connector type {name!r} is already registered")
        try:
            policy = connector_policy(connector)
        except ValueError as exc:
            raise PluginError(str(exc)) from exc
        self._connectors[name] = connector
        self._policies[name] = policy
        self._origins.append(origin or PluginOrigin(CONNECTORS, name))

    def register_dialect(self, dialect: SqlDialect, *, origin: PluginOrigin | None = None) -> None:
        if dialect.name in self._dialects:
            raise PluginError(f"SQL dialect {dialect.name!r} is already registered")
        self._dialects[dialect.name] = dialect
        self._origins.append(origin or PluginOrigin(SQL_DIALECTS, dialect.name))

    def register_store(
        self, scheme: str, factory: StoreFactory, *, origin: PluginOrigin | None = None
    ) -> None:
        if scheme in self._stores:
            raise PluginError(f"secret store {scheme!r} is already registered")
        self._stores[scheme] = factory
        self._origins.append(origin or PluginOrigin(SECRET_STORES, scheme))

    def register_provider(
        self, provider: CredentialProvider, *, origin: PluginOrigin | None = None
    ) -> None:
        if provider.name in self._providers:
            raise PluginError(f"credential provider {provider.name!r} is already registered")
        self._providers[provider.name] = provider
        self._origins.append(origin or PluginOrigin(CREDENTIAL_PROVIDERS, provider.name))

    # --- the policy layer's interface -------------------------------------------------------

    def connector(self, type_name: str) -> ConnectorPolicy | None:
        return self._policies.get(type_name)

    def connectors(self) -> Sequence[ConnectorPolicy]:
        return tuple(self._policies.values())

    # --- lookups ----------------------------------------------------------------------------

    def connector_plugin(self, type_name: str) -> Connector | None:
        return self._connectors.get(type_name)

    def dialect(self, name: str) -> SqlDialect | None:
        return self._dialects.get(name)

    def dialects(self) -> Sequence[SqlDialect]:
        return tuple(self._dialects.values())

    def store_factory(self, scheme: str) -> StoreFactory | None:
        return self._stores.get(scheme)

    def store_schemes(self) -> tuple[str, ...]:
        return tuple(sorted(self._stores))

    def provider(self, name: str) -> CredentialProvider | None:
        return self._providers.get(name)

    def origins(self) -> tuple[PluginOrigin, ...]:
        return tuple(sorted(self._origins, key=lambda o: (o.group, o.name)))


def _origin(group: str, ep: importlib.metadata.EntryPoint) -> PluginOrigin:
    dist = ep.dist
    if dist is None:
        return PluginOrigin(group, ep.name)
    record = dist.read_text("RECORD")
    digest = hashlib.sha256(record.encode("utf-8")).hexdigest() if record is not None else None
    return PluginOrigin(group, ep.name, dist.metadata["Name"], dist.version, digest)


def _as_store_factory(loaded: object) -> StoreFactory:
    # A class or function taking a `StoreContext`; called once at broker start.
    return cast("StoreFactory", loaded)


def _as_connector(instance: object) -> Connector:
    for attr in ("type", "config_model", "operations", "classify", "open"):
        if not hasattr(instance, attr):
            raise PluginError(f"{instance!r} is not a connector (no {attr!r})")
    return cast("Connector", instance)


def _as_dialect(instance: object) -> SqlDialect:
    for attr in ("name", "sqlglot_dialect", "default_port", "bind_style"):
        if not hasattr(instance, attr):
            raise PluginError(f"{instance!r} is not a SQL dialect (no {attr!r})")
    return cast("SqlDialect", instance)


def _as_provider(instance: object) -> CredentialProvider:
    for attr in ("name", "mint", "lock"):
        if not hasattr(instance, attr):
            raise PluginError(f"{instance!r} is not a credential provider (no {attr!r})")
    return cast("CredentialProvider", instance)
