"""Plugin discovery (§9.3) and programmatic registration."""

from __future__ import annotations

import importlib.metadata
from collections.abc import Iterable
from pathlib import Path

import pytest

from modgudr.broker.policy.load import load_policy
from modgudr.broker.registry import (
    CONNECTORS,
    SECRET_STORES,
    PluginError,
    PluginRegistry,
    connector_policy,
)
from modgudr.spi import ActionSpec, Risk
from modgudr.store_bws import BwsStore
from modgudr.store_file import FileStore
from tests.support.brokerfx import COMPANY, TARGETS, write_file
from tests.support.echo_connector import EchoConnector


def test_discovery_finds_the_stores_with_their_distributions() -> None:
    registry = PluginRegistry.discover()
    assert registry.store_factory("file") is FileStore
    assert registry.store_factory("bws") is BwsStore
    origins = [o for o in registry.origins() if o.group == SECRET_STORES]
    assert [(o.name, o.distribution, o.version) for o in origins] == [
        ("bws", "modgudr-store-bws", "0.1.0"),
        ("file", "modgudr-store-file", "0.1.0"),
    ]
    assert all(o.record_sha256 is not None and len(o.record_sha256) == 64 for o in origins)


def test_programmatic_registration_and_duplicates() -> None:
    registry = PluginRegistry()
    registry.register_connector(EchoConnector())
    assert registry.connector_plugin("echo") is not None
    policy = registry.connector("echo")
    assert policy is not None and "put" in policy.actions
    assert [o.distribution for o in registry.origins()] == [None]
    with pytest.raises(PluginError, match="already registered"):
        registry.register_connector(EchoConnector())


def test_connector_policy_collects_constraints() -> None:
    class WithConstraints(EchoConnector):
        def actions(self) -> tuple[ActionSpec, ...]:
            return (
                ActionSpec("delete", Risk.DESTRUCTIVE, frozenset({"requireWhere"})),
                ActionSpec("update", Risk.WRITE, frozenset({"requireWhere", "maxAffectedRows"})),
            )

    policy = connector_policy(WithConstraints())
    assert policy.constraints == {
        "requireWhere": frozenset({"delete", "update"}),
        "maxAffectedRows": frozenset({"update"}),
    }
    assert policy.supports("requireWhere", "delete")


def _points(*items: tuple[str, str, str]) -> object:
    eps = [importlib.metadata.EntryPoint(name, value, group) for name, value, group in items]

    def entry_points(group: str) -> Iterable[importlib.metadata.EntryPoint]:
        return [ep for ep in eps if ep.group == group]

    return entry_points


def test_a_plugin_that_fails_to_load_refuses() -> None:
    entry_points = _points(("bad", "modgudr_nosuch_module:Thing", CONNECTORS))
    with pytest.raises(PluginError, match=r"modgudr\.connectors:bad .* cannot be loaded"):
        PluginRegistry.discover(entry_points)  # type: ignore[arg-type]


def test_a_connector_under_the_wrong_name_refuses() -> None:
    entry_points = _points(("other", "tests.support.echo_connector:EchoConnector", CONNECTORS))
    with pytest.raises(PluginError, match="provides connector type 'echo'"):
        PluginRegistry.discover(entry_points)  # type: ignore[arg-type]


def test_a_connector_entry_point_registers(shortdir: Path) -> None:
    entry_points = _points(("echo", "tests.support.echo_connector:EchoConnector", CONNECTORS))
    registry = PluginRegistry.discover(entry_points)  # type: ignore[arg-type]
    assert registry.connector_plugin("echo") is not None
    write_file(shortdir / "00-company.yaml", COMPANY)
    write_file(shortdir / "50-targets.yaml", TARGETS)
    policy = load_policy(shortdir, registry, dev=True)
    assert list(policy.targets) == ["echo-test", "echo-prod", "echo-fast"]
