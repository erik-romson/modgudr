"""The rule matrix (tests/data/rule-matrix.yaml) through the real engine.

Every example of pre-plan §7.7, then the layer-semantics rows of §13. A wrong layer order, merge
rule or explanation fails one named row.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest

from modgudr.broker.engine.decide import Scope, after_run, build_scope, decide, rule_set
from modgudr.broker.engine.explain import explain
from modgudr.broker.policy.model import EnvironmentConfig, RuleBlock
from modgudr.broker.policy.yaml_strict import load_strict
from modgudr.spi import Action, ConstraintCheck, Fact, Risk, Rule
from tests.support.enginefx import KUBECTL_CHECKS, SQL_CHECKS, FakePlugin

MATRIX_FILE = Path(__file__).resolve().parents[2] / "data" / "rule-matrix.yaml"

CHECKS: Mapping[str, Mapping[str, ConstraintCheck]] = {
    "sql": SQL_CHECKS,
    "kubectl": KUBECTL_CHECKS,
}

#: The §13 layer semantics every matrix must cover.
REQUIRED_TOPICS = frozenset(
    {
        "invariant beats environment allow",
        "guard beats everything",
        "ceiling beats a target allow",
        "target overrides environment",
        "environment overrides plugin default",
        "deny beats allow inside a layer",
        "no rule means deny",
        "constraint merging per key",
    }
)
#: The number of rows of the §7.7 table.
WORKED_EXAMPLES = 18

ROW_KEYS = frozenset(
    {"id", "source", "example", "topic", "call", "target", "env", "action", "measured"}
    | {"expect", "note"}
)
ACTION_KEYS = frozenset({"name", "risk", "facts", "invariantHits", "detail"})
EXPECT_KEYS = frozenset({"decision", "layer", "rule", "constraints", "explain"})


def _map(value: object, where: str) -> dict[str, object]:
    assert isinstance(value, dict), f"{where}: expected a mapping"
    return cast("dict[str, object]", value)


def _list(value: object, where: str) -> list[object]:
    assert isinstance(value, list), f"{where}: expected a list"
    return cast("list[object]", value)


def _str(value: object, where: str) -> str:
    assert isinstance(value, str), f"{where}: expected a string"
    return value


def _keys(data: Mapping[str, object], allowed: frozenset[str], where: str) -> None:
    unknown = set(data) - allowed
    assert not unknown, f"{where}: unknown keys {sorted(unknown)}"


def _fact(value: object) -> Fact:
    if isinstance(value, list):
        return tuple(str(v) for v in cast("list[object]", value))
    assert value is None or isinstance(value, str | int | bool)
    return value


@dataclass(frozen=True)
class MatrixTarget:
    type: str
    env: str
    rules: dict[str, RuleBlock]


@dataclass(frozen=True)
class Matrix:
    plugins: dict[str, FakePlugin]
    guard: tuple[str, ...]
    environments: dict[str, EnvironmentConfig]
    targets: dict[str, MatrixTarget]
    rows: tuple[dict[str, object], ...]

    def scope(self, target: str, env: str | None) -> Scope:
        config = self.targets[target]
        env_name = config.env if env is None else env
        return build_scope(
            target=target,
            env=env_name,
            environment=self.environments[env_name],
            target_rules=config.rules,
            guard=self.guard,
            plugin=self.plugins[config.type],
        )


def _plugin(type_name: str, raw: object) -> FakePlugin:
    data = _map(raw, f"plugins.{type_name}")
    invariants = tuple(
        Rule(_str(entry["rule"], "rule"), _str(entry.get("reason", ""), "reason"))
        for entry in (_map(e, "invariant") for e in _list(data["invariants"], "invariants"))
    )
    defaults = RuleBlock.model_validate(data["defaults"])
    return FakePlugin(type_name, invariants, rule_set(defaults), CHECKS[type_name])


def _target(name: str, raw: object) -> MatrixTarget:
    data = _map(raw, f"targets.{name}")
    type_name = _str(data["type"], "type")
    env = _str(data["env"], "env")
    _keys(data, frozenset({"type", "env", type_name, "all"}), f"targets.{name}")
    rules = {
        key: RuleBlock.model_validate(block)
        for key, block in data.items()
        if key in (type_name, "all")
    }
    return MatrixTarget(type_name, env, rules)


def load_matrix(path: Path) -> Matrix:
    data = _map(load_strict(path.read_text(), path.name), path.name)
    policy = _map(data["policy"], "policy")
    plugins = {k: _plugin(k, v) for k, v in _map(policy["plugins"], "plugins").items()}
    guard = tuple(_str(g, "guard") for g in _list(policy["guard"], "guard"))
    environments = {
        name: EnvironmentConfig.model_validate(env)
        for name, env in _map(policy["environments"], "environments").items()
    }
    targets = {k: _target(k, v) for k, v in _map(policy["targets"], "targets").items()}
    rows = tuple(_map(row, "row") for row in _list(data["rows"], "rows"))
    for row in rows:
        where = f"row {row.get('id')}"
        _keys(row, ROW_KEYS, where)
        _keys(_map(row["action"], where), ACTION_KEYS, f"{where}.action")
        _keys(_map(row["expect"], where), EXPECT_KEYS, f"{where}.expect")
        assert _str(row["target"], where) in targets, f"{where}: unknown target"
        env = row.get("env")
        assert env is None or env in environments, f"{where}: unknown environment"
    return Matrix(plugins, guard, environments, targets, rows)


MATRIX = load_matrix(MATRIX_FILE)


def _action(raw: object) -> Action:
    data = _map(raw, "action")
    facts = {k: _fact(v) for k, v in _map(data.get("facts", {}), "facts").items()}
    hits = tuple(_str(h, "invariantHits") for h in _list(data.get("invariantHits", []), "hits"))
    return Action(
        _str(data["name"], "name"),
        Risk(_str(data["risk"], "risk")),
        facts,
        hits,
        _str(data.get("detail", ""), "detail"),
    )


@pytest.mark.parametrize("row", MATRIX.rows, ids=[str(r["id"]) for r in MATRIX.rows])
def test_row(row: dict[str, object]) -> None:
    env = row.get("env")
    scope = MATRIX.scope(_str(row["target"], "target"), None if env is None else str(env))
    decision = decide(_action(row["action"]), scope)
    if "measured" in row:
        assert decision.allowed, f"the decision before the run must allow: {explain(decision)}"
        measured = {
            k: None if v is None else int(cast("int", v))
            for k, v in _map(row["measured"], "measured").items()
        }
        decision = after_run(decision, scope.checks, measured)

    expect = _map(row["expect"], "expect")
    got = (decision.verdict, str(decision.layer), decision.rule)
    assert got == (expect["decision"], expect["layer"], expect["rule"]), explain(decision)
    if "constraints" in expect:
        want = {
            name: (_fact(_map(spec, name)["value"]), _map(spec, name)["layer"])
            for name, spec in _map(expect["constraints"], "constraints").items()
        }
        got_constraints = {
            name: (c.value, str(c.layer)) for name, c in decision.constraints.items()
        }
        assert got_constraints == want
    if "explain" in expect:
        assert explain(decision) == expect["explain"]


def test_every_worked_example_of_7_7_has_a_row() -> None:
    examples = {r["example"] for r in MATRIX.rows if r["source"] == "7.7"}
    assert examples == set(range(1, WORKED_EXAMPLES + 1))


def test_every_layer_rule_of_13_has_a_row() -> None:
    topics = {r["topic"] for r in MATRIX.rows if r["source"] == "13"}
    assert topics >= REQUIRED_TOPICS


def test_row_ids_are_unique_and_every_row_names_its_source() -> None:
    ids = [r["id"] for r in MATRIX.rows]
    assert len(ids) == len(set(ids))
    for row in MATRIX.rows:
        assert row["source"] in ("7.7", "13")
        assert ("example" in row) == (row["source"] == "7.7")
        assert ("topic" in row) == (row["source"] == "13")
