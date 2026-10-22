"""The kubectl classification corpus format (`tests/data/kubectl-corpus.yaml`) and its checks.

A corpus maps each `argv` (the words after `kubectl`, split like a POSIX shell) to the action the
classifier must return:

    namespaces: [app]               # the list the rows' `namespaces` verdicts are checked against
    rows:
      - argv: "-n app-test delete po web-1"
        action: kubectl:delete/pods  # the action name
        risk: destructive            # the risk class
        facts: { names: [web-1] }    # optional: these facts, compared exactly (lists as tuples)
        invariant: --as              # optional: the invariant that refuses it
        detail: …                    # optional: a phrase the action's detail contains
        requireName: unmet           # optional: met | unmet
        namespaces: met              # optional: met | unmet
        defaultNamespace: app        # optional: the target's defaultNamespace
        note: …                      # optional

`invariant` names an invariant hit (`--as`, `--filename`) or the pattern of one of the connector's
invariant rules (`kubectl:cp/*`). A row without it must break no invariant. Every pair of `argv`
and `defaultNamespace` occurs once.
"""

from __future__ import annotations

import shlex
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from modgudr.broker.policy.yaml_strict import load_strict
from modgudr.kubectl.classify import INVARIANTS, Namespaces, RequireName
from modgudr.spi import RISK_NAMES, Action, Fact, Risk

CORPUS_FILE = Path(__file__).resolve().parents[1] / "data" / "kubectl-corpus.yaml"

_TOP_KEYS = frozenset({"namespaces", "rows"})
_ROW_KEYS = frozenset(
    {
        "argv",
        "action",
        "risk",
        "facts",
        "invariant",
        "detail",
        "requireName",
        "namespaces",
        "defaultNamespace",
        "note",
    }
)
_VERDICTS: Mapping[object, bool | None] = {None: None, "met": True, "unmet": False}


@dataclass(frozen=True)
class CorpusRow:
    argv: str
    action: str
    risk: Risk
    facts: Mapping[str, Fact] = field(default_factory=dict[str, Fact])
    invariant: str | None = None
    detail: str = ""
    #: True: the constraint is met; False: unmet; None: not checked.
    require_name: bool | None = None
    namespaces: bool | None = None
    default_namespace: str | None = None
    note: str = ""

    @property
    def words(self) -> list[str]:
        return shlex.split(self.argv)

    @property
    def id(self) -> str:
        shown = self.argv or "<empty>"
        if self.default_namespace is not None:
            shown += f" [defaultNamespace {self.default_namespace}]"
        return shown


@dataclass(frozen=True)
class Corpus:
    namespaces: tuple[str, ...]
    rows: tuple[CorpusRow, ...]

    def argvs(self) -> frozenset[str]:
        return frozenset(row.argv for row in self.rows)


def _fact(value: object, where: str) -> Fact:
    if isinstance(value, list):
        return tuple(str(item) for item in cast("list[object]", value))
    assert value is None or isinstance(value, str | int | bool), f"{where}: bad fact {value!r}"
    return value


def _optional_str(data: Mapping[str, object], key: str, where: str) -> str | None:
    value = data.get(key)
    assert value is None or isinstance(value, str), f"{where}: {key} must be a string"
    return value


def _verdict(data: Mapping[str, object], key: str, where: str) -> bool | None:
    value = data.get(key)
    assert value in _VERDICTS, f"{where}: {key} is met or unmet"
    return _VERDICTS[value]


def _row(raw: object, where: str) -> CorpusRow:
    assert isinstance(raw, dict), f"{where}: a row is a mapping"
    data = cast("dict[str, object]", raw)
    unknown = set(data) - _ROW_KEYS
    assert not unknown, f"{where}: unknown keys {sorted(unknown)}"
    argv, action, risk = data.get("argv"), data.get("action"), data.get("risk")
    assert isinstance(argv, str), f"{where}: argv must be a string"
    assert isinstance(action, str) and action.startswith("kubectl:"), f"{where}: bad action"
    assert isinstance(risk, str) and risk in RISK_NAMES, f"{where}: bad risk {risk!r}"
    facts_raw = data.get("facts", {})
    assert isinstance(facts_raw, dict), f"{where}: facts must be a mapping"
    facts = {
        str(key): _fact(value, f"{where}.facts.{key}")
        for key, value in cast("dict[object, object]", facts_raw).items()
    }
    return CorpusRow(
        argv=argv,
        action=action,
        risk=Risk(risk),
        facts=facts,
        invariant=_optional_str(data, "invariant", where),
        detail=_optional_str(data, "detail", where) or "",
        require_name=_verdict(data, "requireName", where),
        namespaces=_verdict(data, "namespaces", where),
        default_namespace=_optional_str(data, "defaultNamespace", where),
        note=_optional_str(data, "note", where) or "",
    )


def load_corpus(path: Path = CORPUS_FILE) -> Corpus:
    """Load and validate the kubectl corpus."""
    data = load_strict(path.read_text(encoding="utf-8"), path.name)
    assert isinstance(data, dict), f"{path.name}: the corpus is a mapping"
    top = cast("dict[str, object]", data)
    assert set(top) == _TOP_KEYS, f"{path.name}: keys must be {sorted(_TOP_KEYS)}"
    namespaces = _fact(top["namespaces"], f"{path.name}: namespaces")
    assert isinstance(namespaces, tuple) and namespaces, f"{path.name}: namespaces is a list"
    raw_rows = top["rows"]
    assert isinstance(raw_rows, list) and raw_rows, f"{path.name}: rows must be a list"
    rows = tuple(
        _row(raw, f"{path.name} row {i}") for i, raw in enumerate(cast("list[object]", raw_rows))
    )
    seen: set[tuple[str, str | None]] = set()
    for row in rows:
        key = (row.argv, row.default_namespace)
        assert key not in seen, f"{path.name}: {row.id!r} occurs twice"
        seen.add(key)
    return Corpus(namespaces, rows)


def invariant_of(action: Action) -> str | None:
    """The invariant that refuses an action at layer `plugin-invariant`, if any."""
    if action.invariant_hits:
        return action.invariant_hits[0]
    for rule in INVARIANTS:
        if rule.matches(action):
            return rule.pattern
    return None


def check_row(row: CorpusRow, action: Action, namespaces: tuple[str, ...]) -> None:
    """Assert that a classified action is what the corpus row expects."""
    shown = f"{row.id!r} -> {action.name} ({action.risk.value}) {action.detail}"
    assert action.name == row.action, shown
    assert action.risk is row.risk, shown
    for key, value in row.facts.items():
        assert action.facts.get(key) == value, f"{shown}: fact {key} is {action.facts.get(key)!r}"
    assert invariant_of(action) == row.invariant, f"{shown}: invariant {invariant_of(action)}"
    assert row.detail in action.detail, f"{shown}: detail lacks {row.detail!r}"
    if row.require_name is not None:
        reason = RequireName().before(action, True)
        assert (reason is None) is row.require_name, f"{shown}: requireName {reason}"
    if row.namespaces is not None:
        reason = Namespaces().before(action, namespaces)
        assert (reason is None) is row.namespaces, f"{shown}: namespaces {reason}"
