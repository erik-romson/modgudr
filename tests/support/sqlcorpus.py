"""The SQL classification corpus format (`tests/data/sql/<dialect>-corpus.yaml`) and its checks.

A corpus maps each `sql` string to the action the dialect's classifier must return:

    dialect: snowflake
    rows:
      - sql: "select * from audit where action = 'delete'"
        action: sql:select          # the action name
        risk: read                  # the risk class
        facts: { tables: [audit] }  # optional: these facts, compared exactly (lists as tuples)
        invariant: sql:session      # optional: the plugin invariant that refuses it
        requireWhere: unmet         # optional: met | unmet
        note: …                     # optional

`invariant` names an invariant hit (`multi-statement`) or the pattern of one of the connector's
invariant rules (`sql:session`, `sql:use`, `sql:transaction`). A row without it must break no
invariant. Every `sql` string occurs once.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from modgudr.broker.policy.yaml_strict import load_strict
from modgudr.spi import RISK_NAMES, Action, Fact, Risk
from modgudr.sql.classify import INVARIANTS, RequireWhere

DATA = Path(__file__).resolve().parents[1] / "data" / "sql"

_TOP_KEYS = frozenset({"dialect", "rows"})
_ROW_KEYS = frozenset({"sql", "action", "risk", "facts", "invariant", "requireWhere", "note"})


@dataclass(frozen=True)
class CorpusRow:
    sql: str
    action: str
    risk: Risk
    facts: Mapping[str, Fact] = field(default_factory=dict[str, Fact])
    invariant: str | None = None
    #: True: `requireWhere` is met; False: unmet; None: not checked.
    require_where: bool | None = None
    note: str = ""

    @property
    def id(self) -> str:
        shown = " ".join(self.sql.split()) or "<empty>"
        return shown if len(shown) <= 60 else shown[:57] + "..."


@dataclass(frozen=True)
class Corpus:
    dialect: str
    rows: tuple[CorpusRow, ...]

    def sql(self) -> frozenset[str]:
        return frozenset(row.sql for row in self.rows)


def _fact(value: object, where: str) -> Fact:
    if isinstance(value, list):
        return tuple(str(item) for item in cast("list[object]", value))
    assert value is None or isinstance(value, str | int | bool), f"{where}: bad fact {value!r}"
    return value


def _row(raw: object, where: str) -> CorpusRow:
    assert isinstance(raw, dict), f"{where}: a row is a mapping"
    data = cast("dict[str, object]", raw)
    unknown = set(data) - _ROW_KEYS
    assert not unknown, f"{where}: unknown keys {sorted(unknown)}"
    sql, action, risk = data.get("sql"), data.get("action"), data.get("risk")
    assert isinstance(sql, str), f"{where}: sql must be a string"
    assert isinstance(action, str) and action.startswith("sql:"), f"{where}: bad action"
    assert isinstance(risk, str) and risk in RISK_NAMES, f"{where}: bad risk {risk!r}"
    facts_raw = data.get("facts", {})
    assert isinstance(facts_raw, dict), f"{where}: facts must be a mapping"
    facts = {
        str(key): _fact(value, f"{where}.facts.{key}")
        for key, value in cast("dict[object, object]", facts_raw).items()
    }
    invariant = data.get("invariant")
    assert invariant is None or isinstance(invariant, str), f"{where}: bad invariant"
    require = data.get("requireWhere")
    assert require in (None, "met", "unmet"), f"{where}: requireWhere is met or unmet"
    note = data.get("note", "")
    assert isinstance(note, str), f"{where}: note must be a string"
    return CorpusRow(
        sql=sql,
        action=action,
        risk=Risk(risk),
        facts=facts,
        invariant=invariant,
        require_where=None if require is None else require == "met",
        note=note,
    )


def load_corpus(dialect: str) -> Corpus:
    """Load and validate `tests/data/sql/<dialect>-corpus.yaml`."""
    path = DATA / f"{dialect}-corpus.yaml"
    data = load_strict(path.read_text(encoding="utf-8"), path.name)
    assert isinstance(data, dict), f"{path.name}: the corpus is a mapping"
    top = cast("dict[str, object]", data)
    assert set(top) == _TOP_KEYS, f"{path.name}: keys must be {sorted(_TOP_KEYS)}"
    assert top["dialect"] == dialect, f"{path.name}: dialect must be {dialect}"
    raw_rows = top["rows"]
    assert isinstance(raw_rows, list) and raw_rows, f"{path.name}: rows must be a list"
    rows = tuple(
        _row(raw, f"{path.name} row {i}") for i, raw in enumerate(cast("list[object]", raw_rows))
    )
    seen: set[str] = set()
    for row in rows:
        assert row.sql not in seen, f"{path.name}: {row.sql!r} occurs twice"
        seen.add(row.sql)
    return Corpus(dialect, rows)


def invariant_of(action: Action) -> str | None:
    """The invariant that refuses an action at layer `plugin-invariant`, if any."""
    if action.invariant_hits:
        return action.invariant_hits[0]
    for rule in INVARIANTS:
        if rule.matches(action):
            return rule.pattern
    return None


def check_row(row: CorpusRow, action: Action) -> None:
    """Assert that a classified action is what the corpus row expects."""
    shown = f"{row.sql!r} -> {action.name} ({action.risk.value}) {action.detail}"
    assert action.name == row.action, shown
    assert action.risk is row.risk, shown
    for key, value in row.facts.items():
        assert action.facts.get(key) == value, f"{shown}: fact {key} is {action.facts.get(key)!r}"
    assert invariant_of(action) == row.invariant, f"{shown}: invariant {invariant_of(action)}"
    if row.require_where is not None:
        reason = RequireWhere().before(action, True)
        assert (reason is None) is row.require_where, f"{shown}: requireWhere {reason}"
