"""SQL classification shared by every dialect (§7.1, §7.2, §8.1, M12).

`classify(sql, rules)` turns one SQL text into an `Action`: a name (`sql:select`, `sql:delete`,
`sql:plsql`, `sql:ddl.create`, …), the maximum risk over the whole statement, and the facts the
rules and constraints check. It never raises: whatever it cannot place is `sql:unknown`.

The order is fixed: the size limit, then the first words (PL/SQL and scripting blocks, the
dialect's leading rules), then the parse, the statement count, the top-level whitelist with the
`exp.Command` mapping, and the walk over the whole tree. Everything after the size limit runs in a
worker thread with a time limit, because the parser and `simplify` can take unbounded time on
hostile input.
"""

from __future__ import annotations

import re
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from typing import Literal

import sqlglot
from sqlglot import Token, TokenType, exp
from sqlglot.errors import ErrorLevel, ParseError
from sqlglot.optimizer.normalize_identifiers import normalize_identifiers
from sqlglot.optimizer.simplify import simplify

from modgudr.spi import Action, ConstraintValue, Fact, Measured, Risk, Rule

from .catalogue import DialectRules, WordRule, call_parts, function_name, object_name

TYPE = "sql"

#: Statements longer than this are refused unparsed (M12).
MAX_STATEMENT_CHARS = 100_000
#: The wall-clock limit for tokenising, parsing and analysing one statement (M12).
PARSE_SECONDS = 2.0
#: Parses running at once. A parse that never ends keeps its slot; when every slot is held,
#: classification fails closed (`sql:unknown`) instead of starting more threads.
_PARSE_SLOTS = threading.BoundedSemaphore(4)

#: The invariant hit of a call with more than one statement (§7.3).
MULTI_STATEMENT = "multi-statement"

#: The plugin invariants with a name of their own (§7.3, M12). Multi-statement calls are marked
#: with the invariant hit `MULTI_STATEMENT` instead, because they keep their statement's name.
INVARIANTS: tuple[Rule, ...] = (
    Rule(
        "sql:session",
        "session state belongs to the broker; it would undo the target's role or poison the "
        "next call on a pooled connection",
    ),
    Rule("sql:use", "the target fixes the role, warehouse, database and schema"),
    Rule("sql:transaction", "the broker owns the transaction: one call is one transaction"),
)

#: The values of the `where` fact of an UPDATE or DELETE (M12 `requireWhere`).
WhereState = Literal["column", "constant", "none", "unknown"]

_WHERE_REASONS: Mapping[str, str] = {
    "none": "the statement has no WHERE clause",
    "constant": "the WHERE clause matches every row: it is constant, holds no column or "
    "compares a column with itself",
    "unknown": "the WHERE clause could not be analysed",
}

#: Statement kinds (M12 top-level whitelist), the `kind` fact.
Kind = Literal["query", "dml", "ddl", "other"]


class ClassifyTimeout(Exception):
    """The work did not finish within its time limit, or no parse slot was free."""


def run_limited[T](work: Callable[[], T], seconds: float) -> T:
    """Run `work` in a daemon worker thread and wait at most `seconds` for it.

    Raises `ClassifyTimeout` when it does not finish in time; the thread cannot be stopped and
    keeps its parse slot until it ends. Exceptions raised by `work` propagate.
    """
    deadline = time.monotonic() + seconds
    if not _PARSE_SLOTS.acquire(timeout=seconds):
        raise ClassifyTimeout
    results: list[T] = []
    errors: list[BaseException] = []
    done = threading.Event()

    def run() -> None:
        try:
            results.append(work())
        except BaseException as exc:
            errors.append(exc)
        finally:
            done.set()
            _PARSE_SLOTS.release()

    worker = threading.Thread(target=run, name="modgudr-sql-parse", daemon=True)
    try:
        worker.start()
    except BaseException:
        _PARSE_SLOTS.release()
        raise
    if not done.wait(max(0.0, deadline - time.monotonic())):
        raise ClassifyTimeout
    if errors:
        raise errors[0]
    return results[0]


# --- tokens and parsing --------------------------------------------------------------------

_PREFIX = "x "
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def tokens(sql: str, dialect: str) -> list[Token]:
    """The dialect's tokens of `sql`, with offsets into `sql`.

    The text is tokenised as `"x " + sql` with the prefix token dropped: a command keyword at the
    start (`CALL`, `EXECUTE`) would otherwise swallow the rest of the text into one opaque token.
    Raises sqlglot's `TokenError`.
    """
    out: list[Token] = []
    for token in sqlglot.tokenize(_PREFIX + sql, read=dialect)[1:]:
        token.start -= len(_PREFIX)
        token.end -= len(_PREFIX)
        out.append(token)
    return out


def words(sql: str, toks: list[Token], limit: int = 6) -> list[str]:
    """The first words of a token list, upper-cased, from the source text.

    Strings and quoted identifiers keep their quotes, so `'secret'` never reads as `SECRET`; a
    multi-word keyword token counts as its words.
    """
    out: list[str] = []
    for token in toks:
        out.extend(sql[token.start : token.end + 1].upper().split())
        if len(out) >= limit:
            break
    return out[:limit]


def parse_message(exc: BaseException) -> str:
    """A parser or tokenizer error in one line an agent can act on."""
    if isinstance(exc, ParseError) and exc.errors:
        first = exc.errors[0]
        description = str(first.get("description") or "invalid syntax")
        line, col = first.get("line"), first.get("col")
        highlight = str(first.get("highlight") or "").strip()
        near = f" near {highlight!r}" if highlight else ""
        return f"parse error at line {line}, column {col}{near}: {description}"
    if isinstance(exc, RecursionError):
        return "parse error: the statement is nested too deeply"
    text = " ".join(_ANSI.sub("", str(exc)).split())
    return f"parse error: {text}" if text else f"parse error: {type(exc).__name__}"


def parse_statements(sql: str, dialect: str) -> list[exp.Expr]:
    """The statements of `sql` (M12): parse results that are neither None nor `exp.Semicolon`.

    `sqlglot.parse` with `ErrorLevel.IMMEDIATE`, never `parse_one`. Raises whatever the
    tokenizer or parser raises; run it under `run_limited`.
    """
    trees = sqlglot.parse(sql, read=dialect, error_level=ErrorLevel.IMMEDIATE)
    return [tree for tree in trees if tree is not None and not isinstance(tree, exp.Semicolon)]


def stray_semicolon(toks: list[Token]) -> bool:
    """Whether a `;` separates statements: one is allowed, as the last token (M12)."""
    positions = [i for i, token in enumerate(toks) if token.token_type is TokenType.SEMICOLON]
    return len(positions) > 1 or (len(positions) == 1 and positions[0] != len(toks) - 1)


def executable_sql(sql: str, dialect: str) -> str:
    """The text the driver runs: byte-identical to the classified text minus its one trailing
    `;` (M12). Call it only on a statement `classify` accepted as one statement."""
    toks = tokens(sql, dialect)
    if toks and toks[-1].token_type is TokenType.SEMICOLON:
        start = toks[-1].start
        return sql[:start] + sql[start + 1 :]
    return sql


# --- statements ----------------------------------------------------------------------------


@dataclass(frozen=True)
class _Statement:
    """One statement node's own class: its action name, risk and kind."""

    action: str
    risk: Risk
    kind: Kind


class _Refused(Exception):
    """Raised inside the walk: the statement is `sql:unknown` for this reason."""


_DML_TYPES: tuple[type[exp.Expr], ...] = (
    exp.Insert,
    exp.MultitableInserts,
    exp.Update,
    exp.Delete,
    exp.Merge,
    exp.Copy,
    exp.TruncateTable,
)
_DDL_TYPES: tuple[type[exp.Expr], ...] = (exp.Create, exp.Drop, exp.Alter, exp.Undrop, exp.Comment)
_OTHER_TYPES: tuple[type[exp.Expr], ...] = (
    exp.Grant,
    exp.Revoke,
    exp.Describe,
    exp.Show,
    exp.Use,
    exp.Set,
    exp.Put,
    exp.Get,
    exp.Transaction,
    exp.Commit,
    exp.Rollback,
    exp.Command,
)
#: Every statement type of the M12 whitelist besides `exp.Query`.
_STATEMENT_TYPES = _DML_TYPES + _DDL_TYPES + _OTHER_TYPES

_COMMON_COMMANDS: tuple[WordRule, ...] = (
    WordRule.of("ALTER SESSION", "session", Risk.ADMIN),
    WordRule.of("SET", "session", Risk.ADMIN),
    WordRule.of("CALL|EXECUTE", "plsql", Risk.ADMIN),
    WordRule.of("GRANT", "grant", Risk.ADMIN),
    WordRule.of("REVOKE", "revoke", Risk.ADMIN),
    # Oracle EXPLAIN PLAN writes PLAN_TABLE: only the `plan` op runs it, never `query`.
    WordRule.of("EXPLAIN", "explain", Risk.READ),
)


def _command(node: exp.Command, rules: DialectRules) -> _Statement:
    head = node.name.upper()
    tail = node.args.get("expression")
    if isinstance(tail, str):
        tail_text = tail
    elif isinstance(tail, exp.Expr):
        tail_text = tail.name
    else:
        tail_text = ""
    try:
        tail_words = words(tail_text, tokens(tail_text, rules.sqlglot_dialect))
    except Exception as exc:
        raise _Refused(f"{head} …: {parse_message(exc)}") from exc
    said = [head, *tail_words]
    shared = (r for r in _COMMON_COMMANDS if r.action not in rules.dropped_shared_commands)
    for rule in (*rules.commands, *shared):
        if rule.matches(said):
            return _Statement(rule.action, rule.risk, "other")
    shown = " ".join(said[:3])
    raise _Refused(f"{shown} … is not a statement the sql connector classifies")


def _copy(node: exp.Copy) -> _Statement:
    target = node.this
    if isinstance(target, exp.Schema):
        target = target.this
    if isinstance(target, exp.Table):
        if isinstance(target.this, exp.Var | exp.Literal):
            # COPY INTO @stage or 's3://…': the data leaves the database (§7.2).
            return _Statement("unload", Risk.ADMIN, "dml")
        if isinstance(target.this, exp.Identifier):
            return _Statement("copy", Risk.WRITE, "dml")
    raise _Refused("the target of COPY INTO is neither a table nor a stage or URL")


def _merge_deletes(node: exp.Merge) -> bool:
    for when in node.find_all(exp.When):
        then = when.args.get("then")
        if isinstance(then, exp.Delete) or (
            isinstance(then, exp.Var) and then.name.upper() == "DELETE"
        ):
            return True
    return False


def _statement(node: exp.Expr, rules: DialectRules) -> _Statement:
    """The class of one statement node of the whitelist; anything else is refused."""
    if isinstance(node, exp.Query):
        return _Statement("select", Risk.READ, "query")
    if isinstance(node, exp.Insert | exp.MultitableInserts):
        # INSERT OVERWRITE replaces the table's rows (§7.2: removes data).
        risk = Risk.DESTRUCTIVE if node.args.get("overwrite") else Risk.WRITE
        return _Statement("insert", risk, "dml")
    if isinstance(node, exp.Update):
        return _Statement("update", Risk.WRITE, "dml")
    if isinstance(node, exp.Delete):
        return _Statement("delete", Risk.DESTRUCTIVE, "dml")
    if isinstance(node, exp.Merge):
        risk = Risk.DESTRUCTIVE if _merge_deletes(node) else Risk.WRITE
        return _Statement("merge", risk, "dml")
    if isinstance(node, exp.Copy):
        return _copy(node)
    if isinstance(node, exp.TruncateTable):
        return _Statement("truncate", Risk.DESTRUCTIVE, "dml")
    if isinstance(node, exp.Alter):
        kind = str(node.args.get("kind") or "").upper()
        actions: list[object] = list(node.args.get("actions") or [])
        if kind == "SESSION" or any(isinstance(a, exp.AlterSession) for a in actions):
            return _Statement("session", Risk.ADMIN, "other")
        return _Statement("ddl.alter", Risk.ADMIN, "ddl")
    if isinstance(node, exp.Create):
        return _Statement("ddl.create", Risk.ADMIN, "ddl")
    if isinstance(node, exp.Drop):
        return _Statement("ddl.drop", Risk.DESTRUCTIVE, "ddl")
    if isinstance(node, exp.Undrop):
        return _Statement("ddl.undrop", Risk.ADMIN, "ddl")
    if isinstance(node, exp.Comment):
        return _Statement("ddl.comment", Risk.ADMIN, "ddl")
    if isinstance(node, exp.Grant):
        return _Statement("grant", Risk.ADMIN, "other")
    if isinstance(node, exp.Revoke):
        return _Statement("revoke", Risk.ADMIN, "other")
    if isinstance(node, exp.Describe):
        return _Statement("describe", Risk.READ, "other")
    if isinstance(node, exp.Show):
        return _Statement("show", Risk.READ, "other")
    if isinstance(node, exp.Use):
        return _Statement("use", Risk.ADMIN, "other")
    if isinstance(node, exp.Set):
        return _Statement("session", Risk.ADMIN, "other")
    if isinstance(node, exp.Put):
        return _Statement("put", Risk.ADMIN, "other")
    if isinstance(node, exp.Get):
        return _Statement("get", Risk.ADMIN, "other")
    if isinstance(node, exp.Transaction | exp.Commit | exp.Rollback):
        return _Statement("transaction", Risk.ADMIN, "other")
    if isinstance(node, exp.Command):
        return _command(node, rules)
    raise _Refused(
        f"the statement is not one the sql connector classifies (it parses as "
        f"{type(node).__name__})"
    )


# --- requireWhere --------------------------------------------------------------------------


def _qualifier(column: exp.Column) -> list[str]:
    return [part.name for part in column.parts[:-1]]


def _self_comparison(node: exp.Expr) -> bool:
    """`id = id`, `t.id <= id`, `"ID" >= id`: the same column on both sides (M12)."""
    if not isinstance(node, exp.EQ | exp.LTE | exp.GTE):
        return False
    left, right = node.this.unnest(), node.expression.unnest()
    if not isinstance(left, exp.Column) or not isinstance(right, exp.Column):
        return False
    if left.name != right.name:
        return False
    ql, qr = _qualifier(left), _qualifier(right)
    return not ql or not qr or ql == qr


def where_state(statement: exp.Expr, dialect: str) -> WhereState:
    """Whether an UPDATE's or DELETE's WHERE clause depends on a column (M12 `requireWhere`).

    Folding runs on a copy of the condition: identifiers are normalised for the dialect, every
    self-comparison becomes TRUE, then `simplify` runs. What is left must hold a column.
    """
    where = statement.args.get("where")
    if not isinstance(where, exp.Where):
        return "none"
    try:
        condition: exp.Expr = normalize_identifiers(where.this.copy(), dialect=dialect)
        condition = condition.transform(_true_if_self_comparison)
        condition = simplify(condition, dialect=dialect)
    except Exception:
        return "unknown"
    return "constant" if condition.find(exp.Column) is None else "column"


def _true_if_self_comparison(node: exp.Expr) -> exp.Expr:
    return exp.true() if _self_comparison(node) else node


class RequireWhere:
    """The `requireWhere` constraint (§7.6): checked on the `where` fact before anything runs.

    A guard against accidents, not against an agent: `maxAffectedRows` carries the weight.
    """

    def before(self, action: Action, value: ConstraintValue) -> str | None:
        if value is not True:
            return None
        state = action.facts.get("where")
        if state == "column":
            return None
        return _WHERE_REASONS.get(str(state), _WHERE_REASONS["none"])

    def after(self, action: Action, value: ConstraintValue, measured: Measured) -> str | None:
        return None


# --- the walk ------------------------------------------------------------------------------


_SEQUENCE_COLUMNS = frozenset({"NEXTVAL", "CURRVAL"})
_RUNTIME_NAMES: tuple[type[exp.Expr], ...] = (exp.DynamicIdentifier, exp.Placeholder, exp.Parameter)


def _unique(items: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(items))


def _display(parts: list[exp.Expr]) -> str:
    """A table name for the facts: unquoted parts lower-cased, quoted parts as written."""
    shown: list[str] = []
    for part in parts:
        if isinstance(part, exp.Identifier) and part.quoted:
            shown.append(f'"{part.name}"')
        else:
            shown.append(part.name.lower())
    return ".".join(shown)


@dataclass
class _Walk:
    """The maximum risk over one statement's tree and the facts found on the way."""

    rules: DialectRules
    risk: Risk
    tables: list[str] = field(default_factory=list[str])
    functions: list[str] = field(default_factory=list[str])

    def raise_to(self, risk: Risk) -> None:
        self.risk = max(self.risk, risk)

    def table(self, node: exp.Table) -> None:
        parts: list[exp.Expr] = list(node.parts)
        if any(isinstance(part, _RUNTIME_NAMES) for part in parts):
            raise _Refused("the table name is a bind or variable, known only when it runs")
        if not isinstance(node.this, exp.Identifier) or isinstance(node.parent, exp.Use):
            # A stage (`@s`), a URL, or a table function (its functions are walked on their
            # own); or the role or warehouse of a USE, which names no table.
            return
        if not all(isinstance(part, exp.Identifier) for part in parts):
            raise _Refused("the table name is not a plain name")
        self.tables.append(_display(parts))
        found = self.rules.objects.lookup(object_name([part.name for part in parts]))
        if found is not None:
            self.raise_to(found)

    def function(self, node: exp.Func) -> None:
        parts = call_parts(node)
        if parts is None:
            raise _Refused("a function is called through an expression, not by its name")
        name = function_name(parts)
        if isinstance(node, exp.Anonymous) or len(parts) > 1:
            self.functions.append(name)
        # A function no catalogue knows is read (assumption A9).
        found = self.rules.functions.lookup(name)
        if found is not None:
            self.raise_to(found)
        if self.rules.refine_call is not None:
            refined = self.rules.refine_call(name, node)
            if refined is not None:
                self.raise_to(refined)

    def node(self, node: exp.Expr) -> None:
        if isinstance(node, exp.Select):
            if node.args.get("locks"):
                self.raise_to(Risk.WRITE)  # SELECT … FOR UPDATE
            if node.args.get("into"):
                raise _Refused("SELECT … INTO is not supported")
        if isinstance(node, exp.With) and node.args.get("udfs"):
            self.raise_to(Risk.ADMIN)  # WITH FUNCTION …
        if isinstance(node, exp.Column) and node.name.upper() in _SEQUENCE_COLUMNS:
            self.raise_to(Risk.WRITE)  # seq.nextval
        if isinstance(node, exp.Identifier) and not node.quoted and "@" in node.name:
            self.raise_to(Risk.ADMIN)  # an Oracle database link: leaves the database
        if isinstance(node, exp.DynamicIdentifier):
            raise _Refused("IDENTIFIER(…) names an object only known when it runs")
        if isinstance(node, exp.Table):
            self.table(node)
        elif isinstance(node, exp.Func):
            self.function(node)


def _classify_statement(tree: exp.Expr, rules: DialectRules) -> Action:
    try:
        top = _statement(tree, rules)
        walk = _Walk(rules, top.risk)
        named, named_node = top, tree
        for node in tree.walk():
            if node is not tree and isinstance(node, (exp.Query, *_STATEMENT_TYPES)):
                inner = _statement(node, rules)
                walk.raise_to(inner.risk)
                # The most dangerous statement inside names the action (§7.1).
                if inner.risk > named.risk:
                    named, named_node = inner, node
            walk.node(node)
    except _Refused as refused:
        return Action.unknown(TYPE, str(refused))
    facts: dict[str, Fact] = {"statement": top.action, "kind": top.kind}
    if walk.tables:
        facts["tables"] = _unique(walk.tables)
    if walk.functions:
        facts["functions"] = _unique(walk.functions)
    if isinstance(named_node, exp.Update | exp.Delete):
        facts["where"] = where_state(named_node, rules.sqlglot_dialect)
    return Action(f"{TYPE}:{named.action}", walk.risk, facts)


def _classify(sql: str, rules: DialectRules) -> Action:
    dialect = rules.sqlglot_dialect
    try:
        toks = tokens(sql, dialect)
    except Exception as exc:
        return Action.unknown(TYPE, parse_message(exc))
    first = words(sql, toks)
    # A PL/SQL or scripting block: refused before parsing, because `BEGIN p; END;` parses as a
    # transaction (M12).
    if first and first[0] in rules.block_words:
        return Action(f"{TYPE}:plsql", Risk.ADMIN, {"statement": "plsql", "kind": "other"})
    for rule in rules.leading:
        if rule.matches(first):
            facts: dict[str, Fact] = {"statement": rule.action, "kind": "other"}
            return Action(f"{TYPE}:{rule.action}", rule.risk, facts)
    try:
        statements = parse_statements(sql, dialect)
    except Exception as exc:
        return Action.unknown(TYPE, parse_message(exc))
    if not statements:
        return Action.unknown(TYPE, "the statement is empty")
    actions = [_classify_statement(tree, rules) for tree in statements]
    if len(actions) == 1 and not stray_semicolon(toks):
        return actions[0]
    worst = max(actions, key=lambda action: action.risk.rank)
    facts = {**worst.facts, "statements": len(statements)}
    detail = worst.detail or "one statement per call; a single trailing ';' is allowed"
    return replace(worst, facts=facts, invariant_hits=(MULTI_STATEMENT,), detail=detail)


def classify(sql: str, rules: DialectRules) -> Action:
    """Classify one SQL text for a dialect (M12). Never raises."""
    if len(sql) > MAX_STATEMENT_CHARS:
        return Action.unknown(
            TYPE,
            f"the statement has {len(sql)} characters; at most {MAX_STATEMENT_CHARS} are "
            "classified",
        )
    try:
        return run_limited(lambda: _classify(sql, rules), PARSE_SECONDS)
    except ClassifyTimeout:
        return Action.unknown(TYPE, f"classifying took longer than {PARSE_SECONDS:g} s")
    except RecursionError:
        return Action.unknown(TYPE, "parse error: the statement is nested too deeply")
    except Exception as exc:
        return Action.unknown(TYPE, f"the classifier failed ({type(exc).__name__})")
