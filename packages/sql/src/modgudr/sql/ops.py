"""The `sql` operations (M14): their contracts, the template ops and the statement a call runs.

`statement_text` assembles the SQL of a call (a caller's statement, or a dialect template filled
with validated identifiers). That text, and nothing derived from it afterwards, is classified;
`bind_call` then turns the same text into what the driver runs (M12 `executable_sql`, M13 `bind`).
`apply_contract` holds a classified action to what its op accepts: a statement that breaks the op
contract becomes an invariant hit, so the engine refuses it with the contract's message (exit 2).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import cast

from modgudr.spi import (
    Action,
    ArgSpec,
    BadArguments,
    Call,
    OperationSpec,
    ParamType,
    Risk,
    SqlDialect,
    TypedParam,
)

from .binds import BindError, BoundSql, bind
from .classify import executable_sql, parse_message

#: The invariant hit of a statement the op does not accept.
OP_CONTRACT = "op-contract"

#: The `sample` row count when none is given (M14).
DEFAULT_SAMPLE = 5

#: The dialects that take `plan` and `--schema` (M14, decided by Q3).
SCHEMA_DIALECTS = frozenset({"oracle"})

_SQL = ArgSpec("sql", help="the statement", from_file=True)
_TABLE = ArgSpec("table", help="a table or view: NAME, SCHEMA.NAME or DB.SCHEMA.NAME")
_SCHEMA = ArgSpec(
    "schema",
    help="Oracle only: resolve names in this schema (ALTER SESSION SET CURRENT_SCHEMA)",
    required=False,
    flag="--schema",
)

OPERATIONS: tuple[OperationSpec, ...] = (
    OperationSpec("query", "run a read-only statement", (_SQL, _SCHEMA), params=True),
    OperationSpec(
        "write",
        "run one INSERT, UPDATE, MERGE or DELETE in a transaction (--dry-run rolls it back)",
        (_SQL,),
        params=True,
        dry_run=True,
        rows=False,
    ),
    OperationSpec(
        "tables",
        "list tables and views",
        (ArgSpec("like", help="a LIKE pattern", required=False, flag="--like"), _SCHEMA),
    ),
    OperationSpec("describe", "describe the columns of a table", (_TABLE, _SCHEMA)),
    OperationSpec(
        "count",
        "count the rows of a table, optionally under a condition",
        (
            _TABLE,
            ArgSpec("where", help="a condition; bind values with -p", required=False),
            _SCHEMA,
        ),
        params=True,
    ),
    OperationSpec(
        "sample",
        "show a few rows of a table",
        (_TABLE, ArgSpec("n", "int", "how many rows (default 5)", required=False), _SCHEMA),
    ),
    OperationSpec(
        "plan",
        "Oracle only: show the execution plan of a SELECT (EXPLAIN PLAN, DBMS_XPLAN)",
        (_SQL, _SCHEMA),
        params=True,
    ),
)

_SCHEMA_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_$#]{0,127}")
_UNQUOTED = re.compile(r"[A-Za-z_][A-Za-z0-9_$#]{0,127}")
_BAD_IN_QUOTED = frozenset("\x00\r\n")
_FORM = (
    "use NAME, SCHEMA.NAME or DB.SCHEMA.NAME; a part is letters, digits, _, $ and # (not "
    'starting with a digit), or any text in "double quotes"'
)


def parse_identifier(text: str) -> str:
    """A table name of one to three dotted parts, each plain or quoted (M14). Raises
    `BadArguments`; the result is `text` itself, validated."""
    parts = 0
    i, n = 0, len(text)
    while True:
        if i < n and text[i] == '"':
            j = i + 1
            while True:
                if j >= n or text[j] in _BAD_IN_QUOTED:
                    raise BadArguments(f"{text!r} is not a table name: {_FORM}")
                if text[j] == '"':
                    if j + 1 < n and text[j + 1] == '"':
                        j += 2
                        continue
                    break
                j += 1
            if j == i + 1:
                raise BadArguments(f"{text!r} is not a table name: an empty quoted part")
            i = j + 1
        else:
            match = _UNQUOTED.match(text, i)
            if match is None:
                raise BadArguments(f"{text!r} is not a table name: {_FORM}")
            i = match.end()
        parts += 1
        if i == n:
            break
        if text[i] != ".":
            raise BadArguments(f"{text!r} is not a table name: {_FORM}")
        i += 1
    if parts > 3:
        raise BadArguments(f"{text!r} is not a table name: at most three parts, {_FORM}")
    return text


def schema_of(call: Call) -> str | None:
    """The `--schema` of a call (M14), or None. Raises `BadArguments` for a name that is not a
    plain identifier."""
    schema = call.args.get("schema")
    if schema is None:
        return None
    if not isinstance(schema, str) or not _SCHEMA_NAME.fullmatch(schema):
        raise BadArguments(
            f"{schema!r} is not a schema name: a letter, then letters, digits, _, $ and #, at "
            "most 128 characters in all"
        )
    return schema


def typed_params(call: Call) -> tuple[TypedParam, ...]:
    """The call's `args.params` (shape checked by the broker) as typed parameters."""
    raw = cast("Mapping[str, Mapping[str, object]]", call.args.get("params") or {})
    return tuple(
        TypedParam(name, cast("ParamType", p["t"]), cast("str | int | None", p["v"]))
        for name, p in raw.items()
    )


@dataclass(frozen=True)
class Prepared:
    """The statement a call runs, as classified: with `:name` placeholders, and its binds."""

    text: str
    params: tuple[TypedParam, ...]


def _string(call: Call, key: str) -> str:
    value = call.args.get(key)
    if not isinstance(value, str) or not value.strip():
        raise BadArguments(f"op {call.op} needs a non-empty {key!r}")
    return value


def sample_size(call: Call) -> int:
    n = call.args.get("n", DEFAULT_SAMPLE)
    if type(n) is not int or n < 1:
        raise BadArguments(f"sample: n must be a positive whole number, not {n!r}")
    return n


def statement_text(call: Call, dialect: SqlDialect) -> Prepared:
    """The SQL of a call, assembled before classification (M14). Raises `BadArguments`."""
    op = call.op
    if op in ("query", "write", "plan"):
        return Prepared(_string(call, "sql"), typed_params(call))
    if op == "tables":
        like = call.args.get("like", "%")
        if not isinstance(like, str):
            raise BadArguments("tables: --like must be a string")
        query = dialect.tables_query(in_schema=schema_of(call) is not None)
        return Prepared(query, (TypedParam("pattern", "str", like),))
    table = parse_identifier(_string(call, "table"))
    if op == "describe":
        return Prepared(dialect.describe_query().replace("{table}", table), ())
    if op == "sample":
        sql = (
            dialect.sample_query().replace("{table}", table).replace("{n}", str(sample_size(call)))
        )
        return Prepared(sql, ())
    if op == "count":
        sql = f"select count(*) from {table}"
        where = call.args.get("where")
        if where is not None:
            if not isinstance(where, str) or not where.strip():
                raise BadArguments("count: the condition must be a non-empty string")
            sql = f"{sql} where {where}"
        return Prepared(sql, typed_params(call))
    raise BadArguments(f"the sql connector has no op {op!r}")


def bind_call(call: Call, dialect: SqlDialect, *, lenient: bool = False) -> BoundSql:
    """What the driver runs: the statement without its trailing `;`, with `:1…:n` binds (M12,
    M13). Raises `BadArguments`.

    `lenient` (validation, which runs before classification) lets text the tokenizer cannot read
    through: classification refuses it next, with the parser's message.
    """
    prepared = statement_text(call, dialect)
    style = dialect.sqlglot_dialect
    try:
        text = executable_sql(prepared.text, style)
    except Exception as exc:
        if not lenient:
            raise BadArguments(parse_message(exc)) from exc
        text = prepared.text
    try:
        return bind(text, prepared.params, dialect=style, style=dialect.bind_style)
    except BindError as exc:
        raise BadArguments(str(exc)) from exc


def validate(call: Call, dialect: SqlDialect, *, max_rows: int) -> None:
    """The arguments of an op beyond its spec (M6 step 3): identifiers, `n`, binds."""
    if dialect.name not in SCHEMA_DIALECTS:
        if call.op == "plan":
            raise BadArguments("the plan op is available on Oracle targets only")
        if "schema" in call.args:
            raise BadArguments("--schema is available on Oracle targets only")
    schema_of(call)
    if call.op == "sample":
        n = sample_size(call)
        if n > max_rows:
            raise BadArguments(f"sample: n is {n}, above the call's maxRows {max_rows}")
    bound = bind_call(call, dialect, lenient=True)
    for param in bound.params:
        try:
            dialect.bind_value(param)
        except BindError as exc:  # a value the dialect refuses, such as an Oracle zone
            raise BadArguments(str(exc)) from exc


# --- the contracts ---------------------------------------------------------------------------

_EXEMPT = frozenset({"sql:session", "sql:use", "sql:transaction"})
_WRITE_STATEMENTS = frozenset({"insert", "update", "merge", "delete"})


def _violation(op: str, action: Action) -> str | None:
    statement = action.facts.get("statement")
    if op in ("query", "plan"):
        if action.facts.get("kind") != "query":
            if op == "plan":
                return f"the plan op explains SELECT statements; this is {action.name}"
            return (
                f"the query op runs SELECT statements; this is {action.name}. Use the `write` op "
                "for INSERT, UPDATE, MERGE and DELETE; tables, describe, count and sample "
                "cover the rest"
            )
        if action.risk is Risk.WRITE:
            return f"the {op} has write effects (FOR UPDATE or a sequence's NEXTVAL): " + (
                "use the `write` op" if op == "query" else "it is not explained"
            )
        return None
    if op == "write":
        if statement not in _WRITE_STATEMENTS:
            return (
                "the write op takes exactly one INSERT, UPDATE, MERGE or DELETE statement; "
                f"this is {action.name}"
            )
        return None
    wanted = ("describe", "select") if op == "describe" else ("select",)
    if statement not in wanted:
        return f"the {op} op builds a {' or '.join(wanted)} statement; the result is {action.name}"
    return None


def apply_contract(op: str, action: Action) -> Action:
    """Hold a classified action to its op's contract (M14). What the engine refuses on its own
    (unknown, secret, the session, USE and transaction invariants, a second statement) keeps its
    own message."""
    if (
        action.risk in (Risk.UNKNOWN, Risk.SECRET)
        or action.invariant_hits
        or action.name in _EXEMPT
    ):
        return action
    reason = _violation(op, action)
    if reason is None:
        return action
    return replace(action, invariant_hits=(OP_CONTRACT,), detail=reason)
