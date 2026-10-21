"""Bind parameters on the broker side (§8.1, M13): placeholders, the numeric rewrite, values.

The only placeholder style is `:name`, an ASCII identifier matched case-insensitively to the
caller's parameter names. Placeholders are found with the dialect's tokenizer, so text inside
strings and comments, `::` casts and Snowflake `v:field` paths are left alone. Every problem is a
`BindError` (`bad_request`, exit 64), raised before any driver call.

The functions take the sqlglot dialect name, so every dialect shares them: Oracle binds natively
by name, Snowflake gets `:1…:n` positions with a self-check against the parse tree.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal

from sqlglot import Token, TokenType, exp

from modgudr.spi import BindStyle, TypedParam

from .classify import (
    MAX_STATEMENT_CHARS,
    PARSE_SECONDS,
    ClassifyTimeout,
    parse_message,
    parse_statements,
    run_limited,
    tokens,
)

#: A bind value as the shared parser returns it; each dialect maps it for its driver.
BindValue = str | int | Decimal | date | datetime | bytes | None

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
#: The previous tokens after which `:x` is a path (`v:field`, `f(x):a`, `arr[0]:a`), not a bind.
_PATH_BEFORE = frozenset(
    {TokenType.VAR, TokenType.IDENTIFIER, TokenType.R_PAREN, TokenType.R_BRACKET}
)
#: Tokens after a colon that are never a placeholder name: `:'x'`, `:"x"`.
_NOT_A_NAME = frozenset({TokenType.STRING, TokenType.IDENTIFIER})

# The value gates mirror the client's (`modgudr.client.params`); the broker checks again because
# any program on the socket can send a request.
_INT = re.compile(r"[+-]?[0-9]{1,38}")
_DECIMAL = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}"
    r"(?::[0-9]{2}(?:\.[0-9]{1,6})?)?(?:Z|[+-][0-9]{2}:[0-9]{2})?"
)
_BASE64 = re.compile(r"[A-Za-z0-9+/]*={0,2}")


class BindError(ValueError):
    """A bind parameter problem (M13): `bad_request`, before any driver call."""


@dataclass(frozen=True)
class Placeholder:
    """One `:name` in the statement text: the colon's offset and the offset after the name."""

    name: str
    start: int
    end: int

    @property
    def key(self) -> str:
        """The name as parameters are matched: case-insensitively."""
        return self.name.upper()


@dataclass(frozen=True)
class BoundSql:
    """A statement ready for the driver: its text and its parameters in bind order.

    `numeric` style: the text has `:1…:n` and `params[i]` belongs to `:i+1`. `named` style: the
    text is unchanged and `params` are in the order of first appearance.
    """

    sql: str
    params: tuple[TypedParam, ...]


def _names(placeholders: Sequence[Placeholder]) -> str:
    return ", ".join(dict.fromkeys(f":{p.name}" for p in placeholders)) or "none"


def find_placeholders(sql: str, dialect: str) -> tuple[Placeholder, ...]:
    """Every `:name` placeholder of `sql` in text order (M13).

    A colon is a bind when the next token is adjacent and a name or keyword and the previous
    token is not a name, a quoted identifier, `)` or `]`. Raises `BindError` for a positional
    placeholder (`:1`, `?`), a name that is not an ASCII identifier, or text the tokenizer
    cannot read.
    """
    try:
        toks = tokens(sql, dialect)
    except Exception as exc:
        raise BindError(f"cannot find the placeholders: {parse_message(exc)}") from exc
    return _scan(sql, toks)


def _scan(sql: str, toks: Sequence[Token]) -> tuple[Placeholder, ...]:
    found: list[Placeholder] = []
    for i, token in enumerate(toks):
        if token.token_type is TokenType.PLACEHOLDER:
            raise BindError(
                f"positional placeholder {token.text!r} at offset {token.start}: name it, as in "
                ":name"
            )
        if token.token_type is not TokenType.COLON or i + 1 >= len(toks):
            continue
        after: Token = toks[i + 1]
        before: Token | None = toks[i - 1] if i > 0 else None
        if after.start != token.end + 1 or after.token_type in _NOT_A_NAME:
            continue
        if before is not None and before.token_type in _PATH_BEFORE:
            continue
        text = sql[after.start : after.end + 1]
        if after.token_type is TokenType.NUMBER or text[:1].isdigit():
            raise BindError(f"positional placeholder :{text}: name it, as in :name")
        if not _NAME.fullmatch(text):
            raise BindError(
                f"placeholder :{text} is not an ASCII identifier (letters, digits, underscore)"
            )
        found.append(Placeholder(text, token.start, after.end + 1))
    return tuple(found)


def _by_key(params: Sequence[TypedParam]) -> dict[str, TypedParam]:
    out: dict[str, TypedParam] = {}
    for param in params:
        if not _NAME.fullmatch(param.name):
            raise BindError(
                f"parameter {param.name!r}: the name must be an ASCII identifier (letters, "
                "digits, underscore; not starting with a digit)"
            )
        key = param.name.upper()
        if key in out:
            raise BindError(
                f"duplicate parameter {param.name!r} (already given as {out[key].name!r}; names "
                "are case-insensitive)"
            )
        out[key] = param
    return out


def _in_name_position(node: exp.Placeholder) -> bool:
    """Whether a placeholder stands for a name (a table, a column, an alias), not a value."""
    parent = node.parent
    if isinstance(parent, exp.Table | exp.DynamicIdentifier | exp.Identifier | exp.Dot):
        return True
    if isinstance(parent, exp.Column) and node.arg_key in ("this", "table", "db", "catalog"):
        return True
    return isinstance(parent, exp.Alias | exp.TableAlias) and node.arg_key == "alias"


def _parse(sql: str, dialect: str) -> list[exp.Expr]:
    if len(sql) > MAX_STATEMENT_CHARS:
        raise BindError(f"the statement is longer than {MAX_STATEMENT_CHARS} characters")
    try:
        return run_limited(lambda: parse_statements(sql, dialect), PARSE_SECONDS)
    except ClassifyTimeout as exc:
        raise BindError(f"checking the placeholders took longer than {PARSE_SECONDS:g} s") from exc
    except Exception as exc:
        raise BindError(
            f"the statement does not parse, so its parameters cannot be checked: "
            f"{parse_message(exc)}"
        ) from exc


def _renamed(trees: Sequence[exp.Expr], index: dict[str, int]) -> list[exp.Expr]:
    def rename(node: exp.Expr) -> exp.Expr:
        if isinstance(node, exp.Placeholder) and node.name.upper() in index:
            return exp.Placeholder(this=str(index[node.name.upper()]))
        return node

    return [tree.transform(rename) for tree in trees]


def _rewrite(sql: str, placeholders: Sequence[Placeholder], index: dict[str, int]) -> str:
    out = sql
    for placeholder in reversed(placeholders):  # right to left keeps the offsets valid
        out = f"{out[: placeholder.start]}:{index[placeholder.key]}{out[placeholder.end :]}"
    return out


def bind(sql: str, params: Sequence[TypedParam], *, dialect: str, style: BindStyle) -> BoundSql:
    """Match the caller's parameters to the placeholders of `sql` and prepare the text (M13).

    Refuses (`BindError`): a placeholder without a parameter, a parameter without a placeholder,
    duplicate names (also by case), positional placeholders (`:1`, `?`), placeholders in name
    position, and values that do not match their type. For `numeric` style the placeholders are
    rewritten to `:1…:n` in order of first appearance (the same name keeps its position) and the
    rewritten tree must equal the original with the placeholders renamed.
    """
    by_key = _by_key(params)
    for param in params:
        parse_value(param)
    try:
        toks = tokens(sql, dialect)
    except Exception as exc:
        if not params:
            # Nothing to bind: classification refuses what does not tokenise.
            return BoundSql(sql, ())
        raise BindError(f"cannot find the placeholders: {parse_message(exc)}") from exc
    placeholders = _scan(sql, toks)
    order = list(dict.fromkeys(p.key for p in placeholders))
    spelled = {p.key: p.name for p in reversed(placeholders)}
    for key in order:
        if key not in by_key:
            name = spelled[key]
            raise BindError(
                f"missing parameter {name}: the statement uses :{name}; give it with -p"
            )
    for key, param in by_key.items():
        if key not in spelled:
            raise BindError(
                f"unused parameter {param.name}: the statement has no :{param.name}; its "
                f"placeholders: {_names(placeholders)}"
            )
    if not placeholders and style == "named":
        return BoundSql(sql, ())
    try:
        trees = _parse(sql, dialect)
    except BindError:
        if placeholders:
            raise
        # Nothing to bind and nothing to check: classification refuses what does not parse.
        return BoundSql(sql, ())
    for tree in trees:
        for node in tree.find_all(exp.Placeholder):
            if _in_name_position(node):
                raise BindError(
                    f"parameter {node.name} stands for a name; parameters may only stand for values"
                )
    ordered = tuple(by_key[key] for key in order)
    if style == "named":
        return BoundSql(sql, ordered)
    index = {key: position for position, key in enumerate(order, start=1)}
    rewritten = _rewrite(sql, placeholders, index)
    after = _parse(rewritten, dialect) if placeholders else trees
    survivors = [
        node.name
        for tree in after
        for node in tree.find_all(exp.Placeholder)
        if not node.name.isdigit()
    ]
    # The parser may see a placeholder the token rule does not (`x = : b`): it must not survive.
    if survivors or _renamed(trees, index) != after:
        shown = f":{survivors[0]}" if survivors else _names(placeholders)
        raise BindError(
            f"the placeholders cannot be rewritten safely ({shown}); write each one as :name "
            "standing alone for a value"
        )
    return BoundSql(rewritten, ordered)


def parse_value(param: TypedParam) -> BindValue:
    """A typed parameter (M4, M13) as a Python value; ASCII-strict, a regex gate before
    `fromisoformat`. Raises `BindError`."""
    kind, value, name = param.type, param.value, param.name
    if kind == "null":
        if value is not None:
            raise BindError(f"parameter {name}: type null takes no value")
        return None
    if kind == "int":
        if type(value) is not int or not _INT.fullmatch(str(value)):
            raise BindError(f"parameter {name}: not an integer of at most 38 digits")
        return value
    if not isinstance(value, str):
        raise BindError(f"parameter {name}: a {kind} value must be a string")
    if kind == "str":
        return value
    if kind == "decimal":
        if not _DECIMAL.fullmatch(value):
            raise BindError(f"parameter {name}: {value!r} is not a plain decimal literal")
        return Decimal(value)
    if kind == "date":
        if not _DATE.fullmatch(value):
            raise BindError(f"parameter {name}: {value!r} is not a date (YYYY-MM-DD)")
        try:
            return date.fromisoformat(value)
        except ValueError as exc:
            raise BindError(f"parameter {name}: {value!r} is not a valid date") from exc
    if kind == "timestamp":
        if not _TIMESTAMP.fullmatch(value):
            raise BindError(
                f"parameter {name}: {value!r} is not an ISO timestamp "
                "(YYYY-MM-DDTHH:MM[:SS[.ffffff]][Z|+HH:MM])"
            )
        try:
            return datetime.fromisoformat(value)
        except ValueError as exc:
            raise BindError(f"parameter {name}: {value!r} is not a valid timestamp") from exc
    if kind == "bytes":
        if not _BASE64.fullmatch(value):
            raise BindError(f"parameter {name}: the value is not strict base64")
        try:
            return base64.b64decode(value.encode("ascii"), validate=True)
        except (UnicodeEncodeError, binascii.Error) as exc:
            raise BindError(f"parameter {name}: the value is not strict base64") from exc
    raise BindError(f"parameter {name}: unknown type {kind!r}")
