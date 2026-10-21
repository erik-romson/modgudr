"""Bind parameters (M13): the placeholder scanner, the numeric rewrite and its self-check, values.

The scanner takes the sqlglot dialect name; the Oracle row shows it is shared before the Oracle
dialect exists.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta, timezone
from decimal import Decimal

import pytest

from modgudr.spi import ParamType, TypedParam
from modgudr.sql.binds import BindError, BoundSql, bind, find_placeholders, parse_value
from modgudr.sql.classify import MAX_STATEMENT_CHARS


def _p(name: str, value: str | int | None = "x", kind: ParamType = "str") -> TypedParam:
    return TypedParam(name, kind, value)


def _names(sql: str, dialect: str = "snowflake") -> list[str]:
    return [p.name for p in find_placeholders(sql, dialect)]


def _refused(sql: str, params: list[TypedParam], match: str, dialect: str = "snowflake") -> None:
    style = "numeric" if dialect == "snowflake" else "named"
    with pytest.raises(BindError, match=match):
        bind(sql, params, dialect=dialect, style=style)


# --- the scanner -------------------------------------------------------------------------------


def test_snowflake_paths_and_casts_are_not_placeholders() -> None:
    sql = "select v:a.b::string, v:c, :b, x::int from t where c = :b -- :ignored"
    assert _names(sql) == ["b", "b"]
    bound = bind(sql, [_p("b", 7, "int")], dialect="snowflake", style="numeric")
    assert bound == BoundSql(
        "select v:a.b::string, v:c, :1, x::int from t where c = :1 -- :ignored",
        (_p("b", 7, "int"),),
    )


def test_oracle_strings_comments_and_q_quotes_hold_no_placeholders() -> None:
    sql = (
        "select '12:30', to_char(d, 'HH24:MI'), :ID, q'[:x]' from t "
        "where x = :ID -- :ignored /* :ignored */"
    )
    assert _names(sql, "oracle") == ["ID", "ID"]
    bound = bind(sql, [_p("id")], dialect="oracle", style="named")
    assert bound == BoundSql(sql, (_p("id"),))


@pytest.mark.parametrize(
    "sql",
    [
        "select f(x):a from t",
        "select arr[0]:a from t",
        'select "V":a from t',
        "select t.v:a from t",
        "select x from t where c = : b",  # not adjacent
        "select $$:x$$, '/* :y */', \"a:b\" from t // :z",
        "select x::date from t",
    ],
)
def test_not_placeholders(sql: str) -> None:
    assert _names(sql) == []


def test_placeholders_at_the_start_and_after_keywords() -> None:
    assert _names(":a") == ["a"]
    assert _names("call p(:x)") == ["x"]  # a command keyword would otherwise swallow the text
    assert _names("select case when x then :a else :b end, (:c)") == ["a", "b", "c"]
    assert _names("select :date, :END from t") == ["date", "END"]  # source spelling of keywords


@pytest.mark.parametrize(
    ("sql", "match"),
    [
        ("select :1", "positional placeholder :1"),
        ("select * from t where id = :12", "positional placeholder :12"),
        ("select ?", "positional placeholder '\\?'"),
        ("select :a$b from t", "placeholder :a\\$b is not an ASCII identifier"),
    ],
)
def test_positional_and_odd_placeholders_are_refused(sql: str, match: str) -> None:
    with pytest.raises(BindError, match=match):
        find_placeholders(sql, "snowflake")
    _refused(sql, [], match)


# --- matching names ----------------------------------------------------------------------------


def test_names_match_case_insensitively_and_keep_their_first_position() -> None:
    sql = "select :a, :B, :A, :date from t where x = :b"
    params = [_p("A", 1, "int"), _p("b"), _p("DATE", "2026-10-21", "date")]
    bound = bind(sql, params, dialect="snowflake", style="numeric")
    assert bound.sql == "select :1, :2, :1, :3 from t where x = :2"
    assert [p.name for p in bound.params] == ["A", "b", "DATE"]


def test_named_style_keeps_the_text_and_orders_by_first_appearance() -> None:
    sql = "select * from t where a = :USERNAME and b > :FROM_TS and c = :username"
    params = [_p("from_ts", "2026-10-21T08:00:00", "timestamp"), _p("username")]
    bound = bind(sql, params, dialect="oracle", style="named")
    assert bound.sql == sql
    assert [p.name for p in bound.params] == ["username", "from_ts"]


def test_missing_parameter() -> None:
    _refused("select * from t where x = :ID", [], "missing parameter ID")
    _refused("select * from t where x = :ID", [], "missing parameter ID", "oracle")


def test_unused_parameter() -> None:
    _refused("select 1", [_p("foo")], "unused parameter foo: .* placeholders: none")
    _refused("select :a", [_p("a"), _p("foo")], "unused parameter foo: .* placeholders: :a")


def test_duplicate_parameter_by_case() -> None:
    _refused("select :id", [_p("id"), _p("ID")], "duplicate parameter 'ID'")


def test_parameter_names_are_ascii_identifiers() -> None:
    _refused("select 1", [_p("1x")], "must be an ASCII identifier")
    _refused("select 1", [_p("é")], "must be an ASCII identifier")


@pytest.mark.parametrize(
    "sql",
    [
        "select * from identifier(:t)",
        "select * from :t",
        "select * from :t.x",
        "select :t.c from x",
        "select 1 as :t",
    ],
)
def test_binds_in_name_position_are_refused(sql: str) -> None:
    _refused(sql, [_p("t")], "parameter t stands for a name")


def test_the_self_check_refuses_what_the_rewrite_would_change() -> None:
    # `$1:a` is a path on a positional column: the token rule takes `:a` for a bind, the tree
    # does not, so the rewritten tree differs and the call is refused.
    _refused("select $1:a from @s", [_p("a")], "cannot be rewritten safely")
    # Inside a command tail the parser sees no placeholder at all.
    _refused("call p(:x)", [_p("x")], "cannot be rewritten safely")


def test_no_named_placeholder_may_survive() -> None:
    # sqlglot reads `: b` as a placeholder; the token rule does not, so nothing would bind it.
    _refused("select x from t where c = : b", [], "cannot be rewritten safely \\(:b\\)")


def test_without_placeholders_or_parameters_nothing_changes() -> None:
    sql = "select v:a::int from t;"
    assert bind(sql, [], dialect="snowflake", style="numeric") == BoundSql(sql, ())
    # What does not parse is left to the classifier, which refuses it as unknown.
    broken = "select from where"
    assert bind(broken, [], dialect="snowflake", style="numeric") == BoundSql(broken, ())
    assert bind("select 'abc", [], dialect="snowflake", style="numeric").params == ()


def test_binds_of_an_unparseable_statement_are_refused() -> None:
    _refused("select from where x = :a", [_p("a")], "does not parse")
    _refused("select 'abc", [_p("a")], "cannot find the placeholders")
    _refused(" " * MAX_STATEMENT_CHARS + "select :a", [_p("a")], "longer than")


# --- values ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("param", "expected"),
    [
        (_p("p", "x"), "x"),
        (_p("p", 12, "int"), 12),
        (_p("p", -(10**37), "int"), -(10**37)),
        (_p("p", "1.50", "decimal"), Decimal("1.50")),
        (_p("p", "-.5", "decimal"), Decimal("-0.5")),
        (_p("p", "2026-10-21", "date"), date(2026, 10, 21)),
        (_p("p", "2026-10-21T08:00", "timestamp"), datetime(2026, 10, 21, 8)),
        (
            _p("p", "2026-10-21 08:00:01.123456", "timestamp"),
            datetime(2026, 10, 21, 8, 0, 1, 123456),
        ),
        (
            _p("p", "2026-10-21T08:00:00+02:00", "timestamp"),
            datetime(2026, 10, 21, 8, tzinfo=timezone(timedelta(hours=2))),
        ),
        (_p("p", "2026-10-21T08:00:00Z", "timestamp"), datetime(2026, 10, 21, 8, tzinfo=UTC)),
        (_p("p", "aGk=", "bytes"), b"hi"),
        (_p("p", "", "bytes"), b""),
        (_p("p", None, "null"), None),
    ],
)
def test_values(param: TypedParam, expected: object) -> None:
    assert parse_value(param) == expected


@pytest.mark.parametrize(
    "param",
    [
        _p("p", 10**38, "int"),
        _p("p", "1", "int"),
        _p("p", 1, "str"),
        _p("p", "1e5", "decimal"),
        _p("p", "1,5", "decimal"),
        _p("p", "١٢", "decimal"),
        _p("p", "2026-02-30", "date"),
        _p("p", "2026-1-2", "date"),
        _p("p", "2026-10-21T08:00:00.1234567", "timestamp"),
        _p("p", "2026-10-21T25:00:00", "timestamp"),
        _p("p", "aGk", "bytes"),
        _p("p", "a Gk=", "bytes"),
        _p("p", "x", "null"),
    ],
)
def test_bad_values_are_refused(param: TypedParam) -> None:
    with pytest.raises(BindError, match="parameter p"):
        parse_value(param)


def test_bind_checks_values_before_anything_else() -> None:
    _refused("select :p", [_p("p", "2026-02-30", "date")], "not a valid date")
