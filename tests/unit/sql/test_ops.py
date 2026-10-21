"""The `sql` op contracts, identifiers and statement assembly (M14)."""

from __future__ import annotations

import pytest

from modgudr.spi import BadArguments, Call, Risk
from modgudr.sql.config import SqlConfig
from modgudr.sql.connector import ACTIONS, CHECKS, SqlConnector
from modgudr.sql.dialects.snowflake import SnowflakeDialect
from modgudr.sql.ops import apply_contract, bind_call, parse_identifier, statement_text, validate

DIALECT = SnowflakeDialect()
CONFIG = SqlConfig.model_validate(
    {
        "dialect": "snowflake",
        "account": "acme-example",
        "user": "U",
        "role": "R",
        "warehouse": "W",
    }
)


def call(op: str, **args: object) -> Call:
    return Call(target="t", op=op, args=args)


@pytest.mark.parametrize(
    "name", ["po", "PO", "_x", "a$b#c", "s.po", "db.s.po", '"My Table"', 'db."s"."a""b"', "a1"]
)
def test_valid_identifiers(name: str) -> None:
    assert parse_identifier(name) == name


@pytest.mark.parametrize(
    "name",
    ["", ".", "a.", ".a", "a..b", "a.b.c.d", "1a", "a b", "a;b", "a-b", '"', '""', '"a', 'a"b"',
     '"a"b', "a\nb", '"a\nb"', "x" * 129, "a'b", "a(b)"],
)  # fmt: skip
def test_invalid_identifiers(name: str) -> None:
    with pytest.raises(BadArguments, match="not a table name"):
        parse_identifier(name)


def test_template_statements() -> None:
    assert statement_text(call("describe", table="s.po"), DIALECT).text == "describe table s.po"
    assert statement_text(call("sample", table="po"), DIALECT).text == "select * from po limit 5"
    assert statement_text(call("sample", table="po", n=7), DIALECT).text.endswith("limit 7")
    assert statement_text(call("count", table="po"), DIALECT).text == "select count(*) from po"
    where = statement_text(call("count", table="po", where="a = :a"), DIALECT)
    assert where.text == "select count(*) from po where a = :a"
    tables = statement_text(call("tables"), DIALECT)
    assert [(p.name, p.value) for p in tables.params] == [("pattern", "%")]
    assert statement_text(call("tables", like="X%"), DIALECT).params[0].value == "X%"


def test_bind_call_strips_the_semicolon_and_numbers_the_binds() -> None:
    params = {"b": {"t": "int", "v": 2}, "a": {"t": "str", "v": "x"}}
    bound = bind_call(
        call("query", sql="select 1 where a = :a and b = :b;", params=params), DIALECT
    )
    assert bound.sql == "select 1 where a = :1 and b = :2"
    assert [p.name for p in bound.params] == ["a", "b"]


def test_validation_errors_are_bad_arguments() -> None:
    with pytest.raises(BadArguments, match="missing parameter"):
        validate(call("query", sql="select :a"), DIALECT, max_rows=10)
    with pytest.raises(BadArguments, match="unused parameter"):
        validate(
            call("query", sql="select 1", params={"a": {"t": "int", "v": 1}}), DIALECT, max_rows=10
        )
    with pytest.raises(BadArguments, match="positive"):
        validate(call("sample", table="po", n=0), DIALECT, max_rows=10)
    with pytest.raises(BadArguments, match="above the call's maxRows 10"):
        validate(call("sample", table="po", n=11), DIALECT, max_rows=10)
    with pytest.raises(BadArguments, match="not a table name"):
        validate(call("describe", table="a b"), DIALECT, max_rows=10)


def test_text_the_tokenizer_cannot_read_is_left_to_the_classifier() -> None:
    validate(call("query", sql="select 'unterminated"), DIALECT, max_rows=10)
    action = SqlConnector().classify(call("query", sql="select 'unterminated"), CONFIG)
    assert action.risk is Risk.UNKNOWN


@pytest.mark.parametrize(
    ("op", "sql", "hit"),
    [
        ("query", "select 1", False),
        ("query", "with x as (select 1 as a) select a from x", False),
        ("query", "update t set a = 1 where b = 2", True),
        ("query", "select * from t for update", True),
        ("query", "describe table t", True),
        ("query", "select 1; select 2", False),  # the engine's own multi-statement refusal
        ("query", "use role admin", False),  # the engine's own invariant
        ("write", "update t set a = 1 where b = 2", False),
        ("write", "insert into t select * from u", False),
        ("write", "merge into t using u on t.a = u.a when matched then update set t.b = 1", False),
        ("write", "delete from t where a = 1", False),
        ("write", "select 1", True),
        ("write", "truncate table t", True),
        ("write", "copy into t from @s", True),
        ("write", "create table t (a int)", True),
        ("write", "drop table t", True),
    ],
)
def test_the_op_contract(op: str, sql: str, hit: bool) -> None:
    action = SqlConnector().classify(call(op, sql=sql), CONFIG)
    assert ("op-contract" in action.invariant_hits) is hit, action


def test_unclassifiable_and_secret_calls_keep_their_own_refusal() -> None:
    unknown = SqlConnector().classify(call("query", sql="select ("), CONFIG)
    assert unknown.risk is Risk.UNKNOWN and not unknown.invariant_hits
    secret = SqlConnector().classify(call("query", sql="show secrets"), CONFIG)
    assert secret.risk is Risk.SECRET and not secret.invariant_hits


def test_apply_contract_leaves_the_session_invariants_alone() -> None:
    action = SqlConnector().classify(call("write", sql="alter session set x = 1"), CONFIG)
    assert action.name == "sql:session" and not action.invariant_hits
    assert apply_contract("write", action) is action


def test_the_catalogue_covers_what_the_classifier_names() -> None:
    names = {spec.name for spec in ACTIONS}
    samples = [
        "select 1",
        "insert into t values (1)",
        "update t set a = 1",
        "delete from t",
        "merge into t using u on t.a = u.a when matched then delete",
        "copy into t from @s",
        "copy into @s from t",
        "truncate table t",
        "create table t (a int)",
        "alter table t add column b int",
        "drop table t",
        "undrop table t",
        "comment on table t is 'x'",
        "grant select on t to role r",
        "revoke select on t from role r",
        "describe table t",
        "show tables",
        "use role r",
        "set a = 1",
        "begin; select 1; end;",
        "put file:///x @s",
        "get @s file:///x",
        "remove @s",
        "commit",
        "alter session set a = 1",
    ]
    seen = {SqlConnector().classify(call("query", sql=s), CONFIG).local_name for s in samples}
    assert seen - {"unknown"} <= names, seen - names


def test_connector_surface() -> None:
    connector = SqlConnector()
    assert connector.type == "sql" and connector.config_model is SqlConfig
    assert [o.name for o in connector.operations()] == [
        "query",
        "write",
        "tables",
        "describe",
        "count",
        "sample",
    ]
    assert [r.pattern for r in connector.default_rules().allow] == ["read"]
    assert set(CHECKS) == {"requireWhere", "maxAffectedRows"}
    constrained = {s.name: s.constraints for s in ACTIONS if s.constraints}
    assert constrained["update"] == {"requireWhere", "maxAffectedRows"}
    assert constrained["delete"] == {"requireWhere", "maxAffectedRows"}
    assert constrained["insert"] == {"maxAffectedRows"}
