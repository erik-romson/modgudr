"""The classification shared by every dialect (M12): limits, statement count, the whitelist, the
`exp.Command` mapping, the maximum over the tree, catalogues, `requireWhere` and the invariants.

The rules here are built by hand, so they show what the shared code does for any dialect; the
Snowflake corpus shows what the Snowflake dialect adds.
"""

from __future__ import annotations

import threading
import time

import pytest

from modgudr.broker.engine.decide import Scope, decide
from modgudr.spi import Action, Layer, Risk, Rule, RuleSet
from modgudr.sql import classify as classify_module
from modgudr.sql.catalogue import (
    Catalogue,
    DialectRules,
    WordRule,
    function_name,
    object_name,
)
from modgudr.sql.classify import (
    INVARIANTS,
    MAX_STATEMENT_CHARS,
    MULTI_STATEMENT,
    RequireWhere,
    classify,
    executable_sql,
    tokens,
    words,
)
from modgudr.sql.dialects.snowflake.catalogue import RULES as SNOWFLAKE

#: A dialect with nothing of its own: only the shared rules apply.
PLAIN = DialectRules("snowflake", Catalogue({}), Catalogue({}))

#: Oracle-like catalogues on the Oracle grammar, to show the shared lookups and normalisation.
ORACLE_LIKE = DialectRules(
    "oracle",
    functions=Catalogue(
        {
            "UTL_*": Risk.ADMIN,
            "DBMS_*": Risk.ADMIN,
            "DBMS_XPLAN.*": Risk.READ,
            "DBMS_LOB.SUBSTR": Risk.READ,
        }
    ),
    objects=Catalogue({"DBA_USERS": Risk.SECRET, "USER$": Risk.SECRET, "V$SQL": Risk.SECRET}),
    block_words=frozenset({"BEGIN", "DECLARE", "START"}),
)


def _is(sql: str, name: str, risk: Risk, rules: DialectRules = PLAIN) -> Action:
    action = classify(sql, rules)
    assert (action.name, action.risk) == (name, risk), f"{sql!r}: {action}"
    return action


def _unknown(sql: str, detail: str, rules: DialectRules = PLAIN) -> None:
    action = _is(sql, "sql:unknown", Risk.UNKNOWN, rules)
    assert detail in action.detail, action.detail


# --- limits and failures: never raises ---------------------------------------------------------


def test_statements_over_the_size_limit_are_refused_unparsed() -> None:
    longest = "select 1" + " " * (MAX_STATEMENT_CHARS - len("select 1"))
    _is(longest, "sql:select", Risk.READ)
    _unknown(longest + " ", f"at most {MAX_STATEMENT_CHARS} are classified")


def test_parsing_runs_in_a_worker_with_a_time_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    release = threading.Event()

    def slow(sql: str, dialect: str) -> list[object]:
        release.wait(5)
        return []

    monkeypatch.setattr(classify_module, "PARSE_SECONDS", 0.2)
    monkeypatch.setattr(classify_module, "parse_statements", slow)
    started = time.monotonic()
    try:
        _unknown("select 1", "longer than 0.2 s")
        assert time.monotonic() - started < 2
    finally:
        release.set()


def test_no_free_parse_slot_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    exhausted = threading.BoundedSemaphore(1)
    exhausted.acquire()
    monkeypatch.setattr(classify_module, "_PARSE_SLOTS", exhausted)
    monkeypatch.setattr(classify_module, "PARSE_SECONDS", 0.1)
    _unknown("select 1", "longer than 0.1 s")


@pytest.mark.parametrize(
    ("error", "detail"),
    [
        (RecursionError(), "nested too deeply"),
        (RuntimeError("boom"), "parse error: boom"),
    ],
)
def test_any_parser_exception_is_unknown(
    monkeypatch: pytest.MonkeyPatch, error: Exception, detail: str
) -> None:
    def fail(sql: str, dialect: str) -> list[object]:
        raise error

    monkeypatch.setattr(classify_module, "parse_statements", fail)
    _unknown("select 1", detail)


def test_a_failing_analysis_is_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object) -> object:
        raise KeyError("x")

    monkeypatch.setattr(classify_module, "_statement", fail)
    _unknown("select 1", "the classifier failed (KeyError)")


def test_parse_and_token_errors_name_the_place() -> None:
    _unknown("select * from where", "parse error at line 1, column")
    _unknown("select 'abc", "parse error")
    _unknown("select " + "(" * 3000 + "1" + ")" * 3000, "parse error")


# --- statement count (M12) ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "sql",
    ["select 1; select 2", "select 1;;", "call p() ; drop table t", "call p();drop table t"],
)
def test_more_than_one_statement_is_the_invariant(sql: str) -> None:
    action = classify(sql, PLAIN)
    assert action.invariant_hits == (MULTI_STATEMENT,)
    assert "one statement per call" in action.detail


def test_a_multi_statement_call_takes_its_most_dangerous_statement() -> None:
    action = classify("select 1; delete from po", PLAIN)
    assert (action.name, action.risk, action.invariant_hits) == (
        "sql:delete",
        Risk.DESTRUCTIVE,
        (MULTI_STATEMENT,),
    )
    assert action.facts["statements"] == 2


@pytest.mark.parametrize("sql", ["", ";;", "   ", "-- only a comment"])
def test_no_statement_is_unknown(sql: str) -> None:
    _unknown(sql, "the statement is empty")


@pytest.mark.parametrize(
    ("sql", "executed"),
    [
        ("select 1;", "select 1"),
        ("select 1 ;\n", "select 1 \n"),
        ("select 1; -- note", "select 1 -- note"),
        ("select 'a;b'", "select 'a;b'"),
        ("select 1", "select 1"),
        ("call p();", "call p()"),
    ],
)
def test_the_executed_text_is_the_classified_text_minus_one_trailing_semicolon(
    sql: str, executed: str
) -> None:
    assert executable_sql(sql, "snowflake") == executed


# --- first words (M12) -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "sql",
    [
        "begin",
        "BEGIN TRANSACTION",
        "/* a comment */ begin select 1; end",
        "-- a comment\ndeclare x int; begin null; end;",
    ],
)
def test_block_words_are_plsql_before_parsing(sql: str) -> None:
    action = _is(sql, "sql:plsql", Risk.ADMIN)
    assert action.facts == {"statement": "plsql", "kind": "other"}


def test_block_words_are_the_dialects() -> None:
    _is("start x", "sql:plsql", Risk.ADMIN, ORACLE_LIKE)
    assert classify("start transaction", PLAIN).name != "sql:plsql"


def test_leading_rules_see_words_not_strings_or_quoted_names() -> None:
    rules = DialectRules(
        "snowflake",
        Catalogue({}),
        Catalogue({}),
        leading=(WordRule.of("SELECT SECRET", "select", Risk.SECRET),),
    )
    _is("select secret from t", "sql:select", Risk.SECRET, rules)
    _is("select 'secret' from t", "sql:select", Risk.READ, rules)
    _is('select "SECRET" from t', "sql:select", Risk.READ, rules)
    sql = "call x(:a, 'b')"
    assert words(sql, tokens(sql, "snowflake")) == ["CALL", "X", "(", ":", "A", ","]


# --- the whitelist and the Command mapping (M12) -----------------------------------------------


@pytest.mark.parametrize(
    ("sql", "parsed_as"),
    [("savepoint s", "Alias"), ("exec p", "Alias"), ("list @s", "ListStage")],
)
def test_statements_outside_the_whitelist_are_unknown(sql: str, parsed_as: str) -> None:
    _unknown(sql, f"it parses as {parsed_as}")


@pytest.mark.parametrize(
    ("sql", "name", "risk"),
    [
        ("alter session set query_tag = 'x'", "sql:session", Risk.ADMIN),
        ("call p()", "sql:plsql", Risk.ADMIN),
        ("execute immediate 'select 1'", "sql:plsql", Risk.ADMIN),
        ("grant role r to user u", "sql:grant", Risk.ADMIN),
        ("revoke role r from user u", "sql:revoke", Risk.ADMIN),
        ("explain select 1", "sql:explain", Risk.READ),
    ],
)
def test_the_shared_command_mapping(sql: str, name: str, risk: Risk) -> None:
    _is(sql, name, risk)


def test_command_rules_are_the_dialects_and_everything_else_is_unknown() -> None:
    _unknown("show secrets", "SHOW SECRETS … is not a statement")
    _is("show secrets", "sql:show", Risk.SECRET, SNOWFLAKE)
    _unknown("show grants", "SHOW GRANTS", SNOWFLAKE)
    _unknown("alter user u set rsa_public_key = 'x'", "is not a statement")


def test_the_function_catalogue_never_applies_inside_a_command_tail() -> None:
    _is("explain select system$get_x()", "sql:explain", Risk.READ, SNOWFLAKE)
    _is("call system$get_x()", "sql:plsql", Risk.ADMIN, SNOWFLAKE)


# --- the maximum over the whole tree (M12) -----------------------------------------------------


@pytest.mark.parametrize(
    ("sql", "name"),
    [
        ("select * from (select * from dba_users)", "sql:select"),
        ("with u as (select * from sys.dba_users) select * from u", "sql:select"),
        ("select 1 from dual where exists (select 1 from dba_users)", "sql:select"),
        ("insert into t select * from dba_users", "sql:insert"),
        ('select * from SYS."USER$"', "sql:select"),
        ('select * from "dba_users"', "sql:select"),
    ],
)
def test_a_secret_object_anywhere_makes_the_statement_secret(sql: str, name: str) -> None:
    _is(sql, name, Risk.SECRET, ORACLE_LIKE)


@pytest.mark.parametrize(
    "sql",
    [
        'select * from "V$SQL"',
        "select * from gv$sql",
        "select * from sys.v_$sql",
        "select * from gv_$sql",
    ],
)
def test_view_spellings_are_one_name(sql: str) -> None:
    _is(sql, "sql:select", Risk.SECRET, ORACLE_LIKE)


@pytest.mark.parametrize(
    ("sql", "risk"),
    [
        ("select * from t where x = utl_http.request('h')", Risk.ADMIN),
        ("select sys.utl_http.request('x') from dual", Risk.ADMIN),
        ("select * from table(dbms_xplan.display())", Risk.READ),
        ("select dbms_lob.substr(c, 1, 1) from t", Risk.READ),
        ("select dbms_lob.loadfromfile(c) from t", Risk.ADMIN),
        ("select my_function(1) from dual", Risk.READ),
    ],
)
def test_functions_are_looked_up_by_qualified_name(sql: str, risk: Risk) -> None:
    _is(sql, "sql:select", risk, ORACLE_LIKE)


def test_an_unquoted_identifier_with_at_is_a_database_link() -> None:
    _is("select * from po@remote_link", "sql:select", Risk.ADMIN, ORACLE_LIKE)
    _is('select * from "po@remote_link"', "sql:select", Risk.READ, ORACLE_LIKE)


@pytest.mark.parametrize(
    ("sql", "name", "risk"),
    [
        ("select * from t for update", "sql:select", Risk.WRITE),
        ("select seq.nextval from t", "sql:select", Risk.WRITE),
        ("select seq.currval from t", "sql:select", Risk.WRITE),
        ("describe insert into t values (1)", "sql:insert", Risk.WRITE),
        ("with d as (delete from po returning *) select * from d", "sql:delete", Risk.DESTRUCTIVE),
        ("insert overwrite into t select 1", "sql:insert", Risk.DESTRUCTIVE),
        (
            "merge into t using s on t.id = s.id when matched then delete",
            "sql:merge",
            Risk.DESTRUCTIVE,
        ),
        ("copy into @s from t", "sql:unload", Risk.ADMIN),
        ("copy into t from @s", "sql:copy", Risk.WRITE),
        ("drop table t", "sql:ddl.drop", Risk.DESTRUCTIVE),
        ("create table t (a int)", "sql:ddl.create", Risk.ADMIN),
    ],
)
def test_statement_classes_and_side_effects(sql: str, name: str, risk: Risk) -> None:
    _is(sql, name, risk)


def test_with_function_is_admin() -> None:
    # sqlglot 30.24 fills `With.udfs` for the Trino and ClickHouse grammars only; Oracle's WITH
    # FUNCTION does not parse there and is unknown.
    trino = DialectRules("trino", Catalogue({}), Catalogue({}))
    _is(
        "with function f(x integer) returns integer return x * 2 select f(1)",
        "sql:select",
        Risk.ADMIN,
        trino,
    )


@pytest.mark.parametrize(
    ("sql", "detail"),
    [
        ("select * from identifier(:t)", "known only when it runs"),
        ("select * from identifier('t')", "known only when it runs"),
        ("select * from :t", "known only when it runs"),
        ("select * from $t", "known only when it runs"),
        ("select * from :s.t", "known only when it runs"),
        ("select identifier('f')(1)", "IDENTIFIER"),
        ("select x into y from t", "SELECT … INTO"),
    ],
)
def test_names_known_only_at_run_time_are_unknown(sql: str, detail: str) -> None:
    _unknown(sql, detail)


def test_facts() -> None:
    action = classify('select upper(x), my_fn(y), db.pkg.fn(z) from s.t join "Q" on 1 = 1', PLAIN)
    assert action.facts == {
        "statement": "select",
        "kind": "query",
        "tables": ("s.t", '"Q"'),
        "functions": ("MY_FN", "DB.PKG.FN"),
    }
    assert classify("use role r", PLAIN).facts == {"statement": "use", "kind": "other"}


# --- catalogues and names ----------------------------------------------------------------------


def test_name_normalisation() -> None:
    assert function_name(["sys", "utl_http", "request"]) == "UTL_HTTP.REQUEST"
    assert function_name(["sys"]) == "SYS"
    assert object_name(["SYS", "GV_$SESSION"]) == "V$SESSION"
    assert object_name(["v_$sql"]) == "V$SQL"
    assert object_name(["gv$sql"]) == "V$SQL"
    assert object_name(["app", "user$"]) == "APP.USER$"


def test_catalogue_lookup_prefers_exact_then_the_most_specific_pattern() -> None:
    catalogue = Catalogue(
        {
            "SYSTEM$*": Risk.ADMIN,
            "system$get_*": Risk.SECRET,
            "SYSTEM$TYPEOF": Risk.READ,
            "A*": Risk.READ,
            "*B": Risk.WRITE,
        }
    )
    assert catalogue.lookup("SYSTEM$TYPEOF") is Risk.READ
    assert catalogue.lookup("system$get_x") is Risk.SECRET
    assert catalogue.lookup("SYSTEM$CANCEL_QUERY") is Risk.ADMIN
    assert catalogue.lookup("AB") is Risk.WRITE  # equally specific: the higher class
    assert catalogue.lookup("OTHER") is None
    assert catalogue.lookup("SYSTEM.X") is None


# --- requireWhere --------------------------------------------------------------------------------


def test_require_where_messages() -> None:
    check = RequireWhere()

    def reason(where: str | None) -> str | None:
        facts = {} if where is None else {"where": where}
        return check.before(Action("sql:delete", Risk.DESTRUCTIVE, facts), True)

    assert reason("column") is None
    assert reason("none") == "the statement has no WHERE clause"
    assert reason(None) == "the statement has no WHERE clause"
    assert "matches every row" in str(reason("constant"))
    assert "could not be analysed" in str(reason("unknown"))
    action = Action("sql:delete", Risk.DESTRUCTIVE, {"where": "none"})
    assert check.before(action, False) is None
    assert check.after(action, True, {"affectedRows": 5}) is None


@pytest.mark.parametrize(
    ("sql", "where"),
    [
        ("delete from po where 1 = 1", "constant"),
        ("delete from po", "none"),
        ("delete from po where id = :id", "column"),
        ("delete from po where po.id = id", "constant"),
        ("delete from po where a.id <= b.id", "column"),
        ("delete from po where (id) = id", "constant"),
        ("update t set a = 1 where id = id or id = id", "constant"),
    ],
)
def test_where_state(sql: str, where: str) -> None:
    assert classify(sql, PLAIN).facts["where"] == where


def test_where_is_analysed_with_the_dialects_identifier_rules() -> None:
    # Oracle folds unquoted names to upper case too: "ID" and id are one column.
    assert classify('delete from po where "ID" = id', ORACLE_LIKE).facts["where"] == "constant"
    # A quoted lower-case name is another column.
    assert classify('delete from po where "id" = id', ORACLE_LIKE).facts["where"] == "column"


# --- invariants through the engine (§7.3) ------------------------------------------------------


@pytest.mark.parametrize(
    ("sql", "rule"),
    [
        ("use role x", "sql:use"),
        ("set v = 1", "sql:session"),
        ("alter session set query_tag = 'x'", "sql:session"),
        ("commit", "sql:transaction"),
        ("rollback", "sql:transaction"),
        ("select 1; select 2", MULTI_STATEMENT),
    ],
)
def test_invariants_refuse_at_the_invariant_layer(sql: str, rule: str) -> None:
    scope = Scope(
        target="sf",
        type="sql",
        env="dev",
        ceiling=Risk.ADMIN,
        invariants=INVARIANTS,
        defaults=RuleSet(allow=(Rule("read"), Rule("admin"))),
    )
    decision = decide(classify(sql, SNOWFLAKE), scope)
    assert (decision.allowed, decision.layer, decision.rule) == (False, Layer.INVARIANT, rule)
