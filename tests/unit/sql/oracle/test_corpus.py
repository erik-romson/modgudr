"""The Oracle corpus (tests/data/sql/oracle-corpus.yaml) through the Oracle dialect.

Every row is classified without a database: no connection, no driver.
"""

from __future__ import annotations

import pytest

from modgudr.sql.dialects.oracle import OracleDialect
from tests.support.sqlcorpus import CorpusRow, check_row, load_corpus

CORPUS = load_corpus("oracle")
DIALECT = OracleDialect()

#: Inputs the step 15 table names; the corpus must keep every one of them.
REQUIRED = frozenset(
    {
        "select name, password from sys.user$",
        "select name, host, userid, passwordx from sys.link$",
        "select username, created from all_users",
        "select * from V$SQL",
        'select * from "V$SQL"',
        "select * from gv$sql",
        "select * from sys.v_$sql",
        "select * from SYS.V$SQL",
        "select utl_http.request('http://x/') from dual",
        "select sys.utl_http.request(x) from dual",
        "select dbms_scheduler.run_job('x') from dual",
        "select * from po@remote_link",
        "select pkg.fn@link(x) from dual",
        "select * from table(dbms_xplan.display_cursor(:sql_id, :child, :fmt))",
        "select dbms_metadata.get_ddl('TABLE', 'T', 'O') from dual",
        "select dbms_metadata.get_ddl('USER', 'X') from dual",
        "select dbms_metadata.get_ddl(:t, :n) from dual",
        "select dbms_lob.substr(c, 100, 1) from t",
        "select dbms_lob.loadfromfile(a, b, c) from dual",
        "begin execute immediate 'delete from po'; end;",
        "begin my_proc; end;",
        "declare x number; begin null; end;",
        "call dbms_scheduler.run_job('X')",
        "alter session set current_schema = X",
        "set role app_admin",
        "set transaction read write",
        "commit",
        "rollback",
        "savepoint s",
        "exec p",
        "select seq.nextval from dual",
        "select * from po for update",
        "lock table po in exclusive mode",
        "select x into v from dual",
        "insert all into a values (1) into b values (2) select 1 from dual",
        "merge into t using s on (t.id = s.id) when matched then update set t.a = s.a",
        "explain plan for select * from dual",
        "delete from po where 1=1",
        "explain analyze delete from po where id = 1",
        "select q'[it's; drop]' from dual",
        "select * from t where id = :1",
    }
)


def test_the_corpus_keeps_every_required_row() -> None:
    missing = REQUIRED - CORPUS.sql()
    assert not missing, f"rows missing from the corpus: {sorted(missing)}"


@pytest.mark.parametrize("row", CORPUS.rows, ids=[row.id for row in CORPUS.rows])
def test_row(row: CorpusRow) -> None:
    check_row(row, DIALECT.classify(row.sql))


def test_the_twelve_diagnostic_queries_are_reads_over_generic_views() -> None:
    reads = [
        row
        for row in CORPUS.rows
        if row.risk.value == "read" and "\n" in row.sql and row.action == "sql:select"
    ]
    assert len(reads) >= 12


def test_no_company_names_in_the_corpus() -> None:
    text = " ".join(row.sql.lower() + row.note.lower() for row in CORPUS.rows)
    assert "cbs" not in text


def test_every_unmet_require_where_row_is_an_update_or_delete() -> None:
    rows = [row for row in CORPUS.rows if row.require_where is not None]
    assert rows
    assert {row.action for row in rows} <= {"sql:update", "sql:delete"}
