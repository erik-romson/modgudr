"""The Snowflake corpus (tests/data/sql/snowflake-corpus.yaml) through the Snowflake dialect.

Every row is classified without a database: no connection, no driver.
"""

from __future__ import annotations

import pytest

from modgudr.sql.dialects.snowflake import SnowflakeDialect
from tests.support.sqlcorpus import CorpusRow, check_row, load_corpus

CORPUS = load_corpus("snowflake")
DIALECT = SnowflakeDialect()

#: The inputs the step 09 table names; the corpus must keep every one of them.
REQUIRED = frozenset(
    {
        "select * from audit where action = 'delete'",
        "with d as (delete from po returning *) select * from d",
        "select 1; select 2",
        "select 1;",
        "select 1; -- note",
        "select 'a;b'",
        "use role x",
        "use warehouse w",
        "use secondary roles all",
        "set v = 1",
        "alter session set query_tag='x'",
        "commit",
        "rollback",
        "begin",
        "begin transaction",
        "copy into @s/x from (select 1)",
        "copy into 's3://b/k' from t",
        "copy into t from @s",
        "put file:///x @~",
        "get @~/x file:///tmp",
        "call p()",
        "execute immediate $$select 1$$",
        "begin select 1; end",
        "show secrets",
        "describe integration i",
        "select system$get_x()",
        "select system$cancel_query('1')",
        "select system$typeof(1)",
        "select * from t at(offset => -60)",
        "select * from table(result_scan(last_query_id()))",
        "show tables",
        "describe table t",
        "select * from identifier(:t)",
        "savepoint s",
        "exec p",
        "",
        ";;",
        "create table x as select 1",
        "insert overwrite into t select 1",
        "grant role r to user u",
        "truncate table t",
        "update t set a = 1 where 1=1",
        "update t set a = 1 where 'a'='a'",
        "update t set a = 1 where 1<2",
        "update t set a = 1 where true",
        "update t set a = 1 where not 1=0",
        "update t set a = 1 where id=1 or 1=1",
        "update t set a = 1 where id = id",
        "update t set a = 1 where t.id = id",
        "update t set a = 1 where t.id = t.id",
        'update t set a = 1 where "ID" = id',
        "update t set a = 1 where id >= id",
        "update t set a = 1 where id = id or x = 1",
        "update t set a = 1",
        "update t set a = 1 where id = :id",
        "update t set a = 1 where id = id and x = :x",
        'update t set a = 1 where "ID" = :id',
        "update a set x = 1 from b where a.id = b.id",
    }
)


def test_the_corpus_keeps_every_required_row() -> None:
    missing = REQUIRED - CORPUS.sql()
    assert not missing, f"rows missing from the corpus: {sorted(missing)}"


@pytest.mark.parametrize("row", CORPUS.rows, ids=[row.id for row in CORPUS.rows])
def test_row(row: CorpusRow) -> None:
    check_row(row, DIALECT.classify(row.sql))


def test_every_unmet_require_where_row_is_an_update_or_delete() -> None:
    rows = [row for row in CORPUS.rows if row.require_where is not None]
    assert len(rows) >= 17
    assert {row.action for row in rows} <= {"sql:update", "sql:delete"}
