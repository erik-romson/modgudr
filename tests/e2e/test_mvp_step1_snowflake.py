"""MVP step 1, "done when" (§14.2): `modgudr sf query -p …` and `modgudr.connect().sql("sf")` work
against fakesnow; a `test` target updates under its constraints and the `prod` target refuses;
`modgudr explain` names the layer.

The broker runs on its own thread in this process, where fakesnow is patched in; the CLI is a
subprocess with an allowlisted environment.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterator
from datetime import date
from decimal import Decimal
from pathlib import Path

import pytest

import modgudr
from tests.support.brokerfx import BrokerEnv, read_audit
from tests.support.brokerthread import BrokerThread, cli_environ, run_cli
from tests.support.snowflakefx import Spy, fake_snowflake, sf_env, table_rows

ORIGINAL = [(1, "acme"), (2, "beta"), (3, "gamma"), (4, "delta")]


@pytest.fixture
def spy() -> Iterator[Spy]:
    with fake_snowflake() as s:
        yield s


@pytest.fixture
def served(shortdir: Path, spy: Spy) -> Iterator[BrokerThread]:
    with BrokerThread(sf_env(shortdir)) as thread:
        thread.unlock()
        yield thread


def cli(env: BrokerEnv, *args: str) -> subprocess.CompletedProcess[str]:
    return run_cli(cli_environ(env), *args)


def test_query_with_binds_from_the_cli(served: BrokerThread, spy: Spy) -> None:
    sql = "select id, buyer from po where status = :status and created >= :since order by id"
    done = cli(served.env, "sf", "query", "-p", "status=OPEN", "-p", "since:date=2026-10-01", sql)
    assert (done.returncode, done.stdout, done.stderr) == (0, "ID\tBUYER\n1\tacme\n", "")
    executed = spy.tagged()[0]
    assert executed["sql"].endswith("where status = :1 and created >= :2 order by id")
    assert executed["params"] == ("OPEN", date(2026, 10, 1))
    assert "OPEN" not in executed["sql"]


def test_the_python_api_returns_named_tuples_with_decimal_and_date(
    served: BrokerThread, monkeypatch: pytest.MonkeyPatch
) -> None:
    sql = "select id, amount, created from po where id <= :n order by id"
    result = modgudr.connect(served.env.agent_socket).sql("sf").query(sql, max_rows=2, n=2)
    rows = result.fetchall()
    assert [r.ID for r in rows] == [1, 2]
    assert Decimal("10.50") == rows[0].AMOUNT
    assert date(2026, 10, 2) == rows[0].CREATED


def test_the_template_ops_from_the_cli(served: BrokerThread) -> None:
    env = served.env
    assert "PO" in cli(env, "sf", "tables").stdout
    assert cli(env, "sf", "describe", "PO").stdout.splitlines()[1].startswith("ID\t")
    done = cli(env, "sf", "count", "PO", "status = :s", "-p", "s=OPEN")
    assert done.stdout.splitlines()[1] == "3"
    assert len(cli(env, "sf", "sample", "PO", "3").stdout.splitlines()) == 4
    bad = cli(env, "sf", "count", "PO; drop table t")
    assert bad.returncode == 64
    hostile = cli(env, "sf", "count", "PO", "1=1) or exists(select 1 from secrets")
    assert hostile.returncode == 2


def test_a_test_target_updates_under_its_constraints(served: BrokerThread, spy: Spy) -> None:
    env = served.env
    done = cli(env, "sf", "write", "update po set buyer='x' where id = :id", "-p", "id:int=1")
    assert done.returncode == 0, done.stderr
    assert done.stdout.splitlines()[1].split("\t") == ["1", "true", "false"]
    assert table_rows()[0] == (1, "x")

    breach = cli(env, "sf", "write", "update po set buyer='y' where id < 4")
    assert breach.returncode == 2 and "3 rows, limit 2" in breach.stderr
    assert table_rows()[1:] == ORIGINAL[1:]

    over = cli(env, "sf", "write", "--dry-run", "update po set buyer='y' where id < 4")
    assert over.returncode == 2 and "3 rows, limit 2" in over.stderr
    within = cli(env, "sf", "write", "--dry-run", "update po set buyer='y' where id < 3")
    assert within.returncode == 0
    assert within.stdout.splitlines()[1].split("\t") == ["2", "false", "true"]
    assert table_rows()[1:] == ORIGINAL[1:]

    spy.executes.clear()
    nowhere = cli(env, "sf", "write", "delete from po")
    assert nowhere.returncode == 2 and "WHERE" in nowhere.stderr
    assert spy.tagged() == []


def test_the_prod_target_refuses_before_any_connect(served: BrokerThread, spy: Spy) -> None:
    done = cli(served.env, "sf@prod", "write", "--dry-run", "update po set buyer='x' where id = 1")
    assert done.returncode == 2
    assert "Environment prod allows read only" in done.stderr
    assert spy.connects == []
    read = cli(served.env, "sf@prod", "query", "select count(*) as n from po")
    assert read.returncode == 0 and read.stdout.splitlines()[1] == "4"


def test_the_op_contract_is_exit_2(served: BrokerThread) -> None:
    env = served.env
    for args in (
        ("query", "update po set buyer='x' where id=1"),
        ("query", "select id from po for update"),
        ("write", "select 1"),
        ("write", "update po set buyer='x' where id=1; update po set buyer='y' where id=2"),
    ):
        assert cli(env, "sf", *args).returncode == 2, args


def test_explain_names_the_layer_and_the_rule(served: BrokerThread) -> None:
    env = served.env
    allowed = cli(env, "explain", "sf", "write", "delete from po where id=1")
    assert allowed.returncode == 0, allowed.stderr
    assert "allowed: sql:delete (destructive) on sf-test" in allowed.stdout
    assert "Environment test allows delete (environment)" in allowed.stdout
    refused = cli(env, "explain", "sf@prod", "write", "delete from po where id=1")
    assert refused.returncode == 0, refused.stderr
    assert "ceiling" in refused.stdout and "Environment prod allows read only" in refused.stdout


def test_the_audit_names_the_destination_and_never_the_bind_values(served: BrokerThread) -> None:
    env = served.env
    cli(env, "sf", "query", "select id from po where buyer = :b", "-p", "b=secret-buyer-name")
    records = read_audit(env.audit_dir)
    done = [r for r in records if r.get("type") == "completion"][-1]
    assert done["destination"] == "acme-example.snowflakecomputing.com:443"
    assert "secret-buyer-name" not in json.dumps(records)
