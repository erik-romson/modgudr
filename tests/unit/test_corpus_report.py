"""`scripts/sql_corpus_report.py` run as a subprocess on the sample directory (R10)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "sql_corpus_report.py"
SAMPLE = ROOT / "tests" / "data" / "sql" / "corpus-sample"


def run(*args: str | Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", str(SCRIPT), *map(str, args)],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def test_the_report_counts_the_unknown_and_names_the_gaps() -> None:
    result = run("--dialect", "oracle", SAMPLE)
    assert result.returncode == 0, result.stderr
    out = result.stdout
    assert "files: 3" in out
    assert "sql:select (read): 2" in out
    assert "sql:unknown (unknown): 1" in out
    assert "unknown (1):" in out
    assert "broken.sql: parse error" in out
    assert "functions not in the catalogue (1):" in out
    assert "MYCOMPANY_FN: stats.sql" in out
    assert "objects not in the catalogue (0):" in out


def test_the_report_writes_nothing() -> None:
    before = sorted(SAMPLE.iterdir())
    run("--dialect", "snowflake", SAMPLE)
    assert sorted(SAMPLE.iterdir()) == before


def test_a_table_the_catalogue_does_not_know_is_reported(tmp_path: Path) -> None:
    (tmp_path / "q.sql").write_text("select * from app.orders", encoding="utf-8")
    result = run("--dialect", "oracle", tmp_path)
    assert result.returncode == 0, result.stderr
    assert "APP.ORDERS: q.sql" in result.stdout


def test_usage_errors_exit_non_zero(tmp_path: Path) -> None:
    assert run().returncode != 0
    assert run("--dialect", "postgres", SAMPLE).returncode != 0
    assert run("--dialect", "oracle", tmp_path / "missing").returncode != 0
    empty = run("--dialect", "oracle", tmp_path)
    assert empty.returncode != 0
    assert empty.stdout == ""
