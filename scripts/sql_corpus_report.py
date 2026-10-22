"""Classify a directory of real SQL files and report what the classifier does not understand.

    uv run --locked python scripts/sql_corpus_report.py --dialect oracle|snowflake <dir>

Each `*.sql` file in <dir> (not recursive) is one statement text. The report prints to stdout:
the counts by action, every `unknown` with the parser message, and every function or object name
that the dialect's catalogue does not know. It reads files and writes none (R10).
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

from modgudr.sql.catalogue import Catalogue, object_name
from modgudr.sql.dialects.oracle import OracleDialect
from modgudr.sql.dialects.snowflake import SnowflakeDialect

DIALECTS = {"oracle": OracleDialect, "snowflake": SnowflakeDialect}


def _table_parts(shown: str) -> list[str]:
    """The parts of a table name as the classifier shows it (`sys."V$SQL"`)."""
    return [part.strip('"') for part in shown.split(".")]


def _names(items: object) -> tuple[str, ...]:
    """A `functions` or `tables` fact as names."""
    return tuple(str(item) for item in items) if isinstance(items, tuple) else ()


def report(dialect_name: str, directory: Path) -> list[str]:
    """The report lines for every `*.sql` file of `directory`."""
    dialect = DIALECTS[dialect_name]()
    functions = Catalogue(dialect.function_catalogue())
    objects = Catalogue(dialect.object_catalogue())
    files = sorted(path for path in directory.glob("*.sql") if path.is_file())
    counts: Counter[tuple[str, str]] = Counter()
    unknowns: list[tuple[str, str]] = []
    missing_functions: dict[str, list[str]] = {}
    missing_objects: dict[str, list[str]] = {}
    for path in files:
        action = dialect.classify(path.read_text(encoding="utf-8"))
        counts[(action.name, action.risk.value)] += 1
        if action.name == "sql:unknown":
            unknowns.append((path.name, action.detail))
        for name in _names(action.facts.get("functions")):
            if functions.lookup(name) is None:
                missing_functions.setdefault(name, []).append(path.name)
        for shown in _names(action.facts.get("tables")):
            name = object_name(_table_parts(shown))
            if objects.lookup(name) is None:
                missing_objects.setdefault(name, []).append(path.name)
    lines = [f"dialect: {dialect_name}", f"files: {len(files)}", "", "counts by action:"]
    for (name, risk), count in sorted(counts.items()):
        lines.append(f"  {name} ({risk}): {count}")
    lines += ["", f"unknown ({len(unknowns)}):"]
    lines += [f"  {file}: {detail}" for file, detail in unknowns]
    for title, found in (
        ("functions not in the catalogue", missing_functions),
        ("objects not in the catalogue", missing_objects),
    ):
        lines += ["", f"{title} ({len(found)}):"]
        for name, where in sorted(found.items()):
            lines.append(f"  {name}: {', '.join(sorted(set(where)))}")
    return lines


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sql_corpus_report.py",
        description="Classify the *.sql files of a directory and report the unknowns.",
    )
    parser.add_argument("--dialect", required=True, choices=sorted(DIALECTS))
    parser.add_argument("directory", type=Path)
    args = parser.parse_args(argv)
    directory: Path = args.directory
    if not directory.is_dir():
        parser.error(f"{directory} is not a directory")
    if not any(path.is_file() for path in directory.glob("*.sql")):
        parser.error(f"{directory} holds no *.sql file")
    try:
        lines = report(args.dialect, directory)
    except (OSError, UnicodeDecodeError) as exc:
        parser.error(f"cannot read a file: {exc}")
    sys.stdout.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
