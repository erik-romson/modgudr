"""The fake-executable harness (index.md, "Fakes never read FAKE_*").

`make_fakebin` copies `tests/fixtures/bin/*` into a short temporary `bin/`, rewriting each shebang
to the test interpreter, writes `fake-scenario.json` beside them and exposes the parsed
`fake-log.jsonl`. A fake reads its scenario from its own directory, never from `HOME` or the
environment, and appends one JSON line per run: its tool name, argv, cwd and full environment.
`PATH` for a child is `<bin>:/usr/bin:/bin`, never the developer's own, so a real `kubectl`, `az`
or `claude` is unreachable.
"""

from __future__ import annotations

import json
import shutil
import sys
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from tests.support.shortdir import make_shortdir

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "bin"
SCENARIO_FILE = "fake-scenario.json"
LOG_FILE = "fake-log.jsonl"
SYSTEM_PATH = "/usr/bin:/bin"


@dataclass
class FakeBin:
    root: Path

    @property
    def bin(self) -> Path:
        return self.root / "bin"

    @property
    def log_path(self) -> Path:
        return self.bin / LOG_FILE

    def path_env(self) -> str:
        """`PATH=<bin>:/usr/bin:/bin`: the fakes first, then the system tools and nothing else."""
        return f"{self.bin}:{SYSTEM_PATH}"

    def set_scenario(self, scenario: Mapping[str, Any]) -> None:
        """Write `fake-scenario.json`: one key per fake (`{"claude": {"mode": "all-blocked"}}`)."""
        (self.bin / SCENARIO_FILE).write_text(json.dumps(dict(scenario)), "utf-8")

    def entries(self, tool: str | None = None) -> list[dict[str, Any]]:
        """The parsed log, oldest first; with `tool`, only that fake's runs."""
        if not self.log_path.exists():
            return []
        lines = self.log_path.read_text("utf-8").splitlines()
        parsed = [json.loads(line) for line in lines if line.strip()]
        return [e for e in parsed if tool is None or e["tool"] == tool]


def make_fakebin(root: Path, scenario: Mapping[str, Any] | None = None) -> FakeBin:
    fake = FakeBin(root)
    fake.bin.mkdir(parents=True)
    for source in sorted(FIXTURES.iterdir()):
        if not source.is_file():
            continue
        lines = source.read_text("utf-8").splitlines(keepends=True)
        if lines and lines[0].startswith("#!"):
            lines[0] = f"#!{sys.executable}\n"
        target = fake.bin / source.name
        target.write_text("".join(lines), "utf-8")
        target.chmod(0o755)
    fake.set_scenario(scenario or {})
    return fake


@pytest.fixture
def fakebin() -> Iterator[FakeBin]:
    """A fresh fake `bin/` under a short temporary directory, removed afterwards."""
    root = make_shortdir()
    try:
        yield make_fakebin(root)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def clean_environ(fake: FakeBin, home: Path, **extra: str) -> dict[str, str]:
    """A parent environment for a client under test: the fakes' PATH and a temporary HOME."""
    environ = {"PATH": fake.path_env(), "HOME": str(home)}
    environ.update(extra)
    return environ
