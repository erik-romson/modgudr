"""M24: every user-facing string, generated file and doc says `modgudr`, never the short name.

On macOS `/usr/bin/mg` is an Emacs. The scan matches the bare token as a whole word that is not
followed by `-`, so the `mg-hook` file name and the `mg-` temporary-directory prefix pass. The two
lines that cannot avoid the token (the alias in `install-l0.sh`, the PATH lookup in `doctor`) are
listed below with their exact text. The scan walks the filesystem and never calls git.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from modgudr.client import cli
from modgudr.client.agent.isolation import Facts
from tests.support.stubbroker import StubBroker

ROOT = Path(__file__).resolve().parents[2]
TOKEN = re.compile(r"(?<!\w)mg(?![\w-])")
SKIP_DIRS = {
    ".git",
    ".venv",
    "tmp",
    "target",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "node_modules",
}
SCAN_SUFFIXES = {".py", ".md", ".sh", ".yaml", ".yml", ".toml", ".txt", ".json"}

# File (relative to the repository) -> the exact stripped lines that may hold the bare token.
ALLOWED_LINES: dict[str, set[str]] = {
    # The alias is created only when `command -v` finds nothing of that name (M24).
    "dist/install-l0.sh": {
        "if command -v mg > /dev/null 2>&1; then",
        'run ln -s modgudr "$BIN/mg"',
    },
    # `doctor` looks the short name up on PATH to tell the developer about the editor (M22).
    "packages/client/src/modgudr/client/agent/doctor.py": {'found = ctx.which("mg")'},
}


def bare_tokens(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if TOKEN.search(line)]


def scan_roots() -> list[Path]:
    roots = [ROOT / "README.md", ROOT / "docs", ROOT / "dist", ROOT / "scripts", ROOT / ".github"]
    roots += sorted((ROOT / "packages").glob("*/src"))
    roots += sorted((ROOT / "packages").glob("*/pyproject.toml"))
    return [root for root in roots if root.exists()]


def files_under(root: Path) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.suffix in SCAN_SUFFIXES and not path.is_symlink():
                yield path


def test_the_token_pattern_means_what_it_says() -> None:
    assert TOKEN.search("run mg now")
    assert TOKEN.search("/usr/bin/mg")
    assert TOKEN.search("`mg`")
    assert not TOKEN.search("bin/mg-hook")
    assert not TOKEN.search("prefix mg- here")
    assert not TOKEN.search("modgudr, rmg, mgr, mg2")


def test_no_bare_short_name_in_the_repository() -> None:
    offences: list[str] = []
    seen_allowed: set[tuple[str, str]] = set()
    for root in scan_roots():
        for path in files_under(root):
            relative = path.relative_to(ROOT).as_posix()
            allowed = ALLOWED_LINES.get(relative, set())
            for line in bare_tokens(path.read_text(encoding="utf-8")):
                if line in allowed:
                    seen_allowed.add((relative, line))
                else:
                    offences.append(f"{relative}: {line}")
    assert not offences, "\n".join(offences)
    expected = {(path, line) for path, lines in ALLOWED_LINES.items() for line in lines}
    assert seen_allowed == expected, "an allowlist entry no longer matches a line"


def test_the_run_report_and_skill_are_scanned() -> None:
    scanned = {p.relative_to(ROOT).as_posix() for root in scan_roots() for p in files_under(root)}
    assert "docs/mvp-run-report.md" in scanned
    assert "docs/protocol.md" in scanned
    assert "README.md" in scanned
    assert "packages/client/src/modgudr/client/docs/SKILL.md" in scanned
    assert "packages/client/src/modgudr/client/agent/hook.py" in scanned


def child_environ(home: Path) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "MODGUDR_HOME": str(home / ".modgudr"),
        "MODGUDR_SOCKET": str(home / "none.sock"),
        "LC_ALL": "C.UTF-8",
    }


def run_module(module: str, args: list[str], home: Path) -> str:
    done = subprocess.run(
        [sys.executable, "-m", module, *args],
        capture_output=True,
        text=True,
        env=child_environ(home),
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, (module, args, done.stderr)
    return done.stdout + done.stderr


CLIENT_HELP = [
    [],
    ["targets"],
    ["describe"],
    ["explain"],
    ["actions"],
    ["policy"],
    ["policy", "show"],
    ["policy", "lint"],
    ["status"],
    ["unlock"],
    ["lock"],
    ["audit"],
    ["audit", "tail"],
    ["login"],
    ["login", "azure"],
    ["agent-setup"],
    ["agent-setup", "claude"],
    ["agent"],
    ["agent", "run"],
    ["agent", "run", "claude"],
    ["doctor"],
    ["agent-docs"],
]


@pytest.mark.parametrize("subcommand", CLIENT_HELP, ids=lambda s: " ".join(s) or "top")
def test_client_help_output(subcommand: list[str], shortdir: Path) -> None:
    text = run_module("modgudr.client", [*subcommand, "--help"], shortdir)
    assert "modgudr" in text
    assert bare_tokens(text) == []


def test_broker_help_output(shortdir: Path) -> None:
    text = run_module("modgudr.broker", ["--help"], shortdir)
    assert "modgudr-broker" in text
    assert bare_tokens(text) == []


def test_the_skill_text_says_modgudr(shortdir: Path) -> None:
    text = run_module("modgudr.client", ["agent-docs", "claude"], shortdir)
    assert "modgudr" in text
    assert bare_tokens(text) == []


def test_generated_files_say_modgudr(
    shortdir: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    user_home = shortdir / "u"
    user_home.mkdir()
    modgudr_home = f"{user_home}/.modgudr"
    agent_socket = shortdir / "agent.sock"
    facts = Facts(
        platform="darwin",
        home=modgudr_home,
        agent_socket=str(agent_socket),
        human_socket=f"{modgudr_home}/run/human.sock",
        deny_hosts=("db-test.example.net", "acme-example.snowflakecomputing.com"),
    )
    targets = [
        {
            "name": "snow-test",
            "type": "sql",
            "system": "snow",
            "env": "test",
            "destinations": ["acme-example.snowflakecomputing.com:443"],
        },
        {"name": "aks-test", "type": "kubectl", "system": "aks", "env": "test", "destinations": []},
    ]
    answers = {
        "status": {**facts.to_json(), "isolation": "none"},
        "targets": {"targets": targets},
    }
    out = shortdir / "out"
    monkeypatch.setenv("MODGUDR_SOCKET", str(agent_socket))
    monkeypatch.setenv("HOME", str(user_home))
    with StubBroker(agent_socket, answers):
        code = cli.main(["agent-setup", "claude", "--out", str(out)])
    assert code == 0
    printed = capsys.readouterr()
    assert bare_tokens(printed.out + printed.err) == []
    generated = [p for p in sorted(out.rglob("*")) if p.is_file()]
    assert len(generated) >= 3
    for path in generated:
        assert bare_tokens(path.read_text(encoding="utf-8")) == [], path.name
