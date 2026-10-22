"""The Bitwarden licence boundary (M19): modgudr never imports, vendors, locks, downloads or ships
`bws` or the Bitwarden SDK. The scans walk the filesystem (no git)."""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SKIP_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "tmp",
        "target",
        "__pycache__",
        "node_modules",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        ".pyright",
    }
)
SDK_RE = re.compile(r"bitwarden[-_.]?sdk", re.IGNORECASE)
HOST_RE = re.compile(r"bws\.bitwarden\.com", re.IGNORECASE)
#: A command that fetches or installs something.
FETCH_RE = re.compile(
    r"\b(curl|wget|gh\s+release\s+download|pip3?\s+install|uv\s+pip\s+install|uv\s+tool\s+install"
    r"|uv\s+add|uvx|brew\s+install|cargo\s+install|npm\s+install|go\s+install)\b"
)
BITWARDEN_RE = re.compile(r"bitwarden|sdk-sm|(?<![\w-])bws(?![\w-])", re.IGNORECASE)


def walk(top: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(top):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            yield Path(dirpath) / name


def scanned_files() -> list[Path]:
    """`uv.lock`, every `pyproject.toml`, `ci.yml`, `dist/` and `packages/`."""
    files: list[Path] = [
        ROOT / "uv.lock",
        ROOT / "pyproject.toml",
        ROOT / ".github/workflows/ci.yml",
    ]
    files.extend(walk(ROOT / "dist"))
    files.extend(walk(ROOT / "packages"))
    return sorted(
        {p for p in files if p.is_file() and not p.is_symlink() and not p.name.endswith(".pyc")}
    )


def read(path: Path) -> str | None:
    try:
        return path.read_text("utf-8")
    except UnicodeDecodeError:
        return None


def logical_lines(text: str) -> list[str]:
    """Lines with shell continuations joined."""
    return text.replace("\\\n", " ").splitlines()


def test_the_scan_covers_the_files_the_boundary_names() -> None:
    rel = {p.relative_to(ROOT).as_posix() for p in scanned_files()}
    assert {"uv.lock", "pyproject.toml", ".github/workflows/ci.yml"} <= rel
    assert "dist/install-l0.sh" in rel
    assert "dist/policy.d/00-company.example.yaml" in rel
    assert "packages/broker/pyproject.toml" in rel
    assert "packages/store-bws/src/modgudr/store_bws/store.py" in rel


def test_no_bitwarden_sdk_dependency_or_import() -> None:
    hits: list[str] = []
    for path in scanned_files():
        text = read(path)
        if text is None:
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if SDK_RE.search(line):
                hits.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()}")
    assert hits == []


def test_bws_download_host_appears_nowhere() -> None:
    hits = [
        str(path.relative_to(ROOT))
        for path in scanned_files()
        if (text := read(path)) is not None and HOST_RE.search(text)
    ]
    assert hits == []


def test_no_fetch_command_is_aimed_at_bitwarden() -> None:
    """The release page may be printed as text; it may not be an argument of a fetch command."""
    hits: list[str] = []
    for path in scanned_files():
        text = read(path)
        if text is None:
            continue
        for line in logical_lines(text):
            if line.lstrip().startswith("#"):
                continue
            if FETCH_RE.search(line) and BITWARDEN_RE.search(line):
                hits.append(f"{path.relative_to(ROOT)}: {line.strip()}")
    assert hits == []


def test_install_script_prints_the_release_page_and_fetches_nothing() -> None:
    text = (ROOT / "dist" / "install-l0.sh").read_text()
    assert "https://github.com/bitwarden/sdk-sm/releases" in text
    assert "checksum" in text
    assert "does not install `bws`" in text
    for command in ("curl", "wget", "gh release"):
        assert not re.search(rf"^\s*{command}\b", text, re.MULTILINE)


def test_the_only_bws_executable_is_the_test_fake() -> None:
    found = [
        path.relative_to(ROOT).as_posix()
        for path in walk(ROOT)
        if path.name in ("bws", "bws.exe") and not path.is_dir()
    ]
    assert found == ["tests/fixtures/bin/bws"]
    fake = ROOT / "tests" / "fixtures" / "bin" / "bws"
    assert fake.read_text().startswith("#!/usr/bin/env python3")
    assert stat.S_IMODE(fake.stat().st_mode) & 0o100


def test_the_lock_file_holds_no_bws_or_sdk_package() -> None:
    names = re.findall(r'^name = "([^"]+)"', (ROOT / "uv.lock").read_text(), re.MULTILINE)
    assert names
    assert [n for n in names if SDK_RE.search(n) or n.lower() in ("bws", "bitwarden")] == []
