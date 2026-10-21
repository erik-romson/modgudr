import ast
import importlib
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_gitignore_lists_venv_and_tmp() -> None:
    lines = (ROOT / ".gitignore").read_text().splitlines()
    assert ".venv/" in lines
    assert "tmp/" in lines


def test_all_namespace_packages_import() -> None:
    for name in (
        "modgudr",
        "modgudr.client",
        "modgudr.broker",
        "modgudr.spi",
        "modgudr.sql",
        "modgudr.kubectl",
        "modgudr.store_file",
        "modgudr.store_bws",
    ):
        importlib.import_module(name)


def test_only_the_client_ships_modgudr_init() -> None:
    found = sorted((ROOT / "packages").glob("*/src/modgudr/__init__.py"))
    assert found == [ROOT / "packages" / "client" / "src" / "modgudr" / "__init__.py"]


def test_client_is_stdlib_only() -> None:
    client = ROOT / "packages" / "client"
    data = tomllib.loads((client / "pyproject.toml").read_text())
    assert data["project"]["dependencies"] == []
    allowed = set(sys.stdlib_module_names) | {"modgudr"}
    for path in (client / "src").rglob("*.py"):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                tops = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                tops = [node.module.split(".")[0]]
            else:
                continue
            for top in tops:
                assert top in allowed, f"{path}: imports {top}"
