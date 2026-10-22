"""The example policy files in `dist/policy.d/` load and lint clean through the real loader."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from modgudr.broker.policy.lint import lint_policy
from modgudr.broker.policy.load import load_policy
from modgudr.broker.registry import PluginRegistry

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "dist" / "policy.d"
ME = os.getuid()

#: A host name that ends in a public-looking suffix.
HOST_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|no|dev|local|internal|cloud)\b", re.I)
ALLOWED_SUFFIXES = ("example.net", "example.com")


@pytest.fixture
def policy_dir(shortdir: Path) -> Path:
    """The examples under the names the loader wants, owned by the current user (dev mode)."""
    target = shortdir / "policy.d"
    target.mkdir()
    for source, name in (
        ("00-company.example.yaml", "00-company.yaml"),
        ("50-targets.example.yaml", "50-targets.yaml"),
    ):
        shutil.copyfile(EXAMPLES / source, target / name)
        (target / name).chmod(0o644)
    return target


def test_example_policy_validates_with_the_real_connectors(policy_dir: Path) -> None:
    registry = PluginRegistry.discover()
    policy = load_policy(policy_dir, registry, dev=True, uid=ME)
    assert policy.default_env == "test"
    assert set(policy.company.environments) == {"prod", "stage", "test"}
    assert policy.company.store.default == "bws"
    assert policy.canonical_env("vfy") == "stage"
    assert policy.canonical_env("sol") == "test"
    assert sorted(policy.targets) == ["aks-test", "ora-prod-ro", "ora-test", "sf-prod"]


def test_example_policy_lints_without_errors(policy_dir: Path) -> None:
    report = lint_policy(policy_dir, PluginRegistry.discover(), dev=True, uid=ME)
    assert [str(f) for f in report.errors] == []
    assert [str(f) for f in report.findings if f.severity == "warning"] == []


def test_example_targets_cover_the_pilot_connectors(policy_dir: Path) -> None:
    policy = load_policy(policy_dir, PluginRegistry.discover(), dev=True, uid=ME)
    kinds = {
        (t.type, getattr(t.config, "dialect", None), getattr(t.config, "sid", None) is not None)
        for t in policy.targets.values()
    }
    assert ("sql", "snowflake", False) in kinds
    assert ("sql", "oracle", False) in kinds  # service
    assert ("sql", "oracle", True) in kinds  # sid
    assert ("kubectl", None, False) in kinds


@pytest.mark.parametrize("name", ["00-company.example.yaml", "50-targets.example.yaml"])
def test_example_policy_names_only_example_hosts(name: str) -> None:
    text = (EXAMPLES / name).read_text()
    hosts = [m.group(0).lower() for m in HOST_RE.finditer(text)]
    bad = [h for h in hosts if not h.endswith(ALLOWED_SUFFIXES)]
    assert bad == []


def test_example_policy_says_where_it_is_installed_and_who_owns_it() -> None:
    company = (EXAMPLES / "00-company.example.yaml").read_text()
    targets = (EXAMPLES / "50-targets.example.yaml").read_text()
    assert "policy.d/00-company.yaml" in company
    assert "owned by root" in company
    assert "policy.d/50-targets.yaml" in targets
    assert "owned by you" in targets


@pytest.fixture
def bare_bin(shortdir: Path) -> Path:
    """A PATH with only the tools the installer needs, so no `mg` (macOS has /usr/bin/mg)."""
    bin_dir = shortdir / "bin"
    bin_dir.mkdir()
    for tool in ("cat", "dirname"):
        found = shutil.which(tool, path="/usr/bin:/bin")
        assert found is not None
        (bin_dir / tool).symlink_to(found)
    return bin_dir


def install_dry_run(bin_dir: Path) -> list[str]:
    done = subprocess.run(
        ["/bin/sh", str(ROOT / "dist" / "install-l0.sh"), "--dry-run", "--prefix", "/nonexistent"],
        capture_output=True,
        text=True,
        check=True,
        env={"PATH": str(bin_dir)},
    )
    return done.stdout.splitlines()


def test_install_script_installs_both_the_broker_and_the_client_command(bare_bin: Path) -> None:
    """uv links only the named tool's executables, so `modgudr` needs its own install line (B1)."""
    lines = install_dry_run(bare_bin)
    installs = [line for line in lines if line.startswith("+ uv tool install")]
    assert len(installs) == 2
    assert f"--from {ROOT}/packages/broker modgudr-broker" in installs[0]
    assert installs[1] == f"+ uv tool install --from {ROOT}/packages/client modgudr-client"
    alias = lines.index("+ ln -s modgudr /nonexistent/bin/mg")
    assert alias > lines.index(installs[1])


def test_install_script_creates_no_alias_when_mg_is_taken(bare_bin: Path) -> None:
    (bare_bin / "mg").symlink_to("/bin/echo")
    lines = install_dry_run(bare_bin)
    assert not any("ln -s" in line for line in lines)
    assert "# the short alias name is already taken on this machine; no alias is created" in lines
