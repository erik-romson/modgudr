"""The GitHub Actions workflow: three jobs, every test command through `scripts/check.sh`."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, cast

import yaml

ROOT = Path(__file__).resolve().parents[2]
CI = ROOT / ".github" / "workflows" / "ci.yml"
#: The Oracle image tag lives in the support module that `tests/integration/oracle/conftest.py`
#: imports; the conftest itself only calls it.
ORACLE_FX = ROOT / "tests" / "support" / "oraclefx.py"
TEST_TOOLS = re.compile(r"\b(pytest|ruff|pyright)\b")


def workflow() -> dict[str, Any]:
    return cast("dict[str, Any]", yaml.safe_load(CI.read_text()))


def run_lines(job: dict[str, Any]) -> list[str]:
    """Every logical line of every `run:` step of a job."""
    lines: list[str] = []
    for step in job["steps"]:
        text = step.get("run")
        if text is None:
            continue
        joined = cast("str", text).replace("\\\n", " ")
        lines.extend(line.strip() for line in joined.splitlines() if line.strip())
    return lines


def test_three_jobs() -> None:
    assert list(workflow()["jobs"]) == ["check", "oracle", "kind"]


def test_every_test_command_goes_through_check_sh() -> None:
    for name, job in workflow()["jobs"].items():
        for line in run_lines(job):
            if TEST_TOOLS.search(line) or re.search(r"\buv run\b", line):
                assert line.startswith("sh scripts/check.sh"), f"{name}: {line}"


def test_check_job_runs_on_linux_and_macos() -> None:
    job = workflow()["jobs"]["check"]
    assert job["strategy"]["matrix"]["os"] == ["ubuntu-latest", "macos-latest"]
    assert job["runs-on"] == "${{ matrix.os }}"
    uses = [step["uses"] for step in job["steps"] if "uses" in step]
    assert any(u.startswith("astral-sh/setup-uv@") for u in uses)
    lines = run_lines(job)
    assert "uv sync --locked" in lines
    assert 'sh scripts/check.sh tests -m "not oracle"' in lines
    bats = [line for line in lines if line.startswith("bats ")]
    assert bats == ["bats bats/"]
    text = "\n".join(lines)
    for library in ("bats-support", "bats-assert", "bats-file"):
        assert f"/usr/local/lib/bats/{library}" in text


def test_oracle_job_pulls_the_image_the_tests_use() -> None:
    match = re.search(r'^IMAGE = "([^"]+)"', ORACLE_FX.read_text(), re.MULTILINE)
    assert match is not None
    image = match.group(1)
    job = workflow()["jobs"]["oracle"]
    assert job["runs-on"] == "ubuntu-latest"
    lines = run_lines(job)
    assert f"docker pull {image}" in lines
    assert "sh scripts/check.sh tests/integration/oracle" in lines
    assert lines.index(f"docker pull {image}") < lines.index(
        "sh scripts/check.sh tests/integration/oracle"
    )


def test_kind_job_exports_a_token_and_opts_in() -> None:
    job = workflow()["jobs"]["kind"]
    assert job["runs-on"] == "ubuntu-latest"
    uses = [step["uses"] for step in job["steps"] if "uses" in step]
    assert any(u.startswith("helm/kind-action@") for u in uses)
    text = "\n".join(run_lines(job))
    assert "kubectl create token" in text
    assert "MODGUDR_TEST_KIND=1" in text
    assert "MODGUDR_KIND_KUBECONFIG=" in text
    assert "MODGUDR_KIND_TOKEN=" in text
    assert "::add-mask::" in text
    lines = run_lines(job)
    assert any(line.startswith("sh scripts/check.sh") and "-m kind" in line for line in lines)


def test_no_job_fetches_bitwarden() -> None:
    # One test over all jobs: a parametrised id "kind" would collide with the opt-in marker name.
    for name, job in workflow()["jobs"].items():
        text = "\n".join(run_lines(job)).lower()
        assert "bitwarden" not in text, name
        assert "bws" not in text, name
