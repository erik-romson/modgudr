"""`modgudr-broker` entry point: `--help` and the offline `lint` dispatch."""

from pathlib import Path

import pytest

from modgudr.broker.daemon import main
from tests.support.brokerfx import COMPANY, write_file


def test_help_exits_0(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as stop:
        main(["--help"])
    assert stop.value.code == 0
    assert "lint" in capsys.readouterr().out


def test_an_unknown_option_is_exit_64() -> None:
    assert main(["--nosuch"]) == 64


def test_lint_dispatches_to_the_offline_lint(
    shortdir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write_file(shortdir / "00-company.yaml", COMPANY)
    write_file(shortdir / "50-targets.yaml", "targets: {}\n")
    # Offline lint has no dev mode: a company file not owned by root is an error (exit 78).
    assert main(["lint", "--policy-dir", str(shortdir)]) == 78
    assert "must be owned by root" in capsys.readouterr().out
    assert main(["lint", "--policy-dir", str(shortdir / "missing")]) == 78
    assert main(["lint", "--bogus"]) == 64
