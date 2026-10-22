"""`modgudr agent run claude` (M21): the child environment, `--env`, warnings and exit 69.

The exec is injected, so `claude` never starts; `PATH` comes from `fakebin`.
"""

from __future__ import annotations

import re
import shutil
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from modgudr.client.agent.isolation import L0_WARNING
from modgudr.client.agent.run import (
    ALLOWED_NAMES,
    SCRUB_VARIABLE,
    build_environment,
    check_pass_env,
    run_claude,
)
from modgudr.client.errors import BrokerUnavailable, CannotRun, UsageError
from tests.support.fakebin import FakeBin

SESSION = re.compile(r"s-[0-9a-f]{12}")
ENVIRONMENTS = [
    {"name": "test", "aliases": ["sol"]},
    {"name": "stage", "aliases": ["vfy"]},
    {"name": "prod", "aliases": []},
]


def status(isolation: str = "managed-settings") -> dict[str, Any]:
    return {"isolation": isolation, "environments": ENVIRONMENTS}


class Exec:
    def __init__(self) -> None:
        self.calls: list[tuple[str, list[str], dict[str, str]]] = []

    def __call__(self, path: str, argv: Sequence[str], env: Mapping[str, str]) -> None:
        self.calls.append((path, list(argv), dict(env)))

    @property
    def env(self) -> dict[str, str]:
        assert len(self.calls) == 1
        return self.calls[0][2]


def parent_env(fake: FakeBin, home: Path) -> dict[str, str]:
    return {
        "PATH": fake.path_env(),
        "HOME": str(home),
        "TERM": "xterm-256color",
        "LC_ALL": "C",
        "HTTPS_PROXY": "http://proxy.example.net:3128",
        "no_proxy": "localhost",
        "ANTHROPIC_MODEL": "m",
        "CLAUDE_CODE_FOO": "1",
        "PGPASSWORD": "pg-secret",
        "GH_TOKEN": "gh-secret",
        "KUBECONFIG": "/home/dev/.kube/config",
        "MODGUDR_ENV": "prod",
        "AWS_SECRET_ACCESS_KEY": "aws-secret",
    }


def run(
    fake: FakeBin,
    home: Path,
    *,
    env: str | None = None,
    pass_env: tuple[str, ...] = (),
    claude_args: tuple[str, ...] = (),
    parent: dict[str, str] | None = None,
    isolation: str = "managed-settings",
) -> Exec:
    runner = Exec()
    run_claude(
        env=env,
        pass_env=pass_env,
        claude_args=claude_args,
        environ=parent if parent is not None else parent_env(fake, home),
        exec_fn=runner,
        status_fn=lambda: status(isolation),
    )
    return runner


def discard(runner: Exec) -> None:
    shutil.rmtree(runner.env["AZURE_CONFIG_DIR"], ignore_errors=True)


def test_the_child_environment_is_the_allowlist(
    fakebin: FakeBin, shortdir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    runner = run(fakebin, shortdir, env="stage", claude_args=("--model", "x"))
    try:
        path, argv, env = runner.calls[0]
        assert path == str(fakebin.bin / "claude")
        assert argv == [path, "--model", "x"]
        assert set(env) == {
            "PATH",
            "HOME",
            "TERM",
            "LC_ALL",
            "HTTPS_PROXY",
            "no_proxy",
            "ANTHROPIC_MODEL",
            "CLAUDE_CODE_FOO",
            "MODGUDR_SESSION",
            "MODGUDR_ENV",
            "KUBECONFIG",
            "AZURE_CONFIG_DIR",
            SCRUB_VARIABLE,
        }
        assert env["MODGUDR_ENV"] == "stage"
        assert env["KUBECONFIG"] == "/dev/null"
        assert env[SCRUB_VARIABLE] == "1"
        assert env["HTTPS_PROXY"] == "http://proxy.example.net:3128"
        assert SESSION.fullmatch(env["MODGUDR_SESSION"])
        azure = Path(env["AZURE_CONFIG_DIR"])
        assert azure.is_dir() and not any(azure.iterdir())
        assert stat.S_IMODE(azure.stat().st_mode) == 0o700
        err = capsys.readouterr().err
        assert env["MODGUDR_SESSION"] in err
        assert "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB" in err
        assert L0_WARNING not in err
    finally:
        discard(runner)


def test_the_session_id_differs_between_runs(fakebin: FakeBin, shortdir: Path) -> None:
    first, second = run(fakebin, shortdir), run(fakebin, shortdir)
    try:
        assert first.env["MODGUDR_SESSION"] != second.env["MODGUDR_SESSION"]
        assert first.env["AZURE_CONFIG_DIR"] != second.env["AZURE_CONFIG_DIR"]
        assert "MODGUDR_ENV" not in first.env  # the parent's value is dropped without --env
    finally:
        discard(first)
        discard(second)


def test_modgudr_socket_is_passed_when_set(fakebin: FakeBin, shortdir: Path) -> None:
    parent = {**parent_env(fakebin, shortdir), "MODGUDR_SOCKET": "/tmp/mg-x/agent.sock"}
    runner = run(fakebin, shortdir, parent=parent)
    try:
        assert runner.env["MODGUDR_SOCKET"] == "/tmp/mg-x/agent.sock"
    finally:
        discard(runner)


def test_an_alias_is_canonicalised(fakebin: FakeBin, shortdir: Path) -> None:
    runner = run(fakebin, shortdir, env="sol")
    try:
        assert runner.env["MODGUDR_ENV"] == "test"
    finally:
        discard(runner)


def test_an_unknown_environment_is_64_with_the_list(fakebin: FakeBin, shortdir: Path) -> None:
    runner = Exec()
    with pytest.raises(UsageError) as caught:
        run_claude(
            env="prd",
            pass_env=(),
            claude_args=(),
            environ=parent_env(fakebin, shortdir),
            exec_fn=runner,
            status_fn=lambda: status(),
        )
    assert caught.value.exit_code == 64
    assert "test (sol), stage (vfy), prod" in caught.value.message
    assert not runner.calls


def test_with_the_broker_down_it_warns_and_starts(
    fakebin: FakeBin, shortdir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def down() -> dict[str, Any]:
        raise BrokerUnavailable("broker not running; start it in your own terminal")

    runner = Exec()
    run_claude(
        env="sol",
        pass_env=(),
        claude_args=(),
        environ=parent_env(fakebin, shortdir),
        exec_fn=runner,
        status_fn=down,
    )
    try:
        assert runner.env["MODGUDR_ENV"] == "sol"
        assert "warning: broker not running" in capsys.readouterr().err
    finally:
        discard(runner)


def test_claude_missing_is_69(shortdir: Path) -> None:
    runner = Exec()
    with pytest.raises(CannotRun) as caught:
        run_claude(
            env=None,
            pass_env=(),
            claude_args=(),
            environ={"PATH": str(shortdir), "HOME": str(shortdir)},
            exec_fn=runner,
            status_fn=lambda: status(),
        )
    assert caught.value.exit_code == 69
    assert not runner.calls


def test_pass_env_adds_names_and_warns_on_secrets(
    fakebin: FakeBin, shortdir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    runner = run(fakebin, shortdir, pass_env=("GH_TOKEN", "EDITOR", "MY_NOTES"))
    try:
        assert runner.env["GH_TOKEN"] == "gh-secret"
        assert "EDITOR" not in runner.env  # not set in the parent
        err = capsys.readouterr().err
        assert "--pass-env GH_TOKEN looks like a credential" in err
        assert "MY_NOTES" not in err
    finally:
        discard(runner)


def test_pass_env_names_are_checked() -> None:
    assert check_pass_env(["A_PASSWORD", "X_SECRET_Y", "plain"]) != []
    assert len(check_pass_env(["A_PASSWORD", "X_SECRET_Y", "plain"])) == 2
    with pytest.raises(UsageError):
        check_pass_env(["A=B"])


def test_the_l0_warning_is_printed_when_isolation_is_none(
    fakebin: FakeBin, shortdir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    runner = run(fakebin, shortdir, isolation="none")
    try:
        assert L0_WARNING in capsys.readouterr().err
    finally:
        discard(runner)


def test_the_allowlist_has_no_credential_names() -> None:
    for name in ("PGPASSWORD", "GH_TOKEN", "KUBECONFIG", "MODGUDR_ENV", "AZURE_CONFIG_DIR"):
        assert name not in ALLOWED_NAMES
    env = build_environment(
        {"PATH": "/usr/bin", "AZURE_CONFIG_DIR": "/home/dev/.azure"},
        session="s-000000000000",
        env=None,
        pass_env=(),
        azure_dir="/tmp/mg-azure-x",
    )
    assert env["AZURE_CONFIG_DIR"] == "/tmp/mg-azure-x"
