"""Helpers for the `bws` store tests: the fake `bws` scenario, a company file that uses the store,
an in-process broker config with a root-owned company file, and a pty-driven `modgudr unlock`.

Nothing here reaches a real `bws`: `PATH` for the broker and its children is
`<fake bin>:/usr/bin:/bin`.
"""

from __future__ import annotations

import json
import os
import pty
import select
import subprocess
import sys
import time
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any

from modgudr.broker.policy.load import Fstat
from tests.support.brokerfx import BrokerEnv, make_env
from tests.support.fakebin import FakeBin
from tests.support.policyfx import FakeStat

PROJECT = "6d0c4b2a-1e7f-4a58-8c3d-9b2a7f1e0001"
OTHER_PROJECT = "6d0c4b2a-1e7f-4a58-8c3d-9b2a7f1e0002"
TOKEN = "0.5b1c2d3e-0000-4000-8000-000000000001.exampleSecretPart:ZXhhbXBsZUtleQ=="
SECRETS_JSON = Path(__file__).resolve().parents[1] / "fixtures" / "bws" / "secrets.json"

#: The ids in `tests/fixtures/bws/secrets.json`.
OK = "2f1c0a9e-5b7d-4c3a-9e11-0a1b2c3d4e01"
NO_NOTE = "2f1c0a9e-5b7d-4c3a-9e11-0a1b2c3d4e02"
TWO_HOSTS = "2f1c0a9e-5b7d-4c3a-9e11-0a1b2c3d4e03"
SCHEME_NOTE = "2f1c0a9e-5b7d-4c3a-9e11-0a1b2c3d4e04"
FREE_TEXT = "2f1c0a9e-5b7d-4c3a-9e11-0a1b2c3d4e05"
TWO_ENVS = "2f1c0a9e-5b7d-4c3a-9e11-0a1b2c3d4e06"
PROD_PINNED = "2f1c0a9e-5b7d-4c3a-9e11-0a1b2c3d4e07"
OTHER_PROJECT_SECRET = "2f1c0a9e-5b7d-4c3a-9e11-0a1b2c3d4e08"
UNKNOWN = "2f1c0a9e-5b7d-4c3a-9e11-0a1b2c3d4eff"

#: The value of the secret `OK`.
OK_VALUE = "ora-example-password-0123"

#: Keys the fake's own interpreter adds: the coerced C locale, and macOS's text encoding.
INTERPRETER_KEYS = {"LC_CTYPE", "__CF_USER_TEXT_ENCODING"}
CHILD_KEYS = {"PATH", "HOME", "BWS_CONFIG_FILE", "BWS_ACCESS_TOKEN"}


def fixture_secrets() -> list[dict[str, Any]]:
    return json.loads(SECRETS_JSON.read_text("utf-8"))


def set_bws(fake: FakeBin, **extra: object) -> None:
    """Write the fake's scenario: the accepted token, the fixture secrets and `extra` keys."""
    plan: dict[str, object] = {"token": TOKEN, "secrets": fixture_secrets()}
    plan.update(extra)
    fake.set_scenario({"bws": plan})


def update_bws(fake: FakeBin, **extra: object) -> None:
    """Change the scenario mid-session (for example `revoke=True`)."""
    document = json.loads((fake.bin / "fake-scenario.json").read_text("utf-8"))
    document["bws"].update(extra)
    fake.set_scenario(document)


def bws_runs(fake: FakeBin) -> list[dict[str, Any]]:
    return fake.entries("bws")


def child_keys(entry: Mapping[str, Any]) -> set[str]:
    return set(entry["env"]) - INTERPRETER_KEYS


def company(extra: str = "", *, project: str = PROJECT) -> str:
    return f"""\
store:
  default: bws
  bws:
    project: {project}
{extra}\
defaults:
  env: test
  timeout: 30s
  maxRows: 500
  maxRowsHard: 50000
  maxBytes: 2MiB
  maxRequestBytes: 1MiB
  maxConcurrent: 4
environments:
  test:
    aliases: [sol]
    ceiling: write
    echo:
      allow: [write]
  prod:
    ceiling: read
"""


def echo_targets(**names: str) -> str:
    """Echo targets on `db1.example.net:1521` (the host the fixture notes pin), one per
    `name=secret id`; all in the test environment."""
    out = ["targets:"]
    for name, secret_id in names.items():
        out.append(
            f"""\
  {name}:
    type: echo
    system: {name}
    env: test
    host: db1.example.net
    port: 1521
    secret: bws:{secret_id}
    credential: {{ tier: dedicated }}"""
        )
    return "\n".join(out) + "\n"


def company_as_root(policy_dir: Path) -> Fstat:
    """An fstat that reports the company file as root-owned (it is not, in a test)."""
    inode = (policy_dir / "00-company.yaml").stat().st_ino

    def fstat(fd: int) -> FakeStat:
        real = os.fstat(fd)
        return FakeStat(0 if real.st_ino == inode else real.st_uid, real.st_mode)

    return fstat


def bws_env(
    root: Path,
    fake: FakeBin,
    *,
    company_text: str | None = None,
    targets: str | None = None,
    **overrides: object,
) -> BrokerEnv:
    """A broker config for the `bws` store: not `--dev`, the fake `bin/` first on `PATH`, the
    company file read as root-owned."""
    values: dict[str, object] = {"dev": False, "path": fake.path_env()}
    values.update(overrides)
    env = make_env(
        root,
        company=company_text if company_text is not None else company(),
        targets=targets if targets is not None else echo_targets(**{"echo-ok": OK}),
        **values,
    )
    env.config = replace(env.config, policy_fstat=company_as_root(env.policy_dir))
    return env


#: Runs in the child: open the terminal once, as a session leader without one, which makes it the
#: controlling terminal (so `/dev/tty` works), then become the CLI.
_BOOT = (
    "import os, sys\n"
    "os.close(os.open(os.ttyname(0), os.O_RDWR))\n"
    "os.execv(sys.executable, [sys.executable, '-m', 'modgudr.client', *sys.argv[1:]])\n"
)


def run_in_pty(
    environ: Mapping[str, str], args: list[str], typed: str, *, timeout: float = 30.0
) -> tuple[int, str]:
    """Run `python -m modgudr.client <args>` with a pseudo-terminal as its controlling terminal,
    type `typed` at the prompt and return (exit code, what the terminal showed)."""
    master, slave = pty.openpty()
    child = subprocess.Popen(
        [sys.executable, "-c", _BOOT, *args],
        env=dict(environ),
        cwd=environ["HOME"],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        start_new_session=True,
    )
    os.close(slave)
    shown = b""
    sent = False
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.1)
            if ready:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    chunk = b""
                if not chunk:
                    break
                shown += chunk
                if not sent and b"hidden" in shown:
                    os.write(master, typed.encode() + b"\n")
                    sent = True
        try:
            code = child.wait(max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
            raise TimeoutError(
                f"modgudr {' '.join(args)} did not finish; it showed {shown!r}"
            ) from None
        return code, shown.decode("utf-8", "replace")
    finally:
        os.close(master)
