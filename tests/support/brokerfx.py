"""Helpers for broker tests: a policy with echo targets, a secrets file, a config on short paths,
an in-process broker and a raw protocol client.

Every home, socket, audit directory and managed-settings directory lives under one short
temporary directory (`tests/support/shortdir.py`), never in the developer's home.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import os
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from modgudr.broker.app import Broker, BrokerConfig, build
from modgudr.broker.registry import PluginRegistry
from tests.support.echo_connector import EchoConnector

SECRET = "s3cr3t-echo-value-0123"
PROD_SECRET = "pr0d-echo-value-4567"

COMPANY = """\
store:
  default: file
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

TARGETS = """\
targets:
  echo-test:
    type: echo
    system: echo
    env: test
    secret: file:echo-test
    credential: { tier: dedicated }
    maxConcurrent: 2
  echo-prod:
    type: echo
    system: echo
    env: prod
    host: echo-prod.example.net
    port: 7001
    secret: file:echo-prod
    credential: { tier: dedicated }
  echo-fast:
    type: echo
    env: test
    timeout: 1s
    secret: file:echo-test
    credential: { tier: dedicated }
"""

SECRETS: dict[str, dict[str, object]] = {
    "echo-test": {"value": SECRET, "hosts": ["echo.example.net:7000"], "env": "test"},
    "echo-prod": {"value": PROD_SECRET, "hosts": ["echo-prod.example.net:7001"]},
}


def write_file(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)


def write_secrets(path: Path, secrets: Mapping[str, Mapping[str, object]]) -> None:
    write_file(path, yaml.safe_dump(dict(secrets)), 0o600)


@dataclass
class BrokerEnv:
    root: Path
    config: BrokerConfig
    connector: EchoConnector
    stderr: io.StringIO = field(default_factory=io.StringIO)

    @property
    def home(self) -> Path:
        return self.config.home

    @property
    def agent_socket(self) -> Path:
        return self.config.agent_socket

    @property
    def human_socket(self) -> Path:
        return self.config.human_socket

    @property
    def audit_dir(self) -> Path:
        return self.config.audit_dir

    @property
    def policy_dir(self) -> Path:
        return self.config.policy_dir

    @property
    def secrets_file(self) -> Path:
        assert self.config.secrets_file is not None
        return self.config.secrets_file

    @property
    def settings_base(self) -> Path:
        assert self.config.managed_settings is not None
        return self.config.managed_settings

    @property
    def settings_dir(self) -> Path:
        assert self.config.managed_settings_dir is not None
        return self.config.managed_settings_dir


def make_env(
    root: Path,
    *,
    company: str = COMPANY,
    targets: str = TARGETS,
    secrets: Mapping[str, Mapping[str, object]] = SECRETS,
    **overrides: object,
) -> BrokerEnv:
    """Write the policy and secrets under `root` and build the config (not the broker)."""
    policy_dir = root / "policy.d"
    write_file(policy_dir / "00-company.yaml", company)
    write_file(policy_dir / "50-targets.yaml", targets)
    write_secrets(root / "secrets.yaml", secrets)
    user_home = root / "u"
    user_home.mkdir(exist_ok=True)
    connector = EchoConnector()
    registry = PluginRegistry.discover()
    registry.register_connector(connector)
    stderr = io.StringIO()
    values: dict[str, object] = {
        "home": root / "h",
        "agent_socket": root / "c" / "agent.sock",
        "policy_dir": policy_dir,
        "audit_dir": root / "h" / "audit",
        "secrets_file": root / "secrets.yaml",
        "dev": True,
        "user_home": user_home,
        "managed_settings": root / "ms" / "managed-settings.json",
        "managed_settings_dir": root / "ms" / "managed-settings.d",
        "registry": registry,
        "stderr": stderr,
    }
    values.update(overrides)
    config = BrokerConfig(**values)
    return BrokerEnv(root, config, connector, stderr)


@asynccontextmanager
async def running(env: BrokerEnv) -> AsyncIterator[Broker]:
    broker = build(env.config)
    await broker.start()
    try:
        yield broker
    finally:
        await broker.shutdown()


def request(
    op: str,
    target: str | None = None,
    *,
    args: Mapping[str, object] | None = None,
    env: str | None = None,
    v: object = 1,
    client: Mapping[str, object] | None = None,
) -> dict[str, object]:
    out: dict[str, object] = {"v": v, "op": op}
    if target is not None:
        out["target"] = target
    if env is not None:
        out["env"] = env
    out["args"] = dict(args or {})
    if client is not None:
        out["client"] = dict(client)
    return out


def line(payload: Mapping[str, object]) -> bytes:
    return json.dumps(payload, separators=(",", ":")).encode() + b"\n"


async def raw(
    path: Path, payload: bytes | Mapping[str, object], *, timeout: float = 30.0
) -> list[dict[str, object]]:
    """Send one request and read every frame until the broker closes the connection."""
    data = payload if isinstance(payload, bytes) else line(payload)
    reader, writer = await asyncio.open_unix_connection(os.fspath(path), limit=16 * 1024**2)
    try:
        writer.write(data)
        await writer.drain()
        frames: list[dict[str, object]] = []
        async with asyncio.timeout(timeout):
            while chunk := await reader.readline():
                frames.append(json.loads(chunk))
        return frames
    finally:
        writer.close()
        with contextlib.suppress(ConnectionError, OSError):
            await writer.wait_closed()


async def call(
    path: Path,
    op: str,
    target: str | None = None,
    **kwargs: object,
) -> list[dict[str, object]]:
    return await raw(path, request(op, target, **kwargs))


def result_data(frames: list[dict[str, object]]) -> dict[str, object]:
    assert [f["t"] for f in frames] == ["result", "trailer"], frames
    data = frames[0]["data"]
    assert isinstance(data, dict)
    return data


def error(frames: list[dict[str, object]]) -> dict[str, object]:
    assert frames, "no frames"
    assert frames[-1]["t"] == "error", frames
    return frames[-1]


def read_audit(directory: Path) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for path in sorted(directory.glob("audit-*.jsonl")):
        for text in path.read_text().splitlines():
            out.append(json.loads(text))
    return out


def audit_text(directory: Path) -> str:
    return "".join(p.read_text() for p in sorted(directory.glob("audit-*.jsonl")))


async def wait_for(predicate: Callable[[], bool], timeout: float = 5.0) -> None:
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.02)


class RootFstat:
    """An fstat that reports root as the owner and the real mode (managed-settings tests)."""

    def __call__(self, fd: int) -> os.stat_result:
        real = os.fstat(fd)
        values = list(real)
        values[4] = 0  # st_uid
        return os.stat_result(values)
