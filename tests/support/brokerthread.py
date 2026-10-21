"""A broker on its own thread and event loop, for tests that call it with blocking clients (the
CLI as a subprocess, the Python API) from ordinary synchronous test code."""

from __future__ import annotations

import asyncio
import subprocess
import sys
import threading
from collections.abc import Mapping
from pathlib import Path
from types import TracebackType

from modgudr.broker.app import Broker, build
from tests.support.brokerfx import COMPANY, SECRETS, TARGETS, BrokerEnv, make_env, unlock
from tests.support.echo_connector import EchoConnector
from tests.support.probe_connector import ProbeConnector

PROBE_TARGETS = """\
  probe-test:
    type: probe
    system: probe
    env: test
    secret: file:probe-test
    credential: { tier: dedicated }
"""

PROBE_SECRETS: dict[str, dict[str, object]] = {
    **SECRETS,
    "probe-test": {"value": "pr0be-value-89abcdef", "hosts": ["probe.example.net:7002"]},
}


def make_caller_env(root: Path, **overrides: object) -> BrokerEnv:
    """An environment with the echo targets and `probe-test`; both test connectors registered."""
    company = COMPANY.replace(
        "    echo:\n      allow: [write]\n",
        "    echo:\n      allow: [write]\n    probe:\n      allow: [write]\n",
    )
    assert company != COMPANY
    env = make_env(
        root,
        company=company,
        targets=TARGETS + PROBE_TARGETS,
        secrets=PROBE_SECRETS,
        **overrides,
    )
    assert env.config.registry is not None
    env.config.registry.register_connector(ProbeConnector())
    return env


class BrokerThread:
    def __init__(self, env: BrokerEnv) -> None:
        self.env = env
        self.broker: Broker | None = None
        self.error: BaseException | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop: asyncio.Event | None = None
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._main, name="broker", daemon=True)

    @property
    def connector(self) -> EchoConnector:
        return self.env.connector

    def __enter__(self) -> BrokerThread:
        self._thread.start()
        if not self._ready.wait(30):
            raise TimeoutError("the broker did not start")
        if self.error is not None:
            raise self.error
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._loop is not None and self._stop is not None:
            self._loop.call_soon_threadsafe(self._stop.set)
        self._thread.join(30)

    def _main(self) -> None:
        asyncio.run(self._serve())

    async def _serve(self) -> None:
        try:
            self.broker = build(self.env.config)
            await self.broker.start()
        except BaseException as exc:
            self.error = exc
            self._ready.set()
            return
        self._loop = asyncio.get_running_loop()
        self._stop = asyncio.Event()
        self._ready.set()
        await self._stop.wait()
        await self.broker.shutdown()

    def unlock(self) -> None:
        asyncio.run(unlock(self.env))


def cli_environ(env: BrokerEnv, **extra: str) -> dict[str, str]:
    """The environment of a CLI child: an allowlist, never the developer's own."""
    environ = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(env.root / "u"),
        "MODGUDR_HOME": str(env.home),
        "MODGUDR_SOCKET": str(env.agent_socket),
    }
    environ.update(extra)
    return environ


def cli_command(*args: str) -> list[str]:
    return [sys.executable, "-m", "modgudr.client", *args]


def run_cli(
    environ: Mapping[str, str],
    *args: str,
    stdin: str | None = None,
    timeout: float = 60.0,
) -> subprocess.CompletedProcess[str]:
    """Run the CLI to the end, without a controlling terminal. Output is decoded as is: no
    newline translation, so CRLF stays CRLF."""
    done = subprocess.run(
        cli_command(*args),
        env=dict(environ),
        input=stdin.encode() if stdin is not None else None,
        stdin=None if stdin is not None else subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
        cwd=environ["HOME"],
        start_new_session=True,
        check=False,
    )
    return subprocess.CompletedProcess(
        done.args, done.returncode, done.stdout.decode(), done.stderr.decode()
    )
