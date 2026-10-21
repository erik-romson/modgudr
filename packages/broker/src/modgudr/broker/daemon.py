"""The daemon: `python -m modgudr.broker [--dev] [--policy-dir] [--secrets-file] [--audit-dir]`.

Any start failure exits 78 with nothing listening and no socket left behind. SIGTERM (and
SIGINT) drain: in-flight calls end `cancelled: shutdown`, the sockets are unlinked, then the
`broker.stop` record is written. The re-exec under `python -I` and the process hardening belong to
`main` (M23); `run` is what tests drive.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import NoReturn, TextIO

from .app import Broker, BrokerConfig, build
from .server import StartError

EXIT_OK = 0
EXIT_USAGE = 64
EXIT_CONFIG = 78


class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise _UsageError(message)


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="modgudr-broker",
        description="The modgudr broker: serves agent.sock and human.sock.",
    )
    parser.add_argument(
        "--dev",
        action="store_true",
        help="development mode: enables the file store and marks every audit line dev: true",
    )
    parser.add_argument("--policy-dir", type=Path, help="default: $MODGUDR_HOME/policy.d")
    parser.add_argument("--secrets-file", type=Path, help="the file store's secrets (with --dev)")
    parser.add_argument("--audit-dir", type=Path, help="default: $MODGUDR_HOME/audit")
    return parser


async def run(
    config: BrokerConfig,
    *,
    on_ready: Callable[[Broker], None] | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Build, start and serve until SIGTERM or SIGINT. Returns the exit code."""
    err = stderr or sys.stderr
    try:
        broker = build(config)
        await broker.start()
    except StartError as exc:
        print(f"modgudr-broker: {exc}", file=err)
        return EXIT_CONFIG
    loop = asyncio.get_running_loop()
    signals = (signal.SIGTERM, signal.SIGINT)
    for sig in signals:
        loop.add_signal_handler(sig, broker.request_shutdown)
    try:
        if on_ready is not None:
            on_ready(broker)
        await broker.wait_stopped()
    finally:
        for sig in signals:
            loop.remove_signal_handler(sig)
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except _UsageError as exc:
        print(f"modgudr-broker: {exc}", file=sys.stderr)
        _parser().print_usage(sys.stderr)
        return EXIT_USAGE
    try:
        config = BrokerConfig.from_environment(
            os.environ,
            dev=args.dev,
            policy_dir=args.policy_dir,
            audit_dir=args.audit_dir,
            secrets_file=args.secrets_file,
        )
    except StartError as exc:
        print(f"modgudr-broker: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    return asyncio.run(run(config))
