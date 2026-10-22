"""The daemon: `python -m modgudr.broker [--dev] [--policy-dir] [--secrets-file] [--audit-dir]`.

Any start failure exits 78 with nothing listening and no socket left behind. SIGTERM (and
SIGINT) drain: in-flight calls end `cancelled: shutdown`, the sockets are unlinked, then the
`broker.stop` record is written. The re-exec under `python -I` and the process hardening belong to
`entry`/`main` (M23); `run` is what tests drive.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import os
import signal
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import NoReturn, TextIO

from .app import Broker, BrokerConfig, broker_version, build
from .harden import Hardening, HardeningError, apply, reexec
from .policy.lint import lint_main
from .registry import PluginError, PluginRegistry
from .scrub import Scrubber
from .server import StartError

EXIT_OK = 0
EXIT_USAGE = 64
EXIT_CONFIG = 78


#: How `main` hardens the process: (scrubber, policy directory) to the facts (`harden.apply`).
Hardener = Callable[[Scrubber, Path], Hardening]


class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise _UsageError(message)


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="modgudr-broker",
        description="The modgudr broker: serves agent.sock and human.sock. "
        "`modgudr-broker lint [--policy-dir DIR]` checks the policy offline.",
    )
    parser.add_argument(
        "--dev",
        action="store_true",
        help="development mode: enables the file store and marks every audit line dev: true",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"modgudr-broker {broker_version()} (isolated={sys.flags.isolated})",
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


def _lint(words: Sequence[str]) -> int:
    """`modgudr-broker lint [--policy-dir DIR]`: the offline lint of step 03."""
    try:
        registry = PluginRegistry.discover()
    except PluginError as exc:
        print(f"modgudr-broker: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    return lint_main(words, registry)


def entry() -> NoReturn:
    """The `modgudr-broker` console script: re-execute under `-I`, then serve hardened (M23)."""
    words = sys.argv[1:]
    try:
        reexec(words)
    except HardeningError as exc:
        print(f"modgudr-broker: {exc}", file=sys.stderr)
        sys.exit(EXIT_CONFIG)
    sys.exit(main(words, hardener=apply))


def main(argv: Sequence[str] | None = None, *, hardener: Hardener | None = None) -> int:
    """Parse, then (when `hardener` is given) harden before the policy loads, then serve.

    `MODGUDR_HOME` and `MODGUDR_SOCKET` are read into the config before the hardening replaces
    the environment. A hardening failure exits 78."""
    words = list(sys.argv[1:] if argv is None else argv)
    if words and words[0] == "lint":
        return _lint(words[1:])
    try:
        args = _parser().parse_args(words)
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
    if hardener is not None:
        scrubber = Scrubber()
        try:
            facts = hardener(scrubber, config.policy_dir)
        except HardeningError as exc:
            print(f"modgudr-broker: hardening failed: {exc}", file=sys.stderr)
            return EXIT_CONFIG
        for warning in facts.warnings:
            print(f"modgudr-broker: warning: {warning}", file=sys.stderr)
        config = dataclasses.replace(config, scrubber=scrubber, hardening=facts)
    return asyncio.run(run(config))
