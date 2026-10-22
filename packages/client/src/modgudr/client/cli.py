"""The `modgudr` command line (§6.1, MVP set).

Target-first grammar: the client knows nothing about connectors. For `modgudr <target> <op> …` it
asks the broker for the target's operations (`describe`) and parses the arguments from the
`OperationSpec` it gets back, so a new plugin needs no client change.

    modgudr targets [--json] [--system s]
    modgudr describe <target>
    modgudr <target> <op> …                 [--format F] [--no-header] [--allow-truncated]
                                            [--max-rows N] [-f FILE] [-p name[:type]=value]…
                                            [--dry-run]
    modgudr explain <target> <op> …
    modgudr actions <type> | policy show <target> | policy lint | status [--quiet|--json]
    modgudr unlock | lock | audit tail [...]        (human.sock only)

Messages of `modgudr` itself go to stderr. Exit codes are M5's.
"""

import argparse
import importlib.resources
import json
import os
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, NoReturn

from modgudr.client import paths
from modgudr.client.agent.doctor import run_agent_doctor, run_doctor
from modgudr.client.agent.run import run_claude
from modgudr.client.agent.setup import (
    DROPIN_DIR,
    DROPIN_FILE,
    HOOK_FILE,
    INSTALL_FILE,
    run_setup,
)
from modgudr.client.api import truncation_note
from modgudr.client.errors import BrokerUnavailable, Error, LimitExceeded, Throttled, UsageError
from modgudr.client.params import parse_cli_params
from modgudr.client.protocol import (
    PROTOCOL_VERSION,
    Column,
    Frame,
    Header,
    Row,
    Text,
    Trailer,
)
from modgudr.client.protocol import (
    Result as ResultFrame,
)
from modgudr.client.render import FORMATS, Renderer, make_renderer
from modgudr.client.transport import (
    NOT_FROM_AGENT,
    NOT_RUNNING,
    UNREACHABLE_ERRNOS,
    Call,
    client_info,
    open_call,
    open_socket,
)

EXIT_OK = 0
EXIT_DEVIATION = 1
EXIT_USAGE = 64
EXIT_CONFIG = 78
EXIT_INTERRUPTED = 130
EXIT_PIPE = 141

LATER = "added in a later step"

USAGE = """\
usage: modgudr <command> [options]
       modgudr <target> <op> [arguments]

Reach a target through the modgudr broker.

commands:
  targets [--json] [--system S]     list targets
  describe <target>                 a target's operations, limits and facts
  <target> <op> ...                 run an operation (system@env addresses an environment)
  explain <target> <op> ...         what the policy would decide, without running anything
  actions <type>                    a connector's action catalogue
  policy show <target> | lint       the effective rules; check the policy
  status [--quiet|--json]           broker state (--quiet: exit 0 unlocked, 3 locked, 6 down)
  unlock | lock                     the store session (your own terminal only)
  audit tail [options]              recent audit records (your own terminal only)
  agent-setup claude [--out DIR]    generate the Claude Code managed settings and hook
  agent run claude [--env E] [--pass-env NAME]... [-- ARGS]
                                    start Claude Code with a clean environment
  doctor [--agent claude]           check the set-up; --agent also probes the sandbox (API tokens)
  agent-docs claude                 print the Claude Code skill

The environment of a call is system@env, else $MODGUDR_ENV, else the policy's default.
Exit codes: 0 ok, 2 denied, 3 locked, 4 truncated or timed out, 5 upstream error,
6 broker unavailable, 7 throttled, 64 usage, 70 internal.
"""


class _Exit(Exception):
    def __init__(self, code: int) -> None:
        super().__init__(code)
        self.code = code


class _Parser(argparse.ArgumentParser):
    """argparse that raises `UsageError` (exit 64) and never abbreviates an option."""

    def __init__(self, **kwargs: Any) -> None:  # noqa: ANN401
        super().__init__(allow_abbrev=False, **kwargs)

    def error(self, message: str) -> NoReturn:
        raise UsageError(f"{self.prog}: {message}")

    def exit(self, status: int = 0, message: str | None = None) -> NoReturn:
        if message:
            print(message, file=sys.stderr, end="")
        raise _Exit(status)


class Out:
    """Binary stdout with a flush policy: the first write and then at most every 50 ms, so that
    a closed pipe is noticed while a slow stream is still running."""

    def __init__(self, stream: BinaryIO, interval: float = 0.05) -> None:
        self._stream = stream
        self._interval = interval
        self._last = 0.0

    def write(self, text: str) -> None:
        self._stream.write(text.encode("utf-8", "replace"))
        now = time.monotonic()
        if now - self._last >= self._interval:
            self._last = now
            self._stream.flush()

    def flush(self) -> None:
        self._stream.flush()


def _stdout() -> Out:
    return Out(sys.stdout.buffer)


def _note(message: str) -> None:
    print(f"modgudr: {message}", file=sys.stderr)


# --- the broker, from the CLI ---------------------------------------------------------------------


def _info() -> dict[str, Any]:
    return client_info("cli")


def _env() -> str | None:
    return os.environ.get("MODGUDR_ENV") or None


def _meta(op: str, args: Mapping[str, Any] | None = None) -> Any:  # noqa: ANN401
    """A metadata op on the agent socket (both channels serve them): its `result` data."""
    call = open_call(paths.agent_socket(), op, env=_env(), args=dict(args or {}), client=_info())
    try:
        data: Any = None
        for frame in call.frames():
            if isinstance(frame, ResultFrame):
                data = frame.data
        return data
    finally:
        call.close()


def _reachable(path: Any) -> bool:  # noqa: ANN401
    try:
        open_socket(path).close()
    except OSError:
        return False
    return True


def _open_admin() -> Call:
    """A connection to `human.sock`. When it cannot be reached but the agent socket can, this
    is an agent session (M1, M20); when neither can, the broker is not running."""
    human = paths.human_socket()
    try:
        return Call(open_socket(human))
    except OSError as exc:
        if exc.errno in UNREACHABLE_ERRNOS and _reachable(paths.agent_socket()):
            raise BrokerUnavailable(NOT_FROM_AGENT) from None
        raise BrokerUnavailable(NOT_RUNNING) from None


def _admin(op: str, args: Mapping[str, Any] | None = None) -> Call:
    call = _open_admin()
    call.send(op, args=dict(args or {}), client=_info())
    return call


def _admin_result(op: str, args: Mapping[str, Any] | None = None) -> Any:  # noqa: ANN401
    call = _admin(op, args)
    try:
        data: Any = None
        for frame in call.frames():
            if isinstance(frame, ResultFrame):
                data = frame.data
        return data
    finally:
        call.close()


# --- commands without a target ------------------------------------------------------------------


def _parser(prog: str, description: str = "") -> _Parser:
    return _Parser(prog=f"modgudr {prog}", description=description or None)


def _print_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> None:
    out = _stdout()
    renderer = make_renderer("table", out)
    renderer.begin([Column(h, "string") for h in headers])
    for row in rows:
        renderer.row(row)
    renderer.end()
    out.flush()


def _json_out(data: Any) -> None:  # noqa: ANN401
    sys.stdout.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def cmd_targets(argv: Sequence[str]) -> int:
    parser = _parser("targets", "List the targets, their type, environment, tier and operations.")
    parser.add_argument("--json", action="store_true", help="print the broker's answer as JSON")
    parser.add_argument("--system", help="only the targets of this system")
    ns = parser.parse_args(list(argv))
    data = _meta("targets", {"system": ns.system} if ns.system else {})
    if ns.json:
        _json_out(data)
        return EXIT_OK
    rows = [
        [
            str(t["name"]),
            str(t["type"]),
            str(t["env"]),
            str(t["tier"]),
            str(t["mode"]),
            ",".join(t["ops"]),
        ]
        for t in data["targets"]
    ]
    _print_table(["NAME", "TYPE", "ENV", "TIER", "MODE", "OPS"], rows)
    if data.get("warning"):
        _note(f"warning: {data['warning']}")
    return EXIT_OK


@dataclass(frozen=True)
class ArgDesc:
    name: str
    kind: str
    help: str
    required: bool
    flag: str | None
    from_file: bool


@dataclass(frozen=True)
class OpDesc:
    """An `OperationSpec` as `describe` returns it."""

    name: str
    help: str
    args: tuple[ArgDesc, ...]
    params: bool
    dry_run: bool
    rows: bool
    passthrough: bool

    @property
    def read_only(self) -> bool:
        """`--allow-truncated` applies to reads only (M5): an op that takes `--dry-run` writes."""
        return not self.dry_run

    def usage(self) -> str:
        parts = [self.name]
        for arg in self.args:
            if arg.flag is None:
                text = f"<{arg.name}>"
                parts.append(text if arg.required and not arg.from_file else f"[{text}]")
            else:
                text = f"{arg.flag} <{arg.kind}>" if arg.kind != "bool" else arg.flag
                parts.append(text if arg.required else f"[{text}]")
        if any(a.from_file for a in self.args):
            parts.append("[-f FILE]")
        if self.params:
            parts.append("[-p name[:type]=value]...")
        if self.dry_run:
            parts.append("[--dry-run]")
        if self.rows:
            parts.append("[--max-rows N]")
        if self.passthrough:
            parts.append("<arguments...>")
        return " ".join(parts)


def _op_desc(raw: Mapping[str, Any]) -> OpDesc:
    args = tuple(
        ArgDesc(
            name=str(a["name"]),
            kind=str(a["kind"]),
            help=str(a.get("help", "")),
            required=bool(a["required"]),
            flag=a["flag"] if isinstance(a.get("flag"), str) else None,
            from_file=bool(a.get("fromFile", False)),
        )
        for a in raw["args"]
    )
    return OpDesc(
        name=str(raw["name"]),
        help=str(raw.get("help", "")),
        args=args,
        params=bool(raw["params"]),
        dry_run=bool(raw["dryRun"]),
        rows=bool(raw["rows"]),
        passthrough=bool(raw["passthrough"]),
    )


def _describe(target: str) -> tuple[Mapping[str, Any], dict[str, OpDesc]]:
    data: Mapping[str, Any] = _meta("describe", {"target": target})
    ops = {str(o["name"]): _op_desc(o) for o in data["operations"]}
    return data, ops


def cmd_describe(argv: Sequence[str]) -> int:
    parser = _parser("describe", "Operations, arguments and limits of one target.")
    parser.add_argument("target", help="a target name or system@env")
    ns = parser.parse_args(list(argv))
    data, ops = _describe(ns.target)
    lines = [
        f"{data['name']}  ({data['type']}, system {data['system']}, env {data['env']}, "
        f"envSource {data['envSource']})",
        f"tier: {data['tier']}  mode: {data['mode']}  credential: {data['credential']}",
        f"destinations: {', '.join(data['destinations']) or 'none'}",
        "limits: " + ", ".join(f"{k}={v}" for k, v in data["limits"].items()),
        f"pins: {data['pins']}  scrub: {data['scrub']}",
        "operations:",
    ]
    for desc in ops.values():
        lines.append(f"  {desc.usage()}")
        if desc.help:
            lines.append(f"      {desc.help}")
    sys.stdout.write("\n".join(lines) + "\n")
    return EXIT_OK


def cmd_actions(argv: Sequence[str]) -> int:
    parser = _parser("actions", "A connector's actions with their risk classes.")
    parser.add_argument("type", help="a connector type, for example sql")
    ns = parser.parse_args(list(argv))
    data = _meta("actions", {"type": ns.type})
    rows = [
        [str(a["name"]), str(a["risk"]), ",".join(a["constraints"]), str(a["summary"])]
        for a in data["actions"]
    ]
    _print_table(["ACTION", "RISK", "CONSTRAINTS", "SUMMARY"], rows)
    return EXIT_OK


def cmd_policy(argv: Sequence[str]) -> int:
    parser = _parser("policy", "Show the effective rules of a target, or lint the policy.")
    sub = parser.add_subparsers(dest="what", required=True, metavar="show|lint")
    show = sub.add_parser("show", help="effective rules of a target")
    show.add_argument("target")
    sub.add_parser("lint", help="check the policy files")
    ns = parser.parse_args(list(argv))
    if ns.what == "show":
        _json_out(_meta("policy-show", {"target": ns.target}))
        return EXIT_OK
    data = _meta("policy-lint")
    for finding in data["findings"]:
        where = ": ".join(part for part in (finding.get("file"), finding.get("key")) if part)
        prefix = f"{finding['severity']}: {where}: " if where else f"{finding['severity']}: "
        print(prefix + finding["message"])
    return EXIT_OK if data["ok"] else EXIT_CONFIG


def cmd_status(argv: Sequence[str]) -> int:
    parser = _parser("status", "Broker state, protocol versions and isolation.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--quiet", action="store_true", help="no output; exit 0, 3 or 6")
    group.add_argument("--json", action="store_true", help="print the broker's answer as JSON")
    ns = parser.parse_args(list(argv))
    if ns.quiet:
        try:
            data = _meta("status")
        except Error as exc:
            return exc.exit_code
        return 3 if data["locked"] else EXIT_OK
    data = _meta("status")
    if ns.json:
        _json_out(data)
        return EXIT_OK
    protocol = data["protocol"]
    lines = [
        f"broker: modgudr-broker {data['version']}  state: {data['state']}  "
        f"channel: {data['channel']}",
        f"protocol: client v{PROTOCOL_VERSION}, broker "
        + ", ".join(f"v{v}" for v in protocol["broker"]),
        f"store: {data['store']}  dev: {'yes' if data['dev'] else 'no'}  mode: attended",
        f"default env: {data['defaultEnv']['env']} (from {data['defaultEnv']['source']})",
        f"isolation: {data['isolation']}",
        f"agent socket: {data['agentSocket']}",
        f"human socket: {data['humanSocket']}",
    ]
    store_problem = data.get("storeInfo", {}).get("problem")
    if store_problem:
        lines.append(f"store: {store_problem}")
    policy = data["policy"]
    lines.append(f"policy: {len(policy['files'])} files in {policy['dir']}")
    if policy.get("message"):
        lines.append(f"policy: {policy['message']}")
    if data.get("auditDegraded"):
        lines.append("audit: DEGRADED; new calls are refused until a test write succeeds")
    sys.stdout.write("\n".join(lines) + "\n")
    if data.get("warning"):
        _note(f"warning: {data['warning']}")
    return EXIT_OK


def _read_credential() -> str:
    """The credential, read from `/dev/tty` with echo off. Never argv, stdin or `getpass`."""
    import termios

    try:
        fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
    except OSError:
        raise UsageError("unlock needs a terminal") from None
    try:
        try:
            saved = termios.tcgetattr(fd)
        except termios.error:
            raise UsageError("unlock needs a terminal") from None
        hidden = list(saved)
        hidden[3] = hidden[3] & ~termios.ECHO
        termios.tcsetattr(fd, termios.TCSAFLUSH, hidden)
        try:
            os.write(fd, b"modgudr unlock: store credential (input is hidden): ")
            raw = b""
            while b"\n" not in raw and b"\r" not in raw:
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                raw += chunk
        finally:
            termios.tcsetattr(fd, termios.TCSAFLUSH, saved)
            os.write(fd, b"\n")
    finally:
        os.close(fd)
    if not raw:
        raise UsageError("unlock: no credential entered")
    line = raw.split(b"\n", 1)[0].split(b"\r", 1)[0]
    try:
        return line.decode("utf-8")
    except UnicodeDecodeError:
        raise UsageError("unlock: the credential is not valid UTF-8") from None


def cmd_unlock(argv: Sequence[str]) -> int:
    parser = _parser("unlock", "Unlock the store session. Reads the credential from your terminal.")
    parser.parse_args(list(argv))
    # Reachability first, so that "no human.sock" is told before a prompt that could not work.
    _open_admin().close()
    credential = _read_credential()
    data = _admin_result("unlock", {"credential": credential})
    _note("already unlocked" if data.get("alreadyUnlocked") else "unlocked")
    return EXIT_OK


def cmd_lock(argv: Sequence[str]) -> int:
    parser = _parser("lock", "Lock the store session now and cancel in-flight calls.")
    parser.parse_args(list(argv))
    data = _admin_result("lock")
    cancelled = data.get("cancelled", 0)
    _note(f"locked ({cancelled} calls cancelled)" if cancelled else "locked")
    return EXIT_OK


def cmd_audit(argv: Sequence[str]) -> int:
    parser = _parser("audit", "Read the audit log (your own terminal only).")
    sub = parser.add_subparsers(dest="what", required=True, metavar="tail")
    tail = sub.add_parser("tail", help="the most recent records, oldest first, as ndjson")
    tail.add_argument("--target", help="records of this exact target name")
    tail.add_argument("--session", help="records of this session id")
    tail.add_argument("--client", help="records of this client name, for example python")
    tail.add_argument("-n", type=int, default=50, help="how many records (1-1000, default 50)")
    ns = parser.parse_args(list(argv))
    args: dict[str, Any] = {"n": ns.n}
    for key in ("target", "session", "client"):
        if getattr(ns, key) is not None:
            args[key] = getattr(ns, key)
    call = _admin("audit-tail", args)
    out = _stdout()
    trailer: Mapping[str, Any] = {}
    try:
        for frame in call.frames():
            if isinstance(frame, Text):
                out.write(frame.data + "\n")
            elif isinstance(frame, Trailer):
                trailer = frame.data
    finally:
        out.flush()
        call.close()
    malformed = trailer.get("malformed", 0)
    if malformed:
        _note(f"skipped {malformed} malformed audit lines")
    if trailer.get("truncated"):
        _note(
            "audit output stopped at 4 MiB (reason: bytes); the newest records that fit are shown; "
            "narrow it with --target, --session or --client, or lower -n"
        )
        return LimitExceeded.exit_code
    return EXIT_OK


def cmd_agent_setup(argv: Sequence[str]) -> int:
    parser = _parser(
        "agent-setup",
        "Generate the managed settings, the hook and the install steps for a coding agent. "
        "Nothing is installed: the steps need sudo and are printed.",
    )
    sub = parser.add_subparsers(dest="agent", required=True, metavar="claude")
    claude = sub.add_parser("claude", help="Claude Code")
    claude.add_argument(
        "--out", default="modgudr-agent-setup", help="output directory (default %(default)s)"
    )
    claude.add_argument(
        "--allow-domain",
        action="append",
        default=[],
        metavar="D",
        help="a domain the sandbox may reach (repeatable; default pypi.org, "
        "files.pythonhosted.org, registry.npmjs.org)",
    )
    claude.add_argument("--force", action="store_true", help="overwrite an earlier output")
    ns = parser.parse_args(list(argv))
    out = Path(ns.out)
    instructions = run_setup(out, ns.allow_domain, force=ns.force)
    _note(f"wrote {out.absolute()}: {DROPIN_DIR}/{DROPIN_FILE}, {HOOK_FILE}, {INSTALL_FILE}")
    sys.stdout.write(instructions)
    sys.stdout.flush()
    return EXIT_OK


def cmd_agent(argv: Sequence[str]) -> int:
    rest = list(argv)
    passthrough: list[str] = []
    if "--" in rest:
        split = rest.index("--")
        rest, passthrough = rest[:split], rest[split + 1 :]
    parser = _parser("agent", "Run a coding agent with a clean environment.")
    sub = parser.add_subparsers(dest="action", required=True, metavar="run")
    run = sub.add_parser("run", help="start an agent session")
    which = run.add_subparsers(dest="agent", required=True, metavar="claude")
    claude = which.add_parser(
        "claude",
        help="Claude Code; arguments after -- go to claude",
        description="Start Claude Code with the allowlisted environment of M21 and a session id.",
    )
    claude.add_argument("--env", help="the environment of this session (MODGUDR_ENV)")
    claude.add_argument(
        "--pass-env",
        action="append",
        default=[],
        metavar="NAME",
        help="also pass this variable to claude (repeatable)",
    )
    ns = parser.parse_args(rest)
    return run_claude(env=ns.env, pass_env=ns.pass_env, claude_args=passthrough)


def cmd_doctor(argv: Sequence[str]) -> int:
    parser = _parser(
        "doctor",
        "Check the set-up and the agent isolation. Exit 1 when something deviates.",
    )
    parser.add_argument(
        "--agent",
        choices=["claude"],
        help="also run the isolation probe inside Claude Code (spends API tokens)",
    )
    ns = parser.parse_args(list(argv))
    if ns.agent == "claude":
        return run_agent_doctor()
    return run_doctor()


def skill_text() -> str:
    return importlib.resources.files("modgudr.client").joinpath("docs/SKILL.md").read_text("utf-8")


def cmd_agent_docs(argv: Sequence[str]) -> int:
    parser = _parser("agent-docs", "Print the skill text for a coding agent.")
    parser.add_argument("agent", choices=["claude"])
    parser.parse_args(list(argv))
    sys.stdout.write(skill_text())
    return EXIT_OK


def _later(name: str) -> Callable[[Sequence[str]], int]:
    def stub(argv: Sequence[str]) -> int:
        _note(f"{name}: {LATER}")
        return EXIT_USAGE

    return stub


COMMANDS: Mapping[str, Callable[[Sequence[str]], int]] = {
    "targets": cmd_targets,
    "describe": cmd_describe,
    "actions": cmd_actions,
    "policy": cmd_policy,
    "status": cmd_status,
    "unlock": cmd_unlock,
    "lock": cmd_lock,
    "audit": cmd_audit,
    "login": _later("login"),
    "agent-setup": cmd_agent_setup,
    "agent": cmd_agent,
    "doctor": cmd_doctor,
    "agent-docs": cmd_agent_docs,
}


# --- target operations --------------------------------------------------------------------------

_FLAGS_WITHOUT_VALUE = frozenset({"--no-header", "--allow-truncated", "--dry-run"})
_FLAGS_WITH_VALUE = frozenset({"--format", "--max-rows", "-f", "-p"})
_HELP_FLAGS = frozenset({"-h", "--help"})


@dataclass(frozen=True)
class Prepared:
    """One parsed invocation of a target op."""

    op: str
    args: dict[str, Any]
    fmt: str
    header: bool
    allow_truncated: bool


def _split_op(rest: Sequence[str]) -> tuple[list[str], str | None, list[str]]:
    """Split `[client flags…] <op> [everything else]`: flags before the op name are the client's;
    the first other word is the op."""
    leading: list[str] = []
    i = 0
    while i < len(rest):
        token = rest[i]
        if token in _FLAGS_WITHOUT_VALUE or token.startswith(("--format=", "--max-rows=")):
            leading.append(token)
            i += 1
        elif token in _FLAGS_WITH_VALUE:
            if i + 1 >= len(rest):
                raise UsageError(f"{token} needs a value")
            leading += [token, rest[i + 1]]
            i += 2
        elif token in _HELP_FLAGS:
            leading.append(token)
            i += 1
        elif token.startswith("-") and token != "-":
            raise UsageError(
                f"unknown option {token!r} before the operation name; "
                "client options are --format, --no-header, --allow-truncated, --max-rows, "
                "-f, -p and --dry-run"
            )
        else:
            return leading, token, list(rest[i + 1 :])
    return leading, None, []


def _read_statement(path: str) -> str:
    try:
        raw = sys.stdin.buffer.read() if path == "-" else _read_file(path)
    except OSError as exc:
        raise UsageError(f"cannot read {path}: {exc.strerror or exc}") from None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise UsageError(
            f"{'standard input' if path == '-' else path} is not valid UTF-8"
        ) from None
    if not text.strip():
        raise UsageError(f"{'standard input' if path == '-' else path} is empty")
    return text


def _read_file(path: str) -> bytes:
    with open(path, "rb") as handle:  # noqa: PTH123
        return handle.read()


def _op_parser(target: str, desc: OpDesc) -> _Parser:
    parser = _parser(f"{target} {desc.name}", desc.help)
    parser.add_argument(
        "--format", dest="client_format", choices=FORMATS, default="tsv", help="output format"
    )
    parser.add_argument("--no-header", dest="client_no_header", action="store_true")
    parser.add_argument("--allow-truncated", dest="client_allow_truncated", action="store_true")
    if desc.rows:
        parser.add_argument("--max-rows", dest="client_max_rows", type=int, metavar="N")
    if desc.params:
        parser.add_argument(
            "-p", dest="client_params", action="append", metavar="NAME[:TYPE]=VALUE"
        )
    if desc.dry_run:
        parser.add_argument("--dry-run", dest="client_dry_run", action="store_true")
    if any(a.from_file for a in desc.args):
        parser.add_argument(
            "-f", dest="client_file", metavar="FILE", help="read from FILE; - is stdin"
        )
    if desc.passthrough:
        return parser
    for arg in desc.args:
        kwargs: dict[str, Any] = {"help": arg.help or None}
        if arg.flag is None:
            optional = not arg.required or arg.from_file
            parser.add_argument(
                arg.name,
                nargs="?" if optional else None,
                type=int if arg.kind == "int" else str,
                **kwargs,
            )
        elif arg.kind == "bool":
            parser.add_argument(arg.flag, dest=arg.name, action="store_true", **kwargs)
        else:
            parser.add_argument(
                arg.flag,
                dest=arg.name,
                type=int if arg.kind == "int" else str,
                required=arg.required,
                **kwargs,
            )
    return parser


def _prepare(target: str, desc: OpDesc, leading: list[str], tail: list[str]) -> Prepared:
    parser = _op_parser(target, desc)
    if desc.passthrough:
        # Everything after the op name is verbatim; only the flags before it are ours.
        ns = parser.parse_args(leading)
        args: dict[str, Any] = {"argv": tail}
        if tail and any(ch.isspace() for ch in tail[0]):
            raise UsageError(
                f"the first argument {tail[0]!r} contains spaces; pass the arguments as separate "
                f"words, for example `modgudr {target} {desc.name} get pods -n app`, not "
                f'`"get pods -n app"`'
            )
    else:
        ns = parser.parse_intermixed_args(leading + tail)
        args = {}
        file_arg = next((a for a in desc.args if a.from_file), None)
        for arg in desc.args:
            value = getattr(ns, arg.name)
            if arg is file_arg and arg.flag is None:
                path = getattr(ns, "client_file", None)
                if path is not None:
                    if value is not None:
                        raise UsageError(
                            f"give {arg.name} as an argument or with -f FILE, not both"
                        )
                    value = _read_statement(path)
                elif value is None and arg.required:
                    raise UsageError(f"op {desc.name} needs {arg.name}: an argument, or -f FILE")
            if value is not None and value is not False:
                args[arg.name] = value
    max_rows = getattr(ns, "client_max_rows", None)
    if max_rows is not None:
        if max_rows < 1:
            raise UsageError("--max-rows must be a positive integer")
        args["maxRows"] = max_rows
    params = getattr(ns, "client_params", None)
    if params:
        args["params"] = parse_cli_params(params)
    if getattr(ns, "client_dry_run", False):
        args["dryRun"] = True
    return Prepared(
        op=desc.name,
        args=args,
        fmt=ns.client_format,
        header=not ns.client_no_header,
        allow_truncated=ns.client_allow_truncated,
    )


def _resolve_op(target: str, rest: Sequence[str]) -> tuple[OpDesc, list[str], list[str]] | None:
    """Describe the target and find the op named in `rest`. None when only help was asked."""
    leading, op, tail = _split_op(rest)
    data, ops = _describe(target)
    if op is None:
        if any(flag in _HELP_FLAGS for flag in leading):
            lines = [f"usage: modgudr {target} <op> [arguments]", "", "operations:"]
            lines += [f"  {desc.usage()}" for desc in ops.values()]
            sys.stdout.write("\n".join(lines) + "\n")
            return None
        raise UsageError(f"{target}: missing operation; operations: {', '.join(ops)}")
    desc = ops.get(op)
    if desc is None:
        raise UsageError(f"target {data['name']} has no op {op!r}; operations: {', '.join(ops)}")
    return desc, leading, tail


def cmd_target(target: str, rest: Sequence[str]) -> int:
    resolved = _resolve_op(target, rest)
    if resolved is None:
        return EXIT_OK
    desc, leading, tail = resolved
    prepared = _prepare(target, desc, leading, tail)
    return _execute(target, desc, prepared)


def cmd_explain(argv: Sequence[str]) -> int:
    if not argv or argv[0] in _HELP_FLAGS:
        sys.stdout.write("usage: modgudr explain <target> <op> [arguments]\n")
        return EXIT_OK if argv else EXIT_USAGE
    target = argv[0]
    resolved = _resolve_op(target, argv[1:])
    if resolved is None:
        return EXIT_OK
    desc, leading, tail = resolved
    prepared = _prepare(target, desc, leading, tail)
    data = _meta("explain", {"target": target, "op": desc.name, "args": prepared.args})
    lines = [
        data["explanation"],
        f"action: {data['action']}  risk: {data['risk']}  decision: {data['decision']}  "
        f"layer: {data['layer']}  rule: {data['rule']}",
        f"target: {data['target']}  env: {data['env']} ({data['envSource']})  "
        f"effective env: {data['effectiveEnv']}",
    ]
    for constraint in data["constraints"]:
        lines.append(
            f"constraint: {constraint['name']}={constraint['value']} "
            f"({constraint['layer']}, {constraint['source']})"
        )
    sys.stdout.write("\n".join(lines) + "\n")
    return EXIT_OK


def _execute(target: str, desc: OpDesc, prepared: Prepared) -> int:
    call = open_call(
        paths.agent_socket(),
        prepared.op,
        target=target,
        env=_env(),
        args=prepared.args,
        client=_info(),
    )
    out = _stdout()
    renderer: Renderer | None = None
    trailer: Mapping[str, Any] = {}
    try:
        try:
            for frame in call.frames(decode=False):
                renderer = _handle(frame, prepared, out, renderer)
                if isinstance(frame, Trailer):
                    trailer = frame.data
        except LimitExceeded as exc:
            # A timeout after some output: end the document, then 4 or, for reads, 0.
            if renderer is not None:
                renderer.end(truncated=True)
            out.flush()
            if prepared.allow_truncated and desc.read_only:
                _note(exc.message)
                return EXIT_OK
            raise
        truncated = bool(trailer.get("truncated"))
        if renderer is None and trailer.get("affectedRows") is not None:
            renderer = _write_facts(prepared, out, trailer)
        if renderer is not None:
            renderer.end(truncated=truncated)
    finally:
        out.flush()
        call.close()
    if truncated:
        _note(truncation_note(trailer))
        if not (prepared.allow_truncated and desc.read_only):
            return LimitExceeded.exit_code
    return EXIT_OK


def _handle(
    frame: Frame, prepared: Prepared, out: Out, renderer: Renderer | None
) -> Renderer | None:
    if isinstance(frame, Header):
        renderer = make_renderer(prepared.fmt, out, header=prepared.header)
        renderer.begin(frame.columns)
    elif isinstance(frame, Row):
        if renderer is None:
            raise Error("malformed response from the broker (a row before the header)")
        renderer.row(frame.values)
    elif isinstance(frame, Text):
        if frame.stream == "stderr":
            out.flush()
            sys.stderr.write(frame.data)
            sys.stderr.flush()
        else:
            out.write(frame.data)
    elif isinstance(frame, ResultFrame):
        out.write(json.dumps(frame.data, ensure_ascii=False) + "\n")
    return renderer


def _write_facts(prepared: Prepared, out: Out, trailer: Mapping[str, Any]) -> Renderer:
    """A write that sent no rows: its trailer facts as one result row (§7.7)."""
    renderer = make_renderer(prepared.fmt, out, header=prepared.header)
    renderer.begin(
        [
            Column("affectedRows", "integer"),
            Column("committed", "boolean"),
            Column("dryRun", "boolean"),
        ]
    )
    renderer.row([str(trailer["affectedRows"]), trailer.get("committed"), trailer.get("dryRun")])
    return renderer


# --- entry point --------------------------------------------------------------------------------


def _report(exc: Error) -> None:
    message = exc.message
    if isinstance(exc, Throttled) and exc.retry_after:
        message += f" (retry after {exc.retry_after:g} s)"
    if exc.audit_id and exc.exit_code != EXIT_USAGE:
        message += f" [audit {exc.audit_id}]"
    _note(message)


def _silence_stdout() -> None:
    """The reader closed the pipe: point stdout at /dev/null so that exit does not complain."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except (OSError, ValueError):
        pass


def _run(argv: Sequence[str]) -> int:
    if not argv:
        print(USAGE, file=sys.stderr, end="")
        return EXIT_USAGE
    first = argv[0]
    if first in _HELP_FLAGS:
        sys.stdout.write(USAGE)
        return EXIT_OK
    if first.startswith("-"):
        raise UsageError(f"unknown option {first!r}; see modgudr --help")
    if first == "explain":
        return cmd_explain(argv[1:])
    command = COMMANDS.get(first)
    if command is not None:
        return command(argv[1:])
    return cmd_target(first, argv[1:])


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        return _run(args)
    except _Exit as stop:
        return stop.code
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED
    except BrokenPipeError:
        _silence_stdout()
        return EXIT_PIPE
    except Error as exc:
        _report(exc)
        return exc.exit_code
