"""`modgudr doctor` and `modgudr doctor --agent claude` (M22).

`doctor` checks the set-up from outside the sandbox and prints OK, WARN, FAIL and INFO lines; it
exits 1 when anything fails. The isolation verdict comes from the same predicate the broker and
`agent-setup` use (`modgudr.client.agent.isolation`).

`doctor --agent claude` goes further: it starts `claude -p` non-interactively with a fixed prompt
that runs `probe.py` in the agent's own Bash. The probe writes `probe-result.json` itself, so the
verdict never depends on what the model says. This spends API tokens.
"""

import hashlib
import importlib.metadata
import importlib.resources
import json
import os
import pwd
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO, cast
from urllib.parse import unquote, urlparse

from modgudr.client.agent import probe
from modgudr.client.agent.isolation import (
    L0_WARNING,
    Facts,
    Fstat,
    StatLike,
    absolute_path,
    covering_socket_entries,
    credential_denials,
    credential_paths,
    detect,
    load_managed_settings,
    settings_files,
    settings_locations,
)
from modgudr.client.agent.run import (
    build_environment,
    fetch_meta,
    make_azure_dir,
    new_session,
)
from modgudr.client.agent.setup import HOOK_INSTALL_PATH, HOOK_INTERPRETER
from modgudr.client.errors import BrokerUnavailable, CannotRun

MDM_PLIST = "/Library/Managed Preferences/com.anthropic.claudecode.plist"

OK = "OK"
WARN = "WARN"
FAIL = "FAIL"
INFO = "INFO"

EXIT_DEVIATION = 1

AGENT_TIMEOUT = 180.0
REACH_TIMEOUT = 2.0
MAX_RESULT_BYTES = 1024 * 1024

#: The fixed prompt of `doctor --agent`.
AGENT_PROMPT = "Run exactly `python3 probe.py` with the Bash tool, then stop."
ALLOWED_TOOL = "Bash(python3 probe.py)"

MODE_PRIVATE = 0o077


@dataclass(frozen=True)
class Line:
    level: str
    text: str


def _stat(path: str) -> StatLike:
    return os.stat(path)  # noqa: PTH116


def _dict(value: object) -> dict[str, Any] | None:
    return cast("dict[str, Any]", value) if isinstance(value, dict) else None


def _list(value: object) -> list[Any] | None:
    return cast("list[Any]", value) if isinstance(value, list) else None


def editable_install_dirs() -> list[str]:
    """The source directories of editable installs of the client and the broker."""
    out: list[str] = []
    for name in ("modgudr-client", "modgudr-broker"):
        try:
            raw = importlib.metadata.distribution(name).read_text("direct_url.json")
        except importlib.metadata.PackageNotFoundError:
            continue
        if raw is None:
            continue
        try:
            doc = _dict(json.loads(raw)) or {}
        except ValueError:
            continue
        info = _dict(doc.get("dir_info")) or {}
        url = doc.get("url")
        if info.get("editable") is True and isinstance(url, str):
            parsed = urlparse(url)
            if parsed.scheme == "file":
                out.append(unquote(parsed.path))
    return out


def _writable(path: str) -> bool:
    return os.access(path, os.W_OK)


@dataclass(frozen=True)
class Context:
    """What `doctor` looks at. The defaults are production's; tests point them at temp paths."""

    user_home: str = field(default_factory=lambda: pwd.getpwuid(os.getuid()).pw_dir)
    uid: int = field(default_factory=os.getuid)
    #: `managed-settings.json` and `managed-settings.d/`; None means the platform's own.
    managed_base: Path | None = None
    managed_dir: Path | None = None
    hook: Path = Path(HOOK_INSTALL_PATH)
    python: Path = Path(HOOK_INTERPRETER)
    mdm_plist: Path = Path(MDM_PLIST)
    fstat: Fstat = os.fstat
    stat: Callable[[str], StatLike] = _stat
    editable_dirs: Callable[[], list[str]] = editable_install_dirs
    writable: Callable[[str], bool] = _writable
    which: Callable[[str], str | None] = shutil.which

    def settings_paths(self, platform: str) -> tuple[Path, Path]:
        base, dropin = settings_locations(platform)
        return self.managed_base or base, self.managed_dir or dropin


# --- the plain doctor ----------------------------------------------------------------------------


def _facts(status: Mapping[str, Any]) -> Facts:
    try:
        return Facts.from_json(status)
    except ValueError as exc:
        raise CannotRun(f"the broker's status answer is incomplete: {exc}") from None


def _check_mode(ctx: Context, path: str, *, label: str, directory: bool) -> Line:
    try:
        st = os.lstat(path)
    except OSError:
        return Line(WARN, f"{label} {path} does not exist")
    if stat.S_ISLNK(st.st_mode):
        return Line(FAIL, f"{label} {path} is a symlink")
    if st.st_uid != ctx.uid:
        return Line(FAIL, f"{label} {path} is owned by uid {st.st_uid}, not by you")
    if st.st_mode & MODE_PRIVATE:
        wanted = "0700" if directory else "0600"
        return Line(FAIL, f"{label} {path} has mode {stat.S_IMODE(st.st_mode):04o}, not {wanted}")
    return Line(OK, f"{label} {path} is private ({stat.S_IMODE(st.st_mode):04o})")


def _check_root_file(ctx: Context, path: Path, what: str) -> Line:
    try:
        st = ctx.stat(str(path))
    except OSError:
        return Line(FAIL, f"{what} {path} does not exist")
    if st.st_uid != 0:
        return Line(FAIL, f"{what} {path} is owned by uid {st.st_uid}, not by root")
    if st.st_mode & 0o022:
        return Line(
            FAIL,
            f"{what} {path} is writable by group or others (mode {stat.S_IMODE(st.st_mode):04o})",
        )
    return Line(OK, f"{what} {path} is root-owned and not writable by you")


def _policy_lines(ctx: Context, status: Mapping[str, Any]) -> list[Line]:
    files = _list((_dict(status.get("policy")) or {}).get("files"))
    if files is None:
        return [Line(WARN, "the broker's status lists no policy files")]
    dev = status.get("dev") is True
    lines: list[Line] = []
    for raw in files:
        entry = _dict(raw)
        if entry is None:
            continue
        name = str(entry.get("name"))
        uid = entry.get("uid")
        mode = str(entry.get("mode"))
        what = f"policy file {name} (owner uid {uid}, mode {mode})"
        try:
            writable = int(mode, 8) & 0o022
        except ValueError:
            lines.append(Line(FAIL, f"{what}: unreadable mode"))
            continue
        company = name == "00-company.yaml"
        if writable:
            lines.append(Line(FAIL, f"{what} is writable by group or others"))
        elif uid == 0:
            lines.append(Line(OK, what))
        elif uid == ctx.uid and (dev or not company):
            level = WARN if company else OK
            suffix = ": dev mode accepts a company file you own" if company else ""
            lines.append(Line(level, what + suffix))
        else:
            lines.append(Line(FAIL, f"{what} has an owner the broker should not accept"))
    return lines


def _credential_lines(ctx: Context, facts: Facts, settings: Mapping[str, object]) -> list[Line]:
    lines: list[Line] = []
    home = os.path.normpath(facts.home)
    for written, is_dir in credential_paths(facts, ctx.user_home):
        absolute = absolute_path(written, ctx.user_home)
        if absolute is None:
            continue
        is_home = os.path.normpath(absolute) == home
        if not is_home and not os.path.lexists(absolute):
            continue
        label = f"MODGUDR_HOME {absolute}" if is_home else f"credential path {written}"
        in_sandbox, in_rules = credential_denials(
            settings, written, is_dir, user_home=ctx.user_home
        )
        if in_sandbox and in_rules:
            lines.append(Line(OK, f"{label} exists and the managed settings deny it"))
            continue
        missing: list[str] = []
        if not in_sandbox:
            missing.append("sandbox.credentials.files")
        if not in_rules:
            missing.append("a Read(...) rule in permissions.deny")
        lines.append(Line(FAIL, f"{label} exists and is not denied: lacks {' and '.join(missing)}"))
    return lines


def collect_lines(
    ctx: Context, status: Mapping[str, Any] | None, *, broker_error: str | None = None
) -> tuple[list[Line], bool]:
    """Every check of `modgudr doctor`, and whether isolation is `none`."""
    lines: list[Line] = []
    isolated_none = False
    if status is None:
        lines.append(Line(FAIL, f"broker not reachable: {broker_error}"))
    else:
        versions = _list((_dict(status.get("protocol")) or {}).get("broker"))
        shown = ", ".join(f"v{v}" for v in versions) if versions is not None else "unknown"
        lines.append(
            Line(
                OK,
                f"broker reachable: modgudr-broker {status.get('version')}, "
                f"protocol {shown}, state {status.get('state')}",
            )
        )
        facts = _facts(status)
        base, dropin = ctx.settings_paths(facts.platform)
        isolation = detect(
            facts, user_home=ctx.user_home, base=base, dropin_dir=dropin, fstat=ctx.fstat
        )
        if isolation.isolated:
            lines.append(Line(OK, f"isolation: managed-settings ({', '.join(isolation.files)})"))
        else:
            isolated_none = True
            lines += [Line(FAIL, f"isolation: none; {reason}") for reason in isolation.reasons]
        settings = load_managed_settings(base, dropin, fstat=ctx.fstat).settings
        lines += _credential_lines(ctx, facts, settings)
        covering = covering_socket_entries(settings, facts.human_socket, user_home=ctx.user_home)
        for written in covering:
            lines.append(Line(FAIL, f"allowUnixSockets entry {written} covers human.sock"))
        if not covering:
            if facts.platform == "darwin":
                lines.append(Line(OK, "no allowUnixSockets entry covers human.sock"))
            else:
                lines.append(
                    Line(
                        INFO,
                        "linux has no allowUnixSockets: human.sock is hidden only by the "
                        "MODGUDR_HOME deny",
                    )
                )
        home = Path(facts.home)
        lines.append(_check_mode(ctx, str(home), label="state directory", directory=True))
        lines.append(_check_mode(ctx, str(home / "run"), label="run directory", directory=True))
        lines.append(_check_mode(ctx, str(home / "audit"), label="audit directory", directory=True))
        agent = Path(facts.agent_socket)
        lines.append(
            _check_mode(ctx, str(agent.parent), label="agent socket directory", directory=True)
        )
        lines.append(_check_mode(ctx, facts.agent_socket, label="agent.sock", directory=False))
        lines.append(_check_mode(ctx, facts.human_socket, label="human.sock", directory=False))
        lines += _policy_lines(ctx, status)
    lines.append(_check_root_file(ctx, ctx.hook, "hook"))
    lines.append(_check_root_file(ctx, ctx.python, "hook interpreter"))
    if ctx.mdm_plist.exists():
        lines.append(
            Line(
                WARN,
                f"an MDM profile exists ({ctx.mdm_plist}): the file-based managed settings may "
                "be skipped; check /status in Claude Code",
            )
        )
    else:
        lines.append(Line(OK, "no MDM profile for Claude Code"))
    risky = [d for d in ctx.editable_dirs() if ctx.writable(d)]
    for directory in risky:
        lines.append(
            Line(
                WARN,
                f"modgudr runs from an editable install in {directory}, which you can write: "
                "an agent working in that directory can edit the broker, so L0 protection is void",
            )
        )
    if not risky:
        lines.append(Line(OK, "no editable install in a directory an agent could write"))
    found = ctx.which("mg")
    if found:
        lines.append(
            Line(
                INFO,
                f"{found} is on PATH and is not modgudr (on macOS it is an editor); "
                "the command is modgudr",
            )
        )
    else:
        lines.append(Line(INFO, "no other command shadows the short name; the command is modgudr"))
    return lines, isolated_none


def _print_lines(lines: Sequence[Line], out: TextIO) -> None:
    for line in lines:
        print(f"{line.level:<4} {line.text}", file=out)


def _summary(lines: Sequence[Line]) -> str:
    failed = sum(1 for line in lines if line.level == FAIL)
    warned = sum(1 for line in lines if line.level == WARN)
    return f"doctor: {failed} failed, {warned} warnings"


def run_doctor(
    ctx: Context | None = None,
    *,
    status_fn: Callable[[], dict[str, Any]] | None = None,
    out: TextIO | None = None,
) -> int:
    """`modgudr doctor`: print the checks, return 1 when one failed."""
    context = ctx or Context()
    stdout = out or sys.stdout
    fetch = status_fn or (lambda: fetch_meta("status"))
    status: dict[str, Any] | None
    error: str | None = None
    try:
        status = fetch()
    except BrokerUnavailable as exc:
        status, error = None, exc.message
    lines, none = collect_lines(context, status, broker_error=error)
    _print_lines(lines, stdout)
    print(_summary(lines), file=stdout)
    if none:
        print(L0_WARNING, file=sys.stderr)
    return EXIT_DEVIATION if any(line.level == FAIL for line in lines) else 0


# --- doctor --agent ------------------------------------------------------------------------------


def tcp_reachable(host: str, port: int, timeout: float = REACH_TIMEOUT) -> bool:
    try:
        socket.create_connection((host, port), timeout=timeout).close()
    except (OSError, ValueError):
        return False
    return True


def _split_destination(destination: str) -> tuple[str, int] | None:
    host, _, port = destination.rpartition(":")
    if not host or not port.isdigit():
        return None
    return host.strip("[]"), int(port)


def _destinations(targets: Mapping[str, Any]) -> list[str]:
    out: dict[str, None] = {}
    for entry in _list(targets.get("targets")) or []:
        for destination in _list((_dict(entry) or {}).get("destinations")) or []:
            if isinstance(destination, str):
                out[destination] = None
    return list(out)


def probe_input(
    ctx: Context,
    facts: Facts,
    destinations: Sequence[str],
    reach: Callable[[str, int], bool],
) -> dict[str, Any]:
    """The `probe-input.json` document. Paths and sockets are the broker's own, never recomputed."""
    credentials: list[str] = []
    for written, _ in credential_paths(facts, ctx.user_home):
        absolute = absolute_path(written, ctx.user_home)
        if absolute is not None and os.path.lexists(absolute):
            credentials.append(absolute)
    targets: list[dict[str, Any]] = []
    for destination in destinations:
        parsed = _split_destination(destination)
        reached = reach(*parsed) if parsed is not None else False
        targets.append({"hostPort": destination, "doctorReached": reached})
    return {
        "platform": facts.platform,
        "home": facts.home,
        "agentSocket": facts.agent_socket,
        "humanSocket": facts.human_socket,
        "credentialPaths": credentials,
        "targets": targets,
        "persistenceHome": ctx.user_home,
    }


def claude_command(claude: str) -> list[str]:
    return [
        claude,
        "-p",
        AGENT_PROMPT,
        "--output-format",
        "stream-json",
        "--verbose",
        "--tools",
        "Bash",
        "--max-turns",
        "4",
        "--no-session-persistence",
        "--permission-mode",
        "dontAsk",
        "--allowedTools",
        ALLOWED_TOOL,
    ]


def _excerpt(data: bytes, limit: int = 300) -> str:
    text = data.decode("utf-8", "replace")
    cleaned = "".join(ch if ch.isprintable() or ch in "\n\t" else "?" for ch in text)
    return " ".join(cleaned.split())[:limit]


def _read_result(workdir: Path) -> dict[str, Any] | None:
    path = workdir / probe.RESULT_FILE
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_RESULT_BYTES + 1)
    except OSError:
        return None
    if len(raw) > MAX_RESULT_BYTES:
        raise CannotRun("inconclusive: probe-result.json is too large")
    try:
        doc: Any = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise CannotRun("inconclusive: probe-result.json is not valid JSON") from None
    if not isinstance(doc, dict):
        raise CannotRun("inconclusive: probe-result.json is not a JSON object")
    return doc  # pyright: ignore[reportUnknownVariableType]


@dataclass(frozen=True)
class Verdict:
    level: str
    result: str
    label: str
    detail: str


def judge(spec: Mapping[str, Any], document: Mapping[str, Any]) -> list[Verdict]:
    """Compare the probe's result with the checks the input asked for. Raises `CannotRun` when the
    result is incomplete or malformed."""
    reported: dict[str, Mapping[str, Any]] = {}
    checks: Any = document.get("checks")
    if not isinstance(checks, list):
        raise CannotRun("inconclusive: probe-result.json has no checks")
    for item in checks:  # pyright: ignore[reportUnknownVariableType]
        if isinstance(item, dict) and isinstance(item.get("id"), str):  # pyright: ignore[reportUnknownMemberType]
            reported[str(item["id"])] = item  # pyright: ignore[reportUnknownArgumentType]
    verdicts: list[Verdict] = []
    for check in probe.planned(dict(spec)):
        item = reported.get(check["id"])
        if item is None:
            raise CannotRun(f"inconclusive: probe-result.json lacks the check {check['id']}")
        result = item.get("result")
        if result not in (probe.BLOCKED, probe.REACHABLE, probe.NOT_TESTED):
            raise CannotRun(f"inconclusive: check {check['id']} has the result {result!r}")
        detail = str(item.get("detail", ""))[:200]
        verdicts.append(
            Verdict(_level(check["id"], str(result)), str(result), check["label"], detail)
        )
    return verdicts


def _level(check_id: str, result: str) -> str:
    if result == probe.NOT_TESTED:
        return WARN
    if check_id == probe.AGENT_SOCKET:
        return OK if result == probe.REACHABLE else FAIL
    if check_id == probe.KEYCHAIN:
        return WARN if result == probe.REACHABLE else OK
    return FAIL if result == probe.REACHABLE else OK


def _settings_hashes(ctx: Context, facts: Facts) -> list[str]:
    base, dropin = ctx.settings_paths(facts.platform)
    lines: list[str] = []
    for path in settings_files(base, dropin):
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            digest = f"unreadable ({exc.strerror})"
        lines.append(f"  {digest}  {path}")
    return lines or ["  none: no managed settings were present"]


def _cleanup_probe_files(home: str) -> None:
    directory = Path(home)
    try:
        leftovers = [p for p in directory.iterdir() if p.name.startswith(probe.PROBE_PREFIX)]
    except OSError:
        return
    for path in leftovers:
        if path.is_file() and not path.is_symlink():
            path.unlink(missing_ok=True)


def run_agent_doctor(
    ctx: Context | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    status_fn: Callable[[], dict[str, Any]] | None = None,
    targets_fn: Callable[[], dict[str, Any]] | None = None,
    reach: Callable[[str, int], bool] = tcp_reachable,
    timeout: float = AGENT_TIMEOUT,
    out: TextIO | None = None,
) -> int:
    """`modgudr doctor --agent claude`. Raises `CannotRun` (69) when no verdict is possible."""
    context = ctx or Context()
    parent = os.environ if environ is None else environ
    stdout = out or sys.stdout
    claude = shutil.which("claude", path=parent.get("PATH", ""))
    if claude is None:
        raise CannotRun("claude was not found on PATH; install Claude Code first")
    try:
        status = (status_fn or (lambda: fetch_meta("status")))()
        targets = (targets_fn or (lambda: fetch_meta("targets")))()
    except BrokerUnavailable as exc:
        raise CannotRun(f"the broker is not reachable ({exc.message}); start it first") from None
    facts = _facts(status)
    spec = probe_input(context, facts, _destinations(targets), reach)
    workdir = Path(tempfile.mkdtemp(prefix="mg-doctor-"))
    azure_dir = make_azure_dir()
    try:
        script = importlib.resources.files("modgudr.client.agent").joinpath("probe.py")
        (workdir / "probe.py").write_text(script.read_text("utf-8"), "utf-8")
        (workdir / probe.INPUT_FILE).write_text(json.dumps(spec, indent=2) + "\n", "utf-8")
        child = build_environment(
            parent, session=new_session(), env=None, pass_env=[], azure_dir=azure_dir
        )
        print(
            "modgudr doctor --agent claude: this starts Claude Code and spends API tokens "
            "(a few turns, at most "
            f"{int(timeout)} s).",
            file=stdout,
            flush=True,
        )
        try:
            done = subprocess.run(
                claude_command(claude),
                cwd=workdir,
                env=child,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise CannotRun(
                f"inconclusive: claude did not finish within {int(timeout)} s"
            ) from None
        except OSError as exc:
            raise CannotRun(f"cannot start claude: {exc.strerror or exc}") from None
        document = _read_result(workdir)
        if document is None:
            seen = _excerpt(done.stdout + b" " + done.stderr)
            if "login" in seen.lower() or "not logged in" in seen.lower():
                raise CannotRun("claude is not logged in; run `claude`, then /login, and retry")
            raise CannotRun(
                f"inconclusive: the probe left no result (claude exit {done.returncode}): {seen}"
            )
        verdicts = judge(spec, document)
        print("managed settings tested (sha256):", file=stdout)
        for line in _settings_hashes(context, facts):
            print(line, file=stdout)
        for verdict in verdicts:
            suffix = f"  ({verdict.detail})" if verdict.detail else ""
            print(f"{verdict.level:<4} {verdict.result:<10} {verdict.label}{suffix}", file=stdout)
        failed = sum(1 for v in verdicts if v.level == FAIL)
        warned = sum(1 for v in verdicts if v.level == WARN)
        print(f"doctor --agent: {failed} failed, {warned} warnings", file=stdout)
        return EXIT_DEVIATION if failed else 0
    finally:
        _cleanup_probe_files(context.user_home)
        shutil.rmtree(workdir, ignore_errors=True)
        shutil.rmtree(azure_dir, ignore_errors=True)
