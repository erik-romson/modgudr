"""`modgudr agent run claude`: start Claude Code with a clean environment (M21).

The child gets an allowlist of the parent's variables, plus the names given with `--pass-env`, plus
the variables `agent run` sets itself. Nothing else reaches it: the developer's own credential
variables, `KUBECONFIG` and a `MODGUDR_ENV` of the parent are all dropped. The process is replaced
(exec), so signals and the terminal pass through unchanged.
"""

import os
import re
import secrets
import shutil
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from modgudr.client import paths
from modgudr.client.agent.isolation import L0_WARNING
from modgudr.client.errors import BrokerUnavailable, CannotRun, UsageError
from modgudr.client.protocol import Result
from modgudr.client.transport import client_info, open_call

#: Variables passed through from the parent, by exact name.
ALLOWED_NAMES = frozenset(
    {
        "PATH",
        "HOME",
        "TERM",
        "LANG",
        "SHELL",
        "USER",
        "LOGNAME",
        "TMPDIR",
        "COLORTERM",
        "TERM_PROGRAM",
        "SSH_AUTH_SOCK",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "SSL_CERT_FILE",
        "NODE_EXTRA_CA_CERTS",
    }
)
#: Variables passed through by prefix.
ALLOWED_PREFIXES = ("LC_", "ANTHROPIC_", "CLAUDE_CODE_")
#: What `agent run` sets itself (`MODGUDR_ENV` only with `--env`, `MODGUDR_SOCKET` when set).
SCRUB_VARIABLE = "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"

_SECRETISH = re.compile(r"TOKEN|SECRET|PASSWORD", re.IGNORECASE)
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

Exec = Callable[[str, Sequence[str], Mapping[str, str]], None]


def is_allowed(name: str) -> bool:
    return name in ALLOWED_NAMES or name.startswith(ALLOWED_PREFIXES)


def new_session() -> str:
    return f"s-{secrets.token_hex(6)}"


def check_pass_env(names: Sequence[str]) -> list[str]:
    """Validate `--pass-env` names and return the warnings for the secret-looking ones."""
    warnings: list[str] = []
    for name in names:
        if not _NAME.fullmatch(name):
            raise UsageError(f"--pass-env {name!r} is not a variable name")
        if _SECRETISH.search(name):
            warnings.append(
                f"--pass-env {name} looks like a credential; the agent will see its value"
            )
    return warnings


def build_environment(
    parent: Mapping[str, str],
    *,
    session: str,
    env: str | None,
    pass_env: Sequence[str],
    azure_dir: str,
) -> dict[str, str]:
    """The child environment of M21: the allowlist, `--pass-env` names, then the fixed variables."""
    child = {name: value for name, value in parent.items() if is_allowed(name)}
    for name in pass_env:
        if name in parent:
            child[name] = parent[name]
    child["MODGUDR_SESSION"] = session
    if env is not None:
        child["MODGUDR_ENV"] = env
    else:
        child.pop("MODGUDR_ENV", None)
    if parent.get("MODGUDR_SOCKET"):
        child["MODGUDR_SOCKET"] = parent["MODGUDR_SOCKET"]
    child["KUBECONFIG"] = os.devnull
    child["AZURE_CONFIG_DIR"] = azure_dir
    child[SCRUB_VARIABLE] = "1"
    return child


def make_azure_dir() -> str:
    """A new empty directory, mode 0700, for `AZURE_CONFIG_DIR`."""
    return tempfile.mkdtemp(prefix="mg-azure-")


# --- the broker ----------------------------------------------------------------------------------


def fetch_meta(op: str) -> dict[str, Any]:
    """The `result` data of a metadata op over `agent.sock`. Raises `BrokerUnavailable`."""
    call = open_call(paths.agent_socket(), op, client=client_info("agent-run"))
    try:
        data: Any = None
        for frame in call.frames():
            if isinstance(frame, Result):
                data = frame.data
    finally:
        call.close()
    if not isinstance(data, dict):
        raise CannotRun(f"the broker's {op} answer is malformed")
    return data  # pyright: ignore[reportUnknownVariableType]


def fetch_status() -> dict[str, Any]:
    return fetch_meta("status")


def _environments(status: Mapping[str, Any]) -> list[tuple[str, list[str]]]:
    raw: Any = status.get("environments")
    if not isinstance(raw, list):
        raise CannotRun("the broker's status answer lists no environments")
    out: list[tuple[str, list[str]]] = []
    for item in raw:  # pyright: ignore[reportUnknownVariableType]
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):  # pyright: ignore[reportUnknownMemberType]
            raise CannotRun("the broker's status answer has a malformed environment")
        aliases: Any = item.get("aliases", [])  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        listed = [a for a in aliases if isinstance(a, str)] if isinstance(aliases, list) else []  # pyright: ignore[reportUnknownVariableType]
        out.append((str(item["name"]), listed))  # pyright: ignore[reportUnknownArgumentType]
    return out


def canonical_env(status: Mapping[str, Any], wanted: str) -> str:
    """The canonical name of an environment or alias. Raises `UsageError` with the valid list."""
    environments = _environments(status)
    for name, aliases in environments:
        if wanted == name or wanted in aliases:
            return name
    listing = ", ".join(f"{n} ({', '.join(a)})" if a else n for n, a in environments)
    raise UsageError(f"unknown environment {wanted!r}; valid: {listing}")


def _note(message: str) -> None:
    print(f"modgudr: {message}", file=sys.stderr)


def run_claude(
    *,
    env: str | None,
    pass_env: Sequence[str],
    claude_args: Sequence[str],
    environ: Mapping[str, str] | None = None,
    exec_fn: Exec | None = None,
    status_fn: Callable[[], dict[str, Any]] = fetch_status,
) -> int:
    """Start `claude`. Returns only when the injected `exec_fn` returns; the real one does not."""
    parent = os.environ if environ is None else environ
    warnings = check_pass_env(pass_env)
    claude = shutil.which("claude", path=parent.get("PATH", ""))
    if claude is None:
        raise CannotRun("claude was not found on PATH; install Claude Code first")
    status: dict[str, Any] | None
    try:
        status = status_fn()
    except BrokerUnavailable as exc:
        status = None
        _note(f"warning: {exc.message}; the environment is checked again by every call")
    chosen: str | None = None
    if env is not None:
        chosen = canonical_env(status, env) if status is not None else env
    for warning in warnings:
        _note(f"warning: {warning}")
    session = new_session()
    azure_dir = make_azure_dir()
    child = build_environment(
        parent, session=session, env=chosen, pass_env=pass_env, azure_dir=azure_dir
    )
    _note(f"session {session}" + (f", environment {chosen}" if chosen else ""))
    if status is not None and status.get("isolation") == "none":
        print(L0_WARNING, file=sys.stderr)
    _note(
        f"{SCRUB_VARIABLE}=1 is set: Bash commands the sandbox does not auto-allow ask for "
        "your approval"
    )
    sys.stderr.flush()
    runner: Exec = exec_fn if exec_fn is not None else _execve
    try:
        runner(claude, [claude, *claude_args], child)
    except OSError as exc:
        raise CannotRun(f"cannot start {claude}: {exc.strerror or exc}") from None
    return 0


def _execve(path: str, argv: Sequence[str], env: Mapping[str, str]) -> None:
    os.execve(path, list(argv), dict(env))
