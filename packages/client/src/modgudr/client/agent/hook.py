"""`mg-hook`: the Claude Code PreToolUse steering hook for Bash (M20).

`modgudr agent-setup claude` copies this file, unchanged, to `mg-hook`; it is installed as
`/opt/modgudr/bin/mg-hook` and runs as `/usr/bin/python3 -I /opt/modgudr/bin/mg-hook`. It is one
self-contained file: it runs on the macOS Command Line Tools Python 3.9 (no `match`, no `X | Y`
types at run time, no 3.10+ stdlib API), imports only the standard library and never `modgudr`.

It reads the PreToolUse JSON from stdin and takes `tool_input.command`. The command is split shell-
aware (quotes respected) on `;`, `&&`, `||`, `|`, `&`, newlines, `$( )` and backticks. Leading
assignments and the wrappers `timeout`, `time`, `nice`, `nohup`, `stdbuf`, `command`, `builtin`,
`noglob`, `xargs`, `env` and `sudo` are stripped. The hook blocks (exit 2, the reason on stderr)
when the first word's basename is one of `BLOCKED_TOOLS`, or when `curl`, `wget` or `http` names a
URL whose host is a target destination. The destinations come from the `targets` op on `agent.sock`
(300 ms timeout), cached for 30 s in a 0600 file under `$TMPDIR`. When the broker is down only the
host check is skipped. Everything else exits 0.

This is steering, not a boundary. An internal error writes one line to stderr and exits 0;
`onFailure: "block"` in the settings already covers a hook that cannot start. Known miss, on
purpose: the hook can be bypassed with `bash -c "kubectl …"`, `eval`, a script file or any other
indirection it does not parse. The sandbox and the deny rules of the managed settings are the
boundary, not this hook.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import socket
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, TextIO, cast

#: The tools that only exist for a coding agent through `modgudr` (M20).
BLOCKED_TOOLS = (
    "kubectl",
    "kubelogin",
    "az",
    "sqlplus",
    "sql",
    "snowsql",
    "snow",
    "bw",
    "bws",
    "security",
)
#: Commands that fetch a URL; one naming a target host is blocked.
FETCH_TOOLS = ("curl", "wget", "http")

CACHE_SECONDS = 30.0
BROKER_TIMEOUT = 0.3

_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")

# --- splitting -----------------------------------------------------------------------------------


def split_commands(command: str) -> list[list[str]]:
    """The simple commands of a shell line, each as its words (quotes removed).

    Separators outside quotes end a command; `$(` and a backtick start a nested command even
    inside double quotes, after which the enclosing command resumes. Quoted text stays inside its
    word, so `echo "a; kubectl"` is one command.
    """
    commands: list[list[str]] = []
    words: list[str] = []
    word: list[str] = []
    in_word = False
    # What an enclosing context left behind when a `$(` or a backtick opened:
    # (opener, quote state, words, the word in progress, whether a word is in progress).
    stack: list[tuple[str, str, list[str], list[str], bool]] = []
    quote = ""
    i = 0
    n = len(command)

    def end_word() -> None:
        nonlocal in_word
        if in_word:
            words.append("".join(word))
            word.clear()
            in_word = False

    def end_command() -> None:
        nonlocal words
        end_word()
        if words:
            commands.append(words)
        words = []

    def open_context(opener: str) -> None:
        nonlocal words, quote, in_word
        stack.append((opener, quote, words, list(word), in_word))
        words = []
        word.clear()
        in_word = False
        quote = ""

    def close_context() -> None:
        nonlocal words, quote, in_word
        end_command()
        _, quote, words, saved, _ = stack.pop()
        word[:] = saved
        in_word = True

    while i < n:
        c = command[i]
        if quote == "'":
            if c == "'":
                quote = ""
            else:
                word.append(c)
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            nxt = command[i + 1]
            if nxt != "\n":
                word.append(nxt)
                in_word = True
            i += 2
            continue
        if c == "`":
            if stack and stack[-1][0] == "`":
                close_context()
            else:
                open_context("`")
            i += 1
            continue
        if c == "$" and command.startswith("$(", i):
            open_context("(")
            i += 2
            continue
        if quote == '"':
            if c == '"':
                quote = ""
            else:
                word.append(c)
            i += 1
            continue
        if c in "'\"":
            quote = c
            in_word = True
            i += 1
            continue
        if c == ")" and stack and stack[-1][0] == "(":
            close_context()
            i += 1
            continue
        if c in " \t":
            end_word()
        elif c in "\n;|()":
            end_command()
        elif c == "&":
            previous = command[i - 1] if i > 0 else ""
            following = command[i + 1] if i + 1 < n else ""
            if (previous != "" and previous in "<>") or following == ">":
                word.append(c)
                in_word = True
            else:
                end_command()
        elif c == "#" and not in_word:
            while i < n and command[i] != "\n":
                i += 1
            continue
        else:
            word.append(c)
            in_word = True
        i += 1
    while stack:
        close_context()
    end_command()
    return commands


# --- wrappers ------------------------------------------------------------------------------------

#: Options with a separate argument, per wrapper.
_SUDO_ARG_OPTS = frozenset("ugphCDRTUrt")
_XARGS_ARG_OPTS = frozenset("nILPsdEa")
_TIMEOUT_ARG_OPTS = frozenset("sk")
_STDBUF_ARG_OPTS = frozenset("ioe")


def _skip_options(words: Sequence[str], start: int, short_with_arg: frozenset[str]) -> int:
    """The index after the leading options of a wrapper (`--` ends them)."""
    i = start
    while i < len(words):
        word = words[i]
        if word == "--":
            return i + 1
        if not word.startswith("-") or word == "-":
            return i
        if word.startswith("--"):
            i += 1
            continue
        letter = word[1:2]
        # `-n5` carries its argument; a bare `-n` takes the next word.
        i += 2 if letter in short_with_arg and len(word) == 2 else 1
    return i


def command_word(words: Sequence[str]) -> tuple[str, list[str]] | None:
    """The program a simple command runs and its arguments, after assignments and wrappers.

    None when nothing runs (only assignments) or when the wrapper only looks a command up
    (`command -v kubectl`).
    """
    i = 0
    n = len(words)
    while i < n:
        word = words[i]
        if _ASSIGNMENT.match(word):
            i += 1
            continue
        name = Path(word).name
        if name in ("time", "nohup", "builtin", "noglob"):
            i = _skip_options(words, i + 1, frozenset())
        elif name == "nice":
            i = _skip_options(words, i + 1, frozenset("n"))
        elif name == "stdbuf":
            i = _skip_options(words, i + 1, _STDBUF_ARG_OPTS)
        elif name == "xargs":
            i = _skip_options(words, i + 1, _XARGS_ARG_OPTS)
        elif name == "sudo":
            i = _skip_options(words, i + 1, _SUDO_ARG_OPTS)
        elif name == "timeout":
            i = _skip_options(words, i + 1, _TIMEOUT_ARG_OPTS)
            i += 1  # the duration
        elif name == "command":
            if i + 1 < n and words[i + 1] in ("-v", "-V"):
                return None
            i = _skip_options(words, i + 1, frozenset())
        elif name == "env":
            i += 1
            while i < n:
                item = words[i]
                if item == "--":
                    i += 1
                    break
                if item in ("-u", "-C", "-S"):
                    i += 2
                elif (item.startswith("-") and item != "-") or _ASSIGNMENT.match(item):
                    i += 1
                else:
                    break
        else:
            return word, list(words[i + 1 :])
    return None


# --- hosts ---------------------------------------------------------------------------------------


def _as_dict(value: object) -> dict[str, Any] | None:
    return cast("dict[str, Any]", value) if isinstance(value, dict) else None


def _as_list(value: object) -> list[Any] | None:
    return cast("list[Any]", value) if isinstance(value, list) else None


def host_of(argument: str) -> str | None:
    """The lowercase host a `curl`/`wget`/`http` argument names, or None for an option or a word
    that is no URL or host."""
    text = argument
    if text.startswith("-"):
        if not text.startswith("--") or "=" not in text:
            return None
        text = text.split("=", 1)[1]
    text = _SCHEME.sub("", text, count=1)
    text = re.split(r"[/?#]", text, maxsplit=1)[0]
    text = text.rsplit("@", 1)[-1]
    if text.startswith("["):
        end = text.find("]")
        text = text[1:end] if end > 0 else text
    elif text.count(":") == 1:
        text = text.split(":", 1)[0]
    text = text.rstrip(".").lower()
    return text or None


def agent_socket_path(environ: Mapping[str, str]) -> str:
    """`agent.sock` as the client computes it (M1); the hook cannot import the client."""
    override = environ.get("MODGUDR_SOCKET")
    if override:
        return override
    if sys.platform == "darwin":
        import pwd

        home = pwd.getpwuid(os.getuid()).pw_dir
        return str(Path(home) / "Library" / "Caches" / "modgudr" / "run" / "agent.sock")
    runtime = environ.get("XDG_RUNTIME_DIR")
    if runtime:
        return str(Path(runtime) / "modgudr" / "agent.sock")
    return f"/tmp/modgudr-{os.getuid()}/agent.sock"


def fetch_hosts(socket_path: str) -> list[str]:
    """The destination hosts of every target, from `agent.sock`. Raises OSError or ValueError
    when the broker cannot answer within `BROKER_TIMEOUT`."""
    deadline = time.monotonic() + BROKER_TIMEOUT
    request = {"v": 1, "op": "targets", "args": {}, "client": {"name": "mg-hook", "version": "1"}}
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(BROKER_TIMEOUT)
        sock.connect(socket_path)
        sock.sendall(json.dumps(request).encode("ascii") + b"\n")
        buffer = b""
        while True:
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                frame = _as_dict(json.loads(line.decode("utf-8")))
                if frame is None:
                    raise ValueError("unexpected frame")
                kind = frame.get("t")
                if kind == "error":
                    raise ValueError("the broker refused the targets op")
                if kind == "result":
                    return _hosts_of_result(frame.get("data"))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise OSError("the broker did not answer in time")
            sock.settimeout(remaining)
            chunk = sock.recv(65536)
            if not chunk:
                raise OSError("the broker closed the connection")
            buffer += chunk
    finally:
        sock.close()


def _hosts_of_result(data: object) -> list[str]:
    document = _as_dict(data)
    targets = _as_list(document.get("targets")) if document is not None else None
    if targets is None:
        raise ValueError("unexpected targets answer")
    hosts: set[str] = set()
    for target in targets:
        entry = _as_dict(target)
        destinations = _as_list(entry.get("destinations")) if entry is not None else None
        if destinations is None:
            continue
        for destination in destinations:
            host = host_of(destination) if isinstance(destination, str) else None
            if host:
                hosts.add(host)
    return sorted(hosts)


def cache_path(environ: Mapping[str, str]) -> str:
    return str(Path(environ.get("TMPDIR") or "/tmp") / f"modgudr-hook-{os.getuid()}.json")


def _read_cache(path: str, now: float) -> list[str] | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if st.st_uid != os.getuid() or st.st_mode & 0o077:
            return None
        with os.fdopen(fd, "r", closefd=False) as handle:
            document = _as_dict(json.load(handle))
    except (OSError, ValueError):
        return None
    finally:
        os.close(fd)
    if document is None:
        return None
    stamp = document.get("ts")
    hosts = _as_list(document.get("hosts"))
    if isinstance(stamp, bool) or not isinstance(stamp, (int, float)):
        return None
    if not 0 <= now - stamp < CACHE_SECONDS:
        return None
    if hosts is None or not all(isinstance(h, str) for h in hosts):
        return None
    return [str(h) for h in hosts]


def _write_cache(path: str, hosts: Sequence[str], now: float) -> None:
    temporary = f"{path}.{os.getpid()}"
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError:
        return
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump({"ts": now, "hosts": list(hosts)}, handle)
        Path(temporary).replace(path)
    except OSError:
        with contextlib.suppress(OSError):
            Path(temporary).unlink()


def target_hosts(environ: Mapping[str, str], now: float) -> list[str]:
    """The target destination hosts: the cache while fresh, else the broker. Raises when the
    broker cannot answer."""
    path = cache_path(environ)
    cached = _read_cache(path, now)
    if cached is not None:
        return cached
    hosts = fetch_hosts(agent_socket_path(environ))
    _write_cache(path, hosts, now)
    return hosts


# --- decision ------------------------------------------------------------------------------------

HINT = "Use `modgudr <target> <op> …` instead; list the targets with `modgudr targets`."


def decide(command: str, hosts: Callable[[], Sequence[str]]) -> str | None:
    """The reason to block a Bash command, or None to allow it.

    `hosts` returns the target destination hosts and is only called for a fetch command; when it
    raises, the host check is skipped.
    """
    known: list[str] | None = None
    for words in split_commands(command):
        found = command_word(words)
        if found is None:
            continue
        program, arguments = found
        name = Path(program).name
        if name in BLOCKED_TOOLS:
            return f"Blocked: `{name}` is not available to a coding agent here. {HINT}"
        if name in FETCH_TOOLS:
            if known is None:
                try:
                    known = [h.lower() for h in hosts()]
                except Exception:
                    known = []
            for argument in arguments:
                host = host_of(argument)
                if host is not None and host in known:
                    return f"Blocked: `{name}` names the target host {host}. {HINT}"
    return None


def main(
    stdin: TextIO | None = None,
    stderr: TextIO | None = None,
    environ: Mapping[str, str] | None = None,
    now: Callable[[], float] = time.time,
) -> int:
    """The hook: 2 to block, 0 otherwise. Never raises."""
    err = sys.stderr if stderr is None else stderr
    env = os.environ if environ is None else environ
    try:
        source = sys.stdin if stdin is None else stdin
        try:
            payload = json.loads(source.read())
        except ValueError as exc:
            err.write(f"mg-hook: cannot read the hook input ({exc}); allowing\n")
            return 0
        document = _as_dict(payload)
        tool_input = _as_dict(document.get("tool_input")) if document is not None else None
        command = tool_input.get("command") if tool_input is not None else None
        if not isinstance(command, str):
            return 0
        reason = decide(command, lambda: target_hosts(env, now()))
        if reason is None:
            return 0
        err.write(reason + "\n")
        return 2
    except Exception as exc:
        with contextlib.suppress(Exception):
            err.write(f"mg-hook: internal error ({type(exc).__name__}: {exc}); allowing\n")
        return 0


if __name__ == "__main__":
    sys.exit(main())
