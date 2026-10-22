"""The isolation probe of `modgudr doctor --agent claude` (pre-plan §4.8, §13).

A standalone script: the doctor copies it to a work directory as `probe.py`, and the agent's Bash
runs `python3 probe.py` from there with whatever `python3` its `PATH` finds, which may be the
Command Line Tools Python 3.9. So it uses the standard library only and no 3.10+ syntax.

It reads `probe-input.json` and writes `probe-result.json`, both in the current directory. Every
check ends as one of

- `BLOCKED`: the attempt failed;
- `REACHABLE`: the attempt worked, which the sandbox should have prevented (except `agent.sock`);
- `NOT_TESTED`: no verdict is possible. A target host the doctor itself could not reach is never
  a pass, so a down VPN cannot fake one.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

INPUT_FILE = "probe-input.json"
RESULT_FILE = "probe-result.json"

BLOCKED = "BLOCKED"
REACHABLE = "REACHABLE"
NOT_TESTED = "NOT_TESTED"

AGENT_SOCKET = "agent.sock"
HUMAN_SOCKET = "human.sock"
PERSIST_CREATE = "persist.create"
PERSIST_APPEND = "persist.append"
LAUNCHCTL = "launchctl"
KEYCHAIN = "keychain"

#: `security` exits with this when the keychain was reachable and the item does not exist.
KEYCHAIN_NOT_FOUND = 44
PROBE_PREFIX = ".modgudr-probe-"
TCP_TIMEOUT = 3.0
COMMAND_TIMEOUT = 10.0

Spec = dict[str, Any]
Check = dict[str, Any]


def planned(spec: Spec) -> list[Check]:
    """Every check the input asks for: `id`, a label, and `untested` (a reason) when no verdict is
    possible. The doctor compares the result file against this list."""
    checks: list[Check] = []
    for path in spec.get("credentialPaths", []):
        checks.append({"id": "read:" + path, "label": "read " + path, "untested": None})
    for target in spec.get("targets", []):
        hostport = target["hostPort"]
        reason = None
        if not target.get("doctorReached"):
            reason = "the doctor cannot reach it either"
        checks.append({"id": "tcp:" + hostport, "label": "tcp " + hostport, "untested": reason})
    checks.append({"id": AGENT_SOCKET, "label": "connect agent.sock", "untested": None})
    checks.append({"id": HUMAN_SOCKET, "label": "connect human.sock", "untested": None})
    checks.append({"id": PERSIST_CREATE, "label": "create a file in $HOME", "untested": None})
    checks.append({"id": PERSIST_APPEND, "label": "append to ~/.zshrc", "untested": None})
    if spec.get("platform") == "darwin":
        checks.append({"id": LAUNCHCTL, "label": "launchctl list", "untested": None})
        checks.append({"id": KEYCHAIN, "label": "security find-generic-password", "untested": None})
    return checks


def _outcome(result: str, detail: str) -> dict[str, str]:
    return {"result": result, "detail": detail}


def probe_read(path: str) -> dict[str, str]:
    try:
        target = Path(path)
        if target.is_dir():
            next(target.iterdir(), None)
        else:
            with target.open("rb") as handle:
                handle.read(1)
    except OSError as exc:
        return _outcome(BLOCKED, exc.strerror or type(exc).__name__)
    return _outcome(REACHABLE, "read")


def probe_tcp(hostport: str) -> dict[str, str]:
    host, _, port = hostport.rpartition(":")
    try:
        conn = socket.create_connection((host.strip("[]"), int(port)), timeout=TCP_TIMEOUT)
    except (OSError, ValueError) as exc:
        return _outcome(BLOCKED, str(getattr(exc, "strerror", None) or type(exc).__name__))
    conn.close()
    return _outcome(REACHABLE, "connected")


def probe_socket(path: str) -> dict[str, str]:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(TCP_TIMEOUT)
    try:
        sock.connect(path)
    except OSError as exc:
        return _outcome(BLOCKED, exc.strerror or type(exc).__name__)
    finally:
        sock.close()
    return _outcome(REACHABLE, "connected")


def probe_create(home: str) -> dict[str, str]:
    """Create `$HOME/.modgudr-probe-<rand>` exclusively. The doctor deletes it."""
    path = str(Path(home) / (PROBE_PREFIX + os.urandom(6).hex()))
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        return _outcome(BLOCKED, exc.strerror or type(exc).__name__)
    os.close(fd)
    return _outcome(REACHABLE, "created " + path)


def probe_append(path: str) -> dict[str, str]:
    """Open a start-up file for append without writing a byte."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND)
    except FileNotFoundError:
        return _outcome(NOT_TESTED, "the file does not exist")
    except OSError as exc:
        return _outcome(BLOCKED, exc.strerror or type(exc).__name__)
    os.close(fd)
    return _outcome(REACHABLE, "opened for append")


def _run(argv: list[str]) -> subprocess.CompletedProcess[bytes] | None:
    try:
        return subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=COMMAND_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def probe_launchctl() -> dict[str, str]:
    done = _run(["launchctl", "list"])
    if done is None:
        return _outcome(BLOCKED, "could not run launchctl")
    if done.returncode == 0:
        return _outcome(REACHABLE, "launchctl list worked")
    return _outcome(BLOCKED, "exit " + str(done.returncode))


def probe_keychain() -> dict[str, str]:
    done = _run(["security", "find-generic-password", "-s", "modgudr-probe-none"])
    if done is None:
        return _outcome(BLOCKED, "could not run security")
    if done.returncode == KEYCHAIN_NOT_FOUND:
        return _outcome(REACHABLE, "the keychain answered (exit 44): a documented gap")
    if done.returncode == 0:
        return _outcome(REACHABLE, "the keychain answered")
    return _outcome(BLOCKED, "exit " + str(done.returncode))


def run_check(check_id: str, spec: Spec) -> dict[str, str]:
    if check_id.startswith("read:"):
        return probe_read(check_id[len("read:") :])
    if check_id.startswith("tcp:"):
        return probe_tcp(check_id[len("tcp:") :])
    if check_id == AGENT_SOCKET:
        return probe_socket(spec["agentSocket"])
    if check_id == HUMAN_SOCKET:
        return probe_socket(spec["humanSocket"])
    if check_id == PERSIST_CREATE:
        return probe_create(spec["persistenceHome"])
    if check_id == PERSIST_APPEND:
        return probe_append(str(Path(spec["persistenceHome"]) / ".zshrc"))
    if check_id == LAUNCHCTL:
        return probe_launchctl()
    if check_id == KEYCHAIN:
        return probe_keychain()
    return _outcome(NOT_TESTED, "unknown check")


def run_probe(spec: Spec) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for check in planned(spec):
        if check["untested"]:
            outcome = _outcome(NOT_TESTED, check["untested"])
        else:
            outcome = run_check(check["id"], spec)
        results.append({"id": check["id"], "label": check["label"], **outcome})
    return {"checks": results}


def main() -> int:
    spec = json.loads(Path(INPUT_FILE).read_bytes().decode("utf-8"))
    result = run_probe(spec)
    Path(RESULT_FILE).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
