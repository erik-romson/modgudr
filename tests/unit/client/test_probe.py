"""The isolation probe (`probe.py`): BLOCKED, REACHABLE and NOT_TESTED, run for real against
temporary files, sockets and a temporary home. It never reads the developer's own home."""

from __future__ import annotations

import ast
import json
import socket
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from modgudr.client.agent import probe

PROBE_PY = Path(probe.__file__)


@contextmanager
def listening(path: Path) -> Iterator[socket.socket]:
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(4)
    try:
        yield server
    finally:
        server.close()


def spec_for(root: Path, **overrides: object) -> dict[str, Any]:
    home = root / "u"
    home.mkdir(exist_ok=True)
    spec: dict[str, Any] = {
        "platform": "linux",
        "home": str(root / "h"),
        "agentSocket": str(root / "agent.sock"),
        "humanSocket": str(root / "human.sock"),
        "credentialPaths": [],
        "targets": [],
        "persistenceHome": str(home),
    }
    spec.update(overrides)
    return spec


def results(spec: dict[str, Any]) -> dict[str, str]:
    return {c["id"]: c["result"] for c in probe.run_probe(spec)["checks"]}


def test_it_is_python_39_compatible() -> None:
    ast.parse(PROBE_PY.read_text("utf-8"), feature_version=(3, 9))


def test_readable_paths_and_sockets_are_reachable(shortdir: Path) -> None:
    secret_dir = shortdir / "u" / ".azure"
    secret_dir.mkdir(parents=True)
    (secret_dir / "token").write_text("x")
    secret_file = shortdir / "u" / ".pgpass"
    secret_file.write_text("x")
    with listening(shortdir / "agent.sock"), listening(shortdir / "human.sock"):
        got = results(spec_for(shortdir, credentialPaths=[str(secret_dir), str(secret_file)]))
    assert got[f"read:{secret_dir}"] == probe.REACHABLE
    assert got[f"read:{secret_file}"] == probe.REACHABLE
    assert got[probe.AGENT_SOCKET] == probe.REACHABLE
    assert got[probe.HUMAN_SOCKET] == probe.REACHABLE


def test_a_missing_path_and_a_missing_socket_are_blocked(shortdir: Path) -> None:
    got = results(spec_for(shortdir, credentialPaths=[str(shortdir / "nowhere")]))
    assert got[f"read:{shortdir / 'nowhere'}"] == probe.BLOCKED
    assert got[probe.AGENT_SOCKET] == probe.BLOCKED
    assert got[probe.HUMAN_SOCKET] == probe.BLOCKED


def test_persistence_probes_create_a_file_and_open_for_append(shortdir: Path) -> None:
    spec = spec_for(shortdir)
    home = Path(spec["persistenceHome"])
    assert results(spec)[probe.PERSIST_APPEND] == probe.NOT_TESTED  # no ~/.zshrc yet
    (home / ".zshrc").write_text("# mine\n")
    got = results(spec)
    assert got[probe.PERSIST_CREATE] == probe.REACHABLE
    assert got[probe.PERSIST_APPEND] == probe.REACHABLE
    assert (home / ".zshrc").read_text() == "# mine\n"  # opened, never written
    assert len(list(home.glob(f"{probe.PROBE_PREFIX}*"))) == 2  # one per run; the doctor deletes


def test_a_target_the_doctor_cannot_reach_is_not_tested(shortdir: Path) -> None:
    spec = spec_for(shortdir, targets=[{"hostPort": "192.0.2.1:443", "doctorReached": False}])
    checks = {c["id"]: c for c in probe.run_probe(spec)["checks"]}
    assert checks["tcp:192.0.2.1:443"]["result"] == probe.NOT_TESTED


def test_tcp_reachable_and_blocked(shortdir: Path) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        open_port = server.getsockname()[1]
        reached = results(
            spec_for(
                shortdir,
                targets=[{"hostPort": f"127.0.0.1:{open_port}", "doctorReached": True}],
            )
        )
    assert reached[f"tcp:127.0.0.1:{open_port}"] == probe.REACHABLE
    closed = results(
        spec_for(shortdir, targets=[{"hostPort": f"127.0.0.1:{open_port}", "doctorReached": True}])
    )
    assert closed[f"tcp:127.0.0.1:{open_port}"] == probe.BLOCKED


def test_darwin_adds_the_launchctl_and_keychain_checks(shortdir: Path) -> None:
    ids = [c["id"] for c in probe.planned(spec_for(shortdir, platform="darwin"))]
    assert probe.LAUNCHCTL in ids and probe.KEYCHAIN in ids
    ids = [c["id"] for c in probe.planned(spec_for(shortdir))]
    assert probe.LAUNCHCTL not in ids and probe.KEYCHAIN not in ids


def test_main_reads_the_input_and_writes_the_result(shortdir: Path) -> None:
    work = shortdir / "work"
    work.mkdir()
    (work / probe.INPUT_FILE).write_text(json.dumps(spec_for(shortdir)))
    done = subprocess.run(
        [sys.executable, "-I", str(PROBE_PY)], cwd=work, capture_output=True, check=False
    )
    assert done.returncode == 0, done.stderr
    document = json.loads((work / probe.RESULT_FILE).read_text())
    assert {c["id"] for c in document["checks"]} >= {probe.AGENT_SOCKET, probe.HUMAN_SOCKET}
