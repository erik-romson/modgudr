"""The exec credential plugin and `cred.sock` (M18): only the broker's uid gets the token, the
plugin prints only a valid ExecCredential, and a closed socket is gone."""

from __future__ import annotations

import asyncio
import io
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from modgudr.kubectl.exec_credential import (
    API_VERSION,
    CredentialServer,
    exec_credential,
    is_credential,
    main,
)

TOKEN = "aks-token-unit-0123456789"
EXPIRES = 1_800_000_000.0


async def _fetch(path: Path) -> bytes:
    reader, writer = await asyncio.open_unix_connection(os.fspath(path))
    try:
        return await reader.read()
    finally:
        writer.close()


def test_the_credential_document() -> None:
    document = json.loads(exec_credential(TOKEN, EXPIRES))
    assert document == {
        "apiVersion": API_VERSION,
        "kind": "ExecCredential",
        "status": {"token": TOKEN, "expirationTimestamp": "2027-01-15T08:00:00Z"},
    }
    assert is_credential(exec_credential(TOKEN, EXPIRES))
    assert not is_credential(b"{}")
    assert not is_credential(b"not json")
    assert not is_credential(json.dumps({"kind": "ExecCredential"}).encode())


async def test_the_server_answers_the_brokers_uid_and_is_gone_after_close(
    shortdir: Path,
) -> None:
    path = shortdir / "cred.sock"
    server = CredentialServer(path, TOKEN, EXPIRES, uid=os.getuid())
    await server.start()
    try:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert await _fetch(path) == exec_credential(TOKEN, EXPIRES)
        assert await _fetch(path) == exec_credential(TOKEN, EXPIRES)
    finally:
        server.close()
    assert not path.exists()
    with pytest.raises(OSError):
        await _fetch(path)


async def test_another_uid_gets_nothing(shortdir: Path) -> None:
    path = shortdir / "cred.sock"
    server = CredentialServer(
        path, TOKEN, EXPIRES, uid=os.getuid(), peer_uid=lambda sock: os.getuid() + 1
    )
    await server.start()
    try:
        assert await _fetch(path) == b""
    finally:
        server.close()


async def test_the_plugin_prints_the_credential_in_its_own_process(shortdir: Path) -> None:
    path = shortdir / "cred.sock"
    server = CredentialServer(path, TOKEN, EXPIRES, uid=os.getuid())
    await server.start()
    try:
        child = await asyncio.create_subprocess_exec(
            sys.executable,
            "-I",
            "-m",
            "modgudr.kubectl.exec_credential",
            os.fspath(path),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin"},
        )
        stdout, stderr = await child.communicate()
    finally:
        server.close()
    assert (child.returncode, stderr) == (0, b"")
    assert json.loads(stdout)["status"]["token"] == TOKEN


def test_the_plugin_without_a_broker_prints_nothing_on_stdout(
    shortdir: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([os.fspath(shortdir / "none.sock")]) == 1
    out, err = capsys.readouterr()
    assert out == "" and "cannot reach the broker's credential socket" in err
    assert main([]) == 2
    assert "usage:" in capsys.readouterr().err


def test_the_plugin_refuses_what_is_not_a_credential(
    shortdir: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import modgudr.kubectl.exec_credential as plugin

    monkeypatch.setattr(plugin, "fetch", lambda path: b'{"kind": "Secret"}\n')
    assert main(["/nowhere"]) == 1
    out, err = capsys.readouterr()
    assert out == "" and "sent no credential" in err
    stdout = io.BytesIO()
    monkeypatch.setattr(plugin, "fetch", lambda path: exec_credential(TOKEN, EXPIRES))
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(stdout))
    assert main(["/nowhere"]) == 0
    assert stdout.getvalue() == exec_credential(TOKEN, EXPIRES)
