"""Peer credentials: `LOCAL_PEERCRED` (macOS) and `SO_PEERCRED` (Linux), and the uid check."""

from __future__ import annotations

import asyncio
import os
import socket
import sys
from pathlib import Path

import pytest

from modgudr.broker.server import (
    LOCAL_PEERCRED,
    SO_PEERCRED,
    SOL_LOCAL,
    UCRED,
    XUCRED,
    bind_listen,
    peer_uid,
)
from tests.support.brokerfx import call, error, make_env, read_audit, result_data, running


class FakeSock:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.asked: tuple[int, int, int] | None = None

    def getsockopt(self, level: int, optname: int, buflen: int, /) -> bytes:
        self.asked = (level, optname, buflen)
        return self.raw


def test_peer_uid_of_a_socketpair_is_ours() -> None:
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        assert peer_uid(a) == os.getuid()
        assert peer_uid(b) == os.getuid()
    finally:
        a.close()
        b.close()


async def test_peer_uid_from_the_transport_socket_is_ours(shortdir: Path) -> None:
    seen: list[int] = []

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        seen.append(peer_uid(writer.get_extra_info("socket")))
        writer.close()

    bound = bind_listen(shortdir / "p.sock")
    server = await asyncio.start_unix_server(handler, sock=bound.sock)
    try:
        reader, writer = await asyncio.open_unix_connection(os.fspath(bound.path))
        await reader.read()
        writer.close()
    finally:
        server.close()
        await server.wait_closed()
    assert seen == [os.getuid()]


def test_xucred_is_parsed_on_macos() -> None:
    sock = FakeSock(XUCRED.pack(0, 4242, 1, 20, *([0] * 15)))
    assert peer_uid(sock, platform="darwin") == 4242
    assert sock.asked == (SOL_LOCAL, LOCAL_PEERCRED, 76)


@pytest.mark.parametrize(
    "raw",
    [XUCRED.pack(1, 4242, 1, 20, *([0] * 15)), b"\x00" * 12],
    ids=["version", "size"],
)
def test_unexpected_xucred_is_an_error(raw: bytes) -> None:
    with pytest.raises(OSError, match="xucred"):
        peer_uid(FakeSock(raw), platform="darwin")


def test_ucred_is_parsed_on_linux() -> None:
    sock = FakeSock(UCRED.pack(123, 4242, 20))
    assert peer_uid(sock, platform="linux") == 4242
    assert sock.asked == (socket.SOL_SOCKET, SO_PEERCRED, 12)


def test_other_platforms_are_unsupported() -> None:
    with pytest.raises(OSError, match="not supported"):
        peer_uid(FakeSock(b""), platform="win32")


def test_this_mac_exports_local_peercred() -> None:
    if sys.platform == "darwin":
        assert getattr(socket, "LOCAL_PEERCRED", 1) == LOCAL_PEERCRED


@pytest.mark.parametrize("channel", ["agent", "human"])
async def test_an_injected_foreign_uid_is_denied_and_audited(shortdir: Path, channel: str) -> None:
    env = make_env(shortdir, peer_uid=lambda sock: os.getuid() + 7)
    async with running(env):
        path = env.agent_socket if channel == "agent" else env.human_socket
        err = error(await call(path, "status"))
    assert (err["code"], err["layer"], err["rule"]) == ("denied", "peer", "uid")
    (record,) = [r for r in read_audit(env.audit_dir) if r["type"] == "denied"]
    assert (record["channel"], record["peerUid"], record["auditId"]) == (
        channel,
        os.getuid() + 7,
        err["auditId"],
    )


async def test_an_unreadable_peer_uid_is_denied(shortdir: Path) -> None:
    def broken(sock: object) -> int:
        raise OSError("no credentials")

    env = make_env(shortdir, peer_uid=broken)
    async with running(env):
        assert error(await call(env.agent_socket, "status"))["code"] == "denied"


async def test_the_real_peer_uid_is_accepted(shortdir: Path) -> None:
    env = make_env(shortdir)
    async with running(env):
        assert result_data(await call(env.agent_socket, "status"))["state"] == "locked"
