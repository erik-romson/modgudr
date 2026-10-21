"""Talking to the broker: unix sockets, one request per connection (M1, M4), and who is asking.

The client never half-closes a connection: EOF is how the broker learns that a call was
cancelled (M4). Closing the `Call` closes the socket.
"""

import contextlib
import errno
import importlib.metadata
import os
import socket
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, BinaryIO

from modgudr.client.errors import BrokerUnavailable
from modgudr.client.protocol import Frame, encode_request, read_frames

NOT_RUNNING = "broker not running; start it in your own terminal"
NOT_FROM_AGENT = "admin commands are not available from an agent session"

#: Connect errors on `human.sock` that mean "this process cannot reach it" (M1, M20).
UNREACHABLE_ERRNOS = frozenset({errno.ENOENT, errno.EACCES, errno.EPERM})


def client_version() -> str:
    try:
        return importlib.metadata.version("modgudr-client")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def client_info(
    name: str,
    *,
    session: str | None = None,
    script: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """The `client` object of a request: for audit only, never for authorisation (§5.4)."""
    env = os.environ if environ is None else environ
    info: dict[str, Any] = {"name": name, "version": client_version()}
    if script:
        info["script"] = script
    if env.get("CLAUDECODE") == "1":
        info["agentHint"] = "claude-code"
    with contextlib.suppress(OSError):
        info["cwd"] = str(Path.cwd())
    chosen = session or env.get("MODGUDR_SESSION")
    if chosen:
        info["session"] = chosen
    return info


def open_socket(path: Path) -> socket.socket:
    """Connect to a unix socket. Raises `OSError`."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(os.fspath(path))
    except BaseException:
        sock.close()
        raise
    return sock


def open_agent_socket(path: Path) -> socket.socket:
    """Connect to `agent.sock`, or raise `BrokerUnavailable` (exit 6)."""
    try:
        return open_socket(path)
    except OSError:
        raise BrokerUnavailable(NOT_RUNNING) from None


class Call:
    """One open request: the socket and its frame stream. Closing it cancels the call."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._file: BinaryIO | None = sock.makefile("rb")
        self.closed = False

    def send(
        self,
        op: str,
        *,
        target: str | None = None,
        env: str | None = None,
        args: Mapping[str, Any] | None = None,
        client: Mapping[str, Any] | None = None,
    ) -> None:
        data = encode_request(op, target=target, env=env, args=args, client=client)
        # If the broker answered and hung up, the reply, if any, is read next.
        with contextlib.suppress(OSError):
            self._sock.sendall(data)

    def frames(self, *, decode: bool = True) -> Iterator[Frame]:
        if self._file is None:
            raise BrokerUnavailable("the connection is closed")
        return read_frames(self._file, decode=decode)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        file, self._file = self._file, None
        try:
            if file is not None:
                file.close()
        finally:
            self._sock.close()


def open_call(
    path: Path,
    op: str,
    *,
    target: str | None = None,
    env: str | None = None,
    args: Mapping[str, Any] | None = None,
    client: Mapping[str, Any] | None = None,
) -> Call:
    """Connect to the agent socket and send one request."""
    call = Call(open_agent_socket(path))
    call.send(op, target=target, env=env, args=args, client=client)
    return call
