"""The exec credential plugin and its broker side (M18).

**The plugin** is what kubectl runs for a call's credential:
`<sys.executable> -I -m modgudr.kubectl.exec_credential <socket>`. It connects to the call's
`cred.sock`, reads one ExecCredential and prints it on stdout, where kubectl reads it. It never
writes the token anywhere else, and it imports only the standard library, so it starts fast.

**The broker side**, `CredentialServer`, serves `<call dir>/cred.sock` for one call:

- it answers only this call's ExecCredential, and only to a peer with the broker's uid (peer
  credentials, as on the broker's own sockets); any other peer gets nothing;
- it is closed and unlinked when the call ends, so a later connect fails.

No socket op of the broker returns a token (§3.1): this socket is not one of the broker's channels
and lives only as long as its call.
"""

from __future__ import annotations

import contextlib
import json
import logging
import socket
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    import asyncio

    from modgudr.broker.server import BoundSocket, SupportsGetsockopt

log = logging.getLogger("modgudr.broker")

#: The socket's name inside the per-call directory.
SOCKET_NAME = "cred.sock"
#: The ExecCredential API version (the kubeconfig's exec `apiVersion` must match it).
API_VERSION = "client.authentication.k8s.io/v1"
KIND = "ExecCredential"
#: The most the plugin reads from the socket.
MAX_CREDENTIAL = 64 * 1024
#: How long the plugin waits for the broker.
TIMEOUT = 10.0

USAGE = "usage: python -I -m modgudr.kubectl.exec_credential <socket>"

#: Reads the uid of a connected peer (`modgudr.broker.server.peer_uid`).
PeerUid = Callable[["SupportsGetsockopt"], int]


def exec_credential(token: str, expires_at: float) -> bytes:
    """The ExecCredential document for `token`, as one JSON line."""
    stamp = datetime.fromtimestamp(expires_at, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    document = {
        "apiVersion": API_VERSION,
        "kind": KIND,
        "status": {"token": token, "expirationTimestamp": stamp},
    }
    return json.dumps(document, separators=(",", ":")).encode("utf-8") + b"\n"


# --- the plugin (kubectl's child) -----------------------------------------------------------------


def fetch(path: str) -> bytes:
    """Everything the broker sends on `path`, up to one byte more than `MAX_CREDENTIAL`."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(TIMEOUT)
        sock.connect(path)
        data = bytearray()
        while len(data) <= MAX_CREDENTIAL:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
    return bytes(data)


def is_credential(data: bytes) -> bool:
    """Whether `data` is an ExecCredential with a token."""
    try:
        document: object = json.loads(data)
    except ValueError:
        return False
    if not isinstance(document, dict):
        return False
    fields = cast("dict[str, object]", document)
    status = fields.get("status")
    if fields.get("kind") != KIND or fields.get("apiVersion") != API_VERSION:
        return False
    if not isinstance(status, dict):
        return False
    token = cast("dict[str, object]", status).get("token")
    return isinstance(token, str) and bool(token)


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print(USAGE, file=sys.stderr)
        return 2
    try:
        data = fetch(args[0])
    except OSError as exc:
        print(
            "modgudr exec credential: cannot reach the broker's credential socket "
            f"{args[0]}: {exc.strerror or exc}",
            file=sys.stderr,
        )
        return 1
    if len(data) > MAX_CREDENTIAL or not is_credential(data):
        print("modgudr exec credential: the broker sent no credential", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()
    return 0


# --- the broker side ------------------------------------------------------------------------------


class CredentialServer:
    """`cred.sock` for one call. `start` binds it (0600, in the call's 0700 directory); `close`
    stops serving, unlinks it and forgets the token."""

    def __init__(
        self,
        path: Path,
        token: str,
        expires_at: float,
        *,
        uid: int,
        peer_uid: PeerUid | None = None,
    ) -> None:
        self.path = path
        self._payload = exec_credential(token, expires_at)
        self._uid = uid
        self._peer_uid = peer_uid
        self._bound: BoundSocket | None = None
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        # The broker's modules are imported here, not at the top: the plugin above runs in
        # kubectl's child and stays on the standard library.
        import asyncio

        from modgudr.broker.server import bind_listen

        bound = bind_listen(self.path)
        try:
            self._server = await asyncio.start_unix_server(self._handle, sock=bound.sock)
        except BaseException:
            bound.sock.close()
            bound.unlink()
            raise
        self._bound = bound

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        from modgudr.broker.server import peer_uid

        try:
            sock = writer.get_extra_info("socket")
            try:
                uid = (self._peer_uid or peer_uid)(sock)
            except OSError:
                uid = -1
            if uid != self._uid or not self._payload:
                log.warning("%s refused a peer with uid %d", self.path.name, uid)
                return
            writer.write(self._payload)
            await writer.drain()
        except (ConnectionError, OSError):
            return
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError, OSError):
                await writer.wait_closed()

    def close(self) -> None:
        """Stop serving and remove the socket file; a later connect fails."""
        self._payload = b""
        if self._server is not None:
            self._server.close()
            self._server = None
        if self._bound is not None:
            self._bound.unlink()
            self._bound = None


if __name__ == "__main__":
    sys.exit(main())
