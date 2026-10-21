"""The channel servers (M1): private directories, the broker lock, safe binding, peer uid.

Sockets are bound by hand under `umask 0177` while the broker holds an `flock` on
`$MODGUDR_HOME/run/broker.lock`, then handed to asyncio with `sock=`. Never
`start_unix_server(path=)`: on 3.12 it silently unlinks a live broker's socket.
"""

from __future__ import annotations

import asyncio
import errno
import fcntl
import os
import socket
import stat
import struct
import sys
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Literal, Protocol

#: `sun_path` holds 104 bytes on macOS, including the terminating NUL (OS report §4.1).
MAX_SOCKET_PATH_BYTES = 103
LISTEN_BACKLOG = 64
LOCK_FILE = "broker.lock"

#: macOS `LOCAL_PEERCRED` at level `SOL_LOCAL` returns a `struct xucred`.
SOL_LOCAL = 0
LOCAL_PEERCRED = 1
XUCRED = struct.Struct("=IIh2x16I")
#: Linux `SO_PEERCRED` at `SOL_SOCKET` returns a `struct ucred` (pid, uid, gid).
SO_PEERCRED = getattr(socket, "SO_PEERCRED", 17)
UCRED = struct.Struct("=iII")


class StartError(Exception):
    """The broker cannot start: exit 78, nothing listening, no socket left behind."""

    exit_code = 78


class Channel(StrEnum):
    AGENT = "agent"
    HUMAN = "human"


class StatLike(Protocol):
    @property
    def st_uid(self) -> int: ...

    @property
    def st_mode(self) -> int: ...


Lstat = Callable[[Path], StatLike]
Warn = Callable[[str], None]


def _lstat(path: Path) -> StatLike:
    return os.lstat(path)


def ensure_private_dir(path: Path, *, uid: int, warn: Warn, lstat: Lstat = _lstat) -> None:
    """Create `path` (0700) if missing, then insist it is a real directory owned by `uid`.

    A directory that is ours but wider is tightened to 0700 with a warning. A foreign owner, a
    symlink or something that is not a directory is refused.
    """
    missing: list[Path] = []
    probe = path
    while not os.path.lexists(probe):
        missing.append(probe)
        if probe.parent == probe:
            break
        probe = probe.parent
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700, exist_ok=True)
        except OSError as exc:
            raise StartError(f"cannot create directory {directory}: {exc.strerror}") from exc
    try:
        st = lstat(path)
    except OSError as exc:
        raise StartError(f"cannot inspect {path}: {exc.strerror}") from exc
    if stat.S_ISLNK(st.st_mode):
        raise StartError(f"{path} is a symlink; refusing to use it")
    if not stat.S_ISDIR(st.st_mode):
        raise StartError(f"{path} is not a directory")
    if st.st_uid != uid:
        raise StartError(f"{path} is owned by uid {st.st_uid}, not by this user (uid {uid})")
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o077:
        try:
            path.chmod(0o700)
        except OSError as exc:
            raise StartError(f"cannot tighten {path} to 0700: {exc.strerror}") from exc
        warn(f"tightened {path} from {mode:04o} to 0700")


def check_socket_path(path: Path) -> None:
    size = len(os.fsencode(path))
    if size > MAX_SOCKET_PATH_BYTES:
        raise StartError(
            f"socket path too long ({size} bytes, limit {MAX_SOCKET_PATH_BYTES}): {path}"
        )


def acquire_lock(path: Path) -> int:
    """Hold `flock` on the broker lock for the process lifetime. A second broker is refused."""
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError as exc:
        raise StartError(f"cannot open the broker lock {path}: {exc.strerror}") from exc
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise StartError(f"modgudr-broker is already running (lock {path} is held)") from None
    except OSError as exc:
        os.close(fd)
        raise StartError(f"cannot lock {path}: {exc.strerror}") from exc
    return fd


def release_lock(fd: int) -> None:
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def clear_stale_socket(path: Path, *, uid: int) -> None:
    """Remove a socket nobody listens on. A live one means a broker is running: refused."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(st.st_mode):
        raise StartError(f"{path} exists and is not a socket; refusing to replace it")
    if st.st_uid != uid:
        raise StartError(f"{path} is owned by uid {st.st_uid}; refusing to replace it")
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(1.0)
    try:
        probe.connect(os.fspath(path))
    except (ConnectionRefusedError, FileNotFoundError):
        pass
    except OSError as exc:
        raise StartError(f"cannot probe {path}: {exc.strerror or exc}") from exc
    else:
        raise StartError(f"modgudr-broker is already running (a broker is listening on {path})")
    finally:
        probe.close()
    path.unlink(missing_ok=True)


@dataclass
class BoundSocket:
    path: Path
    sock: socket.socket
    #: (st_dev, st_ino) right after bind: only that file is ever unlinked.
    identity: tuple[int, int]

    def state(self) -> Literal["ok", "missing", "replaced"]:
        try:
            st = os.lstat(self.path)
        except FileNotFoundError:
            return "missing"
        except OSError:
            return "replaced"
        return "ok" if (st.st_dev, st.st_ino) == self.identity else "replaced"

    def unlink(self) -> None:
        """Remove the socket file if it is still the one we bound."""
        if self.state() == "ok":
            self.path.unlink(missing_ok=True)


def bind_listen(path: Path) -> BoundSocket:
    """Bind and listen under `umask 0177`, so the socket is 0600 from the start."""
    check_socket_path(path)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        old = os.umask(0o177)
        try:
            sock.bind(os.fspath(path))
        finally:
            os.umask(old)
        path.chmod(0o600)
        st = os.lstat(path)
        sock.listen(LISTEN_BACKLOG)
        sock.setblocking(False)
    except OSError as exc:
        sock.close()
        raise StartError(f"cannot bind {path}: {exc.strerror or exc}") from exc
    return BoundSocket(path, sock, (st.st_dev, st.st_ino))


class SupportsGetsockopt(Protocol):
    def getsockopt(self, level: int, optname: int, buflen: int, /) -> bytes: ...


def peer_uid(sock: SupportsGetsockopt, platform: str = sys.platform) -> int:
    """The uid the peer had when it connected: `LOCAL_PEERCRED` on macOS, `SO_PEERCRED` on Linux.

    Works on a `socket.socket` and on asyncio's `TransportSocket`.
    """
    if platform == "darwin":
        raw = sock.getsockopt(SOL_LOCAL, LOCAL_PEERCRED, XUCRED.size)
        if len(raw) != XUCRED.size:
            raise OSError(errno.EPROTO, f"unexpected xucred size {len(raw)}")
        version, uid, *_ = XUCRED.unpack(raw)
        if version != 0:
            raise OSError(errno.EPROTO, f"unsupported xucred version {version}")
        return int(uid)
    if platform.startswith("linux"):
        raw = sock.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, UCRED.size)
        if len(raw) != UCRED.size:
            raise OSError(errno.EPROTO, f"unexpected ucred size {len(raw)}")
        _, uid, _ = UCRED.unpack(raw)
        return int(uid)
    raise OSError(errno.ENOTSUP, f"peer credentials are not supported on {platform}")


Handler = Callable[[Channel, asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


class ChannelServer:
    """One listening socket (`agent.sock` or `human.sock`) and its asyncio server."""

    def __init__(self, channel: Channel, path: Path, handler: Handler) -> None:
        self.channel = channel
        self.path = path
        self._handler = handler
        self.bound: BoundSocket | None = None
        self._server: asyncio.Server | None = None
        self._retired: list[asyncio.Server] = []

    async def open(self, *, uid: int) -> None:
        """Clear a stale socket and bind; serving starts with `start_serving`."""
        check_socket_path(self.path)
        clear_stale_socket(self.path, uid=uid)
        self.bound = bind_listen(self.path)
        self._server = await self._serve(self.bound)

    async def _serve(self, bound: BoundSocket) -> asyncio.Server:
        async def callback(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await self._handler(self.channel, reader, writer)

        return await asyncio.start_unix_server(callback, sock=bound.sock, start_serving=False)

    async def start_serving(self) -> None:
        if self._server is not None:
            await self._server.start_serving()

    async def rebind(self, *, uid: int) -> None:
        """The socket file was deleted while running: bind a new one at the same path."""
        old = self._server
        clear_stale_socket(self.path, uid=uid)
        bound = bind_listen(self.path)
        server = await self._serve(bound)
        await server.start_serving()
        self.bound, self._server = bound, server
        if old is not None:
            old.close()
            self._retired.append(old)

    def close(self) -> None:
        for server in (self._server, *self._retired):
            if server is not None:
                server.close()

    async def wait_closed(self, timeout: float) -> None:
        for server in (self._server, *self._retired):
            if server is not None:
                try:
                    async with asyncio.timeout(timeout):
                        await server.wait_closed()
                except TimeoutError:
                    pass

    def unlink(self) -> None:
        if self.bound is not None:
            self.bound.unlink()
