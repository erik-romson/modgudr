"""A stub server on a unix socket that answers metadata ops with canned `result` frames.

It stands in for the broker where a test only needs `status` or `targets` from `agent.sock`
(`agent-setup`, the hook). It never executes anything.
"""

from __future__ import annotations

import json
import socket
import threading
from pathlib import Path
from types import TracebackType


class StubBroker:
    """Answers each request line with the canned data of its op, then a trailer.

    With `silent`, it reads the request and never answers (a hung broker).
    """

    def __init__(self, path: Path, answers: dict[str, object], *, silent: bool = False) -> None:
        self.path = path
        self.answers = answers
        self.silent = silent
        self.ops: list[str] = []
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._held: list[socket.socket] = []

    def __enter__(self) -> StubBroker:
        self._server.bind(str(self.path))
        self._server.listen(8)
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        self._server.close()
        for conn in self._held:
            conn.close()
        self._thread.join(timeout=2)
        self.path.unlink(missing_ok=True)

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._server.accept()
            except OSError:
                return
            self._held.append(conn)
            threading.Thread(target=self._answer, args=(conn,), daemon=True).start()

    def _answer(self, conn: socket.socket) -> None:
        try:
            buffer = b""
            while b"\n" not in buffer:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                buffer += chunk
            request = json.loads(buffer.split(b"\n", 1)[0])
            op = request["op"]
            self.ops.append(op)
            if self.silent:
                return
            if op not in self.answers:
                frame = {"t": "error", "code": "not_found", "message": f"no op {op}"}
                conn.sendall(json.dumps(frame).encode() + b"\n")
                return
            conn.sendall(json.dumps({"t": "result", "data": self.answers[op]}).encode() + b"\n")
            trailer = {"t": "trailer", "rows": 0, "bytes": 0, "truncated": False, "reason": None}
            conn.sendall(json.dumps(trailer).encode() + b"\n")
        except OSError:
            return
