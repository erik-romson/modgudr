"""Frames (M4), the op table and the call pipeline (M6), and the metadata ops.

One request per connection. A request with a `target` is a call to one of that target's ops; a
request without one is a broker op: the metadata ops (both channels, never audited, working while
locked) or the admin ops (`human.sock` only).

The call pipeline runs in the fixed M6 order: frame, resolve, validate, classify and decide
(phase 1), the `maxConcurrent` slot, the lock gate, the secret and its pins with the decision in
the effective environment (phase 2), the decision record, execution, then the trailer or error
and the completion record.

The admin ops `unlock` and `lock` drive the store session (M7); `audit-tail` streams the audit
log (M9); `login-info` arrives in a later step.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Literal, cast

from modgudr.client.protocol import SUPPORTED_VERSIONS

from ..spi import (
    Action,
    AuthFailed,
    Call,
    Decision,
    OperationSpec,
    StoreError,
    UpstreamFailure,
)
from .audit import AuditUnavailable, new_audit_id
from .audit_tail import DEFAULT_N, MAX_N, AuditReadError, TailFilter, read_tail
from .engine.explain import explain
from .limits import Limits, MaxRowsRefused
from .pins import PinError
from .policy.lint import lint_policy
from .policy.resolve import Resolved, ResolveError, resolve_target
from .scrub import CallScrubber
from .secrets import CallScope, Latched, LoginFailed, SessionLocked, call_scope
from .server import Channel
from .session import LockReason
from .sink import LimitedSink, LimitReached

if TYPE_CHECKING:
    from .app import Broker, OpenTarget

log = logging.getLogger("modgudr.broker")

PROTOCOL_VERSIONS: tuple[int, ...] = tuple(SUPPORTED_VERSIONS)

#: Broker ops on both channels: not audited, they work while locked.
META_OPS = ("status", "targets", "describe", "explain", "actions", "policy-show", "policy-lint")
#: Admin ops: `human.sock` only. On `agent.sock` they are refused and audited (M6 step 1).
ADMIN_OPS = ("unlock", "lock", "audit-tail", "login-info")

#: `throttled` carries this `retryAfter` (seconds).
RETRY_AFTER = 1.0
#: How long a cancelled call may take to unwind (roll back, close a cursor) before the broker
#: stops waiting for it.
CANCEL_GRACE = 5.0

LOCKED_MESSAGE = "the store is locked; run `modgudr unlock` in your own terminal"
UNKNOWN_LOCKED = "unknown (locked)"

_CLIENT_FIELDS = ("name", "version", "script", "agentHint", "cwd", "session")
_PARAM_TYPES = frozenset({"str", "int", "decimal", "date", "timestamp", "bytes", "null"})
_MISSING = object()

RecordType = Literal["bad_request", "denied", "throttled", "locked", "failed"]
CancelReason = Literal["client", "lock", "shutdown", "timeout"]


class ClientGone(Exception):
    """The client closed the connection: nothing more can be sent."""


class BadRequest(Exception):
    """A malformed request or argument: `bad_request` (exit 64)."""


class RequestTooLarge(Exception):
    def __init__(self, read: int) -> None:
        super().__init__(read)
        self.read = read


class Refused(Exception):
    """A call or request that ends with an error frame before anything executed."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        record: RecordType | None,
        layer: str | None = None,
        rule: str | None = None,
        retry_after: float | None = None,
        fields: Mapping[str, object] | None = None,
        audited: bool = False,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.record = record
        self.layer = layer
        self.rule = rule
        self.retry_after = retry_after
        self.fields: dict[str, object] = dict(fields or {})
        #: The handler already wrote its record under the request's audit id.
        self.audited = audited


def encode_frame(frame: Mapping[str, object]) -> bytes:
    return json.dumps(frame, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"


@dataclass(eq=False)
class Connection:
    """One client connection: its channel, the peer uid read at connect, and the streams."""

    channel: Channel
    peer_uid: int
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    #: `reading` until the request line is in; shutdown cancels only those connections.
    phase: Literal["reading", "working"] = "reading"
    closed: bool = False

    async def write(self, line: bytes) -> None:
        if self.closed:
            raise ClientGone
        self.writer.write(line)
        try:
            await self.writer.drain()
        except (ConnectionError, RuntimeError) as exc:
            self.closed = True
            raise ClientGone from exc

    async def send(self, frame: Mapping[str, object]) -> None:
        await self.write(encode_frame(frame))


@dataclass(eq=False)
class Flight:
    """An executing call. Lock and shutdown cancel it with a reason (M6 end states)."""

    audit_id: str
    task: asyncio.Task[None]
    reason: CancelReason | None = None

    def cancel(self, reason: CancelReason) -> None:
        if self.reason is None:
            self.reason = reason
        self.task.cancel()


@dataclass(frozen=True)
class ClientInfo:
    """The `client` object: for audit only, never for authorisation (§5.4)."""

    name: str | None = None
    version: str | None = None
    script: str | None = None
    agent_hint: str | None = None
    cwd: str | None = None
    session: str | None = None

    def audit_fields(self) -> dict[str, object]:
        client = {
            "name": self.name,
            "version": self.version,
            "script": self.script,
            "agentHint": self.agent_hint,
            "cwd": self.cwd,
        }
        return {"client": client, "session": self.session}


@dataclass(frozen=True)
class Request:
    v: int
    op: str
    target: str | None = None
    env: str | None = None
    args: Mapping[str, object] = field(default_factory=dict[str, object])
    client: ClientInfo = field(default_factory=ClientInfo)


# --- frames --------------------------------------------------------------------------------------


async def read_request_line(reader: asyncio.StreamReader, limit: int, idle: float) -> bytes | None:
    """The request line without its newline, or None when the client sent nothing at all.

    At most `limit` bytes before the newline; reading stops at `limit + 1` bytes and raises
    `RequestTooLarge`. The whole line must arrive within `idle` seconds (`TimeoutError`).
    """
    buf = bytearray()
    async with asyncio.timeout(idle):
        while True:
            want = limit + 1 - len(buf)
            if want <= 0:
                raise RequestTooLarge(len(buf))
            chunk = await reader.read(min(65536, want))
            if not chunk:
                if not buf:
                    return None
                raise ClientGone
            newline = chunk.find(b"\n")
            if newline >= 0:
                buf += chunk[:newline]
                return bytes(buf)
            buf += chunk


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            raise BadRequest(f"duplicate key {key!r} in the request")
        out[key] = value
    return out


def _reject_constant(name: str) -> object:
    raise BadRequest(f"{name} is not valid JSON")


def _speaks() -> str:
    return f"this broker speaks {list(PROTOCOL_VERSIONS)}"


def parse_request(line: bytes) -> Request:
    """Decode one request line (M4). Unknown top-level and `client` keys are ignored."""
    try:
        text = line.decode("utf-8")
    except UnicodeDecodeError:
        raise BadRequest("the request is not valid UTF-8") from None
    try:
        obj: object = json.loads(
            text, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant
        )
    except BadRequest:
        raise
    except (ValueError, RecursionError) as exc:
        raise BadRequest(f"the request is not valid JSON: {exc}") from None
    if not isinstance(obj, dict):
        raise BadRequest("the request must be a JSON object")
    data = cast("dict[str, object]", obj)
    v = data.get("v", _MISSING)
    if v is _MISSING:
        raise BadRequest(f"the request has no protocol version 'v'; {_speaks()}")
    if type(v) is not int:
        raise BadRequest(f"protocol version must be an integer, not {json.dumps(v)}; {_speaks()}")
    if v not in PROTOCOL_VERSIONS:
        raise BadRequest(f"unsupported protocol version {v}; {_speaks()}")
    op = data.get("op")
    if not isinstance(op, str) or not op:
        raise BadRequest(f"the request has no 'op'; broker ops: {', '.join(META_OPS)}")
    target = _optional_str(data, "target")
    env = _optional_str(data, "env")
    args = data.get("args", {})
    if not isinstance(args, dict):
        raise BadRequest("'args' must be a JSON object")
    raw_client = data.get("client", {})
    if not isinstance(raw_client, dict):
        raise BadRequest("'client' must be a JSON object")
    client_data = cast("dict[str, object]", raw_client)
    values: dict[str, str | None] = {}
    for key in _CLIENT_FIELDS:
        value = client_data.get(key)
        if value is not None and not isinstance(value, str):
            raise BadRequest(f"client.{key} must be a string")
        values[key] = value
    client = ClientInfo(
        name=values["name"],
        version=values["version"],
        script=values["script"],
        agent_hint=values["agentHint"],
        cwd=values["cwd"],
        session=values["session"],
    )
    return Request(v, op, target, env, cast("dict[str, object]", args), client)


def _optional_str(data: Mapping[str, object], key: str) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise BadRequest(f"'{key}' must be a non-empty string")
    return value


# --- arguments -----------------------------------------------------------------------------------


def validate_args(
    spec: OperationSpec, args: Mapping[str, object]
) -> tuple[dict[str, object], int | None]:
    """Check a call's `args` against its `OperationSpec`. Unknown keys are `bad_request`.

    Returns the arguments for the plugin and the requested `maxRows` (taken out of them).
    """
    declared = {a.name: a for a in spec.args}
    out: dict[str, object] = {}
    max_rows: int | None = None
    for key, value in args.items():
        arg = declared.get(key)
        if arg is not None:
            out[key] = _check_kind(spec.name, key, arg.kind, value)
        elif key == "maxRows" and spec.rows:
            if type(value) is not int or value < 1:
                raise BadRequest(f"maxRows must be a positive integer, not {json.dumps(value)}")
            max_rows = value
        elif key == "params" and spec.params:
            out[key] = _check_params(value)
        elif key == "dryRun" and spec.dry_run:
            out[key] = _check_kind(spec.name, key, "bool", value)
        elif key == "argv" and spec.passthrough:
            if not isinstance(value, list) or not all(
                isinstance(item, str) for item in cast("list[object]", value)
            ):
                raise BadRequest("argv must be a list of strings")
            out[key] = list(cast("list[str]", value))
        else:
            raise BadRequest(
                f"op {spec.name} takes no argument {key!r}; arguments: "
                f"{', '.join(_arg_names(spec)) or 'none'}"
            )
    for arg in spec.args:
        if arg.required and arg.name not in out:
            raise BadRequest(f"op {spec.name} needs the argument {arg.name!r}")
    if spec.passthrough and "argv" not in out:
        out["argv"] = []
    return out, max_rows


def _arg_names(spec: OperationSpec) -> list[str]:
    names = [a.name for a in spec.args]
    if spec.rows:
        names.append("maxRows")
    if spec.params:
        names.append("params")
    if spec.dry_run:
        names.append("dryRun")
    if spec.passthrough:
        names.append("argv")
    return names


def _check_kind(op: str, key: str, kind: str, value: object) -> object:
    if kind == "str" and isinstance(value, str):
        return value
    if kind == "int" and type(value) is int:
        return value
    if kind == "bool" and isinstance(value, bool):
        return value
    raise BadRequest(f"op {op}: argument {key!r} must be a {kind}, not {json.dumps(value)}")


def _check_params(value: object) -> dict[str, dict[str, object]]:
    """Bind parameters (M4): `{"<name>": {"t": "<type>", "v": <value>}}`, shape checked here."""
    if not isinstance(value, dict):
        raise BadRequest("params must be a JSON object")
    out: dict[str, dict[str, object]] = {}
    for name, raw in cast("dict[str, object]", value).items():
        if not name:
            raise BadRequest("a parameter needs a name")
        if not isinstance(raw, dict) or set(cast("dict[str, object]", raw)) != {"t", "v"}:
            raise BadRequest(f'parameter {name!r} must be {{"t": <type>, "v": <value>}}')
        param = cast("dict[str, object]", raw)
        kind, item = param["t"], param["v"]
        if not isinstance(kind, str) or kind not in _PARAM_TYPES:
            raise BadRequest(
                f"parameter {name!r}: unknown type {json.dumps(kind)}; "
                f"valid types: {', '.join(sorted(_PARAM_TYPES))}"
            )
        valid = (
            (kind == "null" and item is None)
            or (kind == "int" and type(item) is int)
            or (kind not in ("null", "int") and isinstance(item, str))
        )
        if not valid:
            raise BadRequest(f"parameter {name!r}: {json.dumps(item)} is not a {kind} value")
        out[name] = {"t": kind, "v": item}
    return out


def audit_args(spec: OperationSpec, args: Mapping[str, object]) -> dict[str, object]:
    """What the decision record keeps of the arguments: the statement, the other arguments, and
    the parameter names and types. Never the bind values."""
    out: dict[str, object] = {}
    plain: dict[str, object] = {}
    statement_arg = next((a.name for a in spec.args if a.from_file), None)
    for key, value in args.items():
        if key == "params":
            params = cast("dict[str, dict[str, object]]", value)
            out["params"] = [{"name": name, "type": p["t"]} for name, p in params.items()]
        elif key == statement_arg and isinstance(value, str):
            out["statement"] = value
        else:
            plain[key] = value
    if plain:
        out["args"] = plain
    return out


# --- descriptions --------------------------------------------------------------------------------


def spec_json(spec: OperationSpec) -> dict[str, object]:
    return {
        "name": spec.name,
        "help": spec.help,
        "args": [
            {
                "name": a.name,
                "kind": a.kind,
                "help": a.help,
                "required": a.required,
                "flag": a.flag,
                "fromFile": a.from_file,
            }
            for a in spec.args
        ],
        "params": spec.params,
        "dryRun": spec.dry_run,
        "rows": spec.rows,
        "passthrough": spec.passthrough,
    }


def _constraints_json(decision: Decision) -> list[dict[str, object]]:
    return [
        {
            "name": c.name,
            "value": list(c.value) if isinstance(c.value, tuple) else c.value,
            "layer": str(c.layer),
            "source": c.source,
            "pattern": c.pattern,
        }
        for c in decision.constraints.values()
    ]


def _classify(target: OpenTarget, call: Call) -> Action:
    """The plugin classifies and never raises; if it does anyway, the call is `unknown`."""
    try:
        action = target.connector.classify(call, target.config.config)
    except Exception as exc:
        return Action.unknown(target.config.type, f"the classifier failed ({type(exc).__name__})")
    return action


# --- the dispatcher ------------------------------------------------------------------------------


MetaHandler = Callable[["Connection", Request], Awaitable[dict[str, object]]]
#: An admin op: (request, audit id, record fields) -> (result data, the trailer's audit id).
AdminHandler = Callable[
    [Request, str, Mapping[str, object]], Awaitable[tuple[dict[str, object], str | None]]
]


class Dispatcher:
    """Serves one connection: frame, route, and the call pipeline."""

    def __init__(self, broker: Broker) -> None:
        self.b = broker
        self._meta: dict[str, MetaHandler] = {
            "status": self._status,
            "targets": self._targets,
            "describe": self._describe,
            "explain": self._explain,
            "actions": self._actions,
            "policy-show": self._policy_show,
            "policy-lint": self._policy_lint,
        }
        self._admin_ops: dict[str, AdminHandler] = {
            "unlock": self._unlock,
            "lock": self._lock,
        }

    async def serve(self, conn: Connection) -> None:
        b = self.b
        await b.check_isolation()
        audit_id = new_audit_id()
        try:
            line = await read_request_line(
                conn.reader, b.limits.max_request_bytes, b.config.request_idle_timeout
            )
        except TimeoutError:
            message = f"no request line within {b.config.request_idle_timeout:g} s"
            await self.send_error(conn, "bad_request", message, None)
            return
        except RequestTooLarge as exc:
            await self.refuse(
                conn,
                audit_id,
                Refused(
                    "bad_request",
                    f"the request line exceeds maxRequestBytes "
                    f"({b.limits.max_request_bytes} bytes)",
                    record="bad_request",
                    fields={"bytesRead": exc.read},
                ),
                self._frame_fields(conn),
            )
            return
        if line is None:
            return
        conn.phase = "working"
        # Request entry: a passed idle or absolute deadline locks before anything else (M7).
        await b.check_session()
        try:
            request = parse_request(line)
        except BadRequest as exc:
            refusal = Refused("bad_request", str(exc), record="bad_request")
            await self.refuse(conn, audit_id, refusal, self._frame_fields(conn))
            return
        if request.op in ADMIN_OPS:
            await self._admin(conn, request, audit_id)
        elif request.target is None:
            await self._broker_op(conn, request, audit_id)
        else:
            await self._call(conn, request, audit_id)

    async def refuse_peer(self, conn: Connection) -> None:
        """A peer with another uid: `denied` and audited, before anything is read."""
        refusal = Refused(
            "denied",
            f"peer uid {conn.peer_uid} is not the broker's uid {self.b.uid}",
            record="denied",
            layer="peer",
            rule="uid",
        )
        await self.refuse(conn, new_audit_id(), refusal, self._frame_fields(conn))

    # --- helpers ---------------------------------------------------------------------------

    def _frame_fields(self, conn: Connection) -> dict[str, object]:
        return {"channel": conn.channel.value, "peerUid": conn.peer_uid}

    def _request_fields(self, conn: Connection, request: Request) -> dict[str, object]:
        fields = self._frame_fields(conn)
        fields.update(request.client.audit_fields())
        fields["op"] = request.op
        fields["target"] = request.target
        if request.env is not None:
            fields["requestEnv"] = request.env
        return fields

    async def send_error(
        self,
        conn: Connection,
        code: str,
        message: str,
        audit_id: str | None,
        *,
        layer: str | None = None,
        rule: str | None = None,
        retry_after: float | None = None,
        scrub: CallScrubber | None = None,
    ) -> None:
        scrubber = scrub or self.b.scrubber.call()
        frame: dict[str, object] = {
            "t": "error",
            "code": code,
            "message": scrubber.error(message),
            "auditId": audit_id,
        }
        if layer is not None:
            frame["layer"] = layer
        if rule is not None:
            frame["rule"] = rule
        if retry_after is not None:
            frame["retryAfter"] = retry_after
        with contextlib.suppress(ClientGone):
            await conn.send(frame)

    async def refuse(
        self,
        conn: Connection,
        audit_id: str,
        refusal: Refused,
        fields: Mapping[str, object],
        scrub: CallScrubber | None = None,
    ) -> None:
        if refusal.record is not None:
            record: dict[str, object] = {**fields, **refusal.fields}
            record.update(code=refusal.code, message=refusal.message)
            if refusal.layer is not None:
                record["layer"] = refusal.layer
            if refusal.rule is not None:
                record["rule"] = refusal.rule
            await self.b.audit.event(refusal.record, audit_id, **record)
        await self.send_error(
            conn,
            refusal.code,
            refusal.message,
            audit_id if refusal.record is not None or refusal.audited else None,
            layer=refusal.layer,
            rule=refusal.rule,
            retry_after=refusal.retry_after,
            scrub=scrub,
        )

    async def _result(
        self,
        conn: Connection,
        data: Mapping[str, object],
        started: float,
        audit_id: str | None = None,
    ) -> None:
        await conn.send({"t": "result", "data": data})
        await conn.send(
            {
                "t": "trailer",
                "rows": 0,
                "bytes": 0,
                "truncated": False,
                "reason": None,
                "durationMs": int((time.monotonic() - started) * 1000),
                "auditId": audit_id,
                "scrubbed": 0,
            }
        )

    # --- admin and broker ops --------------------------------------------------------------

    async def _admin(self, conn: Connection, request: Request, audit_id: str) -> None:
        fields = self._request_fields(conn, request)
        if conn.channel is not Channel.HUMAN:
            refusal = Refused(
                "bad_request",
                f"op {request.op!r} is not available on this channel; admin commands work only "
                "from your own terminal (human.sock)",
                record="bad_request",
                fields={"reason": "admin op on agent.sock"},
            )
            await self.refuse(conn, audit_id, refusal, fields)
            return
        if request.op == "audit-tail":
            await self._audit_tail(conn, request, audit_id)
            return
        handler = self._admin_ops.get(request.op)
        if handler is None:
            refusal = Refused(
                "bad_request",
                f"op {request.op!r} is not implemented in this version",
                record="bad_request",
            )
            await self.refuse(conn, audit_id, refusal, fields)
            return
        started = time.monotonic()
        try:
            data, record_id = await handler(request, audit_id, fields)
        except BadRequest as exc:
            refusal = Refused("bad_request", str(exc), record="bad_request")
            await self.refuse(conn, audit_id, refusal, fields)
            return
        except Refused as refusal:
            await self.refuse(conn, audit_id, refusal, fields)
            return
        with contextlib.suppress(ClientGone):
            await self._result(conn, data, started, record_id)

    async def _audit_tail(self, conn: Connection, request: Request, audit_id: str) -> None:
        """`audit tail` (M9): the last records, oldest first, one stored line per `text` frame,
        after a second scrubber pass. Works while locked and is not itself audited."""
        started = time.monotonic()
        try:
            flt, n = self._tail_args(request)
            tail = await asyncio.to_thread(read_tail, self.b.config.audit_dir, flt, n)
        except BadRequest as exc:
            await self.refuse(conn, audit_id, Refused("bad_request", str(exc), record=None), {})
            return
        except AuditReadError as exc:
            await self.refuse(conn, audit_id, Refused("internal", str(exc), record=None), {})
            return
        scrub = self.b.scrubber.call()
        sent = 0
        with contextlib.suppress(ClientGone):
            for line in tail.lines:
                text = scrub.error(line)
                await conn.send({"t": "text", "stream": "audit", "data": text})
                sent += len(text) + 1
            await conn.send(
                {
                    "t": "trailer",
                    "rows": len(tail.lines),
                    "bytes": sent,
                    "truncated": tail.truncated,
                    "reason": "bytes" if tail.truncated else None,
                    "durationMs": int((time.monotonic() - started) * 1000),
                    "auditId": None,
                    "scrubbed": scrub.count,
                    "malformed": tail.malformed,
                }
            )

    def _tail_args(self, request: Request) -> tuple[TailFilter, int]:
        self._meta_args(request, ("target", "session", "client", "n"))
        n = request.args.get("n", DEFAULT_N)
        if type(n) is not int or not 1 <= n <= MAX_N:
            raise BadRequest(
                f"op audit-tail: n must be an integer from 1 to {MAX_N}, not {json.dumps(n)}"
            )
        flt = TailFilter(
            target=self._str_arg(request, "target", required=False),
            session=self._str_arg(request, "session", required=False),
            client=self._str_arg(request, "client", required=False),
        )
        return flt, n

    async def _unlock(
        self, request: Request, audit_id: str, fields: Mapping[str, object]
    ) -> tuple[dict[str, object], str | None]:
        """Unlock the store session. The credential is never audited nor echoed; the `file`
        store accepts any input, including none."""
        self._meta_args(request, ("credential",))
        credential = request.args.get("credential", "")
        if not isinstance(credential, str):
            raise BadRequest("op unlock: 'credential' must be a string")
        outcome = await self.b.unlock(credential, audit_id, fields)
        data: dict[str, object] = {
            "state": "unlocked",
            "alreadyUnlocked": outcome.already,
            "reauthenticated": outcome.reauthenticated,
        }
        return data, audit_id

    async def _lock(
        self, request: Request, audit_id: str, fields: Mapping[str, object]
    ) -> tuple[dict[str, object], str | None]:
        """Lock now; returns at once with the number of calls it cancelled. Idempotent."""
        self._meta_args(request, ())
        outcome = await self.b.lock(LockReason.MANUAL, fields=fields)
        data: dict[str, object] = {
            "state": "locked",
            "alreadyLocked": not outcome.locked,
            "reason": str(self.b.session.reason) if self.b.session.reason else None,
            "cancelled": outcome.cancelled,
        }
        return data, outcome.audit_id

    async def _broker_op(self, conn: Connection, request: Request, audit_id: str) -> None:
        handler = self._meta.get(request.op)
        if handler is None:
            refusal = Refused(
                "bad_request",
                f"unknown op {request.op!r}; broker ops: {', '.join(META_OPS)}; "
                "a target op needs a target",
                record="bad_request",
            )
            await self.refuse(conn, audit_id, refusal, self._request_fields(conn, request))
            return
        started = time.monotonic()
        try:
            data = await handler(conn, request)
        except Refused as refusal:
            # Metadata ops are not audited (M6).
            refusal.record = None
            await self.refuse(conn, audit_id, refusal, {})
            return
        except BadRequest as exc:
            await self.send_error(conn, "bad_request", str(exc), None)
            return
        with contextlib.suppress(ClientGone):
            await self._result(conn, data, started)

    def _meta_args(self, request: Request, allowed: Sequence[str]) -> Mapping[str, object]:
        for key in request.args:
            if key not in allowed:
                raise BadRequest(
                    f"op {request.op} takes no argument {key!r}; arguments: "
                    f"{', '.join(allowed) or 'none'}"
                )
        return request.args

    def _str_arg(self, request: Request, key: str, *, required: bool) -> str | None:
        value = request.args.get(key)
        if value is None:
            if required:
                raise BadRequest(f"op {request.op} needs the argument {key!r}")
            return None
        if not isinstance(value, str) or not value:
            raise BadRequest(f"op {request.op}: argument {key!r} must be a non-empty string")
        return value

    def _resolve(self, name: str, env: str | None) -> tuple[Resolved, OpenTarget]:
        try:
            resolved = resolve_target(self.b.policy, name, env)
        except ResolveError as exc:
            raise Refused("not_found", str(exc), record="bad_request") from None
        return resolved, self.b.targets[resolved.target.name]

    async def _status(self, conn: Connection, request: Request) -> dict[str, object]:
        self._meta_args(request, ())
        return self.b.status(conn, request)

    async def _targets(self, conn: Connection, request: Request) -> dict[str, object]:
        self._meta_args(request, ("system",))
        system = self._str_arg(request, "system", required=False)
        systems = self.b.policy.systems()
        if system is not None and system not in systems:
            raise Refused(
                "not_found",
                f"unknown system {system!r}; systems: {', '.join(sorted(systems)) or 'none'}",
                record=None,
            )
        entries = [
            self.b.target_summary(target)
            for target in self.b.targets.values()
            if system is None or target.config.system == system
        ]
        data: dict[str, object] = {"targets": entries}
        warning = self.b.l0_warning()
        if warning is not None:
            data["warning"] = warning
        return data

    async def _describe(self, conn: Connection, request: Request) -> dict[str, object]:
        self._meta_args(request, ("target",))
        name = cast("str", self._str_arg(request, "target", required=True))
        resolved, target = self._resolve(name, request.env)
        data = self.b.target_summary(target)
        data["envSource"] = resolved.env_source
        data["operations"] = [spec_json(spec) for spec in target.operations.values()]
        data["scrub"] = self.b.scrub_fact(target)
        return data

    async def _explain(self, conn: Connection, request: Request) -> dict[str, object]:
        self._meta_args(request, ("target", "op", "args"))
        name = cast("str", self._str_arg(request, "target", required=True))
        op = cast("str", self._str_arg(request, "op", required=True))
        raw_args = request.args.get("args", {})
        if not isinstance(raw_args, dict):
            raise BadRequest("op explain: 'args' must be a JSON object")
        resolved, target = self._resolve(name, request.env)
        spec = target.operations.get(op)
        if spec is None:
            raise Refused("bad_request", _no_such_op(target, op), record=None)
        args, max_rows = validate_args(spec, cast("dict[str, object]", raw_args))
        try:
            target.limits.with_max_rows(max_rows)
        except MaxRowsRefused as exc:
            raise Refused(
                "denied", str(exc), record=None, layer="limits", rule="maxRowsHard"
            ) from None
        action = _classify(target, Call(target=target.config.name, op=op, args=args))
        decision = self.b.decide(target, action, resolved.env)
        return {
            "target": target.config.name,
            "env": resolved.env,
            "envSource": resolved.env_source,
            "op": op,
            "action": action.name,
            "risk": action.risk.value,
            "decision": decision.verdict,
            "layer": str(decision.layer),
            "rule": decision.rule,
            "message": decision.message,
            "explanation": explain(decision),
            "constraints": _constraints_json(decision),
            "effectiveEnv": self.b.pin_fact(target),
        }

    async def _actions(self, conn: Connection, request: Request) -> dict[str, object]:
        self._meta_args(request, ("type",))
        type_name = cast("str", self._str_arg(request, "type", required=True))
        connector = self.b.registry.connector_plugin(type_name)
        if connector is None:
            known = ", ".join(sorted(c.type for c in self.b.registry.connectors()))
            raise Refused(
                "not_found", f"unknown connector type {type_name!r}; types: {known}", record=None
            )
        return {
            "type": type_name,
            "actions": [
                {
                    "name": f"{type_name}:{spec.name}",
                    "risk": spec.risk.value,
                    "constraints": sorted(spec.constraints),
                    "summary": spec.summary,
                }
                for spec in connector.actions()
            ],
        }

    async def _policy_show(self, conn: Connection, request: Request) -> dict[str, object]:
        self._meta_args(request, ("target",))
        name = cast("str", self._str_arg(request, "target", required=True))
        resolved, target = self._resolve(name, request.env)
        scope = target.scope(self.b.policy, resolved.env)
        return {
            "target": target.config.name,
            "type": target.config.type,
            "env": resolved.env,
            "envSource": resolved.env_source,
            "ceiling": scope.ceiling.value,
            "guard": [rule.pattern for rule in scope.guard],
            "invariants": [{"rule": r.pattern, "reason": r.reason} for r in scope.invariants],
            "layers": [
                {
                    "layer": str(layer.layer),
                    "source": layer.source,
                    "blocks": [
                        {
                            "allow": [r.pattern for r in block.allow],
                            "deny": [r.pattern for r in block.deny],
                            "constraints": {
                                pattern: {
                                    key: list(value) if isinstance(value, tuple) else value
                                    for key, value in values.items()
                                }
                                for pattern, values in block.constraints.items()
                            },
                        }
                        for block in layer.blocks
                    ],
                }
                for layer in scope.layers()
            ],
            "effectiveEnv": self.b.pin_fact(target),
        }

    async def _policy_lint(self, conn: Connection, request: Request) -> dict[str, object]:
        self._meta_args(request, ())
        b = self.b
        report = await asyncio.to_thread(
            lint_policy, b.config.policy_dir, b.registry, dev=b.config.dev
        )
        return {
            "ok": report.ok,
            "findings": [
                {"severity": f.severity, "file": f.file, "key": f.key, "message": f.message}
                for f in report.findings
            ],
        }

    # --- the call pipeline (M6) ------------------------------------------------------------

    async def _call(self, conn: Connection, request: Request, audit_id: str) -> None:
        scrub = self.b.scrubber.call()
        fields = self._request_fields(conn, request)
        started = time.monotonic()
        try:
            await self._pipeline(conn, request, audit_id, scrub, fields, started)
        except Refused as refusal:
            await self.refuse(conn, audit_id, refusal, fields, scrub)

    async def _pipeline(
        self,
        conn: Connection,
        request: Request,
        audit_id: str,
        scrub: CallScrubber,
        fields: dict[str, object],
        started: float,
    ) -> None:
        b = self.b
        # 2. Resolve the target.
        resolved, target = self._resolve(cast("str", request.target), request.env)
        config = target.config
        fields.update(
            target=config.name,
            connector=config.type,
            system=config.system,
            env=resolved.env,
            envSource=resolved.env_source,
            tier=config.credential.tier,
            mode="attended",
        )
        # 3. Validate the arguments against the op contract.
        spec = target.operations.get(request.op)
        if spec is None:
            raise Refused("bad_request", _no_such_op(target, request.op), record="bad_request")
        try:
            args, max_rows = validate_args(spec, request.args)
        except BadRequest as exc:
            raise Refused("bad_request", str(exc), record="bad_request") from None
        fields.update(audit_args(spec, args))
        if max_rows is not None:
            fields["maxRows"] = max_rows
        try:
            limits = target.limits.with_max_rows(max_rows)
        except MaxRowsRefused as exc:
            raise Refused(
                "denied", str(exc), record="denied", layer="limits", rule="maxRowsHard"
            ) from None
        # 4. Classify and decide with the declared environment (phase 1).
        call = Call(target=config.name, op=request.op, args=args, audit_id=audit_id)
        action = _classify(target, call)
        decision = b.decide(target, action, resolved.env)
        fields.update(
            action=action.name,
            risk=action.risk.value,
            decision=decision.verdict,
            layer=str(decision.layer),
            rule=decision.rule,
        )
        if not decision.allowed:
            raise Refused(
                "denied",
                explain(decision),
                record="denied",
                layer=str(decision.layer),
                rule=decision.rule,
            )
        # 5. The target's `maxConcurrent` slot, without blocking.
        if not target.slots.try_acquire():
            raise Refused(
                "throttled",
                f"target {config.name} already runs {target.slots.limit} calls "
                f"(maxConcurrent {target.slots.limit}); retry after {RETRY_AFTER:g} s",
                record="throttled",
                retry_after=RETRY_AFTER,
            )
        try:
            await self._with_slot(conn, target, call, decision, limits, scrub, fields, started)
        finally:
            target.slots.release()

    async def _with_slot(
        self,
        conn: Connection,
        target: OpenTarget,
        call: Call,
        decision: Decision,
        limits: Limits,
        scrub: CallScrubber,
        fields: dict[str, object],
        started: float,
    ) -> None:
        b = self.b
        # 6. The lock gate: broker-wide, every executing call needs UNLOCKED.
        epoch = b.session.epoch
        if not b.session.unlocked:
            raise Refused("locked", b.locked_message(), record="locked")
        # 7. The secret and its pins, then the decision with the effective environment.
        decision = await self._phase_two(target, decision, fields, epoch)
        # 8. The decision record. Without it nothing executes.
        try:
            await b.audit.recover()
            await b.audit.decision(call.audit_id, **fields)
        except AuditUnavailable as exc:
            raise Refused(
                "internal",
                f"the audit log cannot be written ({exc}); nothing was executed",
                record=None,
            ) from None
        # 9. and 10.
        execution = Execution(
            self, conn, target, call, decision, limits, scrub, fields, started, epoch
        )
        await execution.run()

    async def _phase_two(
        self, target: OpenTarget, decision: Decision, fields: dict[str, object], epoch: int
    ) -> Decision:
        """M6 step 7: resolve the secret and its pins, check the destination pin, apply the
        environment pin and decide again (phase 2, final). A failure writes one record.

        A `provider:` target has no stored secret and no pins: phase 2 equals phase 1, and
        nothing is fetched here."""
        b = self.b
        name = target.config.name
        secrets = target.secrets
        if secrets is None:
            fields["effectiveEnv"] = decision.env
            return decision
        ref = str(secrets.ref)
        try:
            pin = await secrets.check()
        except SessionLocked:
            raise Refused("locked", b.locked_message(), record="locked") from None
        except StoreError as exc:
            raise Refused(
                "upstream",
                f"secret {ref} of target {name} cannot be resolved: {exc}",
                record="failed",
                fields={"stage": "secret"},
            ) from None
        except PinError as exc:
            raise Refused(
                "denied",
                exc.message,
                record="denied",
                layer="pinning",
                rule=exc.rule,
                fields={"decision": "deny", "stage": "secret"},
            ) from None
        if not b.session.is_current(epoch):
            raise Refused("locked", b.locked_message(), record="locked")
        fields["effectiveEnv"] = pin.env
        if pin.pinned is not None:
            fields["secretEnv"] = pin.pinned
        if pin.env == decision.env:
            return decision
        final = b.decide(target, decision.action, pin.env)
        fields.update(decision=final.verdict, layer=str(final.layer), rule=final.rule)
        if not final.allowed:
            raise Refused(
                "denied",
                f"{explain(final)} The environment is pinned to {pin.env} by the secret {ref}; "
                f"target {name} declares {decision.env}.",
                record="denied",
                layer=str(final.layer),
                rule=final.rule,
            )
        return final


def _no_such_op(target: OpenTarget, op: str) -> str:
    ops = ", ".join(target.operations) or "none"
    return f"target {target.config.name} ({target.config.type}) has no op {op!r}; ops: {ops}"


async def _watch_eof(reader: asyncio.StreamReader) -> None:
    """Returns when the client closes its side: EOF cancels the call (M4)."""
    try:
        while await reader.read(65536):
            pass
    except (ConnectionError, OSError):
        return


_COMPLETION_SKIP = frozenset({"statement", "args", "params"})


@dataclass
class _Outcome:
    kind: Literal["completed", "truncated", "failed", "cancelled"]
    cancelled: CancelReason | None = None
    code: str | None = None
    message: str | None = None
    stage: str | None = None
    layer: str | None = None
    rule: str | None = None


class Execution:
    """M6 steps 9 and 10: run the plugin with the sink and the deadline, then answer and record."""

    def __init__(
        self,
        dispatcher: Dispatcher,
        conn: Connection,
        target: OpenTarget,
        call: Call,
        decision: Decision,
        limits: Limits,
        scrub: CallScrubber,
        fields: dict[str, object],
        started: float,
        epoch: int,
    ) -> None:
        self.d = dispatcher
        self.b = dispatcher.b
        self.conn = conn
        self.target = target
        self.decision = decision
        self.limits = limits
        self.scrub = scrub
        self.fields = fields
        self.started = started
        #: The session epoch the call passed the lock gate in.
        self.epoch = epoch
        self.deadline = time.monotonic() + self.limits.timeout
        self.call = replace(call, deadline=self.deadline, constraints=decision.constraints)
        self.sink = LimitedSink(
            conn.write, scrub, max_rows=self.limits.max_rows, max_bytes=self.limits.max_bytes
        )

    async def run(self) -> None:
        if self.b.stopping:
            outcome = _Outcome(
                "cancelled", "shutdown", "unavailable", "the broker is shutting down"
            )
        elif not self.b.session.is_current(self.epoch):
            # Locked while the decision record was written: nothing runs.
            outcome = self._cancelled("lock")
        else:
            outcome = await self._execute()
        await self._respond(outcome)

    async def _execute(self) -> _Outcome:
        # The connector's `Secrets.login` sees what this call was decided with.
        with call_scope(CallScope(self.decision.env, self.epoch)):
            task = asyncio.create_task(self.target.target.execute(self.call, self.sink))
        flight = Flight(self.call.audit_id, task)
        self.b.flights.add(flight)
        session = self.b.session
        session.call_started()
        watcher = asyncio.create_task(_watch_eof(self.conn.reader))
        try:
            remaining = max(0.0, self.deadline - time.monotonic())
            done, _ = await asyncio.wait(
                {task, watcher}, timeout=remaining, return_when=asyncio.FIRST_COMPLETED
            )
            if task not in done:
                flight.cancel("client" if watcher in done else "timeout")
                await asyncio.wait({task}, timeout=CANCEL_GRACE)
            outcome = self._outcome(task, flight)
            if outcome.kind == "completed":
                outcome = await self._finish()
            return outcome
        finally:
            watcher.cancel()
            if not task.done():
                task.cancel()
            self.b.flights.discard(flight)
            session.call_finished()

    def _outcome(self, task: asyncio.Task[None], flight: Flight) -> _Outcome:
        if flight.reason is not None:
            return self._cancelled(flight.reason)
        if not task.done() or task.cancelled():
            return self._cancelled("client")
        exc = task.exception()
        if exc is None:
            return _Outcome("completed")
        if self.conn.closed or isinstance(exc, ClientGone):
            return self._cancelled("client")
        if self.sink.truncated or isinstance(exc, LimitReached):
            return _Outcome("truncated")
        if isinstance(exc, TimeoutError):
            return self._cancelled("timeout")
        if isinstance(exc, SessionLocked):
            return self._cancelled("lock")
        if isinstance(exc, PinError):
            return _Outcome(
                "failed", None, "denied", exc.message, "login", layer="pinning", rule=exc.rule
            )
        if isinstance(exc, StoreError):
            return _Outcome("failed", None, "upstream", str(exc), "secret")
        if isinstance(exc, AuthFailed):
            return _Outcome("failed", None, "upstream", f"authentication failed: {exc}", "exec")
        if isinstance(exc, LoginFailed | Latched):
            return _Outcome("failed", None, "upstream", str(exc), exc.stage)
        if isinstance(exc, UpstreamFailure):
            return _Outcome("failed", None, "upstream", str(exc), "exec")
        return _Outcome(
            "failed",
            None,
            "internal",
            f"the {self.target.config.type} connector failed: {type(exc).__name__}: {exc}",
            "exec",
        )

    def _cancelled(self, reason: CancelReason) -> _Outcome:
        if reason == "timeout":
            message = f"the call exceeded its deadline of {self.limits.timeout:g} s"
            return _Outcome("cancelled", reason, "timeout", message)
        if reason == "shutdown":
            message = "the broker is shutting down; the call was cancelled"
            return _Outcome("cancelled", reason, "unavailable", message)
        if reason == "lock":
            message = f"the call was cancelled: {self.b.locked_message()}"
            return _Outcome("cancelled", reason, "locked", message)
        return _Outcome("cancelled", reason)

    async def _finish(self) -> _Outcome:
        try:
            await self.sink.finish()
        except LimitReached:
            return _Outcome("truncated")
        except ClientGone:
            return self._cancelled("client")
        return _Outcome("completed")

    async def _respond(self, outcome: _Outcome) -> None:
        sink = self.sink
        duration = int((time.monotonic() - self.started) * 1000)
        message = self.scrub.error(outcome.message) if outcome.message is not None else None
        if outcome.kind in ("completed", "truncated"):
            trailer: dict[str, object] = {
                "t": "trailer",
                "rows": sink.rows,
                "bytes": sink.bytes,
                "truncated": sink.truncated,
                "reason": sink.reason,
                "durationMs": duration,
                "auditId": self.call.audit_id,
                "scrubbed": self.scrub.count,
            }
            for key, value in (
                ("affectedRows", sink.affected_rows),
                ("committed", sink.committed),
                ("dryRun", sink.dry_run),
                ("exitCode", sink.exit_code),
            ):
                if value is not None:
                    trailer[key] = value
            try:
                await self.conn.send(trailer)
            except ClientGone:
                outcome = self._cancelled("client")
        elif outcome.code is not None and message is not None:
            await self.d.send_error(
                self.conn,
                outcome.code,
                message,
                self.call.audit_id,
                layer=outcome.layer,
                rule=outcome.rule,
                scrub=self.scrub,
            )
        if outcome.kind in ("failed", "cancelled") and outcome.cancelled != "client":
            log.warning(
                "call %s on %s ended %s: %s",
                self.call.audit_id,
                self.target.config.name,
                outcome.code,
                message,
            )
        record = {k: v for k, v in self.fields.items() if k not in _COMPLETION_SKIP}
        record.update(
            outcome=outcome.kind,
            cancelled=outcome.cancelled,
            rows=sink.rows,
            bytes=sink.bytes,
            truncated=sink.truncated,
            reason=sink.reason,
            durationMs=duration,
            scrubbed=self.scrub.count,
            affectedRows=sink.affected_rows,
            committed=sink.committed,
            dryRun=sink.dry_run,
            exitCode=sink.exit_code,
            destination=self.target.destination_text(),
            error=(
                {"code": outcome.code, "message": message} if outcome.code is not None else None
            ),
        )
        if outcome.stage is not None:
            record["stage"] = outcome.stage
        if outcome.layer is not None:
            record.update(layer=outcome.layer, rule=outcome.rule)
        await self.b.audit.completion(self.call.audit_id, **record)
