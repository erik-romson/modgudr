"""The `sql` connector (§8.1, M14): config, operations, action catalogue, rules and targets.

The connector classifies with the target's dialect and executes through the dialect's driver
adapter. One call is one transaction on one pooled session: a read ends with a rollback (Snowflake
has no read-only transaction, so classification and the role carry read safety), a write commits
only when every constraint measured after the run is met.
"""

from __future__ import annotations

import asyncio
import functools
import math
import time
from collections.abc import Mapping, Sequence
from typing import Protocol

from pydantic import BaseModel

from modgudr.broker.sink import LimitReached
from modgudr.spi import (
    Action,
    ActionSpec,
    BadArguments,
    Call,
    Cell,
    ConstraintBreach,
    ConstraintCheck,
    Destination,
    OperationSpec,
    ResolvedSecret,
    ResultSink,
    Risk,
    Rule,
    RuleSet,
    Secrets,
    SqlDialect,
    TargetContext,
    TypedParam,
)

from . import ops
from .classify import INVARIANTS, TYPE
from .config import SqlConfig
from .constraints import MaxAffectedRows, RequireWhere
from .driver import CellTooLarge, Driver, Session, SessionDead, Statement, StatementError
from .pool import SessionPool, dispose

#: What a driver binds: values by position (`numeric` placeholders) or by name (`named`).
Binds = Sequence[object] | Mapping[str, object]

#: Rows fetched from the driver per round trip to a worker thread.
FETCH_ROWS = 256

_WHERE = frozenset({"requireWhere", "maxAffectedRows"})
_ROWS = frozenset({"maxAffectedRows"})

#: The action catalogue (`modgudr actions sql`); the names are the classifier's (M12).
ACTIONS: tuple[ActionSpec, ...] = (
    ActionSpec("select", Risk.READ, summary="a query"),
    ActionSpec("describe", Risk.READ, summary="DESCRIBE a table or view"),
    ActionSpec("show", Risk.READ, summary="SHOW objects"),
    ActionSpec("explain", Risk.READ, summary="EXPLAIN a statement"),
    ActionSpec("insert", Risk.WRITE, _ROWS, "INSERT (OVERWRITE is destructive)"),
    ActionSpec("update", Risk.WRITE, _WHERE, "UPDATE"),
    ActionSpec("merge", Risk.WRITE, _ROWS, "MERGE (a delete arm is destructive)"),
    ActionSpec("copy", Risk.WRITE, summary="COPY INTO a table"),
    ActionSpec("delete", Risk.DESTRUCTIVE, _WHERE, "DELETE"),
    ActionSpec("truncate", Risk.DESTRUCTIVE, summary="TRUNCATE"),
    ActionSpec("ddl.drop", Risk.DESTRUCTIVE, summary="DROP"),
    ActionSpec("ddl.create", Risk.ADMIN, summary="CREATE"),
    ActionSpec("ddl.alter", Risk.ADMIN, summary="ALTER"),
    ActionSpec("ddl.undrop", Risk.ADMIN, summary="UNDROP"),
    ActionSpec("ddl.comment", Risk.ADMIN, summary="COMMENT"),
    ActionSpec("grant", Risk.ADMIN, summary="GRANT"),
    ActionSpec("revoke", Risk.ADMIN, summary="REVOKE"),
    ActionSpec("unload", Risk.ADMIN, summary="COPY INTO a stage or URL"),
    ActionSpec("put", Risk.ADMIN, summary="PUT a file to a stage"),
    ActionSpec("get", Risk.ADMIN, summary="GET a file from a stage"),
    ActionSpec("remove", Risk.ADMIN, summary="REMOVE staged files"),
    ActionSpec("plsql", Risk.ADMIN, summary="a scripting block, CALL or EXECUTE"),
    ActionSpec("session", Risk.ADMIN, summary="session state (an invariant: never allowed)"),
    ActionSpec("use", Risk.ADMIN, summary="USE (an invariant: never allowed)"),
    ActionSpec("transaction", Risk.ADMIN, summary="transaction control (an invariant)"),
)

CHECKS: Mapping[str, ConstraintCheck] = {
    "requireWhere": RequireWhere(),
    "maxAffectedRows": MaxAffectedRows(),
}


class DialectBackend(SqlDialect, Protocol):
    """A `SqlDialect` that can also classify a statement and build its driver."""

    def classify(self, sql: str) -> Action: ...

    def driver(self, config: SqlConfig) -> Driver: ...


def builtin_dialects() -> dict[str, DialectBackend]:
    from .dialects.oracle import OracleDialect
    from .dialects.snowflake import SnowflakeDialect

    return {"snowflake": SnowflakeDialect(), "oracle": OracleDialect()}


def _sql_config(config: BaseModel) -> SqlConfig:
    if not isinstance(config, SqlConfig):
        raise TypeError(f"not a sql target config: {type(config).__name__}")
    return config


class SqlConnector:
    """`type: sql`."""

    def __init__(self, dialects: Mapping[str, DialectBackend] | None = None) -> None:
        self._dialects = dict(dialects) if dialects is not None else builtin_dialects()

    @property
    def type(self) -> str:
        return TYPE

    @property
    def config_model(self) -> type[BaseModel]:
        return SqlConfig

    def operations(self) -> Sequence[OperationSpec]:
        return ops.OPERATIONS

    def actions(self) -> Sequence[ActionSpec]:
        return ACTIONS

    def invariants(self) -> Sequence[Rule]:
        return INVARIANTS

    def default_rules(self) -> RuleSet:
        return RuleSet(allow=(Rule("read"),))

    def constraint_checks(self) -> Mapping[str, ConstraintCheck]:
        return CHECKS

    def _backend(self, config: BaseModel) -> DialectBackend:
        name = _sql_config(config).dialect
        backend = self._dialects.get(name)
        if backend is None:
            raise BadArguments(f"the sql dialect {name!r} is not installed")
        return backend

    def validate(self, call: Call, config: BaseModel, *, max_rows: int) -> None:
        ops.validate(call, self._backend(config), max_rows=max_rows)

    def classify(self, call: Call, config: BaseModel) -> Action:
        try:
            backend = self._backend(config)
            prepared = ops.statement_text(call, backend)
        except (BadArguments, TypeError) as exc:
            return Action.unknown(TYPE, str(exc))
        return ops.apply_contract(call.op, backend.classify(prepared.text))

    async def open(
        self, name: str, config: BaseModel, secrets: Secrets | None, *, context: TargetContext
    ) -> SqlTarget:
        if secrets is None:
            raise ValueError(f"sql target {name} needs a secret, not a provider")
        sql = _sql_config(config)
        backend = self._backend(sql)
        return SqlTarget(name, backend, backend.driver(sql), secrets)


def _remaining(call: Call) -> float:
    """Seconds left of the call's deadline; `TimeoutError` when none is."""
    if call.deadline is None:
        return 30.0
    left = call.deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError
    return left


class SqlTarget:
    """One configured SQL target: its driver, its session pool and the login through `Secrets`."""

    def __init__(
        self, name: str, backend: DialectBackend, driver: Driver, secrets: Secrets
    ) -> None:
        self.name = name
        self._backend = backend
        self._driver = driver
        self._secrets = secrets
        self._pool = SessionPool()

    @property
    def default_port(self) -> int:
        return self._backend.default_port

    def destinations(self) -> frozenset[Destination]:
        return self._driver.destinations()

    async def aclose(self) -> None:
        self._pool.close_all()

    # --- the call -----------------------------------------------------------------------------

    async def execute(self, call: Call, sink: ResultSink) -> None:
        bound = ops.bind_call(call, self._backend)
        params = self._binds(bound.params)
        if call.op == "write":
            await self._write(call, sink, bound.sql, params)
        else:
            await self._read(call, sink, bound.sql, params)

    def _binds(self, params: Sequence[TypedParam]) -> Binds:
        """The values the driver binds: by name for `named` placeholders, else by position."""
        if self._backend.bind_style == "named":
            return {p.name: self._backend.bind_value(p) for p in params}
        return [self._backend.bind_value(p) for p in params]

    async def _read(self, call: Call, sink: ResultSink, sql: str, params: Binds) -> None:
        session, statement = await self._run(call, sql, params, retry=True)
        held: Session | None = session
        try:
            try:
                await sink.header(statement.columns)
                while rows := await self._fetch(statement, sink):
                    for row in rows:
                        await sink.row(row)
            except LimitReached:
                await self._end_read(session, statement)
                held = None
                raise
            await self._end_read(session, statement)
            held = None
        finally:
            if held is not None:
                self._pool.discard(held)

    async def _fetch(self, statement: Statement, sink: ResultSink) -> Sequence[Sequence[Cell]]:
        try:
            return await asyncio.to_thread(statement.fetch, FETCH_ROWS, sink.room)
        except CellTooLarge as exc:
            sink.cell_too_large(exc.column, exc.size)

    async def _end_read(self, session: Session, statement: Statement) -> None:
        """Close the cursor and roll back the read's transaction, then pool the session."""
        await asyncio.to_thread(statement.close)
        await asyncio.to_thread(session.rollback)
        self._pool.release(session)

    async def _write(self, call: Call, sink: ResultSink, sql: str, params: Binds) -> None:
        dry_run = bool(call.args.get("dryRun", False))
        sink.report(committed=False, dry_run=dry_run)
        session, statement = await self._run(call, sql, params, retry=False)
        held: Session | None = session
        try:
            affected = statement.rowcount
            await asyncio.to_thread(statement.close)
            sink.report(affected_rows=affected)
            breach = self._breach(call, affected)
            if breach is not None or dry_run:
                await asyncio.to_thread(session.rollback)
                self._pool.release(session)
                held = None
                if breach is not None:
                    raise breach
                return
            held = None
            await self._commit(session, sink)
        finally:
            if held is not None:
                self._pool.discard(held)

    async def _commit(self, session: Session, sink: ResultSink) -> None:
        """COMMIT, and decide the session's fate. The COMMIT is not cancelled halfway: once it
        is sent the call is recorded `committed` whatever happens next (M6, M7), and the session
        is dropped when the COMMIT has returned."""
        commit = asyncio.ensure_future(asyncio.to_thread(session.commit))
        try:
            await asyncio.shield(commit)
        except asyncio.CancelledError:
            sink.report(committed=True)
            commit.add_done_callback(lambda done: self._after_commit(session, done))
            raise
        except BaseException:
            self._pool.discard(session)
            raise
        sink.report(committed=True)
        self._pool.release(session)

    def _after_commit(self, session: Session, done: asyncio.Future[None]) -> None:
        if not done.cancelled():
            done.exception()  # retrieved: a failure was reported as `committed` already
        self._pool.discard(session)

    def _breach(self, call: Call, affected: int | None) -> ConstraintBreach | None:
        """The first constraint that the run's measurements do not meet (M14), as an error."""
        action = self._backend.classify(ops.statement_text(call, self._backend).text)
        measured = {"affectedRows": affected}
        for constraint in call.constraints.values():
            check = CHECKS.get(constraint.name)
            if check is None:
                reason = f"the sql connector has no check for {constraint.name}"
            else:
                reason = check.after(action, constraint.value, measured)
            if reason is not None:
                return ConstraintBreach(
                    f"Constraint {constraint.name} from {constraint.source} is not met: {reason}",
                    rule=constraint.name,
                )
        return None

    async def _run(
        self, call: Call, sql: str, params: Binds, *, retry: bool
    ) -> tuple[Session, Statement]:
        """Check out a session and start the statement. A read whose pooled session died
        reconnects once (M14); a statement the server refused leaves a healthy session."""
        attempts = 2 if retry else 1
        for attempt in range(1, attempts + 1):
            session = await self._pool.acquire(lambda: self._open(call))
            try:
                statement = await asyncio.to_thread(
                    functools.partial(
                        session.run,
                        sql,
                        params,
                        timeout=_remaining(call),
                        tag=call.audit_id,
                        op=call.op,
                        schema=ops.schema_of(call),
                    )
                )
            except SessionDead:
                self._pool.discard(session)
                if attempt == attempts:
                    raise
            except StatementError:
                await self._rollback_quietly(session)
                raise
            except BaseException:
                self._pool.discard(session)
                raise
            else:
                return session, statement
        raise AssertionError("unreachable")

    async def _rollback_quietly(self, session: Session) -> None:
        try:
            await asyncio.to_thread(session.rollback)
        except BaseException:
            self._pool.discard(session)
            raise
        self._pool.release(session)

    async def _open(self, call: Call) -> Session:
        """A new session, logged in through the secret service (M8)."""
        timeout = math.ceil(_remaining(call))

        async def connect(secret: ResolvedSecret) -> Session:
            work = asyncio.ensure_future(
                asyncio.to_thread(self._driver.connect, secret.value, timeout=timeout)
            )
            try:
                return await asyncio.shield(work)
            except asyncio.CancelledError:
                work.add_done_callback(_close_late)
                raise

        return await self._secrets.login(connect)


def _close_late(work: asyncio.Future[Session]) -> None:
    """A login that finished after its call was cancelled: the session is closed, not leaked."""
    if not work.cancelled() and work.exception() is None:
        dispose(work.result(), abandon=False)
