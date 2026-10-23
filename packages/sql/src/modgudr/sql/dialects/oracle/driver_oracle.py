# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false
"""The Oracle driver adapter (M16): the only module that imports `oracledb`.

Blocking calls, meant for worker threads. Thin mode only (`init_oracle_client` is never called).
Library exceptions become the ones in `modgudr.sql.driver` and `modgudr.spi`; a message of ours
never holds a secret. Sessions are the connector's pooled standalone connections: a login goes
through `Secrets.login`, so the latch, the single flight and the "only while connecting" rule of
M8 hold (see the run report for why this is not `oracledb.create_pool`).
"""

from __future__ import annotations

import contextlib
import logging
import math
import re
import socket
import threading
from collections.abc import Callable, Generator, Mapping, Sequence
from decimal import Decimal
from typing import TYPE_CHECKING, Any

import oracledb

from modgudr.spi import AuthFailed, Cell, Column, ColumnType, Destination, UpstreamFailure
from modgudr.sql.driver import SessionDead, Statement, StatementError

from .connect import connect_params, oracle_port
from .types import column_type, encode_row

if TYPE_CHECKING:
    from modgudr.sql.config import SqlConfig

log = logging.getLogger("modgudr.broker")

#: ORA-01017 invalid credential; ORA-28000 the account is locked and ORA-28001 the password has
#: expired are final: never retried (M8).
AUTH_CODES = frozenset({"ORA-01017"})
FINAL_CODES = frozenset({"ORA-28000", "ORA-28001"})
#: The pooled connection died (M14): ORA-00028 (killed), ORA-03113/03114/03135, DPY-4011.
DEAD_CODES = frozenset({"ORA-00028", "ORA-03113", "ORA-03114", "ORA-03135", "DPY-4011"})
#: DPY-4024 the call timeout was reached; ORA-01013 the call was cancelled.
TIMEOUT_CODES = frozenset({"DPY-4024", "ORA-01013"})
#: The listener cannot be reached: refused, unresolvable, timed out.
UNREACHABLE_CODES = frozenset({"DPY-6005", "ORA-12541", "ORA-12170", "ORA-12535"})

#: After this long without the cancelled call returning, `abandon` logs a warning and keeps waiting.
ABANDON_WARN = 10.0

#: An audit id goes into `EXPLAIN PLAN SET STATEMENT_ID = '…'` (30 characters at most).
_STATEMENT_ID = re.compile(r"[A-Za-z0-9_-]{1,30}")


def _code(exc: oracledb.Error) -> str:
    return str(getattr(exc.args[0], "full_code", "")) if exc.args else ""


def _message(exc: oracledb.Error) -> str:
    """The server's text without the `Help:` link lines."""
    raw = str(getattr(exc.args[0], "message", "")) if exc.args else ""
    lines = [line for line in raw.splitlines() if line.strip() and not line.startswith("Help:")]
    return "\n".join(lines) or type(exc).__name__


def _translate(exc: oracledb.Error) -> Exception:
    """A failure while a statement runs or a result is read."""
    code = _code(exc)
    if code in DEAD_CODES:
        return SessionDead(f"the Oracle session is gone ({code})")
    if code in TIMEOUT_CODES:
        return TimeoutError(f"Oracle stopped the call at its timeout ({code})")
    if isinstance(exc, oracledb.DatabaseError) and code.startswith("ORA-"):
        return StatementError(_message(exc))
    return UpstreamFailure(f"Oracle {type(exc).__name__} {code}: {_message(exc)}".strip())


def _output_type_handler(cursor: oracledb.Cursor, metadata: oracledb.FetchInfo) -> object:
    """NUMBER arrives as `Decimal` (never a float)."""
    if metadata.type_code is oracledb.DB_TYPE_NUMBER:
        return cursor.var(Decimal, arraysize=cursor.arraysize)
    return None


class OracleStatement:
    def __init__(
        self, cursor: oracledb.Cursor, using: Callable[[], contextlib.AbstractContextManager[None]]
    ) -> None:
        self._cursor = cursor
        self._using = using
        description: list[Any] = cursor.description or []
        self._names = [str(d.name) for d in description]
        self._type_names = [str(d.type_code.name) for d in description]
        self._kinds: list[ColumnType] = [
            column_type(t, d.precision, d.scale)
            for t, d in zip(self._type_names, description, strict=True)
        ]
        self.columns: Sequence[Column] = [
            Column(name, kind) for name, kind in zip(self._names, self._kinds, strict=True)
        ]
        #: A row with a LOB is fetched alone and its LOBs are read before the next row.
        self._lobs = any(
            t in ("DB_TYPE_CLOB", "DB_TYPE_NCLOB", "DB_TYPE_BLOB", "DB_TYPE_BFILE")
            for t in self._type_names
        )

    @property
    def rowcount(self) -> int | None:
        count = self._cursor.rowcount
        return count if count >= 0 else None

    def fetch(self, size: int, budget: int) -> Sequence[Sequence[Cell]]:
        with self._using():
            try:
                rows: list[Any] = self._cursor.fetchmany(1 if self._lobs else size)
                return [
                    encode_row(row, self._kinds, self._type_names, self._names, budget)
                    for row in rows
                ]
            except oracledb.Error as exc:
                raise _translate(exc) from None

    def close(self) -> None:
        with contextlib.suppress(SessionDead), self._using():
            self._cursor.close()


class OracleSession:
    """One connection. Every blocking call on it holds `_lock`, so `abandon`, which runs in a
    disposal thread, never drops the connection under a call that is still inside it."""

    def __init__(self, conn: oracledb.Connection, own_schema: str) -> None:
        self._conn = conn
        self._own_schema = own_schema
        self._lock = threading.Lock()
        self._abandoned = False

    @contextlib.contextmanager
    def _using(self) -> Generator[None]:
        with self._lock:
            if self._abandoned:
                raise SessionDead("the Oracle session was abandoned")
            yield

    def run(
        self,
        sql: str,
        params: Sequence[object] | Mapping[str, object],
        *,
        timeout: float,
        tag: str,
        op: str,
        schema: str | None,
    ) -> Statement:
        assert isinstance(params, Mapping)
        with self._using():
            conn = self._conn
            cursor = conn.cursor()
            try:
                conn.call_timeout = max(1, math.ceil(timeout * 1000))
                conn.module = "modgudr"
                conn.action = op
                conn.client_identifier = tag
                conn.current_schema = schema if schema is not None else self._own_schema
                binds = dict(params) or None
                if op == "plan":
                    self._explain(cursor, sql, binds, tag)
                else:
                    if op != "write":
                        cursor.execute("SET TRANSACTION READ ONLY")
                    cursor.execute(sql, binds)
                return OracleStatement(cursor, self._using)
            except oracledb.Error as exc:
                cursor.close()
                raise _translate(exc) from None
            except BaseException:
                cursor.close()
                raise

    @staticmethod
    def _explain(
        cursor: oracledb.Cursor, sql: str, binds: dict[str, object] | None, tag: str
    ) -> None:
        """`EXPLAIN PLAN` and the `DBMS_XPLAN` read on one connection, outside a read-only
        transaction. The audit id is the `STATEMENT_ID`, so concurrent plans never mix."""
        if not _STATEMENT_ID.fullmatch(tag):
            raise ValueError("the audit id cannot be a plan STATEMENT_ID")
        cursor.execute(f"EXPLAIN PLAN SET STATEMENT_ID = '{tag}' FOR {sql}", binds)
        cursor.execute(
            "SELECT plan_table_output FROM TABLE(DBMS_XPLAN.DISPLAY(NULL, :statement_id, "
            "'TYPICAL'))",
            {"statement_id": tag},
        )

    def _reset(self) -> None:
        """Tags and schema go back to the login's own before the closing round trip carries them
        to the server, so a pooled session shows nothing of the call that left it."""
        conn: Any = self._conn  # the stubs do not allow None, which clears a tag
        conn.module = None
        conn.action = None
        conn.client_identifier = None
        conn.current_schema = self._own_schema

    def commit(self) -> None:
        with self._using():
            try:
                self._reset()
                self._conn.commit()
            except oracledb.Error as exc:
                raise _translate(exc) from None

    def rollback(self) -> None:
        with self._using():
            try:
                self._reset()
                self._conn.rollback()
            except oracledb.Error as exc:
                raise _translate(exc) from None

    def close(self) -> None:
        with contextlib.suppress(SessionDead), self._using():
            self._conn.close()

    def abandon(self) -> None:
        """Break what runs from this thread (`connection.cancel()`), wait for that call to return,
        then drop the connection without a logoff round trip.

        `cancel()` is safe while another thread is inside the connection; `terminate()` is not:
        it closes the socket under the running call, which can crash the interpreter. So the
        drop waits for `_lock`. This runs in a disposal thread (`pool.dispose`), so the wait
        blocks nothing else; the call's `call_timeout` bounds it, and after `ABANDON_WARN`
        seconds a warning is logged.
        `close()` would talk to the server again and can fail on a connection that was just
        broken (`StopIteration`); `terminate()` of the implementation closes the socket at once,
        which frees the server session and any LOB locators. Errors are logged by type and never
        raised. Afterwards every call on the session raises `SessionDead`."""
        conn: Any = self._conn  # `terminate` is not on the sync stubs
        try:
            conn.cancel()
        except Exception as exc:
            log.warning("could not cancel the Oracle call: %s", type(exc).__name__)
        if not self._lock.acquire(timeout=ABANDON_WARN):
            log.warning(
                "the Oracle call has not returned %.0f s after its cancel; still waiting",
                ABANDON_WARN,
            )
            self._lock.acquire()
        try:
            self._abandoned = True
            conn._impl.terminate()
        except Exception as exc:
            log.warning("could not drop the Oracle session: %s", type(exc).__name__)
        finally:
            self._lock.release()


class OracleDriver:
    def __init__(self, config: SqlConfig) -> None:
        assert config.host is not None
        self._config = config
        self._host = config.host
        self._port = oracle_port(config)

    def destinations(self) -> frozenset[Destination]:
        return frozenset({Destination(self._host, self._port)})

    def connect(self, secret: str, *, timeout: float) -> OracleSession:
        if not oracledb.is_thin_mode():
            raise UpstreamFailure("the Oracle driver is in thick mode; modgudr runs thin mode only")
        params = connect_params(self._config, timeout)
        try:
            conn = oracledb.connect(params=params, password=secret)
        except oracledb.Error as exc:
            raise self._login_error(exc) from None
        except socket.gaierror:
            # Thin mode lets a failed name lookup through unwrapped; off the VPN, that is the
            # usual failure for a host only the VPN's DNS knows.
            raise UpstreamFailure(
                f"cannot resolve {self._host}; check that your VPN is up"
            ) from None
        except OSError:
            where = f"{self._host}:{self._port}"
            raise UpstreamFailure(f"cannot reach {where}; check that your VPN is up") from None
        try:
            conn.outputtypehandler = _output_type_handler
            cursor = conn.cursor()
            cursor.execute("SELECT SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA') FROM DUAL")
            row = cursor.fetchone()
            cursor.close()
            assert row is not None
            own_schema = str(row[0])
        except oracledb.Error as exc:
            conn.close()
            raise UpstreamFailure(f"Oracle login failed ({_code(exc)}): {_message(exc)}") from None
        return OracleSession(conn, own_schema)

    def _login_error(self, exc: oracledb.Error) -> Exception:
        """A failure while connecting, in the words of M16."""
        code = _code(exc)
        text = _message(exc)
        where = f"{self._host}:{self._port}"
        if code in FINAL_CODES:
            return AuthFailed(text, final=True)
        if code in AUTH_CODES:
            return AuthFailed(text)
        if "DPY-6001" in text or "ORA-12514" in text:
            return UpstreamFailure(
                f"the listener at {where} does not know the service {self._config.service!r}; "
                "check the target's `service` (or use `sid`)"
            )
        if "DPY-6003" in text or "ORA-12505" in text:
            return UpstreamFailure(
                f"the listener at {where} does not know the SID {self._config.sid!r}; "
                "check the target's `sid` (or use `service`)"
            )
        if code in UNREACHABLE_CODES:
            return UpstreamFailure(f"cannot reach {where}; check that your VPN is up")
        if code == "DPY-3001":
            return UpstreamFailure(
                "the database demands Native Network Encryption, which needs thick mode; "
                "modgudr runs thin mode only"
            )
        return UpstreamFailure(f"Oracle login failed ({code}): {text}")
