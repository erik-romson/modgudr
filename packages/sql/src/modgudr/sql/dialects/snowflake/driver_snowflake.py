# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false
"""The Snowflake driver adapter (M15): the only module that imports the connector.

Blocking calls, meant for worker threads. Every statement runs with a per-statement `QUERY_TAG`
(the audit id) and a `timeout`, never through `ALTER SESSION`. Library exceptions become the
ones in `modgudr.sql.driver`; a message of ours never holds a secret.
"""

from __future__ import annotations

import logging
import math
import os
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

import snowflake.connector
from snowflake.connector import errors

from modgudr.spi import AuthFailed, Cell, Column, ColumnType, Destination, UpstreamFailure
from modgudr.sql.driver import SessionDead, Statement, StatementError
from modgudr.sql.encode import encode_value

from .connect import PORT, KeyUnusable, connect_kwargs, private_key_der, snowflake_host
from .types import column_type

if TYPE_CHECKING:
    from modgudr.sql.config import SqlConfig

log = logging.getLogger("modgudr.broker")

#: 390100 incorrect username or password; 390144 the JWT was refused.
AUTH_ERRNOS = frozenset({390100, 390144})
#: 390102 the user is temporarily locked: never retried.
LOCKED_ERRNOS = frozenset({390102})
#: 390114 the session token expired; 390111 the session no longer exists.
DEAD_ERRNOS = frozenset({390114, 390111})
#: 604 the statement was cancelled by a timeout; 630 the statement timeout was reached.
TIMEOUT_ERRNOS = frozenset({604, 630})


def _message(exc: errors.Error) -> str:
    return str(exc.msg or exc).strip()


def _translate(exc: errors.Error) -> Exception:
    errno = exc.errno
    if errno in DEAD_ERRNOS:
        return SessionDead(f"the Snowflake session is gone (error {errno})")
    if errno in TIMEOUT_ERRNOS or exc.sqlstate == "57014":
        return TimeoutError(f"Snowflake stopped the statement at its timeout (error {errno})")
    if isinstance(exc, errors.ProgrammingError):
        return StatementError(f"Snowflake error {errno}: {_message(exc)}")
    return UpstreamFailure(f"Snowflake {type(exc).__name__} {errno}: {_message(exc)}")


class SnowflakeStatement:
    def __init__(self, cursor: snowflake.connector.cursor.SnowflakeCursor) -> None:
        self._cursor = cursor
        self.columns: Sequence[Column] = [
            Column(meta.name, column_type(meta.type_code, meta.scale))
            for meta in cursor.description or []
        ]

    @property
    def rowcount(self) -> int | None:
        count = self._cursor.rowcount
        return count if isinstance(count, int) and count >= 0 else None

    def fetch(self, size: int, budget: int) -> Sequence[Sequence[Cell]]:
        try:
            rows = self._cursor.fetchmany(size)
        except errors.Error as exc:
            raise _translate(exc) from None
        kinds: list[ColumnType] = [column.type for column in self.columns]
        return [
            [encode_value(value, kind) for value, kind in zip(row, kinds, strict=False)]
            for row in rows
        ]

    def close(self) -> None:
        self._cursor.close()


class SnowflakeSession:
    def __init__(
        self, conn: snowflake.connector.SnowflakeConnection, kwargs: dict[str, object]
    ) -> None:
        self._conn = conn
        self._kwargs = kwargs
        self._tag = ""
        self._timeout = 1.0

    def _execute(self, sql: str, params: Sequence[object], timeout: float, tag: str) -> Statement:
        self._tag, self._timeout = tag, timeout
        cursor = self._conn.cursor()
        try:
            cursor.execute(
                sql,
                params=tuple(params) if params else None,
                timeout=max(1, math.ceil(timeout)),
                _statement_params={"QUERY_TAG": tag},
            )
            return SnowflakeStatement(cursor)
        except errors.Error as exc:
            cursor.close()
            raise _translate(exc) from None
        except BaseException:
            cursor.close()
            raise

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
        assert not isinstance(params, Mapping) and schema is None
        return self._execute(sql, params, timeout, tag)

    def commit(self) -> None:
        self._execute("COMMIT", (), self._timeout, self._tag).close()

    def rollback(self) -> None:
        self._execute("ROLLBACK", (), self._timeout, self._tag).close()

    def close(self) -> None:
        self._conn.close()

    def abandon(self) -> None:
        """Cancel the session's queries from a short second connection when the session id is
        known, then close. Errors are logged by type and never raised (M15)."""
        try:
            session_id = getattr(self._conn, "session_id", None)
            if isinstance(session_id, int) and session_id > 0:
                other = snowflake.connector.connect(**self._kwargs)
                try:
                    other.cursor().execute(f"SELECT SYSTEM$CANCEL_ALL_QUERIES({int(session_id)})")
                finally:
                    other.close()
        except Exception as exc:
            log.warning("could not cancel the Snowflake session's queries: %s", type(exc).__name__)
        try:
            self._conn.close()
        except Exception as exc:
            log.warning("could not close the Snowflake session: %s", type(exc).__name__)


class SnowflakeDriver:
    def __init__(self, config: SqlConfig) -> None:
        assert config.account is not None
        self._config = config
        self._host = snowflake_host(config.account)

    def destinations(self) -> frozenset[Destination]:
        return frozenset({Destination(self._host, PORT)})

    def connect(self, secret: str, *, timeout: float) -> SnowflakeSession:
        try:
            der = private_key_der(secret)
        except KeyUnusable as exc:
            raise UpstreamFailure(f"the Snowflake private key cannot be used: {exc}") from None
        kwargs = connect_kwargs(self._config, der, timeout)
        os.environ["SF_TELEMETRY_DISABLE_CONNECTION_SHAPE"] = "true"
        try:
            conn = snowflake.connector.connect(**kwargs)
        except errors.Error as exc:
            if exc.errno in LOCKED_ERRNOS:
                raise AuthFailed(_message(exc), final=True) from None
            if exc.errno in AUTH_ERRNOS:
                raise AuthFailed(_message(exc)) from None
            raise UpstreamFailure(
                f"Snowflake login failed ({type(exc).__name__} {exc.errno}): {_message(exc)}"
            ) from None
        return SnowflakeSession(conn, kwargs)
