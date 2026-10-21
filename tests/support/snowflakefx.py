"""Helpers for the Snowflake tests: fakesnow, a driver spy, a generated key and a policy.

fakesnow's `patch()` replaces `snowflake.connector.connect` for the whole process, so a broker
running in this process (a thread, or the test's own loop) talks to an in-memory DuckDB. Nothing
here reaches a network or a real account.
"""

from __future__ import annotations

import functools
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import fakesnow
import snowflake.connector
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fakesnow.conn import FakeSnowflakeConnection
from fakesnow.cursor import FakeSnowflakeCursor

from tests.support.brokerfx import BrokerEnv, make_env

HOST = "acme-example.snowflakecomputing.com"

COMPANY = """\
store:
  default: file
defaults:
  env: test
  timeout: 30s
  maxRows: 500
  maxRowsHard: 50000
  maxBytes: 2MiB
  maxRequestBytes: 1MiB
  maxConcurrent: 4
environments:
  test:
    ceiling: destructive
    sql:
      allow: [write, delete]
      constraints:
        update: { requireWhere: true, maxAffectedRows: 2 }
        delete: { requireWhere: true, maxAffectedRows: 2 }
  prod:
    ceiling: read
"""


def _target(name: str, env: str, extra: str = "") -> str:
    return f"""\
  {name}:
    type: sql
    system: sf
    env: {env}
    dialect: snowflake
    account: acme-example
    user: APP_RO
    role: APP_RO_ROLE
    warehouse: APP_WH
    database: APPDB
    schema: PUBLIC
    secret: file:sf-key
    credential: {{ tier: dedicated }}
{extra}"""


TARGETS = "targets:\n" + _target("sf-test", "test") + _target("sf-prod", "prod")

#: Targets for the pool tests: one slot only.
TARGETS_ONE = "targets:\n" + _target("sf-test", "test", "    maxConcurrent: 1\n")


@functools.cache
def private_key_pem() -> str:
    """A generated RSA key as unencrypted PKCS#8 PEM. Not a secret of anyone's."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def secrets(pem: str | None = None) -> dict[str, dict[str, object]]:
    return {"sf-key": {"value": pem or private_key_pem(), "hosts": [f"{HOST}:443"]}}


def sf_env(
    root: Path, *, targets: str = TARGETS, company: str = COMPANY, **kw: object
) -> BrokerEnv:
    return make_env(root, company=company, targets=targets, secrets=secrets(), **kw)


SEED = (
    "create or replace table po (id number(38,0), status varchar, buyer varchar, "
    "amount number(10,2), doc variant, seen timestamp_tz, raw binary, flag boolean, "
    "created date)",
    "insert into po select 1, 'OPEN', 'acme', 10.50, parse_json('{\"a\": [1, 2]}'), "
    "'2026-10-01 10:00:00 +02:00'::timestamp_tz, to_binary('cafe', 'HEX'), true, "
    "'2026-10-02'::date",
    "insert into po select 2, 'OPEN', 'beta', 1.5, null, null, null, false, '2026-09-01'::date",
    "insert into po select 3, 'OPEN', 'gamma', 0, null, null, null, null, null",
    "insert into po select 4, 'DONE', 'delta', 7, null, null, null, null, null",
)


def seed() -> None:
    conn = snowflake.connector.connect(database="APPDB", schema="PUBLIC")
    try:
        cur = conn.cursor()
        for sql in SEED:
            cur.execute(sql)
    finally:
        conn.close()


def table_rows(sql: str = "select id, buyer from po order by id") -> list[tuple[Any, ...]]:
    """Read the fake database directly, as a bystander (the broker is not involved)."""
    conn = snowflake.connector.connect(database="APPDB", schema="PUBLIC")
    try:
        cur = conn.cursor()
        cur.execute(sql)
        return [tuple(row) for row in cur.fetchall()]
    finally:
        conn.close()


@dataclass
class Spy:
    """Records what reaches the driver: every `connect` and every `cursor.execute`."""

    connects: list[dict[str, Any]] = field(default_factory=list[dict[str, Any]])
    executes: list[dict[str, Any]] = field(default_factory=list[dict[str, Any]])
    #: Called with the statement text before it runs; may block (a slow query) or raise (a
    #: driver failure).
    before: Callable[[str], None] | None = None
    #: Called with the statement text after it ran; may block (the answer is slow to arrive).
    after: Callable[[str], None] | None = None
    #: Raised by `connect` instead of connecting, to fake a login failure.
    connect_error: Callable[[], Exception] | None = None
    #: How many times `close` ran on a connection that this spy saw.
    closes: int = 0

    def tagged(self) -> list[dict[str, Any]]:
        """The statements the connector ran (they carry `_statement_params`); a test's own
        bystander reads do not."""
        return [e for e in self.executes if "_statement_params" in e["kwargs"]]

    def statements(self) -> list[str]:
        return [str(e["sql"]) for e in self.tagged()]

    def logins(self) -> list[dict[str, Any]]:
        """The `connect` calls of the broker (they name an authenticator)."""
        return [c for c in self.connects if "authenticator" in c]


@contextmanager
def fake_snowflake() -> Iterator[Spy]:
    """fakesnow patched in, the table `po` seeded, and a spy on connect and execute."""
    spy = Spy()
    with fakesnow.patch():
        seed()
        real_connect = snowflake.connector.connect

        def connect(*args: object, **kwargs: object) -> object:
            spy.connects.append(dict(kwargs))
            if spy.connect_error is not None and "authenticator" in kwargs:
                raise spy.connect_error()
            return real_connect(*args, **kwargs)

        real_execute = FakeSnowflakeCursor.execute
        real_close = FakeSnowflakeConnection.close

        def execute(
            self: FakeSnowflakeCursor,
            command: object,
            params: object = None,
            *args: object,
            **kwargs: object,
        ) -> object:
            if spy.before is not None:
                spy.before(str(command))
            spy.executes.append({"sql": command, "params": params, "kwargs": dict(kwargs)})
            result = real_execute(self, command, params, *args, **kwargs)
            if spy.after is not None:
                spy.after(str(command))
            return result

        def close(self: FakeSnowflakeConnection, *args: object, **kwargs: object) -> object:
            spy.closes += 1
            return real_close(self, *args, **kwargs)

        snowflake.connector.connect = connect
        FakeSnowflakeCursor.execute = execute  # type: ignore[method-assign]
        FakeSnowflakeConnection.close = close  # type: ignore[method-assign]
        try:
            yield spy
        finally:
            snowflake.connector.connect = real_connect
            FakeSnowflakeCursor.execute = real_execute  # type: ignore[method-assign]
            FakeSnowflakeConnection.close = real_close  # type: ignore[method-assign]


def args_of(**kwargs: object) -> Mapping[str, object]:
    return kwargs
