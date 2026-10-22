"""Helpers for the Oracle tests: a disposable Oracle Free container driven through the `docker`
CLI, its schema, a driver spy and the policy of the in-process broker.

Nothing here reaches anything but the container on 127.0.0.1 (and a free local port for the
"nothing listening" case). All passwords are generated per session.
"""

from __future__ import annotations

import socket
import subprocess
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from secrets import token_hex
from typing import Any

import oracledb

from tests.support.brokerfx import BrokerEnv, make_env

IMAGE = "gvenzl/oracle-free:23-slim-faststart"
LABEL = "modgudr-test=1"
SERVICE = "FREEPDB1"
SID = "FREE"
HOST = "127.0.0.1"
NOT_AVAILABLE = "Docker or the Oracle Free image is not available (see Before running B3)"

#: Passwords of the fixture's users, generated per session.
USERS = ("SYSTEM", "APP", "APP_RO", "APP_RW", "C##MG_SID", "MG_LOCKED")


def docker(*args: str, timeout: float = 120.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout, check=False
    )


def require_docker() -> None:
    """The stop condition of step 16: Docker answers and the image is present. Never pulls."""
    try:
        info = docker("info", timeout=60.0)
        image = docker("image", "inspect", IMAGE, timeout=60.0)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"{NOT_AVAILABLE}: {type(exc).__name__}") from None
    if info.returncode != 0 or image.returncode != 0:
        raise RuntimeError(NOT_AVAILABLE)


def remove_leftovers() -> None:
    found = docker("ps", "-aq", "--filter", f"label={LABEL}").stdout.split()
    if found:
        docker("rm", "-f", *found)


def free_port() -> int:
    """A local port with nothing listening on it (it was free a moment ago)."""
    with socket.socket() as sock:
        sock.bind((HOST, 0))
        return int(sock.getsockname()[1])


@dataclass
class OracleDb:
    name: str
    port: int
    passwords: dict[str, str]

    def connect(self, user: str = "SYSTEM", **kw: str) -> oracledb.Connection:
        """A connection of the test itself, as a bystander of the broker."""
        params = oracledb.ConnectParams(
            host=HOST, port=self.port, tcp_connect_timeout=10, retry_count=0, **kw
        )
        return oracledb.connect(params=params, user=user, password=self.passwords[user])

    def system(self) -> oracledb.Connection:
        return self.connect("SYSTEM", service_name=SERVICE)

    def query(self, sql: str, **binds: object) -> list[tuple[Any, ...]]:
        conn = self.system()
        try:
            cur = conn.cursor()
            cur.execute(sql, binds or None)
            return [tuple(row) for row in cur.fetchall()]
        finally:
            conn.close()

    def execute(self, sql: str) -> None:
        conn = self.system()
        try:
            conn.cursor().execute(sql)
        finally:
            conn.close()

    def po(self) -> list[tuple[Any, ...]]:
        return self.query("select id, status, buyer from app.po order by id")


def start() -> OracleDb:
    """Start a container, wait until it is ready and build the schema as SYSTEM."""
    require_docker()
    remove_leftovers()
    passwords = {user: f"Pw_{token_hex(10)}" for user in USERS}
    name = f"modgudr-oracle-{uuid.uuid4().hex[:8]}"
    # The image declares no EXPOSE, so -P publishes nothing: map the listener port explicitly.
    run = docker(
        "run", "-d", "--rm", "-p", f"{HOST}::1521",
        "-e", f"ORACLE_PASSWORD={passwords['SYSTEM']}",
        "-e", "APP_USER=APP",
        "-e", f"APP_USER_PASSWORD={passwords['APP']}",
        "--label", LABEL, "--name", name, IMAGE,
    )  # fmt: skip
    if run.returncode != 0:
        raise RuntimeError(f"docker run failed: {run.stderr.strip()}")
    try:
        _wait_ready(name)
        port = int(
            docker("port", name, "1521/tcp").stdout.strip().splitlines()[0].rsplit(":", 1)[1]
        )
        db = OracleDb(name, port, passwords)
        _setup(db)
        return db
    except BaseException:
        docker("rm", "-f", name)
        raise


def stop(db: OracleDb) -> None:
    docker("rm", "-f", db.name)


def _wait_ready(name: str, timeout: float = 600.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        logs = docker("logs", name)
        if "DATABASE IS READY TO USE!" in logs.stdout + logs.stderr:
            return
        if docker("ps", "-q", "--filter", f"name={name}").stdout.strip() == "":
            raise RuntimeError(f"the Oracle container {name} stopped before it was ready")
        time.sleep(2.0)
    raise RuntimeError(f"the Oracle container {name} was not ready after {timeout:g} s")


def _setup(db: OracleDb) -> None:
    pw = db.passwords
    conn = db.system()
    try:
        cur = conn.cursor()
        for statement in (
            "create table app.po (id number(10) primary key, status varchar2(10), "
            "buyer varchar2(30), amount number(10,2), note varchar2(40))",
            f'create user app_ro identified by "{pw["APP_RO"]}"',
            "grant create session to app_ro",
            "grant select on app.po to app_ro",
            "create view app.v_po as select id, status from app.po",
            "grant select on app.v_po to app_ro",
            f'create user app_rw identified by "{pw["APP_RW"]}"',
            "grant create session to app_rw",
            f'create user mg_locked identified by "{pw["MG_LOCKED"]}" account lock',
            "grant create session to mg_locked",
            "grant select, insert, update, delete on app.po to app_rw",
            "create function app.f_side return number is begin "
            "insert into app.po (id, status) values (999, 'SIDE'); return 1; end;",
            "grant execute on app.f_side to app_ro",
            "create table app.lobs (id number, kind varchar2(20), c clob, b blob)",
            "grant select on app.lobs to app_ro",
        ):
            cur.execute(statement)
        for i, (status, buyer, amount) in enumerate(
            [
                ("OPEN", "acme", 10.5),
                ("OPEN", "beta", 1.5),
                ("OPEN", "gamma", 0),
                ("DONE", "delta", 7),
            ],
            start=1,
        ):
            cur.execute(
                "insert into app.po (id, status, buyer, amount) values (:1, :2, :3, :4)",
                [i, status, buyer, amount],
            )
        conn.commit()
        cur.execute(LOBS)
        conn.commit()
    finally:
        conn.close()
    root = db.connect("SYSTEM", sid=SID)
    try:
        cur = root.cursor()
        cur.execute(f'create user c##mg_sid identified by "{pw["C##MG_SID"]}" container=all')
        cur.execute("grant create session to c##mg_sid container=all")
    finally:
        root.close()


#: APP.LOBS, built with DBMS_LOB.APPEND: 32 MiB of CLOB and of BLOB (row 1), a CLOB of 1 Mi
#: three-byte characters (row 2) and 1 KiB ones (row 3).
LOBS = """
declare
  c clob; b blob; piece varchar2(32000); rawp raw(32000);
  procedure add_row(p_id number, p_kind varchar2, p_c clob, p_b blob) is
  begin insert into app.lobs values (p_id, p_kind, p_c, p_b); end;
begin
  dbms_lob.createtemporary(c, true);
  dbms_lob.createtemporary(b, true);
  piece := rpad('x', 16384, 'x');
  rawp := utl_raw.copies(hextoraw('AB'), 16384);
  for i in 1..2048 loop
    dbms_lob.append(c, to_clob(piece));
    dbms_lob.append(b, to_blob(rawp));
  end loop;
  add_row(1, 'big', c, b);
  dbms_lob.trim(c, 0);
  piece := rpad(unistr('\\20AC'), 8192, unistr('\\20AC'));
  for i in 1..128 loop dbms_lob.append(c, to_clob(piece)); end loop;
  add_row(2, 'euro', c, to_blob(hextoraw('00')));
  dbms_lob.trim(c, 0);
  dbms_lob.append(c, to_clob(rpad('y', 1024, 'y')));
  add_row(3, 'small', c, to_blob(utl_raw.copies(hextoraw('CD'), 1024)));
end;
"""

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


def _target(
    name: str,
    *,
    system: str,
    env: str = "test",
    user: str = "APP_RO",
    secret: str = "ora-ro",
    port: int,
    key: str = f"service: {SERVICE}",
    extra: str = "",
) -> str:
    return f"""\
  {name}:
    type: sql
    system: {system}
    env: {env}
    dialect: oracle
    host: {HOST}
    port: {port}
    {key}
    user: {user}
    secret: file:{secret}
    credential: {{ tier: dedicated }}
{extra}"""


def targets(db: OracleDb, dead_port: int) -> str:
    port = db.port
    return "targets:\n" + "".join(
        [
            _target("ora-test", system="ora", port=port),
            _target("ora-prod", system="ora", env="prod", port=port),
            _target(
                "ora-sid",
                system="orasid",
                user="C##MG_SID",
                secret="ora-sid",
                port=port,
                key=f"sid: {SID}",
            ),
            _target("ora-rw", system="orarw", user="APP_RW", secret="ora-rw", port=port),
            _target(
                "ora-rw-prod",
                system="orarw",
                env="prod",
                user="APP_RW",
                secret="ora-rw",
                port=port,
            ),
            _target("ora-one", system="oraone", port=port, extra="    maxConcurrent: 1\n"),
            _target("ora-fast", system="orafast", port=port, extra="    timeout: 1s\n"),
            _target("ora-bad", system="orabad", secret="ora-bad", port=port),
            _target("ora-down", system="oradown", port=dead_port),
            _target("ora-nosvc", system="oranosvc", port=port, key="service: NOSUCHSVC"),
            _target("ora-nosid", system="oranosid", port=port, key="sid: NOSUCH"),
            _target(
                "ora-locked", system="oralocked", user="MG_LOCKED", secret="ora-locked", port=port
            ),
        ]
    )


def secrets(db: OracleDb, dead_port: int) -> dict[str, dict[str, object]]:
    hosts = [f"{HOST}:{db.port}"]
    pw = db.passwords
    return {
        "ora-ro": {"value": pw["APP_RO"], "hosts": [*hosts, f"{HOST}:{dead_port}"]},
        "ora-rw": {"value": pw["APP_RW"], "hosts": hosts},
        "ora-sid": {"value": pw["C##MG_SID"], "hosts": hosts},
        "ora-locked": {"value": pw["MG_LOCKED"], "hosts": hosts},
        "ora-bad": {"value": "wrong-" + token_hex(6), "hosts": hosts},
    }


def ora_env(root: Path, db: OracleDb, **kw: object) -> BrokerEnv:
    dead = free_port()
    return make_env(
        root,
        company=COMPANY,
        targets=targets(db, dead),
        secrets=secrets(db, dead),
        **kw,
    )


@dataclass
class Spy:
    """Records what reaches the driver: every `oracledb.connect`, `Connection.cancel`
    and `LOB.read`."""

    connects: list[dict[str, Any]] = field(default_factory=list[dict[str, Any]])
    cancels: int = 0
    reads: list[tuple[int, int]] = field(default_factory=list[tuple[int, int]])
    #: Called with the offset and amount before a LOB read; may block.
    before_read: Callable[[int, int], None] | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)

    def logins(self) -> list[dict[str, Any]]:
        """The broker's logins: the test's own connections name the user as an argument."""
        return [c for c in self.connects if "password" in c and "user" not in c]


@contextmanager
def spying() -> Iterator[Spy]:
    spy = Spy()
    real_connect = oracledb.connect
    real_cancel = oracledb.Connection.cancel
    real_read = oracledb.LOB.read

    def connect(*args: object, **kwargs: object) -> object:
        with spy.lock:
            spy.connects.append(dict(kwargs))
        return real_connect(*args, **kwargs)  # type: ignore[arg-type]

    def cancel(self: oracledb.Connection) -> object:
        with spy.lock:
            spy.cancels += 1
        return real_cancel(self)

    def read(self: oracledb.LOB, offset: int = 1, amount: int | None = None) -> object:
        with spy.lock:
            spy.reads.append((offset, amount or 0))
        if spy.before_read is not None:
            spy.before_read(offset, amount or 0)
        return real_read(self, offset, amount)

    oracledb.connect = connect  # type: ignore[assignment]
    oracledb.Connection.cancel = cancel  # type: ignore[method-assign]
    oracledb.LOB.read = read  # type: ignore[method-assign]
    try:
        yield spy
    finally:
        oracledb.connect = real_connect  # type: ignore[assignment]
        oracledb.Connection.cancel = real_cancel  # type: ignore[method-assign]
        oracledb.LOB.read = real_read  # type: ignore[method-assign]


Frames = list[dict[str, Any]]


async def run(env: BrokerEnv, op: str, target: str = "ora-test", **args: object) -> Frames:
    from tests.support.brokerfx import call

    return await call(env.agent_socket, op, target, args=args)  # type: ignore[return-value]


def rows(frames: Frames) -> list[list[Any]]:
    return [f["v"] for f in frames if f["t"] == "row"]


def trailer(frames: Frames) -> dict[str, Any]:
    assert frames[-1]["t"] == "trailer", frames
    return frames[-1]


def param(kind: str, value: object) -> dict[str, object]:
    return {"t": kind, "v": value}


def completion(env: BrokerEnv) -> dict[str, Any]:
    from tests.support.brokerfx import read_audit

    return [r for r in read_audit(env.audit_dir) if r.get("type") == "completion"][-1]
