"""Broker lifecycle: directories, the lock, binding, stale and live sockets, the watchdog,
start-up refusals, the lifecycle records and SIGTERM draining."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import signal
import socket
import stat
from dataclasses import dataclass
from pathlib import Path

import pytest

from modgudr.broker import daemon
from modgudr.broker.app import Broker, BrokerConfig, build
from modgudr.broker.server import (
    MAX_SOCKET_PATH_BYTES,
    StartError,
    bind_listen,
    check_socket_path,
    ensure_private_dir,
)
from tests.support.brokerfx import (
    COMPANY,
    BrokerEnv,
    call,
    error,
    line,
    make_env,
    read_audit,
    request,
    result_data,
    running,
    unlock,
    wait_for,
)


def stale_socket(path: Path) -> int:
    """A socket file nobody listens on: bound, then closed without unlinking."""
    path.parent.mkdir(parents=True, exist_ok=True)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(os.fspath(path))
    sock.close()
    return os.lstat(path).st_ino


# --- directories -------------------------------------------------------------------------------


@dataclass
class FakeStat:
    st_uid: int
    st_mode: int


def test_a_wider_directory_of_ours_is_tightened_with_a_warning(shortdir: Path) -> None:
    run = shortdir / "run"
    run.mkdir()
    run.chmod(0o755)
    warnings: list[str] = []
    ensure_private_dir(run, uid=os.getuid(), warn=warnings.append)
    assert stat.S_IMODE(run.stat().st_mode) == 0o700
    assert warnings == [f"tightened {run} from 0755 to 0700"]


def test_a_missing_directory_is_created_0700(shortdir: Path) -> None:
    deep = shortdir / "a" / "b" / "run"
    ensure_private_dir(deep, uid=os.getuid(), warn=pytest.fail)
    for path in (shortdir / "a", shortdir / "a" / "b", deep):
        assert stat.S_IMODE(path.stat().st_mode) == 0o700


def test_a_foreign_owner_is_refused(shortdir: Path) -> None:
    run = shortdir / "run"
    run.mkdir(mode=0o700)

    def lstat(path: Path) -> FakeStat:
        return FakeStat(os.getuid() + 1, stat.S_IFDIR | 0o700)

    with pytest.raises(StartError, match=r"owned by uid \d+, not by this user"):
        ensure_private_dir(run, uid=os.getuid(), warn=pytest.fail, lstat=lstat)


def test_a_symlinked_directory_is_refused(shortdir: Path) -> None:
    real = shortdir / "real"
    real.mkdir(mode=0o700)
    link = shortdir / "run"
    link.symlink_to(real)
    with pytest.raises(StartError, match="is a symlink"):
        ensure_private_dir(link, uid=os.getuid(), warn=pytest.fail)


def test_a_file_where_a_directory_belongs_is_refused(shortdir: Path) -> None:
    (shortdir / "run").write_text("")
    with pytest.raises(StartError, match="is not a directory"):
        ensure_private_dir(shortdir / "run", uid=os.getuid(), warn=pytest.fail)


async def test_start_tightens_the_run_directory(shortdir: Path) -> None:
    env = make_env(shortdir)
    (env.home / "run").mkdir(parents=True)
    env.home.chmod(0o700)
    (env.home / "run").chmod(0o755)
    async with running(env):
        assert stat.S_IMODE((env.home / "run").stat().st_mode) == 0o700
    assert f"tightened {env.home / 'run'} from 0755 to 0700" in env.stderr.getvalue()


# --- binding -----------------------------------------------------------------------------------


def test_a_socket_is_0600_right_after_bind_whatever_the_umask(shortdir: Path) -> None:
    old = os.umask(0)
    try:
        bound = bind_listen(shortdir / "x.sock")
    finally:
        os.umask(old)
    try:
        assert stat.S_IMODE(os.lstat(bound.path).st_mode) == 0o600
        assert os.umask(old) == old
    finally:
        bound.sock.close()


async def test_both_sockets_are_0600(shortdir: Path) -> None:
    env = make_env(shortdir)
    async with running(env):
        for path in (env.agent_socket, env.human_socket):
            st = os.lstat(path)
            assert stat.S_ISSOCK(st.st_mode)
            assert stat.S_IMODE(st.st_mode) == 0o600


def test_a_socket_path_over_103_bytes_is_an_error(shortdir: Path) -> None:
    def path_of(size: int) -> Path:
        return shortdir / ("s" * (size - len(os.fsencode(shortdir)) - 1))

    check_socket_path(path_of(MAX_SOCKET_PATH_BYTES))
    with pytest.raises(StartError, match=r"socket path too long \(104 bytes, limit 103\)"):
        check_socket_path(path_of(104))


async def test_a_broker_with_a_long_socket_path_refuses_and_leaves_nothing(shortdir: Path) -> None:
    long_dir = shortdir / ("d" * 60)
    env = make_env(shortdir, agent_socket=long_dir / ("s" * 40) / "agent.sock")
    broker = build(env.config)
    with pytest.raises(StartError, match="socket path too long"):
        await broker.start()
    assert not env.human_socket.exists()
    assert not read_audit(env.audit_dir)


async def test_stale_sockets_are_unlinked_and_rebound(shortdir: Path) -> None:
    env = make_env(shortdir)
    env.home.mkdir(mode=0o700)
    old = {path: stale_socket(path) for path in (env.agent_socket, env.human_socket)}
    async with running(env):
        for path, inode in old.items():
            assert os.lstat(path).st_ino != inode
        assert result_data(await call(env.agent_socket, "status"))["channel"] == "agent"
        assert result_data(await call(env.human_socket, "status"))["channel"] == "human"


async def test_a_second_broker_exits_78_and_the_first_keeps_serving(shortdir: Path) -> None:
    env = make_env(shortdir)
    async with running(env):
        inodes = [os.lstat(p).st_ino for p in (env.agent_socket, env.human_socket)]
        err = io.StringIO()
        assert await daemon.run(env.config, stderr=err) == 78
        assert "already running" in err.getvalue()
        assert [os.lstat(p).st_ino for p in (env.agent_socket, env.human_socket)] == inodes
        assert result_data(await call(env.agent_socket, "status"))["state"] == "locked"
        assert result_data(await call(env.human_socket, "status"))["state"] == "locked"
    assert [r["type"] for r in read_audit(env.audit_dir)] == ["broker.start", "broker.stop"]


async def test_a_live_agent_socket_of_another_home_refuses_start(shortdir: Path) -> None:
    env = make_env(shortdir)
    async with running(env):
        other = BrokerConfig(
            **{**vars(env.config), "home": shortdir / "h2", "audit_dir": shortdir / "h2" / "a"}
        )
        broker = build(other)
        with pytest.raises(StartError, match="a broker is listening on"):
            await broker.start()
        assert not (shortdir / "h2" / "run" / "human.sock").exists()
        assert result_data(await call(env.agent_socket, "status"))["state"] == "locked"


async def test_a_failure_after_the_first_bind_leaves_no_socket(shortdir: Path) -> None:
    env = make_env(shortdir)
    env.human_socket.parent.mkdir(parents=True, mode=0o700)
    env.home.chmod(0o700)
    env.human_socket.write_text("not a socket")
    broker = build(env.config)
    with pytest.raises(StartError, match="is not a socket"):
        await broker.start()
    assert not env.agent_socket.exists()
    env.human_socket.unlink()
    # The lock was released: a new broker starts.
    async with running(env):
        pass


async def test_a_deleted_socket_is_bound_again(shortdir: Path) -> None:
    env = make_env(shortdir, watchdog_interval=0.05)
    async with running(env):
        env.agent_socket.unlink()
        await wait_for(env.agent_socket.exists, timeout=3)
        assert result_data(await call(env.agent_socket, "status"))["channel"] == "agent"
        assert stat.S_IMODE(os.lstat(env.agent_socket).st_mode) == 0o600
    assert "was deleted; bound it again" in env.stderr.getvalue()
    assert not env.agent_socket.exists()


# --- start-up refusals and records -------------------------------------------------------------


def test_policy_errors_refuse_start(shortdir: Path) -> None:
    env = make_env(shortdir, company=COMPANY.replace("ceiling: read", "ceiling: nonsense"))
    with pytest.raises(StartError, match="the policy cannot be loaded"):
        build(env.config)


def test_without_dev_the_company_file_must_be_root_owned(shortdir: Path) -> None:
    env = make_env(shortdir, dev=False)
    with pytest.raises(StartError, match="must be owned by root"):
        build(env.config)


@pytest.mark.parametrize(
    "store",
    ["store:\n  default: bws\n", "store:\n  default: file\n  bws: { project: p-1 }\n"],
    ids=["default", "configured"],
)
def test_dev_mode_refuses_the_bws_store(shortdir: Path, store: str) -> None:
    company = COMPANY.replace("store:\n  default: file\n", store)
    env = make_env(shortdir, company=company)
    with pytest.raises(StartError, match="dev mode refuses the bws store"):
        build(env.config)


async def test_a_bad_secrets_file_refuses_start(shortdir: Path) -> None:
    env = make_env(shortdir)
    env.secrets_file.chmod(0o644)
    with pytest.raises(StartError, match="must be 0600"):
        await build(env.config).start()
    assert not env.agent_socket.exists()


async def test_an_unwritable_audit_dir_refuses_start(shortdir: Path) -> None:
    parent = shortdir / "ro"
    parent.mkdir(mode=0o500)
    env = make_env(shortdir, audit_dir=parent / "audit")
    try:
        with pytest.raises(StartError, match="not writable"):
            await build(env.config).start()
    finally:
        parent.chmod(0o700)
    assert not env.agent_socket.exists()
    assert not env.human_socket.exists()


async def test_dev_mode_banner_and_stamps(shortdir: Path) -> None:
    env = make_env(shortdir)
    async with running(env):
        await unlock(env)
        await call(env.agent_socket, "echo", "echo-test", args={"text": "x"})
        assert result_data(await call(env.agent_socket, "status"))["dev"] is True
    assert "DEV MODE" in env.stderr.getvalue()
    lines = read_audit(env.audit_dir)
    assert [r["type"] for r in lines] == [
        "broker.start",
        "unlock",
        "decision",
        "completion",
        "lock",
        "broker.stop",
    ]
    assert {(r["dev"], r["store"], r["isolation"]) for r in lines} == {(True, "file", "none")}


async def test_broker_start_and_stop_records(shortdir: Path) -> None:
    env = make_env(shortdir)
    async with running(env):
        pass
    start, stop = read_audit(env.audit_dir)
    assert (start["type"], stop["type"]) == ("broker.start", "broker.stop")
    assert (start["dev"], start["store"], start["isolation"]) == (True, "file", "none")
    assert start["isolationReasons"]
    assert start["home"] == os.path.realpath(env.home)
    company = env.policy_dir / "00-company.yaml"
    assert start["policy"][0] == {
        "name": "00-company.yaml",
        "sha256": hashlib.sha256(company.read_bytes()).hexdigest(),
        "uid": os.getuid(),
        "mode": "0644",
    }
    plugins = {(p["group"], p["name"]): p for p in start["plugins"]}
    store = plugins[("modgudr.secret_stores", "file")]
    assert (store["distribution"], store["version"]) == ("modgudr-store-file", "0.1.0")
    assert len(str(store["recordSha256"])) == 64
    assert plugins[("modgudr.connectors", "echo")]["distribution"] is None


# --- SIGTERM -----------------------------------------------------------------------------------


async def test_sigterm_drains_in_flight_calls(shortdir: Path) -> None:
    env = make_env(shortdir)
    ready: asyncio.Future[Broker] = asyncio.get_running_loop().create_future()
    task = asyncio.create_task(daemon.run(env.config, on_ready=ready.set_result))
    await asyncio.wait_for(ready, 10)
    await unlock(env)
    reader, writer = await asyncio.open_unix_connection(os.fspath(env.agent_socket))
    writer.write(line(request("slow", "echo-test", args={"rows": 100, "delayMs": 50})))
    await writer.drain()
    while json.loads(await reader.readline())["t"] != "row":
        pass
    os.kill(os.getpid(), signal.SIGTERM)
    assert await asyncio.wait_for(task, 10) == 0
    frames = [json.loads(chunk) for chunk in (await reader.read()).splitlines()]
    writer.close()
    assert error(frames)["code"] == "unavailable"
    assert not env.agent_socket.exists()
    assert not env.human_socket.exists()
    lines = read_audit(env.audit_dir)
    completion = next(r for r in lines if r["type"] == "completion")
    assert (completion["outcome"], completion["cancelled"]) == ("cancelled", "shutdown")
    assert lines[-1]["type"] == "broker.stop"
    assert env.connector.targets["echo-test"].cancelled == ["slow"]
    assert env.connector.targets["echo-test"].closed
    # The lock is free again.
    async with running(env):
        pass


async def test_shutdown_closes_idle_connections(shortdir: Path) -> None:
    env = make_env(shortdir)
    broker = build(env.config)
    await broker.start()
    reader, writer = await asyncio.open_unix_connection(os.fspath(env.agent_socket))
    await asyncio.sleep(0.05)
    await asyncio.wait_for(broker.shutdown(), 5)
    assert await asyncio.wait_for(reader.read(), 5) == b""
    writer.close()


# --- the daemon's argv -------------------------------------------------------------------------


def test_daemon_usage_errors_exit_64(capsys: pytest.CaptureFixture[str]) -> None:
    assert daemon.main(["--nosuch"]) == 64
    assert "modgudr-broker" in capsys.readouterr().err


def test_config_from_the_environment(shortdir: Path) -> None:
    config = BrokerConfig.from_environment(
        {"MODGUDR_HOME": str(shortdir / "h"), "MODGUDR_SOCKET": str(shortdir / "a.sock")},
        dev=True,
        secrets_file=shortdir / "s.yaml",
    )
    assert config.home == shortdir / "h"
    assert config.human_socket == shortdir / "h" / "run" / "human.sock"
    assert config.agent_socket == shortdir / "a.sock"
    assert (config.policy_dir, config.audit_dir) == (
        shortdir / "h" / "policy.d",
        shortdir / "h" / "audit",
    )
    assert config.dev and config.secrets_file == shortdir / "s.yaml"
    with pytest.raises(StartError, match="too long"):
        BrokerConfig.from_environment({"MODGUDR_SOCKET": "/tmp/" + "x" * 120})


def test_managed_settings_default_to_the_production_location(env_config: BrokerConfig) -> None:
    base, dropin = BrokerConfig(
        home=Path("/h"), agent_socket=Path("/a"), policy_dir=Path("/p"), audit_dir=Path("/d")
    ).settings_paths()
    assert base.name == "managed-settings.json" and dropin.name == "managed-settings.d"
    assert env_config.settings_paths()[0].is_relative_to("/tmp")


@pytest.fixture
def env_config(shortdir: Path) -> BrokerConfig:
    env: BrokerEnv = make_env(shortdir)
    return env.config
