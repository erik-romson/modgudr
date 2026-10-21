from pathlib import Path

import pytest

from modgudr.client import paths
from modgudr.client.errors import UsageError


def test_override_used() -> None:
    env = {"MODGUDR_SOCKET": "/tmp/mg-x/agent.sock"}
    assert paths.agent_socket(env=env, platform="darwin") == Path("/tmp/mg-x/agent.sock")
    assert paths.agent_socket(env=env, platform="linux") == Path("/tmp/mg-x/agent.sock")


def test_macos_default_comes_from_the_passwd_home_not_home_or_tmpdir() -> None:
    env = {"HOME": "/wrong", "TMPDIR": "/also/wrong"}
    got = paths.agent_socket(env=env, platform="darwin", home_dir="/Users/u")
    assert got == Path("/Users/u/Library/Caches/modgudr/run/agent.sock")


def test_macos_default_reads_pwd(monkeypatch: pytest.MonkeyPatch) -> None:
    class Entry:
        pw_dir = "/Users/pw"

    monkeypatch.setattr(paths.pwd, "getpwuid", lambda uid: Entry())  # pyright: ignore[reportUnknownArgumentType,reportUnknownLambdaType]
    assert paths.agent_socket(env={}, platform="darwin") == Path(
        "/Users/pw/Library/Caches/modgudr/run/agent.sock"
    )
    assert paths.modgudr_home(env={"HOME": "/wrong"}) == Path("/Users/pw/.modgudr")


def test_linux_with_xdg() -> None:
    env = {"XDG_RUNTIME_DIR": "/run/user/1000"}
    assert paths.agent_socket(env=env, platform="linux", uid=1000) == Path(
        "/run/user/1000/modgudr/agent.sock"
    )


def test_linux_without_xdg() -> None:
    assert paths.agent_socket(env={}, platform="linux", uid=501) == Path(
        "/tmp/modgudr-501/agent.sock"
    )


def test_unsupported_platform() -> None:
    with pytest.raises(UsageError, match="unsupported platform"):
        paths.agent_socket(env={}, platform="win32")


def test_home_override_and_human_socket() -> None:
    env = {"MODGUDR_HOME": "/tmp/mg-h"}
    assert paths.modgudr_home(env=env) == Path("/tmp/mg-h")
    assert paths.human_socket(env=env) == Path("/tmp/mg-h/run/human.sock")


def test_human_socket_default() -> None:
    assert paths.human_socket(env={}, home_dir="/Users/u") == Path(
        "/Users/u/.modgudr/run/human.sock"
    )


def test_path_too_long() -> None:
    long = "/tmp/" + "a" * 115
    assert len(long) == 120
    with pytest.raises(UsageError, match="socket path too long"):
        paths.agent_socket(env={"MODGUDR_SOCKET": long})
    with pytest.raises(UsageError, match="socket path too long"):
        paths.human_socket(env={"MODGUDR_HOME": long})


def test_limit_is_103_bytes() -> None:
    ok = "/tmp/" + "a" * 98
    assert len(ok) == 103
    assert paths.agent_socket(env={"MODGUDR_SOCKET": ok}) == Path(ok)
    with pytest.raises(UsageError):
        paths.agent_socket(env={"MODGUDR_SOCKET": ok + "a"})
