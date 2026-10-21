"""Socket and state locations (M1). Platform, environment, uid and home are injectable."""

import os
import pwd
import sys
from collections.abc import Mapping
from pathlib import Path

from modgudr.client.errors import UsageError

MAX_SOCKET_PATH_BYTES = 103


def _check_length(path: Path) -> Path:
    if len(os.fsencode(path)) > MAX_SOCKET_PATH_BYTES:
        raise UsageError(
            f"socket path too long ({len(os.fsencode(path))} bytes, limit "
            f"{MAX_SOCKET_PATH_BYTES}): {path}"
        )
    return path


def _home_dir(uid: int | None, home_dir: str | None) -> str:
    if home_dir is not None:
        return home_dir
    return pwd.getpwuid(os.getuid() if uid is None else uid).pw_dir


def modgudr_home(
    *,
    env: Mapping[str, str] | None = None,
    uid: int | None = None,
    home_dir: str | None = None,
) -> Path:
    """`MODGUDR_HOME`, else `<pw_dir>/.modgudr`. The home never comes from `$HOME`."""
    environment = os.environ if env is None else env
    override = environment.get("MODGUDR_HOME")
    if override:
        return Path(override)
    return Path(_home_dir(uid, home_dir)) / ".modgudr"


def agent_socket(
    *,
    env: Mapping[str, str] | None = None,
    platform: str | None = None,
    uid: int | None = None,
    home_dir: str | None = None,
) -> Path:
    """The path of `agent.sock`: `MODGUDR_SOCKET`, else the per-platform default."""
    environment = os.environ if env is None else env
    override = environment.get("MODGUDR_SOCKET")
    if override:
        return _check_length(Path(override))
    system = sys.platform if platform is None else platform
    if system == "darwin":
        home = Path(_home_dir(uid, home_dir))
        return _check_length(home / "Library" / "Caches" / "modgudr" / "run" / "agent.sock")
    if system.startswith("linux"):
        runtime = environment.get("XDG_RUNTIME_DIR")
        if runtime:
            return _check_length(Path(runtime) / "modgudr" / "agent.sock")
        user = os.getuid() if uid is None else uid
        return _check_length(Path(f"/tmp/modgudr-{user}") / "agent.sock")
    raise UsageError(f"unsupported platform {system!r}; supported: darwin, linux")


def human_socket(
    *,
    env: Mapping[str, str] | None = None,
    uid: int | None = None,
    home_dir: str | None = None,
) -> Path:
    """The path of `human.sock`: `$MODGUDR_HOME/run/human.sock` on both platforms."""
    home = modgudr_home(env=env, uid=uid, home_dir=home_dir)
    return _check_length(home / "run" / "human.sock")
