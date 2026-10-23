"""The `bws` files under `$MODGUDR_HOME/bws` (M2, M19): the generated config and the state guard.

`bws` is told to keep no state (`state_opt_out = "true"`, a string: `bws` 2.x refuses a boolean)
and where it would keep it (`state_dir`). The cleanup is a guard on top: at start and at lock
both state paths are emptied, and symlinks are removed, never followed. The second path is where
a `bws` version that ignores `state_dir` would write, under the `HOME` its children run with.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
from pathlib import Path

CONFIG_NAME = "config"


def bws_dir(home: Path) -> Path:
    return home / "bws"


def state_paths(home: Path) -> tuple[Path, Path]:
    """`bws/state` (the configured `state_dir`) and `bws/.config/bws/state` (`$HOME/.config/…`)."""
    base = bws_dir(home)
    return base / "state", base / ".config" / "bws" / "state"


def ensure_private_dir(path: Path, *, uid: int) -> None:
    """A 0700 directory owned by us. A symlink or a foreign owner is refused."""
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        st = os.lstat(path)
    except OSError as exc:
        raise OSError(f"{path} cannot be created: {exc.strerror}") from None
    if not stat.S_ISDIR(st.st_mode):
        raise OSError(f"{path} is not a directory (a symlink is refused)")
    if st.st_uid != uid:
        raise OSError(f"{path} is owned by uid {st.st_uid}, not by this user")
    if stat.S_IMODE(st.st_mode) != 0o700:
        path.chmod(0o700)


def config_text(home: Path, server_url: str | None) -> str:
    """The `[profiles.default]` profile. Values are JSON strings, which TOML reads as they are."""
    lines = [
        "[profiles.default]",
        'state_opt_out = "true"',
        f"state_dir = {json.dumps(str(state_paths(home)[0]))}",
    ]
    if server_url is not None:
        lines.append(f"server_base = {json.dumps(server_url)}")
    return "\n".join(lines) + "\n"


def write_config(home: Path, server_url: str | None, *, uid: int) -> Path:
    """Write `bws/config` (0600) in `bws/` (0700), replacing what was there."""
    base = bws_dir(home)
    ensure_private_dir(base, uid=uid)
    path = base / CONFIG_NAME
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise OSError(f"{path} cannot be replaced: {exc.strerror}") from None
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, config_text(home, server_url).encode("utf-8"))
    finally:
        os.close(fd)
    return path


def empty_state(home: Path) -> list[str]:
    """Empty both state paths. Returns what was removed, for the log.

    A state path that is itself a symlink is removed (never followed), and so is a symlinked
    parent below `bws/`: nothing behind it is ours to clean.
    """
    removed: list[str] = []
    base = bws_dir(home)
    for path in state_paths(home):
        parts = path.relative_to(base).parts
        current = base
        for index, part in enumerate(parts):
            current = current / part
            try:
                st = os.lstat(current)
            except (FileNotFoundError, NotADirectoryError):
                break
            if stat.S_ISLNK(st.st_mode):
                current.unlink()
                removed.append(str(current))
                break
            if index == len(parts) - 1 and stat.S_ISDIR(st.st_mode):
                removed.extend(_empty(current))
    return removed


def _empty(directory: Path) -> list[str]:
    removed: list[str] = []
    for entry in os.scandir(directory):
        path = Path(entry.path)
        if entry.is_dir(follow_symlinks=False):
            shutil.rmtree(path)
        else:
            path.unlink()
        removed.append(str(path))
    return removed
