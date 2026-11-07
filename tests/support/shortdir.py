"""Short temporary directories: pytest's tmp_path exceeds the macOS socket path limit."""

import os
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

#: The longest base that leaves room for a socket path under it. macOS's default $TMPDIR, around
#: 49 bytes, is over this on purpose.
MAX_BASE_BYTES = 32


def short_base(tmpdir: str | None) -> str:
    """`$TMPDIR` when it is absolute and short, else /tmp.

    The agent sandbox allows writes to its short $TMPDIR but not to /tmp.
    """
    if tmpdir and tmpdir.startswith("/") and len(os.fsencode(tmpdir)) <= MAX_BASE_BYTES:
        return tmpdir
    return "/tmp"


def make_shortdir() -> Path:
    """Create a directory like /tmp/mg-abcd1234. The caller removes it."""
    return Path(tempfile.mkdtemp(prefix="mg-", dir=short_base(os.environ.get("TMPDIR"))))


@pytest.fixture
def shortdir() -> Iterator[Path]:
    path = make_shortdir()
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)
