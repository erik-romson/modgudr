"""Short temporary directories: pytest's tmp_path exceeds the macOS socket path limit."""

import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest


def make_shortdir() -> Path:
    """Create a directory like /tmp/mg-abcd1234. The caller removes it."""
    return Path(tempfile.mkdtemp(prefix="mg-", dir="/tmp"))


@pytest.fixture
def shortdir() -> Iterator[Path]:
    path = make_shortdir()
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)
