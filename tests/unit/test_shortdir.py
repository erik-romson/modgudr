"""Where the short temporary directories go."""

import pytest

from tests.support.shortdir import MAX_BASE_BYTES, short_base


def test_a_short_tmpdir_is_used() -> None:
    assert short_base("/tmp/claude-501") == "/tmp/claude-501"


@pytest.mark.parametrize(
    "tmpdir",
    [
        None,
        "",
        "relative/tmp",
        "/var/folders/ab/cdefghijklmnopqrstuvwxyz012345/T/",
        "/" + "x" * MAX_BASE_BYTES,
    ],
)
def test_anything_else_uses_tmp(tmpdir: str | None) -> None:
    assert short_base(tmpdir) == "/tmp"
