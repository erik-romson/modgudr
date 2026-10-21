"""The scrubber (D21): known values, prefixed tokens, rolling tail, no false positives."""

from __future__ import annotations

import time
import tracemalloc
import uuid

import pytest

from modgudr.broker.scrub import REDACTED, CallScrubber, Scrubber

R = REDACTED
PEM_BODY = (
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n"
    "MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\n"
    "NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ\n"
)
PEM = f"-----BEGIN PRIVATE KEY-----\n{PEM_BODY}-----END PRIVATE KEY-----\n"
GHP = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"


def stream(scrubber: Scrubber, chunks: list[str]) -> tuple[str, int]:
    call = scrubber.call()
    s = call.stream()
    out = "".join(s.feed(c) for c in chunks) + s.flush()
    return out, call.count


def splits(text: str) -> list[list[str]]:
    """Every two-way split, plus one character at a time."""
    return [[text[:i], text[i:]] for i in range(len(text) + 1)] + [list(text)]


def make(*values: str) -> Scrubber:
    s = Scrubber()
    for v in values:
        s.add(v)
    return s


def test_eight_and_seven_characters() -> None:
    s = make("abcdefgh", "1234567")
    call = s.call()
    assert call.cells(["abcdefgh", "1234567", None, True]) == [R, "1234567", None, True]
    assert call.error("bad abcdefgh and 1234567") == f"bad {R} and {R}"
    assert call.count == 3
    assert s.data("x 1234567 y") == "x 1234567 y"
    assert s.error("x 1234567 y") == f"x {R} y"


def test_short_value_is_not_replaced_in_streams() -> None:
    assert stream(make("1234567"), ["a 1234567 b"]) == ("a 1234567 b", 0)


@pytest.mark.parametrize("chunks", splits("before s3cr3t-value-XYZ after"))
def test_split_everywhere(chunks: list[str]) -> None:
    assert stream(make("s3cr3t-value-XYZ"), chunks) == (f"before {R} after", 1)


@pytest.mark.parametrize("chunks", splits("päss€wörd-9 end"))
def test_multibyte(chunks: list[str]) -> None:
    assert stream(make("päss€wörd-9"), chunks) == (f"{R} end", 1)


@pytest.mark.parametrize("chunks", splits("x abcdefghijkl y abcdefgh z"))
def test_nested_longest_first(chunks: list[str]) -> None:
    out = stream(make("abcdefgh", "abcdefghijkl"), chunks)
    assert out == (f"x {R} y {R} z", 2)


@pytest.mark.parametrize("chunks", splits("secret-ABC" * 3))
def test_repeated(chunks: list[str]) -> None:
    assert stream(make("secret-ABC"), chunks) == (R * 3, 3)


def test_tail_is_flushed_at_the_end() -> None:
    call = make("secret-ABC").call()
    s = call.stream()
    fed = "data " * 20 + "secret-AB"
    out = s.feed(fed)
    assert 0 < len(out) < len(fed)
    assert out + s.flush() == fed


def test_special_characters() -> None:
    value = 'p"a\\ss\tword-é'
    s = make(value)
    assert s.call().cells([f"x{value}y"]) == [f"x{R}y"]
    assert stream(s, [f"x{value}y"]) == (f"x{R}y", 1)


def test_pem_whole_and_line_by_line() -> None:
    s = make(PEM)
    assert s.data(f"key: {PEM}") == f"key: {R}"
    line = PEM_BODY.splitlines()[1]
    assert s.data(f"part {line} end") == f"part {R} end"
    assert s.data("-----BEGIN PRIVATE KEY-----") == "-----BEGIN PRIVATE KEY-----"
    s.remove(PEM)
    assert s.data(f"part {line} end") == f"part {line} end"


@pytest.mark.parametrize("chunks", splits(f"a {PEM} b"))
def test_registered_pem_streams(chunks: list[str]) -> None:
    out, _ = stream(make(PEM), chunks)
    assert out == f"a {R} b"


@pytest.mark.parametrize("chunks", splits(f"a {PEM} b")[::7])
def test_unregistered_pem_block_streams(chunks: list[str]) -> None:
    out, count = stream(Scrubber(), chunks)
    assert out == f"a {R}\n b"
    assert count == 1


def test_unterminated_pem_is_redacted_at_the_end() -> None:
    out, count = stream(Scrubber(), ["x -----BEGIN RSA PRIVATE KEY-----\nMIIE", "vQIBADAN\n"])
    assert out == f"x {R}"
    assert count == 1


def test_very_long_unterminated_pem_does_not_buffer_forever() -> None:
    call = Scrubber().call()
    s = call.stream()
    out = s.feed("-----BEGIN PRIVATE KEY-----\n")
    for _ in range(40):
        out += s.feed("A" * 4096 + "\n")
    out += s.feed("-----END PRIVATE KEY-----\nafter") + s.flush()
    assert out == f"{R}\nafter"


@pytest.mark.parametrize("text", [GHP, JWT, "github_pat_" + "A1b2C3d4" * 4, "AKIAIOSFODNN7EXAMPLE"])
def test_prefixed_formats(text: str) -> None:
    s = Scrubber()
    assert s.data(f"t={text};") == f"t={R};"
    assert stream(s, list(f"t={text};")) == (f"t={R};", 1)
    assert stream(s, [f"t={text[:9]}", f"{text[9:]};"]) == (f"t={R};", 1)


def test_more_prefixes() -> None:
    s = Scrubber()
    for t in (
        "gho_" + "x" * 30,
        "ATATT3xFfGF0" + "abcdEFGH12345678",
        "xoxb-1234567890-abcdef",
        "xoxp-1234567890-abcdef",
    ):
        assert s.data(f"[{t}]") == f"[{R}]"


def test_hashes_uuids_and_base64_are_untouched() -> None:
    s = make("secret-ABC")
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    blob = "SGVsbG8gd29ybGQsIHRoaXMgaXMgYSBiYXNlNjQgYmxvYg=="
    json_blob = "eyJhIjoxfQ=="
    text = f"{sha1} {sha256} {uuid.uuid4()} {blob} {json_blob} 7f9c2ba4e88f827d61604550"
    assert s.data(text) == text
    assert stream(s, list(text)) == (text, 0)


def test_clear_drops_values() -> None:
    s = make("abcdefgh")
    s.clear()
    assert len(s) == 0
    assert s.data("abcdefgh") == "abcdefgh"


def test_empty_secret_is_refused() -> None:
    with pytest.raises(ValueError):
        Scrubber().add("")


def test_row_spanning_pem_does_not_hide_other_cells() -> None:
    call = Scrubber().call()
    row = ["-----BEGIN PRIVATE KEY-----", "ok", "-----END PRIVATE KEY-----"]
    assert call.cells(row) == row


def test_large_result_is_fast_and_flat() -> None:
    secrets = [f"secret-{i}-value" for i in range(5)]
    s = make(*secrets)
    call: CallScrubber = s.call()
    row: list[str | None] = [f"col{j}-plain" for j in range(20)]
    for i, v in enumerate(secrets):
        row[i * 3] = f"x {v} y"
    start = time.monotonic()
    for _ in range(100_000):
        out = call.cells(row)
    assert time.monotonic() - start < 5
    assert out[0] == f"x {R} y"
    assert call.count == 500_000
    tracemalloc.start()
    for _ in range(10_000):
        call.cells(row)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert peak < 100_000


def test_large_stream_keeps_memory_flat() -> None:
    s = make("secret-ABC")
    st = s.call().stream()
    chunk = "lorem ipsum dolor sit amet " * 400 + "secret-ABC "
    tracemalloc.start()
    emitted = 0
    for _ in range(300):
        emitted += len(st.feed(chunk))
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert emitted > 3_000_000
    assert peak < 1_000_000
