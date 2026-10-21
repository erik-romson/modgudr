"""`audit-tail` on `human.sock` (M9): raw protocol against an in-process broker."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from modgudr.broker.app import Broker
from modgudr.broker.scrub import REDACTED
from tests.support.brokerfx import (
    SECRET,
    BrokerEnv,
    FakeClock,
    call,
    error,
    lock,
    make_env,
    read_audit,
    running,
    unlock,
)

TODAY = "2026-10-22"
YESTERDAY = "2026-10-21"


@pytest.fixture
def env(shortdir: Path) -> BrokerEnv:
    return make_env(shortdir, clock=FakeClock(datetime(2026, 10, 22, 8, 0, tzinfo=UTC)))


@pytest.fixture
async def broker(env: BrokerEnv) -> AsyncIterator[Broker]:
    async with running(env) as b:
        yield b


async def tail(env: BrokerEnv, **args: object) -> list[dict[str, object]]:
    return await call(env.human_socket, "audit-tail", args=args)


def lines(frames: list[dict[str, object]]) -> list[dict[str, object]]:
    texts = [f for f in frames if f["t"] == "text"]
    assert all(f["stream"] == "audit" for f in texts)
    return [json.loads(str(f["data"])) for f in texts]


def trailer(frames: list[dict[str, object]]) -> dict[str, object]:
    assert frames[-1]["t"] == "trailer", frames[-1]
    return frames[-1]


def day_file(env: BrokerEnv, day: str) -> Path:
    return env.audit_dir / f"audit-{day}.jsonl"


async def test_audit_tail_on_the_agent_socket_is_refused_and_audited(
    env: BrokerEnv, broker: Broker
) -> None:
    err = error(await call(env.agent_socket, "audit-tail"))
    assert err["code"] == "bad_request"
    assert "not available on this channel" in str(err["message"])
    record = [r for r in read_audit(env.audit_dir) if r["type"] == "bad_request"][-1]
    assert (record["op"], record["channel"], record["auditId"]) == (
        "audit-tail",
        "agent",
        err["auditId"],
    )


async def test_it_streams_matching_records_oldest_first_and_is_not_audited(
    env: BrokerEnv, broker: Broker
) -> None:
    await unlock(env)
    for text in ("a", "b"):
        await call(
            env.agent_socket,
            "echo",
            "echo-test",
            args={"text": text},
            client={"name": "python", "session": "s-1"},
        )
    before = len(read_audit(env.audit_dir))
    frames = await tail(env, n=3)
    assert [f["t"] for f in frames] == ["text", "text", "text", "trailer"]
    got = lines(frames)
    assert [r["type"] for r in got] == ["completion", "decision", "completion"]
    assert [r["auditId"] for r in got[:1]] == [got[0]["auditId"]]
    end = trailer(frames)
    assert (end["rows"], end["truncated"], end["reason"], end["malformed"]) == (3, False, None, 0)
    assert end["auditId"] is None
    assert len(read_audit(env.audit_dir)) == before  # not itself audited
    only = lines(await tail(env, session="s-1", client="python", target="echo-test"))
    assert len(only) == 4 and {r["session"] for r in only} == {"s-1"}


async def test_it_works_while_locked(env: BrokerEnv, broker: Broker) -> None:
    await unlock(env)
    await lock(env)
    frames = await tail(env)
    assert trailer(frames)["rows"] == len(lines(frames)) >= 3
    assert [r["type"] for r in lines(frames)][-1] == "lock"


async def test_a_partial_last_line_a_garbage_line_and_an_older_file(
    env: BrokerEnv, broker: Broker
) -> None:
    older = "".join(json.dumps({"type": "old", "n": i}) + "\n" for i in range(3))
    day_file(env, YESTERDAY).write_text(older)
    await unlock(env)
    path = day_file(env, TODAY)
    written = path.read_text()
    path.write_text(written + "garbage\n")
    with path.open("a") as handle:
        handle.write('{"type":"half","n')  # the writer mid-line
    frames = await tail(env, n=50)
    got = lines(frames)
    assert trailer(frames)["malformed"] == 1
    assert [r["type"] for r in got[:3]] == ["old", "old", "old"]  # yesterday first, in order
    assert [r["type"] for r in got[3:]] == ["broker.start", "unlock"]
    assert "half" not in "".join(str(f.get("data")) for f in frames)


async def test_records_written_while_it_reads_are_never_torn(
    env: BrokerEnv, broker: Broker
) -> None:
    await unlock(env)

    async def writer() -> None:
        await asyncio.gather(
            *(
                call(env.agent_socket, "echo", "echo-fast", args={"text": f"w{i}"})
                for i in range(20)
            )
        )

    async def reader() -> None:
        for _ in range(10):
            frames = await tail(env, n=1000)
            assert trailer(frames)["malformed"] == 0
            lines(frames)  # every line parses
            await asyncio.sleep(0.005)

    await asyncio.gather(writer(), reader())
    final = await tail(env, n=1000)
    assert trailer(final)["malformed"] == 0
    # Four calls fit the target's slots; the rest are throttled (one record each).
    ended = [r for r in lines(final) if r["type"] in ("completion", "throttled")]
    assert len(ended) == 20


async def test_a_planted_secret_is_redacted(env: BrokerEnv, broker: Broker) -> None:
    await unlock(env)
    await call(env.agent_socket, "echo", "echo-test", args={"text": "x"})  # registers the secret
    with day_file(env, TODAY).open("a") as handle:
        handle.write(json.dumps({"type": "planted", "note": f"password is {SECRET}"}) + "\n")
    frames = await tail(env, n=1)
    data = str(frames[0]["data"])
    assert SECRET not in data and REDACTED in data
    assert trailer(frames)["scrubbed"] == 1


@pytest.mark.parametrize("n", [0, 1001, -1, "5", 1.5, True, None])
async def test_n_outside_1_to_1000_is_bad_request(
    env: BrokerEnv, broker: Broker, n: object
) -> None:
    err = error(await tail(env, n=n))
    assert err["code"] == "bad_request" and err["auditId"] is None
    assert "1 to 1000" in str(err["message"])


async def test_unknown_arguments_and_empty_filters_are_bad_request(
    env: BrokerEnv, broker: Broker
) -> None:
    assert error(await tail(env, since="x"))["code"] == "bad_request"
    assert error(await tail(env, session=""))["code"] == "bad_request"
    assert error(await tail(env, target=3))["code"] == "bad_request"


async def test_output_above_4_mib_is_truncated_and_works_while_locked(
    env: BrokerEnv, broker: Broker
) -> None:
    pad = "x" * 8000
    day_file(env, YESTERDAY).write_text(
        "".join(json.dumps({"type": "big", "n": i, "pad": pad}) + "\n" for i in range(1000))
    )
    frames = await tail(env, n=1000)
    end = trailer(frames)
    assert end["truncated"] is True and end["reason"] == "bytes"
    assert 4 * 1024 * 1024 - 20_000 < int(str(end["bytes"])) <= 4 * 1024 * 1024
    got = lines(frames)
    assert 0 < len(got) < 1000
    assert [r["n"] for r in got if r["type"] == "big"] == sorted(
        r["n"] for r in got if r["type"] == "big"
    )
    assert got[-1]["type"] != "big" or got[-1]["n"] == 999  # the newest records are kept


async def test_an_unreadable_audit_file_is_internal(env: BrokerEnv, broker: Broker) -> None:
    link = day_file(env, "2026-10-20")
    link.symlink_to(env.root / "secrets.yaml")
    err = error(await tail(env, n=1000))
    assert err["code"] == "internal" and "audit-2026-10-20.jsonl" in str(err["message"])
