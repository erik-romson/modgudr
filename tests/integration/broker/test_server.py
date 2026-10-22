"""An in-process broker on a short temporary directory, driven with a raw protocol client."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import socket
import threading
import time
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from modgudr.broker.app import Broker
from modgudr.broker.scrub import REDACTED
from modgudr.client.agent.isolation import L0_WARNING, Facts, required_settings
from tests.support.brokerfx import (
    PROD_SECRET,
    SECRET,
    SECRETS,
    TARGETS,
    BrokerEnv,
    RootFstat,
    audit_text,
    call,
    error,
    line,
    make_env,
    raw,
    read_audit,
    request,
    result_data,
    running,
    unlock,
    wait_for,
    write_file,
    write_secrets,
)


@pytest.fixture
def env(shortdir: Path) -> BrokerEnv:
    return make_env(shortdir)


@pytest.fixture
async def broker(env: BrokerEnv) -> AsyncIterator[Broker]:
    async with running(env) as b:
        yield b


def records(env: BrokerEnv, record_type: str) -> list[dict[str, object]]:
    return [r for r in read_audit(env.audit_dir) if r["type"] == record_type]


# --- status, isolation, metadata ---------------------------------------------------------------


async def test_status_json_has_the_isolation_facts(env: BrokerEnv, broker: Broker) -> None:
    frames = await call(env.agent_socket, "status", client={"name": "test", "version": "0.1.0"})
    data = result_data(frames)
    assert frames[1]["auditId"] is None
    assert data["home"] == os.path.realpath(env.home)
    assert data["agentSocket"] == os.path.realpath(env.agent_socket.parent) + "/agent.sock"
    assert data["humanSocket"] == os.path.realpath(env.home / "run") + "/human.sock"
    assert data["denyHosts"] == ["echo-prod.example.net", "echo.example.net"]
    assert data["platform"] == env.config.platform
    assert data["isolation"] == "none"
    reasons = data["isolationReasons"]
    assert isinstance(reasons, list) and "no managed settings" in reasons[0]
    assert data["warning"] == L0_WARNING
    assert data["protocol"] == {"broker": [1], "client": 1, "clientVersion": "0.1.0"}
    assert (data["state"], data["locked"]) == ("locked", True)
    assert (data["dev"], data["store"], data["auditDegraded"]) == (True, "file", False)
    assert data["channel"] == "agent"
    policy = data["policy"]
    assert isinstance(policy, dict) and policy["restartToApply"] is False
    files = policy["files"]
    assert [f["name"] for f in files] == ["00-company.yaml", "50-targets.yaml"]
    assert all(f["uid"] == os.getuid() for f in files)


async def test_status_works_on_both_channels(env: BrokerEnv, broker: Broker) -> None:
    human = result_data(await call(env.human_socket, "status"))
    assert human["channel"] == "human"


async def test_policy_edited_while_running_says_restart_to_apply(
    env: BrokerEnv, broker: Broker
) -> None:
    write_file(env.policy_dir / "50-targets.yaml", TARGETS + "# edited\n")
    policy = result_data(await call(env.agent_socket, "status"))["policy"]
    assert isinstance(policy, dict)
    assert policy["restartToApply"] is True
    assert policy["changed"] == ["50-targets.yaml"]
    assert "restart to apply" in str(policy["message"])


async def test_isolation_flips_when_managed_settings_appear(shortdir: Path) -> None:
    env = make_env(shortdir, settings_fstat=RootFstat())
    async with running(env):
        first = result_data(await call(env.agent_socket, "status"))
        assert first["isolation"] == "none"
        facts = Facts.from_json(first)
        env.settings_dir.mkdir(parents=True)
        drop_in = required_settings(facts, user_home=str(env.config.user_home))
        write_file(env.settings_dir / "50-modgudr.json", json.dumps(drop_in))
        second = result_data(await call(env.agent_socket, "status"))
        assert (second["isolation"], second["isolationReasons"]) == ("managed-settings", [])
        assert "warning" not in second
        assert "warning" not in result_data(await call(env.agent_socket, "targets"))
        changed = records(env, "isolation.changed")
        assert [(r["previous"], r["current"]) for r in changed] == [("none", "managed-settings")]
        assert changed[0]["isolation"] == "managed-settings"
        # Weakened again: back to none, naming the requirement.
        drop_in["sandbox"]["enabled"] = False  # type: ignore[index]
        write_file(env.settings_dir / "50-modgudr.json", json.dumps(drop_in))
        third = result_data(await call(env.agent_socket, "status"))
        assert third["isolation"] == "none"
        assert third["isolationReasons"] == ["sandbox.enabled must be true (found false)"]
    assert len(records(env, "isolation.changed")) == 2


async def test_metadata_ops_work_while_locked_and_are_not_audited(
    env: BrokerEnv, broker: Broker
) -> None:
    before = audit_text(env.audit_dir)
    sock = env.agent_socket

    status = result_data(await call(sock, "status"))
    assert status["state"] == "locked"

    targets = result_data(await call(sock, "targets"))
    entries = targets["targets"]
    assert isinstance(entries, list)
    assert [t["name"] for t in entries] == ["echo-test", "echo-prod", "echo-fast"]
    assert {t["pins"] for t in entries} == {"unknown (locked)"}
    assert entries[0]["ops"] == ["echo", "put", "slow", "boom", "leak", "auth"]
    assert entries[0]["destinations"] == ["echo.example.net:7000"]
    assert targets["warning"] == L0_WARNING

    described = result_data(await call(sock, "describe", args={"target": "echo-test"}))
    assert (described["pins"], described["scrub"]) == ("unknown (locked)", "unknown (locked)")
    ops = described["operations"]
    assert isinstance(ops, list) and [o["name"] for o in ops][:2] == ["echo", "put"]
    assert ops[1]["dryRun"] is True and ops[1]["args"][1]["flag"] == "--delay-ms"

    explained = result_data(
        await call(
            sock,
            "explain",
            args={"target": "echo-prod", "op": "put", "args": {"value": "x"}},
        )
    )
    assert explained["decision"] == "deny"
    assert explained["layer"] == "ceiling"
    assert explained["explanation"] == (
        "denied: echo:put (write) on echo-prod. Environment prod allows read only (ceiling)."
    )
    assert explained["effectiveEnv"] == "unknown (locked)"

    actions = result_data(await call(sock, "actions", args={"type": "echo"}))
    assert {"name": "echo:put", "risk": "write", "constraints": [], "summary": ""} in (
        actions["actions"]  # type: ignore[operator]
    )

    shown = result_data(await call(sock, "policy-show", args={"target": "echo@test"}))
    assert (shown["target"], shown["ceiling"], shown["effectiveEnv"]) == (
        "echo-test",
        "write",
        "unknown (locked)",
    )
    layers = shown["layers"]
    assert isinstance(layers, list)
    assert [layer["layer"] for layer in layers] == ["target", "environment", "plugin-default"]
    assert layers[1]["blocks"][0]["allow"] == ["write"]

    lint = result_data(await call(sock, "policy-lint"))
    assert lint["ok"] is True

    assert audit_text(env.audit_dir) == before


async def test_metadata_op_errors(env: BrokerEnv, broker: Broker) -> None:
    sock = env.agent_socket
    missing = error(await call(sock, "describe", args={"target": "nosuch"}))
    assert (missing["code"], missing["auditId"]) == ("not_found", None)
    assert error(await call(sock, "describe"))["code"] == "bad_request"
    assert error(await call(sock, "status", args={"x": 1}))["code"] == "bad_request"
    assert error(await call(sock, "actions", args={"type": "nosuch"}))["code"] == "not_found"
    systems = error(await call(sock, "targets", args={"system": "nosuch"}))
    assert "systems: echo" in str(systems["message"])
    filtered = result_data(await call(sock, "targets", args={"system": "echo"}))
    assert [t["name"] for t in filtered["targets"]] == ["echo-test", "echo-prod"]  # type: ignore[union-attr]
    unknown = error(await call(sock, "frobnicate"))
    assert unknown["code"] == "bad_request" and "broker ops:" in str(unknown["message"])


# --- framing -----------------------------------------------------------------------------------


@pytest.mark.parametrize("version", [2, "1", None, True], ids=["2", "string", "missing", "true"])
async def test_unsupported_protocol_versions(
    env: BrokerEnv, broker: Broker, version: object
) -> None:
    payload: dict[str, object] = {"op": "status", "args": {}}
    if version is not None:
        payload["v"] = version
    frames = await raw(env.agent_socket, payload)
    err = error(frames)
    assert err["code"] == "bad_request"
    assert "[1]" in str(err["message"])
    assert records(env, "bad_request")[-1]["auditId"] == err["auditId"]


@pytest.mark.parametrize(
    "payload",
    [b"not json\n", b"[1]\n", b'{"v":1,"op":"status","op":"targets"}\n', b"\xff\xfe\n"],
    ids=["not-json", "not-object", "duplicate-key", "not-utf8"],
)
async def test_malformed_requests(env: BrokerEnv, broker: Broker, payload: bytes) -> None:
    assert error(await raw(env.agent_socket, payload))["code"] == "bad_request"


def _padded(size: int) -> bytes:
    """A status request whose line (without the newline) is exactly `size` bytes."""
    empty = len(json.dumps({"v": 1, "op": "status", "pad": ""}, separators=(",", ":")))
    text = json.dumps({"v": 1, "op": "status", "pad": "x" * (size - empty)}, separators=(",", ":"))
    assert len(text) == size
    return text.encode() + b"\n"


async def test_request_of_exactly_max_request_bytes_is_accepted(
    env: BrokerEnv, broker: Broker
) -> None:
    limit = broker.limits.max_request_bytes
    assert limit == 1024**2
    result_data(await raw(env.agent_socket, _padded(limit)))
    err = error(await raw(env.agent_socket, _padded(limit + 1)))
    assert err["code"] == "bad_request"
    assert "maxRequestBytes" in str(err["message"])


async def test_reading_stops_at_limit_plus_one(env: BrokerEnv, broker: Broker) -> None:
    limit = broker.limits.max_request_bytes
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(os.fspath(env.agent_socket))
    sock.settimeout(20)

    def blast() -> None:
        with contextlib.suppress(OSError):
            sock.sendall(b"x" * (5 * 1024**2))

    sender = threading.Thread(target=blast)
    sender.start()

    def receive() -> bytes:
        data = b""
        try:
            while chunk := sock.recv(65536):
                data += chunk
        except OSError:
            pass
        return data

    data = await asyncio.to_thread(receive)
    sender.join(timeout=20)
    sock.close()
    frame = json.loads(data.splitlines()[0])
    assert frame["code"] == "bad_request"
    record = records(env, "bad_request")[-1]
    assert record["bytesRead"] == limit + 1
    assert record["auditId"] == frame["auditId"]


async def test_a_silent_client_is_closed_after_ten_seconds(env: BrokerEnv, broker: Broker) -> None:
    await unlock(env)
    reader, writer = await asyncio.open_unix_connection(os.fspath(env.agent_socket))
    started = time.monotonic()
    data = await asyncio.wait_for(reader.read(), timeout=20)
    elapsed = time.monotonic() - started
    writer.close()
    assert 9.5 <= elapsed < 13, elapsed
    frame = json.loads(data)
    assert frame["code"] == "bad_request" and "10 s" in frame["message"]
    assert broker.targets["echo-test"].slots.used == 0
    assert (await call(env.agent_socket, "echo", "echo-test", args={"text": "a"}))[-1]["t"] == (
        "trailer"
    )


async def test_a_probe_connection_writes_nothing(env: BrokerEnv, broker: Broker) -> None:
    before = audit_text(env.audit_dir)
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.connect(os.fspath(env.agent_socket))
    probe.close()
    await asyncio.sleep(0.1)
    assert audit_text(env.audit_dir) == before


# --- channels and peers ------------------------------------------------------------------------


@pytest.mark.parametrize("op", ["unlock", "lock", "audit-tail", "login-info"])
async def test_admin_ops_are_refused_on_agent_sock(env: BrokerEnv, broker: Broker, op: str) -> None:
    err = error(await call(env.agent_socket, op))
    assert err["code"] == "bad_request"
    assert "not available on this channel" in str(err["message"])
    record = records(env, "bad_request")[-1]
    assert (record["op"], record["channel"], record["auditId"]) == (op, "agent", err["auditId"])
    assert result_data(await call(env.agent_socket, "status"))["state"] == "locked"


async def test_login_info_needs_a_target_with_a_custody_login(
    env: BrokerEnv, broker: Broker
) -> None:
    missing = error(await call(env.human_socket, "login-info"))
    assert missing["code"] == "bad_request"
    assert "needs the argument 'target'" in str(missing["message"])
    unknown = error(await call(env.human_socket, "login-info", args={"target": "nosuch"}))
    assert unknown["code"] == "not_found"
    secret = error(await call(env.human_socket, "login-info", args={"target": "echo-test"}))
    assert secret["code"] == "bad_request"
    assert "has no credential provider" in str(secret["message"])
    assert result_data(await call(env.agent_socket, "status"))["state"] == "locked"


async def test_a_peer_with_another_uid_is_denied_and_audited(shortdir: Path) -> None:
    env = make_env(shortdir, peer_uid=lambda sock: os.getuid() + 1)
    async with running(env):
        err = error(await call(env.agent_socket, "status"))
    assert err["code"] == "denied"
    assert f"peer uid {os.getuid() + 1}" in str(err["message"])
    record = records(env, "denied")[-1]
    assert (record["peerUid"], record["layer"], record["auditId"]) == (
        os.getuid() + 1,
        "peer",
        err["auditId"],
    )


# --- the call pipeline -------------------------------------------------------------------------


async def test_a_call_while_locked_is_locked_then_runs_after_unlock(
    env: BrokerEnv, broker: Broker
) -> None:
    client = {"name": "python", "version": "0.1.0", "session": "s-abc", "cwd": "/w"}
    locked = error(
        await call(env.agent_socket, "echo", "echo-test", args={"text": "hi"}, client=client)
    )
    assert locked["code"] == "locked"
    assert "modgudr unlock" in str(locked["message"])
    assert records(env, "locked")[-1]["auditId"] == locked["auditId"]
    assert env.connector.targets["echo-test"].executed == []

    await unlock(env)
    frames = await call(env.agent_socket, "echo", "echo-test", args={"text": "hi"}, client=client)
    assert [f["t"] for f in frames] == ["header", "row", "trailer"]
    assert frames[0]["columns"] == [{"name": "text", "type": "string"}]
    assert frames[1]["v"] == ["hi"]
    trailer = frames[2]
    assert (trailer["rows"], trailer["truncated"], trailer["reason"]) == (1, False, None)
    decision = records(env, "decision")[-1]
    completion = records(env, "completion")[-1]
    assert decision["auditId"] == completion["auditId"] == trailer["auditId"]
    assert decision["client"] == {
        "name": "python",
        "version": "0.1.0",
        "script": None,
        "agentHint": None,
        "cwd": "/w",
    }
    assert decision["session"] == "s-abc"
    assert (decision["target"], decision["env"], decision["envSource"]) == (
        "echo-test",
        "test",
        "explicit",
    )
    assert (decision["action"], decision["risk"], decision["decision"]) == (
        "echo:echo",
        "read",
        "allow",
    )
    assert (decision["layer"], decision["rule"]) == ("plugin-default", "read")
    assert decision["args"] == {"text": "hi"}
    assert (decision["dev"], decision["store"], decision["isolation"]) == (True, "file", "none")
    assert (completion["outcome"], completion["rows"], completion["cancelled"]) == (
        "completed",
        1,
        None,
    )
    assert completion["destination"] == "echo.example.net:7000"
    assert "args" not in completion


async def test_denied_calls_are_refused_before_the_lock_gate(
    env: BrokerEnv, broker: Broker
) -> None:
    err = error(await call(env.agent_socket, "put", "echo-prod", args={"value": "x"}))
    assert (err["code"], err["layer"], err["rule"]) == ("denied", "ceiling", "read")
    record = records(env, "denied")[-1]
    assert (record["auditId"], record["layer"]) == (err["auditId"], "ceiling")
    assert not records(env, "decision")


async def test_target_resolution(env: BrokerEnv, broker: Broker) -> None:
    await unlock(env)
    sock = env.agent_socket
    await call(sock, "echo", "echo@prod", args={"text": "a"})
    assert records(env, "decision")[-1]["target"] == "echo-prod"
    await call(sock, "echo", "echo", env="sol", args={"text": "a"})
    decision = records(env, "decision")[-1]
    assert (decision["target"], decision["envSource"]) == ("echo-test", "session")
    await call(sock, "echo", "echo", args={"text": "a"})
    assert records(env, "decision")[-1]["envSource"] == "default"
    missing = error(await call(sock, "echo", "nosuch", args={"text": "a"}))
    assert missing["code"] == "not_found"
    bad_env = error(await call(sock, "echo", "echo@nosuch", args={"text": "a"}))
    assert bad_env["code"] == "not_found" and "valid: test (sol), prod" in str(bad_env["message"])
    assert records(env, "bad_request")[-1]["code"] == "not_found"


@pytest.mark.parametrize(
    ("args", "code", "text"),
    [
        ({}, "bad_request", "needs the argument 'text'"),
        ({"text": 1}, "bad_request", "must be a str"),
        ({"text": "a", "nosuch": 1}, "bad_request", "takes no argument 'nosuch'"),
        ({"text": "a", "params": {}}, "bad_request", "takes no argument 'params'"),
        ({"text": "a", "maxRows": 0}, "bad_request", "positive integer"),
        ({"text": "a", "maxRows": 50001}, "denied", "maxRowsHard 50000"),
    ],
)
async def test_argument_validation(
    env: BrokerEnv, broker: Broker, args: dict[str, object], code: str, text: str
) -> None:
    err = error(await call(env.agent_socket, "echo", "echo-test", args=args))
    assert err["code"] == code
    assert text in str(err["message"])
    if code == "denied":
        assert (err["layer"], err["rule"]) == ("limits", "maxRowsHard")


async def test_an_unknown_op_lists_the_targets_ops(env: BrokerEnv, broker: Broker) -> None:
    err = error(await call(env.agent_socket, "drop", "echo-test"))
    assert err["code"] == "bad_request"
    assert "ops: echo, put, slow, boom, leak, auth" in str(err["message"])


async def test_max_rows_truncates_at_a_row_boundary(env: BrokerEnv, broker: Broker) -> None:
    await unlock(env)
    frames = await call(
        env.agent_socket, "slow", "echo-test", args={"rows": 5, "delayMs": 0, "maxRows": 2}
    )
    assert [f["t"] for f in frames] == ["header", "row", "row", "trailer"]
    assert (frames[-1]["truncated"], frames[-1]["reason"], frames[-1]["rows"]) == (True, "rows", 2)
    completion = records(env, "completion")[-1]
    assert (completion["outcome"], completion["truncated"]) == ("truncated", True)
    assert broker.targets["echo-test"].slots.used == 0


async def test_writes_report_their_facts_in_the_trailer(env: BrokerEnv, broker: Broker) -> None:
    await unlock(env)
    wet = (await call(env.agent_socket, "put", "echo-test", args={"value": "v"}))[-1]
    assert (wet["affectedRows"], wet["committed"]) == (1, True)
    dry = (await call(env.agent_socket, "put", "echo-test", args={"value": "v", "dryRun": True}))[
        -1
    ]
    assert (dry["affectedRows"], dry["committed"], dry["dryRun"]) == (1, False, True)


async def test_auth_failure_is_upstream_and_latches_the_target(
    env: BrokerEnv, broker: Broker
) -> None:
    await unlock(env)
    echo = env.connector.targets["echo-test"]
    echo.rejected.add(SECRET)
    err = error(await call(env.agent_socket, "auth", "echo-test"))
    assert err["code"] == "upstream"
    assert "authentication failed" in str(err["message"])
    assert records(env, "completion")[-1]["stage"] == "login"
    # M8: the value in the store is unchanged, so the target is latched.
    again = error(await call(env.agent_socket, "auth", "echo-test"))
    assert again["code"] == "upstream" and "latched" in str(again["message"])
    assert echo.opens == 1


async def test_a_missing_secret_is_upstream_with_one_record(env: BrokerEnv, broker: Broker) -> None:
    await unlock(env)
    write_secrets(env.secrets_file, {"echo-prod": SECRETS["echo-prod"]})
    err = error(await call(env.agent_socket, "echo", "echo-test", args={"text": "a"}))
    assert err["code"] == "upstream"
    assert "file:echo-test" in str(err["message"])
    assert [r["stage"] for r in records(env, "failed")] == ["secret"]
    assert not records(env, "decision")
    assert env.connector.targets["echo-test"].executed == []


async def test_leak_is_scrubbed_from_the_error_audit_and_log(
    env: BrokerEnv, broker: Broker, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger="modgudr.broker")
    await unlock(env)
    err = error(await call(env.agent_socket, "leak", "echo-test"))
    assert err["code"] == "upstream"
    assert SECRET not in json.dumps(err)
    assert REDACTED in str(err["message"])
    text = audit_text(env.audit_dir)
    assert SECRET not in text and REDACTED in text
    logged = [r.getMessage() for r in caplog.records]
    assert any(REDACTED in m for m in logged), logged
    assert not any(SECRET in m for m in logged)
    assert PROD_SECRET not in text


async def test_audit_degraded_refuses_new_calls_until_a_write_succeeds(
    env: BrokerEnv, broker: Broker
) -> None:
    await unlock(env)
    sock = env.agent_socket
    task = asyncio.create_task(call(sock, "slow", "echo-test", args={"rows": 3, "delayMs": 200}))
    await wait_for(lambda: bool(records(env, "decision")))
    (day,) = env.audit_dir.glob("audit-*.jsonl")
    day.chmod(0o400)
    try:
        frames = await task
        assert frames[-1]["t"] == "trailer"
        assert result_data(await call(sock, "status"))["auditDegraded"] is True
        refused = error(await call(sock, "echo", "echo-test", args={"text": "a"}))
        assert refused["code"] == "internal"
        assert "audit log cannot be written" in str(refused["message"])
    finally:
        day.chmod(0o600)
    assert (await call(sock, "echo", "echo-test", args={"text": "a"}))[-1]["t"] == "trailer"
    assert result_data(await call(sock, "status"))["auditDegraded"] is False
    assert records(env, "audit.probe")


# --- concurrency, deadlines, cancellation ------------------------------------------------------

THROTTLE_TARGETS = TARGETS.replace(
    "    maxConcurrent: 2\n", "    maxConcurrent: 2\n    echo:\n      deny: [put]\n", 1
)


async def test_max_concurrent_throttles_without_queueing_and_never_leaks(
    shortdir: Path,
) -> None:
    env = make_env(shortdir, targets=THROTTLE_TARGETS)
    async with running(env) as broker:
        await unlock(env)
        sock = env.agent_socket
        slots = broker.targets["echo-test"].slots
        slow = [
            asyncio.create_task(call(sock, "slow", "echo-test", args={"rows": 10, "delayMs": 200}))
            for _ in range(2)
        ]
        await wait_for(lambda: slots.used == 2)

        started = time.monotonic()
        third = error(await call(sock, "slow", "echo-test", args={"rows": 1}))
        assert time.monotonic() - started < 0.5
        assert (third["code"], third["retryAfter"]) == ("throttled", 1.0)
        assert "echo-test" in str(third["message"]) and "maxConcurrent 2" in str(third["message"])
        assert records(env, "throttled")[-1]["auditId"] == third["auditId"]

        # M6 decides before it takes the slot: a call the policy denies is denied, holding none.
        fourth = error(await call(sock, "put", "echo-test", args={"value": "x"}))
        assert (fourth["code"], fourth["layer"], fourth["rule"]) == ("denied", "target", "put")
        # A call that would fail only after the slot (its secret is gone) is throttled.
        write_secrets(env.secrets_file, {"echo-prod": SECRETS["echo-prod"]})
        fifth = error(await call(sock, "echo", "echo-test", args={"text": "x"}))
        assert fifth["code"] == "throttled"
        write_secrets(env.secrets_file, SECRETS)

        for frames in await asyncio.gather(*slow):
            assert frames[-1]["t"] == "trailer" and frames[-1]["rows"] == 10
        assert slots.used == 0

        for _ in range(100):
            assert error(await call(sock, "boom", "echo-test"))["code"] == "internal"
        assert slots.used == 0
        pair = await asyncio.gather(
            *(call(sock, "slow", "echo-test", args={"rows": 2, "delayMs": 50}) for _ in range(2))
        )
        assert [frames[-1]["t"] for frames in pair] == ["trailer", "trailer"]


async def test_the_call_deadline_ends_with_partial_rows_then_timeout(
    env: BrokerEnv, broker: Broker
) -> None:
    await unlock(env)
    started = time.monotonic()
    frames = await call(env.agent_socket, "slow", "echo-fast", args={"rows": 10, "delayMs": 300})
    assert time.monotonic() - started < 2.5
    kinds = [f["t"] for f in frames]
    assert kinds[0] == "header" and kinds[-1] == "error"
    assert 2 <= kinds.count("row") <= 4, kinds
    assert "trailer" not in kinds
    assert frames[-1]["code"] == "timeout"
    completion = records(env, "completion")[-1]
    assert (completion["outcome"], completion["cancelled"]) == ("cancelled", "timeout")
    assert completion["error"] == {"code": "timeout", "message": frames[-1]["message"]}
    assert broker.targets["echo-fast"].slots.used == 0
    assert env.connector.targets["echo-fast"].cancelled == ["slow"]


async def test_a_client_that_closes_mid_call_cancels_it(env: BrokerEnv, broker: Broker) -> None:
    await unlock(env)
    reader, writer = await asyncio.open_unix_connection(os.fspath(env.agent_socket))
    writer.write(line(request("slow", "echo-test", args={"rows": 50, "delayMs": 100})))
    await writer.drain()
    rows = 0
    while rows < 2:
        frame = json.loads(await reader.readline())
        rows += frame["t"] == "row"
    writer.close()
    closed = time.monotonic()

    def cancelled() -> bool:
        return any(r.get("cancelled") == "client" for r in records(env, "completion"))

    await wait_for(cancelled, timeout=1.0)
    assert time.monotonic() - closed < 1.0
    completion = records(env, "completion")[-1]
    assert (completion["outcome"], completion["cancelled"]) == ("cancelled", "client")
    assert completion["auditId"] == records(env, "decision")[-1]["auditId"]
    assert env.connector.targets["echo-test"].cancelled == ["slow"]
    assert broker.targets["echo-test"].slots.used == 0


async def test_scrub_is_partial_for_a_short_secret(shortdir: Path) -> None:
    short = {"echo-test": {"value": "abc123", "hosts": ["echo.example.net:7000"]}}
    env = make_env(shortdir, secrets={**SECRETS, **short})
    async with running(env):
        await unlock(env)
        described = result_data(
            await call(env.agent_socket, "describe", args={"target": "echo-test"})
        )
        assert described["scrub"] == "unknown (secret not resolved yet)"
        await call(env.agent_socket, "echo", "echo-test", args={"text": "x"})
        await call(env.agent_socket, "echo", "echo-prod", args={"text": "x"})
        test = result_data(await call(env.agent_socket, "describe", args={"target": "echo-test"}))
        prod = result_data(await call(env.agent_socket, "describe", args={"target": "echo-prod"}))
        assert (test["scrub"], prod["scrub"]) == ("partial", "full")
        assert test["pins"] == "not checked"
