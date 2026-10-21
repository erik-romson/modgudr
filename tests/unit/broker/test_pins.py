"""Destination and environment pins (M8): parsing, matching, the environment pin, and M6 step 7
through an in-process broker."""

from __future__ import annotations

from pathlib import Path

import pytest

from modgudr.broker.app import build
from modgudr.broker.pins import (
    EnvPin,
    HostPin,
    PinError,
    canonical_host,
    check_destinations,
    env_pin,
    host_matches,
    parse_host,
    parse_note,
    pins_of,
)
from modgudr.broker.policy.load import Policy
from modgudr.spi import Destination, PinEntry, ResolvedSecret, SecretRef
from tests.support.brokerfx import (
    SECRET,
    SECRETS,
    BrokerEnv,
    call,
    error,
    make_env,
    read_audit,
    running,
    unlock,
)

ORACLE = 1521
REF = SecretRef("file", "db1")


def secret(
    *,
    note: str | None = None,
    hosts: tuple[str | PinEntry, ...] = (),
    env: tuple[str, ...] = (),
) -> ResolvedSecret:
    return ResolvedSecret(REF, "pa55word-long", note=note, hosts=hosts, env=env)


# --- destination pins --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("destination", "matches"),
    [
        (Destination("db1.example.net", 1521), True),
        (Destination("DB1.Example.NET.", 1521), True),
        (Destination("db1.example.net", 1522), False),
        (Destination("db2.example.net", 1521), False),
        (Destination("10.0.0.5", 1521), False),
        # A target configured without a port connects to the dialect default.
        (Destination("db1.example.net", ORACLE), True),
    ],
    ids=["exact", "case-and-dot", "other-port", "other-host", "ip-address", "default-port"],
)
def test_pin_with_a_port(destination: Destination, matches: bool) -> None:
    assert host_matches(parse_host("db1.example.net:1521"), destination, ORACLE) is matches


def test_a_pin_without_a_port_means_the_default_port() -> None:
    pin = parse_host("db1.example.net")
    assert pin == HostPin("db1.example.net", None)
    assert host_matches(pin, Destination("db1.example.net", 1521), ORACLE)
    assert not host_matches(pin, Destination("db1.example.net", 1522), ORACLE)
    assert host_matches(pin, Destination("acme-example.snowflakecomputing.com", 443), 443) is False


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("https://user@db1.example.net:1521", "scheme"),
        ("user:pw@db1.example.net:1521", "userinfo"),
        ("oracle://db1.example.net:1521", "scheme"),
        ("db1.example.net:1521/ORCL", "path"),
        ("db1.example.net:port", "port"),
        ("db1.example.net:0", "port"),
        ("db1.example.net:65536", "port"),
        ("db1 example.net", "whitespace"),
        ("", "empty"),
        ("::1", "brackets"),
        ("db1..example.net", "host name"),
    ],
)
def test_malformed_pins_are_rejected_without_echoing_them(text: str, reason: str) -> None:
    with pytest.raises(ValueError, match=reason) as caught:
        parse_host(text)
    if text:
        assert text not in str(caught.value)
    assert "pw" not in str(caught.value)


def test_hosts_are_canonical_idna_and_ipv6() -> None:
    assert canonical_host("Bücher.Example.") == "xn--bcher-kva.example"
    assert parse_host("[2001:DB8::1]:1521") == HostPin("2001:db8::1", 1521)
    assert host_matches(parse_host("[2001:db8::1]:1521"), Destination("2001:DB8:0::1", 1521), 1)
    assert str(HostPin("2001:db8::1", 1521)) == "[2001:db8::1]:1521"


def test_note_lines_are_strict_and_unioned() -> None:
    note = (
        "Snowflake key of the diag user\r\n"
        "modgudr-hosts: db1.example.net:1521, db2.example.net\n"
        "modgudr-hosts: db1.example.net:1521\n"
        "\n"
        "modgudr-env: test\n"
        "see the runbook\n"
    )
    pins = parse_note(note)
    assert pins.hosts == (
        HostPin("db1.example.net", 1521),
        HostPin("db2.example.net"),
        HostPin("db1.example.net", 1521),
    )
    assert pins.env == ("test",)
    assert pins.warnings == (
        "line 1 of the note is not a pin line; ignored",
        "line 6 of the note is not a pin line; ignored",
    )
    assert pins_of(secret(note=note)).hosts == (
        HostPin("db1.example.net", 1521),
        HostPin("db2.example.net"),
    )


@pytest.mark.parametrize(
    "line",
    [
        "modgudr-hosts: https://user:hunter2@db1.example.net",
        "modgudr-hosts: db1.example.net:1521,",
        "Modgudr-Hosts: db1.example.net",
        "  modgudr-env: prod",
        "modgudr-env: prod test",
        "modgudr-hostz: db1.example.net",
    ],
    ids=["uri", "trailing-comma", "case", "indented", "two-names", "unknown-key"],
)
def test_a_malformed_modgudr_line_refuses_the_secret(line: str) -> None:
    with pytest.raises(PinError) as caught:
        pins_of(secret(note=f"modgudr-hosts: db1.example.net\n{line}\n"))
    assert "hunter2" not in caught.value.message
    assert "line 2 of the note" in caught.value.message


def test_structured_hosts_skip_match_never_and_reject_userinfo() -> None:
    pins = pins_of(
        secret(
            hosts=(
                PinEntry("db1.example.net:1521", match=5),
                PinEntry("db2.example.net:1521", match=1),
                "db3.example.net",
            )
        )
    )
    assert pins.hosts == (HostPin("db2.example.net", 1521), HostPin("db3.example.net"))
    assert pins.warnings == ("hosts entry 1 has match type 5 (never); skipped",)
    with pytest.raises(PinError, match=r"db1\.example\.net:1521, which no pin"):
        check_destinations(
            pins, [Destination("db1.example.net", 1521)], ORACLE, secret="file:db1", target="t"
        )
    with pytest.raises(PinError, match=r"hosts entry 1 of secret file:db1 .* userinfo") as caught:
        pins_of(secret(hosts=("user:hunter2@db1.example.net:1521",)))
    assert "hunter2" not in caught.value.message


def test_a_secret_without_pins_is_refused_with_how_to_add_one() -> None:
    with pytest.raises(PinError) as caught:
        check_destinations(
            pins_of(secret()),
            [Destination("db1.example.net", 1521)],
            ORACLE,
            secret="file:db1",
            target="cbsl-test",
        )
    assert caught.value.rule == "hosts"
    message = caught.value.message
    assert "no destination pins" in message
    assert "modgudr-hosts: db1.example.net:1521" in message
    assert "hosts: [db1.example.net:1521]" in message


def test_a_destination_no_pin_allows_is_refused_naming_it() -> None:
    pins = pins_of(secret(hosts=("db1.example.net:1521",)))
    with pytest.raises(PinError) as caught:
        check_destinations(
            pins,
            [Destination("db1.example.net", 1521), Destination("evil.example.net", 1521)],
            ORACLE,
            secret="file:db1",
            target="cbsl-test",
        )
    assert "contacts evil.example.net:1521, which no pin of secret file:db1 allows" in (
        caught.value.message
    )
    check_destinations(pins, [Destination("db1.example.net", 1521)], ORACLE, secret="s", target="t")


# --- the environment pin -----------------------------------------------------------------------

ENV_COMPANY = """\
store:
  default: file
defaults:
  env: test
environments:
  test:
    aliases: [sol]
    ceiling: destructive
  stage:
    ceiling: write
  prod:
    ceiling: read
"""


@pytest.fixture
def policy(shortdir: Path) -> Policy:
    return build(make_env(shortdir, company=ENV_COMPANY).config).policy


@pytest.mark.parametrize(
    ("declared", "pinned", "effective"),
    [
        ("test", "prod", EnvPin("prod", "prod")),
        ("test", "test", EnvPin("test", "test")),
        ("test", "sol", EnvPin("test", "test")),
        ("test", "stage", EnvPin("stage", "stage")),
        ("prod", "test", EnvPin("prod", "test")),
        ("stage", "prod", EnvPin("prod", "prod")),
    ],
)
def test_the_stricter_environment_wins(
    policy: Policy, declared: str, pinned: str, effective: EnvPin
) -> None:
    assert env_pin(policy, declared, (pinned,), secret="file:db1") == effective


def test_no_environment_pin_keeps_the_declared_environment(policy: Policy) -> None:
    assert env_pin(policy, "test", (), secret="file:db1") == EnvPin("test", None)


def test_an_unknown_or_second_environment_pin_refuses_the_secret(policy: Policy) -> None:
    with pytest.raises(PinError, match="'production', which the policy does not define") as one:
        env_pin(policy, "test", ("production",), secret="file:db1")
    assert one.value.rule == "env"
    with pytest.raises(PinError, match="2 environment pins"):
        env_pin(policy, "test", ("test", "prod"), secret="file:db1")
    note_and_entry = pins_of(secret(note="modgudr-env: prod\n", env=("test",)))
    with pytest.raises(PinError, match="at most one modgudr-env"):
        env_pin(policy, "test", note_and_entry.env, secret="file:db1")


# --- M6 step 7 through the broker ----------------------------------------------------------------


def records(env: BrokerEnv, record_type: str) -> list[dict[str, object]]:
    return [r for r in read_audit(env.audit_dir) if r["type"] == record_type]


def with_secret(**entry: object) -> dict[str, dict[str, object]]:
    return {**SECRETS, "echo-test": {"value": SECRET, **entry}}


async def test_a_secret_without_pins_is_denied_at_layer_pinning(shortdir: Path) -> None:
    env = make_env(shortdir, secrets=with_secret())
    async with running(env):
        await unlock(env)
        err = error(await call(env.agent_socket, "echo", "echo-test", args={"text": "x"}))
    assert (err["code"], err["layer"], err["rule"]) == ("denied", "pinning", "hosts")
    assert "hosts: [echo.example.net:7000]" in str(err["message"])
    assert env.connector.targets["echo-test"].executed == []
    (record,) = records(env, "denied")
    assert (record["layer"], record["decision"], record["auditId"]) == (
        "pinning",
        "deny",
        err["auditId"],
    )
    assert not records(env, "decision")


async def test_a_destination_mismatch_is_denied_before_anything_is_contacted(
    shortdir: Path,
) -> None:
    env = make_env(shortdir, secrets=with_secret(hosts=["echo.example.net:7001"]))
    async with running(env):
        await unlock(env)
        err = error(await call(env.agent_socket, "auth", "echo-test"))
    assert (err["code"], err["layer"]) == ("denied", "pinning")
    assert "echo.example.net:7000" in str(err["message"])
    assert env.connector.targets["echo-test"].opens == 0


async def test_a_pin_without_a_port_matches_the_targets_default_port(shortdir: Path) -> None:
    env = make_env(shortdir, secrets=with_secret(hosts=["ECHO.example.net."]))
    async with running(env):
        await unlock(env)
        frames = await call(env.agent_socket, "echo", "echo-test", args={"text": "x"})
    assert frames[-1]["t"] == "trailer"


async def test_an_environment_pin_to_prod_holds_a_test_target_to_prod(shortdir: Path) -> None:
    env = make_env(shortdir, secrets=with_secret(hosts=["echo.example.net:7000"], env="prod"))
    async with running(env):
        await unlock(env)
        read = await call(env.agent_socket, "echo", "echo-test", args={"text": "x"})
        assert read[-1]["t"] == "trailer"
        err = error(await call(env.agent_socket, "put", "echo-test", args={"value": "v"}))
    assert (err["code"], err["layer"], err["rule"]) == ("denied", "ceiling", "read")
    assert "pinned to prod by the secret file:echo-test" in str(err["message"])
    assert "Environment prod allows read only" in str(err["message"])
    decision = records(env, "decision")[0]
    assert (decision["env"], decision["effectiveEnv"], decision["secretEnv"]) == (
        "test",
        "prod",
        "prod",
    )
    denied = records(env, "denied")[-1]
    assert (denied["effectiveEnv"], denied["layer"]) == ("prod", "ceiling")
    assert env.connector.targets["echo-test"].executed == ["echo"]


@pytest.mark.parametrize(
    ("pinned", "code"),
    [("production", "denied"), ("sol", None)],
    ids=["unknown", "alias"],
)
async def test_unknown_environment_pins_refuse_and_aliases_canonicalise(
    shortdir: Path, pinned: str, code: str | None
) -> None:
    env = make_env(shortdir, secrets=with_secret(hosts=["echo.example.net:7000"], env=pinned))
    async with running(env):
        await unlock(env)
        frames = await call(env.agent_socket, "put", "echo-test", args={"value": "v"})
    if code is None:
        assert frames[-1]["t"] == "trailer"
        decision = records(env, "decision")[0]
        assert (decision["effectiveEnv"], decision["secretEnv"]) == ("test", "test")
    else:
        err = error(frames)
        assert (err["code"], err["layer"], err["rule"]) == (code, "pinning", "env")
