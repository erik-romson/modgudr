"""Destination and environment pins (§4.3, M8).

A secret names the hosts it may be sent to, and may name the strictest environment it may be
used in. The pins live with the secret in the store, never in the policy, so an edited policy
file cannot send a secret anywhere new or relabel a production database as test.

**Sources.** Note-based stores (`bws`) return the secret's note. The note is untrusted text: only
strict `modgudr-hosts: <host[:port]>[, …]` and `modgudr-env: <name>` lines count, several
`modgudr-hosts` lines are unioned, and other lines are ignored with a warning. A line that starts
with `modgudr-` but is not one of the two strict forms refuses the secret: a mistyped pin is a
parse failure, never silently dropped. Structured stores (`file`) return `hosts` and `env`
directly; an entry carrying Bitwarden's URI match type 5 ("never") is skipped.

**Values.** A pin is `host[:port]`. A value with a scheme, userinfo or path refuses the secret.
Hosts are lowercased, IDNA-encoded and stripped of one trailing dot; IPv6 addresses go in
brackets. A pin without a port means the target's default port (Oracle 1521, Snowflake 443).

**Matching** is exact: the host string and the port. No wildcards, no suffix match, no DNS
lookup, so `10.0.0.5` never matches `db1.example.net`. A secret without host pins is never used
(D6).

**Environment.** The effective environment is the stricter of the target's environment and the
secret's `modgudr-env`, ordered by ceiling: the pin replaces the target's environment only when
its ceiling is lower. Aliases are canonicalised. An unknown name, or more than one `modgudr-env`,
refuses the secret.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from ..spi import Destination, PinEntry, ResolvedSecret, Risk
from .policy.load import Policy

HOSTS_KEY = "modgudr-hosts"
ENV_KEY = "modgudr-env"
#: Bitwarden's URI match type "never": the entry is not used for pinning.
MATCH_NEVER = 5

#: The `rule` of a pin refusal (layer `pinning`).
RULE_HOSTS = "hosts"
RULE_ENV = "env"
RULE_NOTE = "note"

_HOSTS_LINE = re.compile(r"modgudr-hosts:[ \t]*(\S.*?)[ \t]*")
_ENV_LINE = re.compile(r"modgudr-env:[ \t]*([a-z0-9][a-z0-9_-]*)[ \t]*")
_HOST_NAME = re.compile(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)*")
_PORT = re.compile(r"[0-9]{1,5}")
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")


class PinError(Exception):
    """The secret's pins refuse it: `denied`, layer `pinning`. The message never holds a value
    that failed to parse (a pin with userinfo may carry a password)."""

    def __init__(self, message: str, *, rule: str) -> None:
        super().__init__(message)
        self.message = message
        self.rule = rule


@dataclass(frozen=True)
class HostPin:
    """A canonical destination pin. `port` None means the target's default port."""

    host: str
    port: int | None = None

    def __str__(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return host if self.port is None else f"{host}:{self.port}"


@dataclass(frozen=True)
class Pins:
    hosts: tuple[HostPin, ...] = ()
    #: Environment names as the store wrote them (not yet canonical).
    env: tuple[str, ...] = ()
    #: Ignored note lines and skipped entries, for the broker's log.
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class EnvPin:
    """The effective environment of a target with a secret (M8)."""

    #: The environment the final decision uses.
    env: str
    #: The secret's `modgudr-env`, canonical; None when the secret has none.
    pinned: str | None = None


def canonical_host(text: str) -> str:
    """Lowercase, IDNA, one trailing dot stripped. Raises ValueError saying what is wrong."""
    host = text.strip()
    if host.endswith("."):
        host = host[:-1]
    if not host:
        raise ValueError("the host is empty")
    if ":" in host:
        try:
            return str(ipaddress.IPv6Address(host))
        except ValueError:
            raise ValueError("the host is not a valid IPv6 address") from None
    try:
        encoded = host.lower().encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("the host is not a valid host name") from None
    if not _HOST_NAME.fullmatch(encoded):
        raise ValueError("the host is not a valid host name")
    return encoded


def parse_host(text: str) -> HostPin:
    """One `host[:port]` pin. Raises ValueError saying what is wrong, never echoing the value."""
    value = text.strip()
    if not value:
        raise ValueError("it is empty")
    if _SCHEME.match(value) or "://" in value:
        raise ValueError("it has a scheme; write host[:port]")
    if "@" in value:
        raise ValueError("it has userinfo (user@); write host[:port]")
    if any(c in value for c in "/?#"):
        raise ValueError("it has a path; write host[:port]")
    if any(c.isspace() for c in value):
        raise ValueError("it holds whitespace")
    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            raise ValueError("an IPv6 address needs its closing bracket")
        host = canonical_host(value[1:end])
        if ":" not in host:
            raise ValueError("only an IPv6 address goes in brackets")
        rest = value[end + 1 :]
    else:
        if value.count(":") > 1:
            raise ValueError("an IPv6 address must be in brackets")
        name, sep, port_text = value.partition(":")
        host = canonical_host(name)
        rest = f":{port_text}" if sep else ""
    if not rest:
        return HostPin(host)
    port_text = rest[1:]
    if not rest.startswith(":") or not _PORT.fullmatch(port_text) or not 0 < int(port_text) < 65536:
        raise ValueError("its port is not a number from 1 to 65535")
    return HostPin(host, int(port_text))


def parse_note(note: str) -> Pins:
    """The strict pin lines of a note. Raises PinError for a malformed `modgudr-` line."""
    hosts: list[HostPin] = []
    envs: list[str] = []
    warnings: list[str] = []
    for number, raw in enumerate(note.splitlines(), 1):
        line = raw.rstrip()
        if not line:
            continue
        hosts_line = _HOSTS_LINE.fullmatch(line)
        if hosts_line is not None:
            for index, item in enumerate(hosts_line.group(1).split(","), 1):
                try:
                    hosts.append(parse_host(item))
                except ValueError as exc:
                    raise PinError(
                        f"line {number} of the note: {HOSTS_KEY} value {index} is not "
                        f"host[:port]: {exc}",
                        rule=RULE_HOSTS,
                    ) from None
            continue
        env_line = _ENV_LINE.fullmatch(line)
        if env_line is not None:
            envs.append(env_line.group(1))
            continue
        if line.strip().lower().startswith("modgudr-"):
            raise PinError(
                f"line {number} of the note starts with 'modgudr-' but is neither "
                f"'{HOSTS_KEY}: host[:port], …' nor '{ENV_KEY}: <environment>'",
                rule=RULE_NOTE,
            )
        warnings.append(f"line {number} of the note is not a pin line; ignored")
    return Pins(tuple(hosts), tuple(envs), tuple(warnings))


def pins_of(secret: ResolvedSecret) -> Pins:
    """Every pin of a resolved secret: its note's lines and its structured `hosts` and `env`."""
    from_note = parse_note(secret.note) if secret.note else Pins()
    hosts = list(from_note.hosts)
    warnings = list(from_note.warnings)
    for index, entry in enumerate(secret.hosts, 1):
        value, match = (entry.value, entry.match) if isinstance(entry, PinEntry) else (entry, None)
        if match == MATCH_NEVER:
            warnings.append(f"hosts entry {index} has match type {MATCH_NEVER} (never); skipped")
            continue
        try:
            hosts.append(parse_host(value))
        except ValueError as exc:
            raise PinError(
                f"hosts entry {index} of secret {secret.ref} is not host[:port]: {exc}",
                rule=RULE_HOSTS,
            ) from None
    return Pins(
        tuple(dict.fromkeys(hosts)),
        from_note.env + tuple(secret.env),
        tuple(warnings),
    )


def host_matches(pin: HostPin, destination: Destination, default_port: int) -> bool:
    """Exact host and exact port; a pin without a port means `default_port`."""
    try:
        host = canonical_host(destination.host)
    except ValueError:
        return False
    port = default_port if pin.port is None else pin.port
    return pin.host == host and port == destination.port


def check_destinations(
    pins: Pins,
    destinations: Iterable[Destination],
    default_port: int,
    *,
    secret: str,
    target: str,
) -> None:
    """Every destination must match a pin (M8). Raises PinError (layer `pinning`)."""
    wanted = sorted(destinations, key=str)
    if not pins.hosts:
        example = ", ".join(str(d) for d in wanted) or "<host>:<port>"
        raise PinError(
            f"secret {secret} has no destination pins, and a secret without pins is never used; "
            f"target {target} cannot use it. Add the hosts it contacts to the secret in the "
            f"store: a line '{HOSTS_KEY}: {example}' in its note, or "
            f"'hosts: [{example}]' in its file-store entry",
            rule=RULE_HOSTS,
        )
    unmatched = [d for d in wanted if not any(host_matches(p, d, default_port) for p in pins.hosts)]
    if unmatched:
        raise PinError(
            f"target {target} contacts {', '.join(str(d) for d in unmatched)}, which no pin of "
            f"secret {secret} allows (pins: {', '.join(str(p) for p in pins.hosts)}; a pin "
            f"without a port means port {default_port}). The pins live with the secret in the "
            "store, not in the policy",
            rule=RULE_HOSTS,
        )


def env_pin(policy: Policy, declared: str, pinned: Sequence[str], *, secret: str) -> EnvPin:
    """The effective environment: the stricter of `declared` and the secret's pin, by ceiling."""
    if not pinned:
        return EnvPin(declared)
    if len(pinned) > 1:
        raise PinError(
            f"secret {secret} has {len(pinned)} environment pins ({', '.join(pinned)}); "
            f"at most one {ENV_KEY} is allowed, so the secret is refused",
            rule=RULE_ENV,
        )
    canonical = policy.canonical_env(pinned[0])
    if canonical is None:
        raise PinError(
            f"secret {secret} is pinned to environment {pinned[0]!r}, which the policy does not "
            f"define (valid: {policy.env_listing()}), so the secret is refused",
            rule=RULE_ENV,
        )
    environments = policy.company.environments
    if Risk(environments[canonical].ceiling) < Risk(environments[declared].ceiling):
        return EnvPin(canonical, canonical)
    return EnvPin(declared, canonical)
