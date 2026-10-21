"""Destinations, secret references, resolved secrets and minted tokens (§4.3, §8.4, M8)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Destination:
    """A host and port a target contacts. Every destination must match a pin of its secret (M8)."""

    host: str
    port: int

    def __str__(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"


@dataclass(frozen=True)
class SecretRef:
    """A reference into a secret store: `<store>:<item>` (`bws:2f1c…`, `file:sf-key`)."""

    store: str
    item: str

    @classmethod
    def parse(cls, text: str) -> SecretRef:
        store, sep, item = text.partition(":")
        if not sep or not store or not item:
            raise ValueError(f"invalid secret reference {text!r}: expected <store>:<item>")
        return cls(store, item)

    def __str__(self) -> str:
        return f"{self.store}:{self.item}"


@dataclass(frozen=True)
class ResolvedSecret:
    """A secret value with the pins its store holds for it (§4.3, M8).

    Note-based stores (`bws`) return the item's `note`; the broker parses its strict
    `modgudr-hosts:` and `modgudr-env:` lines. Structured stores (`file`) fill `hosts` and `env`
    directly. The value is never part of the repr.
    """

    ref: SecretRef
    value: str = field(repr=False)
    note: str | None = None
    #: Raw `host[:port]` pins.
    hosts: tuple[str, ...] = ()
    #: Raw environment pins; more than one refuses the secret.
    env: tuple[str, ...] = ()


@dataclass(frozen=True)
class TokenRequest:
    """What a credential provider mints a token for (§8.4, M18)."""

    target: str
    #: The target's `credential.tier`: `borrowed` uses the developer's own login, `custody` the
    #: broker's own state directory.
    tier: str
    #: The resource the token is for (the AKS server application id).
    resource: str
    #: The provider's own state directory (custody), else None.
    state_dir: str | None = None


@dataclass(frozen=True)
class MintedToken:
    """A short-lived token. The broker registers it with the scrubber when it is minted (M8)."""

    value: str = field(repr=False)
    #: Expiry as seconds since the epoch.
    expires_at: float
