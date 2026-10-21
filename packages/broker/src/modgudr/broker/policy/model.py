"""Policy models (M10): pydantic 2, `extra="forbid"`, `frozen=True`.

The company file holds `store`, `defaults`, `guard` and `environments`; a targets file holds
`targets`. The core validates the common target keys; the connector's `config_model` validates the
rest (see `build_target`).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Annotated, Literal, cast

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from .registry import ConnectorPolicy

NOT_SUPPORTED = "not supported in this version"

#: Keys the pre-plan defines for later slices. Refused, never ignored.
LATER_SLICE_KEYS = frozenset(
    {
        "channels",
        "maxCallsPerMinute",
        "breaker",
        "columns",
        "sessionRole",
        "unattended",
        "presets",
        "allowSecretActions",
        "auditRetention",
        "tokenFile",
    }
)

RESERVED_NAMES = frozenset(
    {
        "targets",
        "describe",
        "explain",
        "actions",
        "policy",
        "status",
        "doctor",
        "unlock",
        "lock",
        "audit",
        "agent",
        "agent-setup",
        "agent-docs",
        "login",
        "help",
        "version",
    }
)

COMPANY_KEYS = frozenset({"store", "defaults", "guard", "environments"})
TARGETS_KEYS = frozenset({"targets"})

#: The risk classes a rule may name. The order is the ceiling order for the first four.
CEILINGS = ("read", "write", "destructive", "admin")
RISK_CLASSES = frozenset({*CEILINGS, "secret", "unknown"})

_NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]*")
_CONSTRAINT_RE = re.compile(r"[A-Za-z][A-Za-z0-9]*")
_PATTERN_RE = re.compile(r"[a-z0-9_./*-]+")
_GUARD_RE = re.compile(r"[a-z0-9][a-z0-9_-]*:[a-z0-9_./*-]+")
_SECRET_RE = re.compile(r"[a-z][a-z0-9_-]*:\S.*")
_DURATION_RE = re.compile(r"(\d+)(s|m|h|d)")
_SIZE_RE = re.compile(r"(\d+)(B|KiB|MiB|GiB)")
_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_SIZE_UNITS = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3}


def _check_name(value: str) -> str:
    if not _NAME_RE.fullmatch(value):
        raise ValueError(f"invalid name {value!r}: must match [a-z0-9][a-z0-9_-]*")
    return value


def _check_target_name(value: str) -> str:
    _check_name(value)
    if value in RESERVED_NAMES:
        raise ValueError(f"{value!r} is a reserved name")
    return value


def _check_constraint_name(value: str) -> str:
    if not _CONSTRAINT_RE.fullmatch(value):
        raise ValueError(f"invalid constraint name {value!r}")
    return value


def _check_pattern(value: str) -> str:
    if not _PATTERN_RE.fullmatch(value):
        raise ValueError(f"invalid rule {value!r}: use a risk class, an action or a wildcard")
    return value


def _check_guard(value: str) -> str:
    if not _GUARD_RE.fullmatch(value):
        raise ValueError(f"invalid guard rule {value!r}: expected <connector>:<action>")
    return value


def _check_secret(value: str) -> str:
    if not _SECRET_RE.fullmatch(value):
        raise ValueError(f"invalid secret reference {value!r}: expected <store>:<item>")
    return value


Name = Annotated[str, AfterValidator(_check_name)]
ConstraintName = Annotated[str, AfterValidator(_check_constraint_name)]
TargetName = Annotated[str, AfterValidator(_check_target_name)]
Pattern = Annotated[str, AfterValidator(_check_pattern)]
GuardPattern = Annotated[str, AfterValidator(_check_guard)]
SecretRef = Annotated[str, AfterValidator(_check_secret)]
PosInt = Annotated[int, Field(strict=True, gt=0)]
ConstraintValue = bool | int | str | tuple[str, ...]


def parse_duration(value: object) -> float:
    """`30s`, `5m`, `1h`, `1d` to seconds."""
    match = _DURATION_RE.fullmatch(value) if isinstance(value, str) else None
    if match is None or int(match.group(1)) == 0:
        raise ValueError("expected a duration such as 30s, 5m or 1h")
    return float(int(match.group(1)) * _DURATION_UNITS[match.group(2)])


def parse_size(value: object) -> int:
    """`2MiB`, `512KiB`, `100B` to bytes."""
    match = _SIZE_RE.fullmatch(value) if isinstance(value, str) else None
    if match is None or int(match.group(1)) == 0:
        raise ValueError("expected a size such as 2MiB, 512KiB or 100B")
    return int(match.group(1)) * _SIZE_UNITS[match.group(2)]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class RuleBlock(_Model):
    """`allow`, `deny` and `constraints` of one connector block (or `all`)."""

    allow: tuple[Pattern, ...] = ()
    deny: tuple[Pattern, ...] = ()
    constraints: dict[Pattern, dict[ConstraintName, ConstraintValue]] = Field(default_factory=dict)


class EnvironmentConfig(_Model):
    ceiling: Literal["read", "write", "destructive", "admin"]
    aliases: tuple[Name, ...] = ()
    #: Rule blocks by connector type (and `all`). Lint checks the type names.
    rules: dict[str, RuleBlock] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _split_rule_blocks(cls, data: object) -> object:
        if not isinstance(data, Mapping):
            return data
        raw = cast("Mapping[object, object]", data)
        known = ("ceiling", "aliases")
        out: dict[object, object] = {k: v for k, v in raw.items() if k in known}
        out["rules"] = {k: v for k, v in raw.items() if k not in known}
        return out


class StoreConfig(_Model):
    default: Name
    #: Per-store settings, for example `bws`; the store plugins validate them (step 14).
    stores: dict[Name, dict[str, object]] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _split_stores(cls, data: object) -> object:
        if not isinstance(data, Mapping):
            return data
        raw = cast("Mapping[object, object]", data)
        out: dict[object, object] = {k: v for k, v in raw.items() if k == "default"}
        out["stores"] = {k: v for k, v in raw.items() if k != "default"}
        return out


class Defaults(_Model):
    env: Name
    timeout: float = 30.0
    maxRows: PosInt = 500
    maxRowsHard: PosInt = 50000
    maxBytes: int = 2 * 1024**2
    maxRequestBytes: int = 1024**2
    maxConcurrent: PosInt = 4
    idleLock: float = 3600.0
    absoluteLock: float = 36000.0

    @field_validator("timeout", "idleLock", "absoluteLock", mode="before")
    @classmethod
    def _duration(cls, value: object) -> float:
        return parse_duration(value)

    @field_validator("maxBytes", "maxRequestBytes", mode="before")
    @classmethod
    def _size(cls, value: object) -> int:
        return parse_size(value)


class Guard(_Model):
    forbid: tuple[GuardPattern, ...] = ()


class CompanyFile(_Model):
    store: StoreConfig
    defaults: Defaults
    guard: Guard = Field(default_factory=Guard)
    environments: dict[Name, EnvironmentConfig]


class Credential(_Model):
    tier: Literal["dedicated", "custody", "borrowed"]


class TargetConfig(_Model):
    """A target: the common keys of M10 plus the connector's validated `config`."""

    name: TargetName
    type: Name
    env: Name
    system: TargetName | None = None
    credential: Credential
    secret: SecretRef | None = None
    provider: Name | None = None
    timeout: float | None = None
    maxRows: PosInt | None = None
    maxBytes: int | None = None
    maxConcurrent: PosInt | None = None
    #: Rule blocks by connector type (the target's own) and `all`.
    rules: dict[str, RuleBlock] = Field(default_factory=dict)
    #: The connector's own keys, validated by its `config_model`.
    config: BaseModel

    @field_validator("timeout", mode="before")
    @classmethod
    def _duration(cls, value: object) -> float | None:
        return None if value is None else parse_duration(value)

    @field_validator("maxBytes", mode="before")
    @classmethod
    def _size(cls, value: object) -> int | None:
        return None if value is None else parse_size(value)

    @model_validator(mode="after")
    def _secret_xor_provider(self) -> TargetConfig:
        if (self.secret is None) == (self.provider is None):
            raise ValueError("exactly one of 'secret' and 'provider' is required")
        return self


COMMON_TARGET_KEYS = frozenset(
    {
        "type",
        "env",
        "system",
        "credential",
        "secret",
        "provider",
        "timeout",
        "maxRows",
        "maxBytes",
        "maxConcurrent",
    }
)


class _NoConfig(_Model):
    """Stands in for the connector config while that config failed validation."""


class TargetKeyError(Exception):
    """A target that fails validation: `problems` are (key relative to the target, message)."""

    def __init__(self, problems: list[tuple[str, str]]) -> None:
        self.problems = problems
        super().__init__("; ".join(f"{key}: {message}" for key, message in problems))


def format_validation_error(exc: ValidationError, prefix: str = "") -> list[tuple[str, str]]:
    """Turn a pydantic error into (dotted key, message) pairs."""
    out: list[tuple[str, str]] = []
    for err in exc.errors():
        parts = [str(p) for p in err["loc"] if p != "[key]"]
        # `rules` and `stores` hold keys that are written directly under the parent in YAML.
        for synthetic in ("rules", "stores"):
            if synthetic in parts:
                parts.remove(synthetic)
        key = ".".join(([prefix] if prefix else []) + parts)
        if err["type"] == "extra_forbidden":
            message = "unknown key"
        elif err["type"] == "missing":
            message = "required key is missing"
        elif err["type"] == "value_error":
            message = str(err["ctx"]["error"]) if "ctx" in err else err["msg"]
        else:
            message = err["msg"]
        out.append((key, message))
    return out


def build_target(
    name: str, raw: object, connector_for: Mapping[str, ConnectorPolicy]
) -> TargetConfig:
    """Validate one target. `connector_for` holds the registered connector types.

    The key named after the target's own type, and `all`, are rule blocks; every other key that is
    not a common key is validated by the connector's `config_model`.
    """
    if not isinstance(raw, Mapping):
        raise TargetKeyError([("", "a target must be a mapping")])
    data = cast("Mapping[str, object]", raw)
    type_name = data.get("type")
    if not isinstance(type_name, str) or not type_name:
        raise TargetKeyError([("type", "required key is missing")])
    connector = connector_for.get(type_name)
    if connector is None:
        known = ", ".join(sorted(connector_for)) or "none"
        raise TargetKeyError(
            [("type", f"no connector registered for type {type_name!r}; registered: {known}")]
        )
    block_keys = (type_name, "all")
    common = {k: v for k, v in data.items() if k in COMMON_TARGET_KEYS}
    rules = {k: v for k, v in data.items() if k in block_keys}
    rest = {k: v for k, v in data.items() if k not in COMMON_TARGET_KEYS and k not in block_keys}
    problems: list[tuple[str, str]] = []
    config: BaseModel = _NoConfig()
    try:
        config = connector.config_model.model_validate(rest)
    except ValidationError as exc:
        problems.extend(format_validation_error(exc))
    try:
        target = TargetConfig.model_validate(
            {**common, "name": name, "rules": rules, "config": config}
        )
    except ValidationError as exc:
        # The target's own name is reported against the target itself.
        problems.extend(("" if k == "name" else k, m) for k, m in format_validation_error(exc))
        raise TargetKeyError(problems) from exc
    if problems:
        raise TargetKeyError(problems)
    return target
