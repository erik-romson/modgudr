"""Target resolution (M6 step 2): exact name, `system@env`, the request's env, `defaults.env`."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .load import Policy
from .model import TargetConfig

EnvSource = Literal["explicit", "session", "default"]


class ResolveError(Exception):
    """The target cannot be resolved. The wire code is always `not_found`."""

    code = "not_found"


@dataclass(frozen=True)
class Resolved:
    target: TargetConfig
    #: Canonical environment name of the target.
    env: str
    env_source: EnvSource


def resolve_target(policy: Policy, name: str, env_field: str | None = None) -> Resolved:
    """Resolve a request's `target` and `env` fields. Raises ResolveError (`not_found`)."""
    exact = policy.targets.get(name)
    if exact is not None:
        return Resolved(exact, exact.env, "explicit")
    if "@" in name:
        return _resolve_system_at_env(policy, name)
    systems = policy.systems()
    if name not in systems:
        raise ResolveError(
            f"unknown target or system {name!r}; targets: {', '.join(sorted(policy.targets))}"
        )
    if env_field is not None:
        env, source, origin = env_field, "session", "the request's env field (MODGUDR_ENV)"
    else:
        env, source, origin = policy.company.defaults.env, "default", "defaults.env"
    canonical = policy.canonical_env(env)
    if canonical is None:
        raise ResolveError(
            f"environment {env!r} (from {origin}) is not defined; valid: {policy.env_listing()}"
        )
    note = f" [environment {canonical!r} comes from {origin}]"
    return Resolved(_in_env(policy, name, canonical, note), canonical, source)


def _resolve_system_at_env(policy: Policy, name: str) -> Resolved:
    parts = name.split("@")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ResolveError(f"malformed target {name!r}; expected system@env")
    system, env = parts
    if system not in policy.systems():
        raise ResolveError(f"unknown system {system!r} in {name!r}")
    canonical = policy.canonical_env(env)
    if canonical is None:
        raise ResolveError(
            f"environment {env!r} in {name!r} is not defined; valid: {policy.env_listing()}"
        )
    return Resolved(_in_env(policy, system, canonical, ""), canonical, "explicit")


def _in_env(policy: Policy, system: str, env: str, note: str) -> TargetConfig:
    members = policy.systems()[system]
    for target in members:
        if target.env == env:
            return target
    available = ", ".join(t.env for t in members)
    raise ResolveError(f"system {system} has no target in env {env}; available: {available}{note}")
