"""Policy lint (M10): everything the loader refuses, plus catalogue checks and warnings.

`lint_policy` is the library entry; `lint_main` is the offline entry that
`modgudr-broker lint [--policy-dir]` dispatches to.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, TextIO

from modgudr.client import paths

from .load import Fstat, Policy, PolicyError, load_policy
from .model import RISK_CLASSES, RuleBlock
from .registry import ConnectorPolicy, PolicyRegistry, action_matches

Severity = Literal["error", "warning", "info"]
EXIT_CONFIG = 78
EXIT_USAGE = 64


@dataclass(frozen=True)
class Finding:
    severity: Severity
    file: str | None
    key: str
    message: str

    def __str__(self) -> str:
        where = ": ".join(part for part in (self.file, self.key) if part)
        return (
            f"{self.severity}: {where}: {self.message}"
            if where
            else f"{self.severity}: {self.message}"
        )


@dataclass(frozen=True)
class LintReport:
    findings: tuple[Finding, ...]

    @property
    def errors(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.severity == "error")

    @property
    def ok(self) -> bool:
        return not self.errors


class StoreSession(Protocol):
    """An unlocked store session: step 07 implements the pin check."""

    def check_pins(self, target_name: str, secret: str) -> Sequence[str]:
        """Problems with the pins of one secret (empty when it is fine)."""
        ...


def lint_policy(
    policy_dir: Path,
    registry: PolicyRegistry,
    *,
    dev: bool = False,
    uid: int | None = None,
    fstat: Fstat = os.fstat,
    store_session: StoreSession | None = None,
) -> LintReport:
    try:
        policy = load_policy(policy_dir, registry, dev=dev, uid=uid, fstat=fstat)
    except PolicyError as exc:
        return LintReport(tuple(Finding("error", p.file, p.key, p.message) for p in exc.problems))
    findings: list[Finding] = []
    _lint_default_env(policy, findings)
    _lint_guard(policy, registry, findings)
    _lint_environments(policy, registry, findings)
    _lint_targets(policy, registry, findings)
    _lint_pins(policy, store_session, findings)
    return LintReport(tuple(findings))


def _lint_default_env(policy: Policy, findings: list[Finding]) -> None:
    env = policy.company.defaults.env
    if "prod" in env or "prod" in policy.default_env:
        findings.append(
            Finding(
                "warning",
                "00-company.yaml",
                "defaults.env",
                f"the default environment {env!r} contains 'prod'; "
                "a call without @env would reach it. Prefer the least privileged non-prod "
                "environment",
            )
        )


def _lint_guard(policy: Policy, registry: PolicyRegistry, findings: list[Finding]) -> None:
    for index, entry in enumerate(policy.company.guard.forbid):
        key = f"guard.forbid[{index}]"
        type_name, _, pattern = entry.partition(":")
        connector = registry.connector(type_name)
        if connector is None:
            findings.append(
                Finding("error", "00-company.yaml", key, f"unknown connector type {type_name!r}")
            )
        elif not connector.has_action(pattern):
            findings.append(
                Finding(
                    "error", "00-company.yaml", key, f"unknown action {pattern!r} for {type_name}"
                )
            )


def _lint_environments(policy: Policy, registry: PolicyRegistry, findings: list[Finding]) -> None:
    for env, config in policy.company.environments.items():
        for type_name, block in config.rules.items():
            _lint_block(
                "00-company.yaml",
                f"environments.{env}.{type_name}",
                type_name,
                block,
                registry,
                findings,
            )


def _lint_targets(policy: Policy, registry: PolicyRegistry, findings: list[Finding]) -> None:
    for name, target in policy.targets.items():
        for type_name, block in target.rules.items():
            _lint_block(None, f"targets.{name}.{type_name}", type_name, block, registry, findings)


def _lint_block(
    file: str | None,
    key: str,
    type_name: str,
    block: RuleBlock,
    registry: PolicyRegistry,
    findings: list[Finding],
) -> None:
    """Check one rule block against the connector's catalogue (`all` checks against every one)."""
    specs: Sequence[ConnectorPolicy]
    if type_name == "all":
        specs = registry.connectors()
    else:
        connector = registry.connector(type_name)
        if connector is None:
            findings.append(Finding("error", file, key, f"unknown connector type {type_name!r}"))
            return
        specs = (connector,)
    for field_name in ("allow", "deny"):
        for index, pattern in enumerate(getattr(block, field_name)):
            if pattern in RISK_CLASSES or any(s.has_action(pattern) for s in specs):
                continue
            findings.append(
                Finding(
                    "error", file, f"{key}.{field_name}[{index}]", f"unknown action {pattern!r}"
                )
            )
    for pattern, constraints in block.constraints.items():
        matched = {a for s in specs for a in s.actions if action_matches(pattern, a)}
        where = f"{key}.constraints.{pattern}"
        if not matched:
            findings.append(Finding("error", file, where, f"unknown action {pattern!r}"))
            continue
        for constraint in constraints:
            if not _constraint_supported(constraint, matched, specs):
                findings.append(
                    Finding(
                        "error",
                        file,
                        f"{where}.{constraint}",
                        f"constraint {constraint!r} is not supported for action {pattern!r}",
                    )
                )


def _constraint_supported(
    constraint: str, actions: set[str], specs: Sequence[ConnectorPolicy]
) -> bool:
    return all(any(s.supports(constraint, action) for s in specs) for action in actions)


def _lint_pins(policy: Policy, store_session: StoreSession | None, findings: list[Finding]) -> None:
    for name, target in policy.targets.items():
        if target.secret is None:
            continue
        key = f"targets.{name}.secret"
        if store_session is None:
            findings.append(Finding("info", None, key, "pins not checked (store locked)"))
            continue
        for problem in store_session.check_pins(name, target.secret):
            findings.append(Finding("error", None, key, problem))


def lint_main(
    argv: Sequence[str],
    registry: PolicyRegistry,
    *,
    environ: Mapping[str, str] | None = None,
    out: TextIO | None = None,
    err: TextIO | None = None,
    uid: int | None = None,
    fstat: Fstat = os.fstat,
) -> int:
    """`modgudr-broker lint [--policy-dir DIR]`, offline. Exit 0, 78 on errors, 64 on usage."""
    stdout = sys.stdout if out is None else out
    stderr = sys.stderr if err is None else err
    parser = argparse.ArgumentParser(prog="modgudr-broker lint", exit_on_error=False)
    parser.add_argument("--policy-dir", type=Path, default=None)
    try:
        args = parser.parse_args(list(argv))
    except (argparse.ArgumentError, SystemExit):
        print("usage: modgudr-broker lint [--policy-dir DIR]", file=stderr)
        return EXIT_USAGE
    policy_dir: Path | None = args.policy_dir
    if policy_dir is None:
        policy_dir = paths.modgudr_home(env=environ) / "policy.d"
    report = lint_policy(policy_dir, registry, uid=uid, fstat=fstat)
    for finding in report.findings:
        print(finding, file=stdout)
    return 0 if report.ok else EXIT_CONFIG
