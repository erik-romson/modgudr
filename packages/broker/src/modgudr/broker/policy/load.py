"""Load `policy.d/*.yaml` (M10): ownership, strict YAML, validation and the cross-file rules."""

from __future__ import annotations

import errno
import hashlib
import os
import re
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, cast

from pydantic import ValidationError

from .model import (
    COMPANY_KEYS,
    LATER_SLICE_KEYS,
    NOT_SUPPORTED,
    TARGETS_KEYS,
    CompanyFile,
    EnvironmentConfig,
    TargetConfig,
    TargetKeyError,
    build_target,
    format_validation_error,
)
from .registry import ConnectorPolicy, PolicyRegistry
from .yaml_strict import StrictYamlError, load_strict

COMPANY_FILE = "00-company.yaml"
_TARGETS_FILE_RE = re.compile(r"5\d-.+\.yaml")


class StatLike(Protocol):
    @property
    def st_uid(self) -> int: ...

    @property
    def st_mode(self) -> int: ...


Fstat = Callable[[int], StatLike]


@dataclass(frozen=True)
class Problem:
    """One thing wrong with the policy: the file, the dotted key, and what is wrong."""

    file: str | None
    key: str
    message: str

    def __str__(self) -> str:
        return ": ".join(part for part in (self.file, self.key, self.message) if part)


class PolicyError(Exception):
    """The policy cannot be loaded. Every problem names its file and key."""

    def __init__(self, problems: list[Problem]) -> None:
        self.problems = tuple(problems)
        super().__init__("\n".join(str(p) for p in problems))


@dataclass(frozen=True)
class PolicyFile:
    """A loaded file with the facts step 06 records at start-up and compares for `status`."""

    name: str
    path: str
    sha256: str
    uid: int
    mode: int


@dataclass(frozen=True)
class Policy:
    company: CompanyFile
    #: In file-name order, then definition order. Environments are canonical names.
    targets: Mapping[str, TargetConfig]
    files: tuple[PolicyFile, ...]
    #: Environment names and aliases to the canonical environment name.
    env_names: Mapping[str, str] = field(default_factory=dict[str, str])

    @property
    def default_env(self) -> str:
        return self.env_names[self.company.defaults.env]

    def canonical_env(self, name: str) -> str | None:
        return self.env_names.get(name)

    def env_listing(self) -> str:
        return env_listing(self.company.environments)

    def systems(self) -> dict[str, tuple[TargetConfig, ...]]:
        out: dict[str, list[TargetConfig]] = {}
        for target in self.targets.values():
            if target.system is not None:
                out.setdefault(target.system, []).append(target)
        return {system: tuple(items) for system, items in out.items()}


def env_listing(environments: Mapping[str, EnvironmentConfig]) -> str:
    """`test (sol), stage (vfy), prod`."""
    parts: list[str] = []
    for name, env in environments.items():
        parts.append(f"{name} ({', '.join(env.aliases)})" if env.aliases else name)
    return ", ".join(parts)


def check_file_stat(name: str, st: StatLike, *, company: bool, dev: bool, uid: int) -> str | None:
    """The M10 ownership and mode rules for an opened file. Returns the refusal, or None."""
    if not stat.S_ISREG(st.st_mode):
        return "not a regular file"
    if st.st_mode & 0o022:
        return f"mode {stat.S_IMODE(st.st_mode):04o} is group- or world-writable"
    if company:
        if st.st_uid == 0 or (dev and st.st_uid == uid):
            return None
        wanted = "root" if not dev else "root or the current user (dev mode)"
        return f"the company file must be owned by {wanted}, not uid {st.st_uid}"
    if st.st_uid in (0, uid):
        return None
    return f"owner uid {st.st_uid} is neither root nor the current user"


def _walk_later_slice(data: object, path: str) -> list[Problem]:
    """Find later-slice keys at any depth. Target and environment names are not keys to check."""
    out: list[Problem] = []
    if isinstance(data, Mapping):
        for key, value in cast("Mapping[object, object]", data).items():
            child = f"{path}.{key}" if path else str(key)
            if key in LATER_SLICE_KEYS:
                out.append(Problem(None, child, NOT_SUPPORTED))
            elif key == "mode" and value == "unattended":
                out.append(Problem(None, child, f"mode 'unattended' is {NOT_SUPPORTED}"))
            elif path == "" and key in ("targets", "environments") and isinstance(value, Mapping):
                for name, item in cast("Mapping[object, object]", value).items():
                    out.extend(_walk_later_slice(item, f"{child}.{name}"))
            else:
                out.extend(_walk_later_slice(value, child))
    elif isinstance(data, list):
        for index, item in enumerate(cast("list[object]", data)):
            out.extend(_walk_later_slice(item, f"{path}[{index}]"))
    return out


@dataclass
class _Loaded:
    company: CompanyFile | None = None
    #: name -> (file, target)
    targets: dict[str, tuple[str, TargetConfig]] = field(
        default_factory=dict[str, tuple[str, TargetConfig]]
    )
    files: list[PolicyFile] = field(default_factory=list[PolicyFile])
    problems: list[Problem] = field(default_factory=list[Problem])


def load_policy(
    policy_dir: Path,
    registry: PolicyRegistry,
    *,
    dev: bool = False,
    uid: int | None = None,
    fstat: Fstat = os.fstat,
) -> Policy:
    """Load and validate the policy directory. Raises PolicyError naming file and key."""
    me = os.getuid() if uid is None else uid
    if not policy_dir.is_dir():
        raise PolicyError([Problem(None, "", f"policy directory {policy_dir} does not exist")])
    names = sorted(p.name for p in policy_dir.iterdir() if p.name.endswith(".yaml"))
    if COMPANY_FILE not in names:
        raise PolicyError(
            [Problem(None, "", f"required company file {policy_dir / COMPANY_FILE} is missing")]
        )
    connectors = {c.type: c for c in registry.connectors()}
    loaded = _Loaded()
    for name in names:
        is_company = name == COMPANY_FILE
        if not is_company and not _TARGETS_FILE_RE.fullmatch(name):
            loaded.problems.append(
                Problem(name, "", f"unexpected policy file; use {COMPANY_FILE} and 5x-*.yaml")
            )
            continue
        read = _read_policy_file(policy_dir / name, name, is_company, dev, me, fstat)
        if isinstance(read, Problem):
            loaded.problems.append(read)
            continue
        info, text = read
        loaded.files.append(info)
        try:
            data = load_strict(text, name)
        except StrictYamlError as exc:
            where = f"line {exc.line}: " if exc.line is not None else ""
            loaded.problems.append(Problem(name, exc.key or "", where + exc.message))
            continue
        if is_company:
            _load_company(loaded, name, data)
        else:
            _load_targets(loaded, name, data, connectors)
    return _finish(loaded)


def _read_policy_file(
    path: Path, name: str, company: bool, dev: bool, uid: int, fstat: Fstat
) -> tuple[PolicyFile, str] | Problem:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return Problem(name, "", "is a symlink; policy files must be regular files")
        return Problem(name, "", f"cannot be opened: {exc.strerror}")
    try:
        st = fstat(fd)
        refusal = check_file_stat(name, st, company=company, dev=dev, uid=uid)
        if refusal is not None:
            return Problem(name, "", refusal)
        with os.fdopen(fd, "rb", closefd=False) as handle:
            raw = handle.read()
    finally:
        os.close(fd)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return Problem(name, "", "is not valid UTF-8")
    info = PolicyFile(
        name=name,
        path=str(path),
        sha256=hashlib.sha256(raw).hexdigest(),
        uid=st.st_uid,
        mode=stat.S_IMODE(st.st_mode),
    )
    return info, text


def _top_level(
    loaded: _Loaded, name: str, data: object, allowed: frozenset[str], kind: str
) -> Mapping[str, object] | None:
    if not isinstance(data, Mapping):
        loaded.problems.append(Problem(name, "", "must be a mapping at the top level"))
        return None
    mapping = cast("Mapping[object, object]", data)
    ok = True
    for key in mapping:
        if key in allowed:
            continue
        ok = False
        if key in LATER_SLICE_KEYS:
            loaded.problems.append(Problem(name, str(key), NOT_SUPPORTED))
        elif key in COMPANY_KEYS | TARGETS_KEYS:
            loaded.problems.append(
                Problem(name, str(key), f"not allowed in {kind}; it belongs in the other file kind")
            )
        else:
            loaded.problems.append(Problem(name, str(key), "unknown key"))
    return cast("Mapping[str, object]", mapping) if ok else None


def _file_problems(name: str, problems: list[Problem]) -> list[Problem]:
    return [Problem(name, p.key, p.message) for p in problems]


def _load_company(loaded: _Loaded, name: str, data: object) -> None:
    mapping = _top_level(loaded, name, data, COMPANY_KEYS, "the company file")
    if mapping is None:
        return
    walk = _file_problems(name, _walk_later_slice(mapping, ""))
    loaded.problems.extend(walk)
    try:
        company = CompanyFile.model_validate(mapping)
    except ValidationError as exc:
        reported = {p.key for p in walk}
        loaded.problems.extend(
            Problem(name, key, message)
            for key, message in format_validation_error(exc)
            if key not in reported
        )
        return
    if not walk:
        loaded.company = company


def _load_targets(
    loaded: _Loaded, name: str, data: object, connectors: Mapping[str, ConnectorPolicy]
) -> None:
    mapping = _top_level(loaded, name, data, TARGETS_KEYS, "a targets file")
    if mapping is None:
        return
    walk = _file_problems(name, _walk_later_slice(mapping, ""))
    loaded.problems.extend(walk)
    reported = {p.key for p in walk}
    targets = mapping.get("targets")
    if not isinstance(targets, Mapping):
        loaded.problems.append(Problem(name, "targets", "must be a mapping of target names"))
        return
    for target_name, raw in cast("Mapping[object, object]", targets).items():
        base = f"targets.{target_name}"
        if not isinstance(target_name, str):
            loaded.problems.append(Problem(name, base, "target names must be strings"))
            continue
        try:
            target = build_target(target_name, raw, connectors)
        except TargetKeyError as exc:
            loaded.problems.extend(
                Problem(name, f"{base}.{key}" if key else base, message)
                for key, message in exc.problems
                if f"{base}.{key}" not in reported
            )
            continue
        earlier = loaded.targets.get(target_name)
        if earlier is not None:
            loaded.problems.append(
                Problem(name, base, f"target is already defined in {earlier[0]}")
            )
            continue
        loaded.targets[target_name] = (name, target)


def _finish(loaded: _Loaded) -> Policy:
    problems = loaded.problems
    company = loaded.company
    env_names: dict[str, str] = {}
    targets = dict(loaded.targets)
    if company is not None:
        env_names = _check_environments(company, problems)
        _check_default_env(company, env_names, problems)
        targets = _canonical_envs(company, env_names, targets, problems)
    _check_systems(targets, problems)
    if problems or company is None:
        raise PolicyError(problems)
    return Policy(
        company=company,
        targets={name: target for name, (_, target) in targets.items()},
        files=tuple(loaded.files),
        env_names=env_names,
    )


def _check_environments(company: CompanyFile, problems: list[Problem]) -> dict[str, str]:
    names: dict[str, str] = {env: env for env in company.environments}
    for env, config in company.environments.items():
        for alias in config.aliases:
            key = f"environments.{env}.aliases"
            if alias in names:
                owner = names[alias]
                kind = "an environment name" if alias == owner else f"an alias of {owner}"
                problems.append(Problem(COMPANY_FILE, key, f"alias {alias!r} is already {kind}"))
            else:
                names[alias] = env
    return names


def _check_default_env(
    company: CompanyFile, env_names: Mapping[str, str], problems: list[Problem]
) -> None:
    if company.defaults.env not in env_names:
        problems.append(
            Problem(
                COMPANY_FILE,
                "defaults.env",
                f"{company.defaults.env!r} is not an environment; "
                f"valid: {env_listing(company.environments)}",
            )
        )


def _canonical_envs(
    company: CompanyFile,
    env_names: Mapping[str, str],
    targets: dict[str, tuple[str, TargetConfig]],
    problems: list[Problem],
) -> dict[str, tuple[str, TargetConfig]]:
    out: dict[str, tuple[str, TargetConfig]] = {}
    for name, (file, target) in targets.items():
        canonical = env_names.get(target.env)
        if canonical is None:
            problems.append(
                Problem(
                    file,
                    f"targets.{name}.env",
                    f"{target.env!r} is not an environment; "
                    f"valid: {env_listing(company.environments)}",
                )
            )
            continue
        out[name] = (file, target.model_copy(update={"env": canonical}))
    return out


def _check_systems(
    targets: Mapping[str, tuple[str, TargetConfig]], problems: list[Problem]
) -> None:
    by_system: dict[str, list[str]] = {}
    seen: dict[tuple[str, str], str] = {}
    for name, (file, target) in targets.items():
        if target.system is None:
            continue
        by_system.setdefault(target.system, []).append(name)
        slot = (target.system, target.env)
        if slot in seen:
            problems.append(
                Problem(
                    file,
                    f"targets.{name}",
                    f"system {target.system!r} in env {target.env!r} is already the target "
                    f"{seen[slot]!r}",
                )
            )
        else:
            seen[slot] = name
    for system, members in by_system.items():
        if len(members) > 1 and system in targets:
            file = targets[system][0]
            problems.append(
                Problem(
                    file,
                    f"targets.{system}",
                    f"target name equals the name of system {system!r}, which has "
                    f"{len(members)} targets",
                )
            )
