"""Helpers for the policy tests: a fake registry, fixture copying and an injectable fstat."""

from __future__ import annotations

import os
import shutil
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from modgudr.broker.policy.load import Fstat
from modgudr.broker.policy.registry import ConnectorPolicy, StaticRegistry

DATA = Path(__file__).resolve().parent.parent / "data" / "policy"
ME = 4242


class FakeSqlConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    dialect: str
    host: str
    port: int | None = None
    sid: str | None = None
    service: str | None = None
    user: str


class FakeKubectlConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    cluster: dict[str, str]


def fake_registry() -> StaticRegistry:
    return StaticRegistry(
        ConnectorPolicy(
            type="sql",
            config_model=FakeSqlConfig,
            actions=frozenset(
                {
                    "select",
                    "insert",
                    "update",
                    "delete",
                    "truncate",
                    "grant",
                    "user.create",
                    "ddl.drop",
                    "ddl.create",
                }
            ),
            constraints={
                "requireWhere": frozenset({"update", "delete"}),
                "maxAffectedRows": frozenset({"insert", "update", "delete"}),
            },
        ),
        ConnectorPolicy(
            type="kubectl",
            config_model=FakeKubectlConfig,
            actions=frozenset(
                {"get/pods", "get/secrets", "delete/pods", "rollout/restart", "scale/deployments"}
            ),
            constraints={"requireName": frozenset({"delete/*"})},
        ),
    )


def copy_valid(dst: Path) -> Path:
    """Copy the valid fixture set to `dst/policy.d` and return that directory."""
    policy_dir = dst / "policy.d"
    policy_dir.mkdir()
    for source in (DATA / "valid").glob("*.yaml"):
        shutil.copyfile(source, policy_dir / source.name)
        (policy_dir / source.name).chmod(0o644)
    return policy_dir


def put(policy_dir: Path, name: str, text: str) -> None:
    path = policy_dir / name
    path.write_text(text)
    path.chmod(0o644)


@dataclass
class FakeStat:
    st_uid: int
    st_mode: int


def fake_fstat(
    policy_dir: Path,
    owners: dict[str, int],
    modes: dict[str, int] | None = None,
) -> Fstat:
    """An fstat that reports the given owner (and mode) per file name, found by inode."""
    by_inode: dict[int, str] = {}
    for path in policy_dir.iterdir():
        if not path.is_symlink():
            by_inode[path.stat().st_ino] = path.name
    modes = modes or {}

    def fstat(fd: int) -> FakeStat:
        real = os.fstat(fd)
        name = by_inode.get(real.st_ino)
        if name is None:
            return FakeStat(real.st_uid, real.st_mode)
        return FakeStat(owners.get(name, ME), modes.get(name, real.st_mode))

    return fstat


def root_company_fstat(policy_dir: Path) -> Fstat:
    """Company file owned by root, everything else by `ME`."""
    return fake_fstat(policy_dir, {"00-company.yaml": 0})


def regular(mode: int) -> int:
    return stat.S_IFREG | mode


UidMaker = Callable[[], int]
