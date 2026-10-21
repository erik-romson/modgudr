import os
from pathlib import Path

import pytest

from modgudr.broker.policy.load import PolicyError, check_file_stat, load_policy
from tests.support.policyfx import (
    ME,
    FakeStat,
    copy_valid,
    fake_fstat,
    fake_registry,
    regular,
)


def run(
    policy_dir: Path, owners: dict[str, int], modes: dict[str, int] | None = None, dev: bool = False
) -> None:
    load_policy(
        policy_dir,
        fake_registry(),
        dev=dev,
        uid=ME,
        fstat=fake_fstat(policy_dir, owners, modes),
    )


def test_company_file_owned_by_root_is_ok(shortdir: Path) -> None:
    run(copy_valid(shortdir), {"00-company.yaml": 0})


def test_company_file_owned_by_me_is_refused_without_dev(shortdir: Path) -> None:
    with pytest.raises(
        PolicyError, match=r"00-company.yaml: the company file must be owned by root"
    ):
        run(copy_valid(shortdir), {"00-company.yaml": ME})


def test_company_file_owned_by_me_is_ok_with_dev(shortdir: Path) -> None:
    run(copy_valid(shortdir), {"00-company.yaml": ME}, dev=True)


def test_company_file_owned_by_someone_else_is_refused_even_with_dev(shortdir: Path) -> None:
    with pytest.raises(PolicyError, match="uid 999"):
        run(copy_valid(shortdir), {"00-company.yaml": 999}, dev=True)


def test_group_writable_company_file_is_refused(shortdir: Path) -> None:
    with pytest.raises(
        PolicyError, match=r"00-company.yaml: mode 0664 is group- or world-writable"
    ):
        run(copy_valid(shortdir), {"00-company.yaml": 0}, {"00-company.yaml": regular(0o664)})


def test_world_writable_targets_file_is_refused(shortdir: Path) -> None:
    with pytest.raises(PolicyError, match=r"50-targets.yaml: mode 0646"):
        run(copy_valid(shortdir), {"00-company.yaml": 0}, {"50-targets.yaml": regular(0o646)})


def test_targets_file_may_be_owned_by_me_or_root(shortdir: Path) -> None:
    policy_dir = copy_valid(shortdir)
    run(policy_dir, {"00-company.yaml": 0, "50-targets.yaml": ME})
    run(policy_dir, {"00-company.yaml": 0, "50-targets.yaml": 0})


def test_targets_file_owned_by_someone_else_is_refused(shortdir: Path) -> None:
    with pytest.raises(PolicyError, match=r"50-targets.yaml: owner uid 999"):
        run(copy_valid(shortdir), {"00-company.yaml": 0, "50-targets.yaml": 999})


def test_a_symlink_is_refused(shortdir: Path) -> None:
    policy_dir = copy_valid(shortdir)
    real = shortdir / "real-targets.yaml"
    (policy_dir / "50-targets.yaml").rename(real)
    (policy_dir / "50-targets.yaml").symlink_to(real)
    with pytest.raises(PolicyError, match=r"50-targets.yaml: is a symlink"):
        run(policy_dir, {"00-company.yaml": 0})


def test_a_symlinked_company_file_is_refused(shortdir: Path) -> None:
    policy_dir = copy_valid(shortdir)
    real = shortdir / "real-company.yaml"
    (policy_dir / "00-company.yaml").rename(real)
    (policy_dir / "00-company.yaml").symlink_to(real)
    with pytest.raises(PolicyError, match=r"00-company.yaml: is a symlink"):
        run(policy_dir, {})


def test_a_symlink_reported_by_fstat_is_refused() -> None:
    link = FakeStat(0, 0o120777)
    assert check_file_stat("x", link, company=True, dev=False, uid=ME) == "not a regular file"


def test_a_directory_named_like_a_policy_file_is_refused(shortdir: Path) -> None:
    policy_dir = copy_valid(shortdir)
    (policy_dir / "51-dir.yaml").mkdir()
    with pytest.raises(PolicyError, match=r"51-dir.yaml: not a regular file"):
        run(policy_dir, {"00-company.yaml": 0})


def test_a_refused_file_is_not_parsed(shortdir: Path) -> None:
    policy_dir = copy_valid(shortdir)
    (policy_dir / "50-targets.yaml").write_text("[unclosed")
    with pytest.raises(PolicyError) as info:
        run(policy_dir, {"00-company.yaml": 0, "50-targets.yaml": 999})
    assert "YAML" not in str(info.value)


def test_company_keys_in_a_developer_owned_targets_file_are_refused(shortdir: Path) -> None:
    policy_dir = copy_valid(shortdir)
    (policy_dir / "50-targets.yaml").write_text(
        "environments:\n  anything:\n    ceiling: admin\ntargets: {}\n"
    )
    with pytest.raises(
        PolicyError, match=r"50-targets.yaml: environments: not allowed in a targets file"
    ):
        run(policy_dir, {"00-company.yaml": 0, "50-targets.yaml": ME})


def test_company_keys_are_refused_in_a_root_owned_targets_file_too(shortdir: Path) -> None:
    policy_dir = copy_valid(shortdir)
    (policy_dir / "50-targets.yaml").write_text("guard: {forbid: []}\n")
    with pytest.raises(PolicyError, match="guard: not allowed in a targets file"):
        run(policy_dir, {"00-company.yaml": 0, "50-targets.yaml": 0})


def test_real_files_owned_by_me_are_refused_for_the_company_file_by_default(shortdir: Path) -> None:
    policy_dir = copy_valid(shortdir)
    if os.getuid() == 0:
        pytest.skip("running as root")
    with pytest.raises(PolicyError, match="must be owned by root"):
        load_policy(policy_dir, fake_registry())
