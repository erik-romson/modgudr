from pathlib import Path

import pytest

from modgudr.broker.policy.load import Policy, PolicyError, load_policy
from modgudr.broker.policy.registry import ConnectorPolicy, StaticRegistry
from tests.support.policyfx import (
    DATA,
    ME,
    FakeSqlConfig,
    copy_valid,
    fake_registry,
    put,
    root_company_fstat,
)


def load(policy_dir: Path) -> Policy:
    return load_policy(policy_dir, fake_registry(), uid=ME, fstat=root_company_fstat(policy_dir))


def refusal(policy_dir: Path) -> str:
    with pytest.raises(PolicyError) as info:
        load(policy_dir)
    return str(info.value)


def test_valid_set_loads(shortdir: Path) -> None:
    policy = load(copy_valid(shortdir))
    assert list(policy.targets) == ["cbsl-test", "cbsl-stage", "cbsl-prod", "sf", "aks-test"]
    assert policy.default_env == "test"
    assert policy.company.defaults.timeout == 30.0
    assert policy.company.defaults.maxBytes == 2 * 1024**2
    assert policy.company.defaults.idleLock == 3600.0
    assert policy.company.defaults.absoluteLock == 36000.0
    stage = policy.targets["cbsl-stage"]
    assert (stage.maxRows, stage.timeout, stage.credential.tier) == (200, 20.0, "custody")
    assert list(stage.rules) == ["sql"]
    assert isinstance(stage.config, FakeSqlConfig) and stage.config.service == "STAGESVC"
    # An alias in a target's env is canonicalised.
    assert policy.targets["aks-test"].env == "test"
    assert policy.env_names["sol"] == "test"


def test_files_record_hash_and_owner(shortdir: Path) -> None:
    import hashlib

    policy_dir = copy_valid(shortdir)
    policy = load(policy_dir)
    assert [f.name for f in policy.files] == ["00-company.yaml", "50-targets.yaml"]
    company, targets = policy.files
    assert (
        company.sha256 == hashlib.sha256((policy_dir / "00-company.yaml").read_bytes()).hexdigest()
    )
    assert (company.uid, targets.uid) == (0, ME)
    assert company.mode == 0o644


def test_missing_policy_dir_names_the_path(shortdir: Path) -> None:
    with pytest.raises(PolicyError, match=str(shortdir / "policy.d")):
        load_policy(shortdir / "policy.d", fake_registry())


def test_missing_company_file_names_the_path(shortdir: Path) -> None:
    policy_dir = copy_valid(shortdir)
    (policy_dir / "00-company.yaml").unlink()
    assert str(policy_dir / "00-company.yaml") in refusal(policy_dir)


COMPANY_CASES = [
    ("unknown-key", "defaults.bogus", "unknown key"),
    ("syntax-error", "00-company.yaml", "YAML syntax error"),
    ("duplicate-key", "env", "duplicate key"),
    ("missing-default-env", "defaults.env", "required key is missing"),
    ("default-env-not-environment", "defaults.env", "is not an environment"),
    ("alias-equals-environment", "environments.stage.aliases", "alias 'prod'"),
    ("alias-equals-alias", "environments.stage.aliases", "alias 'sol'"),
    ("with-targets", "targets", "not allowed in the company file"),
]

TARGET_CASES = [
    ("unknown-key", "targets.cbsl-stage.bogus", "unknown key"),
    ("no-env", "targets.cbsl-stage.env", "required key is missing"),
    ("no-tier", "targets.cbsl-stage.credential.tier", "required key is missing"),
    ("no-credential", "targets.cbsl-stage.credential", "required key is missing"),
    ("secret-and-provider", "targets.cbsl-stage", "exactly one of 'secret' and 'provider'"),
    ("neither-secret-nor-provider", "targets.cbsl-stage", "exactly one of 'secret' and 'provider'"),
    ("same-system-and-env", "targets.cbsl-test-two", "already the target 'cbsl-test'"),
    ("reserved-name", "targets.status", "reserved name"),
    ("name-equals-multi-target-system", "targets.cbsl", "equals the name of system 'cbsl'"),
    ("bad-name", "targets.A@b", "invalid name"),
    ("unknown-env", "targets.sf.env", "is not an environment"),
    ("unknown-type", "targets.sf.type", "no connector registered for type 'nope'"),
    ("bad-secret-reference", "targets.cbsl-stage.secret", "invalid secret reference"),
    ("with-company-key", "defaults", "not allowed in a targets file"),
]


@pytest.mark.parametrize(("case", "key", "message"), COMPANY_CASES)
def test_invalid_company_file(shortdir: Path, case: str, key: str, message: str) -> None:
    policy_dir = copy_valid(shortdir)
    put(policy_dir, "00-company.yaml", (DATA / "invalid" / f"company--{case}.yaml").read_text())
    text = refusal(policy_dir)
    assert "00-company.yaml" in text and key in text and message in text


@pytest.mark.parametrize(("case", "key", "message"), TARGET_CASES)
def test_invalid_targets_file(shortdir: Path, case: str, key: str, message: str) -> None:
    policy_dir = copy_valid(shortdir)
    put(policy_dir, "50-targets.yaml", (DATA / "invalid" / f"targets--{case}.yaml").read_text())
    text = refusal(policy_dir)
    assert "50-targets.yaml" in text and key in text and message in text


LATER_COMPANY = [
    ("channels", "channels"),
    ("maxCallsPerMinute", "defaults.maxCallsPerMinute"),
    ("breaker", "defaults.breaker"),
    ("allowSecretActions", "environments.prod.allowSecretActions"),
    ("auditRetention", "auditRetention"),
    ("tokenFile", "store.bws.tokenFile"),
    ("mode-unattended", "store.bws.mode"),
    ("columns", "environments.stage.sql.constraints.select.columns"),
]

LATER_TARGETS = [
    ("columns", "targets.cbsl-stage.columns"),
    ("sessionRole", "targets.cbsl-stage.sessionRole"),
    ("unattended", "targets.cbsl-stage.unattended"),
    ("presets", "presets"),
    ("breaker", "targets.cbsl-stage.breaker"),
    ("maxCallsPerMinute", "targets.cbsl-stage.maxCallsPerMinute"),
]


@pytest.mark.parametrize(("case", "key"), LATER_COMPANY)
def test_later_slice_keys_in_the_company_file(shortdir: Path, case: str, key: str) -> None:
    policy_dir = copy_valid(shortdir)
    put(policy_dir, "00-company.yaml", (DATA / "invalid" / f"company--{case}.yaml").read_text())
    text = refusal(policy_dir)
    assert key in text and "not supported in this version" in text


@pytest.mark.parametrize(("case", "key"), LATER_TARGETS)
def test_later_slice_keys_in_the_targets_file(shortdir: Path, case: str, key: str) -> None:
    policy_dir = copy_valid(shortdir)
    put(policy_dir, "50-targets.yaml", (DATA / "invalid" / f"targets--{case}.yaml").read_text())
    text = refusal(policy_dir)
    assert key in text and "not supported in this version" in text
    # Reported once, as the later-slice refusal and not also as an unknown key.
    assert "unknown key" not in text


def test_a_target_may_be_named_like_a_later_slice_key(shortdir: Path) -> None:
    policy_dir = copy_valid(shortdir)
    text = (policy_dir / "50-targets.yaml").read_text().replace("  sf:\n", "  breaker:\n")
    put(policy_dir, "50-targets.yaml", text)
    assert "breaker" in load(policy_dir).targets


def test_targets_merge_across_files_in_name_order(shortdir: Path) -> None:
    policy_dir = copy_valid(shortdir)
    put(
        policy_dir,
        "51-more.yaml",
        "targets:\n  extra:\n    env: prod\n    type: sql\n    dialect: oracle\n"
        "    host: db.example.net\n    user: APP_RO\n    secret: file:extra\n"
        "    credential: { tier: dedicated }\n",
    )
    assert list(load(policy_dir).targets)[-1] == "extra"


def test_same_target_name_in_two_files_is_refused(shortdir: Path) -> None:
    policy_dir = copy_valid(shortdir)
    put(policy_dir, "51-dup.yaml", (policy_dir / "50-targets.yaml").read_text())
    text = refusal(policy_dir)
    assert "51-dup.yaml" in text and "already defined in 50-targets.yaml" in text


def test_system_env_duplicates_across_files_are_refused(shortdir: Path) -> None:
    policy_dir = copy_valid(shortdir)
    put(
        policy_dir,
        "51-more.yaml",
        "targets:\n  other:\n    system: sf\n    env: prod\n    type: sql\n    dialect: oracle\n"
        "    host: db.example.net\n    user: APP_RO\n    secret: file:other\n"
        "    credential: { tier: dedicated }\n",
    )
    assert "already the target 'sf'" in refusal(policy_dir)


def test_unexpected_file_name_is_refused(shortdir: Path) -> None:
    policy_dir = copy_valid(shortdir)
    put(policy_dir, "10-extra.yaml", "targets: {}\n")
    assert "10-extra.yaml: unexpected policy file" in refusal(policy_dir)


def test_non_yaml_files_are_ignored(shortdir: Path) -> None:
    policy_dir = copy_valid(shortdir)
    put(policy_dir, "notes.txt", "hello")
    assert "sf" in load(policy_dir).targets


def test_a_non_mapping_file_is_refused(shortdir: Path) -> None:
    policy_dir = copy_valid(shortdir)
    put(policy_dir, "50-targets.yaml", "- a\n- b\n")
    assert "50-targets.yaml: must be a mapping" in refusal(policy_dir)


def test_connector_config_model_must_forbid_extra_keys() -> None:
    from pydantic import BaseModel

    class Loose(BaseModel):
        pass

    with pytest.raises(ValueError, match="extra='forbid'"):
        ConnectorPolicy(type="x", config_model=Loose)


def test_duplicate_registration_is_refused() -> None:
    registry = StaticRegistry(ConnectorPolicy(type="sql", config_model=FakeSqlConfig))
    with pytest.raises(ValueError, match="already registered"):
        registry.register(ConnectorPolicy(type="sql", config_model=FakeSqlConfig))
