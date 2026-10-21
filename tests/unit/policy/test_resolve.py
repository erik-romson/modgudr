from pathlib import Path

import pytest

from modgudr.broker.policy.load import Policy, load_policy
from modgudr.broker.policy.resolve import ResolveError, resolve_target
from tests.support.policyfx import ME, copy_valid, fake_registry, put, root_company_fstat


@pytest.fixture
def policy(shortdir: Path) -> Policy:
    policy_dir = copy_valid(shortdir)
    return load_policy(policy_dir, fake_registry(), uid=ME, fstat=root_company_fstat(policy_dir))


@pytest.mark.parametrize(
    ("name", "env_field", "target", "source"),
    [
        ("cbsl", None, "cbsl-test", "default"),
        ("cbsl", "stage", "cbsl-stage", "session"),
        ("cbsl@prod", "stage", "cbsl-prod", "explicit"),
        ("cbsl", "sol", "cbsl-test", "session"),
        ("cbsl-prod", "stage", "cbsl-prod", "explicit"),
        ("cbsl@sol", None, "cbsl-test", "explicit"),
        ("cbsl@vfy", "prod", "cbsl-stage", "explicit"),
        ("sf@prod", None, "sf", "explicit"),
        ("sf", "stage", "sf", "explicit"),  # the target is named like its system
        ("aks", None, "aks-test", "default"),
    ],
)
def test_resolution(
    policy: Policy, name: str, env_field: str | None, target: str, source: str
) -> None:
    resolved = resolve_target(policy, name, env_field)
    assert (resolved.target.name, resolved.env_source) == (target, source)
    assert resolved.env == resolved.target.env


def test_an_unknown_session_environment_lists_the_valid_ones(policy: Policy) -> None:
    with pytest.raises(ResolveError) as info:
        resolve_target(policy, "cbsl", "prd")
    message = str(info.value)
    assert "test (sol), stage (vfy), prod" in message
    assert "'prd'" in message and "env field" in message
    assert info.value.code == "not_found"


def test_a_system_without_a_target_in_the_environment(policy: Policy) -> None:
    with pytest.raises(ResolveError, match="system sf has no target in env test; available: prod"):
        resolve_target(policy, "sf@test")


def test_the_session_environment_is_named_as_the_source(policy: Policy) -> None:
    with pytest.raises(ResolveError) as info:
        resolve_target(policy, "aks", "stage")
    assert "system aks has no target in env stage; available: test" in str(info.value)
    assert "MODGUDR_ENV" in str(info.value)


def test_the_default_environment_is_named_as_the_source(shortdir: Path) -> None:
    policy_dir = copy_valid(shortdir)
    company = policy_dir / "00-company.yaml"
    put(policy_dir, "00-company.yaml", company.read_text().replace("env: test\n", "env: prod\n", 1))
    policy = load_policy(policy_dir, fake_registry(), uid=ME, fstat=root_company_fstat(policy_dir))
    with pytest.raises(ResolveError) as info:
        resolve_target(policy, "aks")
    assert "system aks has no target in env prod; available: test" in str(info.value)
    assert "defaults.env" in str(info.value)


@pytest.mark.parametrize("name", ["cbsl@", "@test", "a@b@c", "cbsl@TEST", "nope", "nope@test", ""])
def test_not_found(policy: Policy, name: str) -> None:
    with pytest.raises(ResolveError) as info:
        resolve_target(policy, name)
    assert info.value.code == "not_found"


def test_an_explicit_name_ignores_the_env_field_even_when_invalid(policy: Policy) -> None:
    resolved = resolve_target(policy, "cbsl-prod", "nonsense")
    assert resolved.target.name == "cbsl-prod" and resolved.env_source == "explicit"
