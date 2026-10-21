import io
from collections.abc import Sequence
from pathlib import Path

import modgudr.broker.policy.lint as lint_module
from modgudr.broker.policy.lint import Finding, lint_main, lint_policy
from tests.support.policyfx import ME, copy_valid, fake_fstat, fake_registry, put


def lint(policy_dir: Path, **kwargs: object) -> list[Finding]:
    report = lint_policy(
        policy_dir,
        fake_registry(),
        uid=ME,
        fstat=fake_fstat(policy_dir, {"00-company.yaml": 0}),
        **kwargs,  # pyright: ignore[reportArgumentType]
    )
    return list(report.findings)


def messages(findings: list[Finding], severity: str) -> list[str]:
    return [str(f) for f in findings if f.severity == severity]


def substitute(policy_dir: Path, name: str, old: str, new: str) -> None:
    text = (policy_dir / name).read_text()
    assert old in text
    put(policy_dir, name, text.replace(old, new, 1))


def test_good_file_has_no_errors_or_warnings(shortdir: Path) -> None:
    findings = lint(copy_valid(shortdir))
    assert [f for f in findings if f.severity != "info"] == []


def test_pins_are_not_checked_while_locked(shortdir: Path) -> None:
    findings = lint(copy_valid(shortdir))
    infos = messages(findings, "info")
    assert len(infos) == 4  # the four targets with a secret; aks-test uses a provider
    assert all("pins not checked (store locked)" in m for m in infos)


def test_pins_are_checked_with_a_store_session(shortdir: Path) -> None:
    class Session:
        def check_pins(self, target_name: str, secret: str) -> Sequence[str]:
            return ["no modgudr-hosts line"] if target_name == "sf" else []

    findings = lint(copy_valid(shortdir), store_session=Session())
    assert messages(findings, "info") == []
    assert messages(findings, "error") == ["error: targets.sf.secret: no modgudr-hosts line"]


def test_default_env_containing_prod_is_one_warning(shortdir: Path) -> None:
    policy_dir = copy_valid(shortdir)
    substitute(policy_dir, "00-company.yaml", "defaults:\n  env: test", "defaults:\n  env: prod")
    findings = lint(policy_dir)
    assert messages(findings, "error") == []
    warnings = messages(findings, "warning")
    assert len(warnings) == 1 and "defaults.env" in warnings[0] and "prod" in warnings[0]


def test_default_env_alias_of_a_prod_environment_warns(shortdir: Path) -> None:
    policy_dir = copy_valid(shortdir)
    substitute(policy_dir, "00-company.yaml", "  prod:\n", "  prod:\n    aliases: [live]\n")
    substitute(policy_dir, "00-company.yaml", "defaults:\n  env: test", "defaults:\n  env: live")
    assert len(messages(lint(policy_dir), "warning")) == 1


def test_loader_errors_become_error_findings(shortdir: Path) -> None:
    policy_dir = copy_valid(shortdir)
    put(policy_dir, "50-targets.yaml", "targets:\n  status: {}\n")
    findings = lint(policy_dir)
    assert findings and all(f.severity == "error" for f in findings)
    assert any(f.file == "50-targets.yaml" and f.key.startswith("targets.status") for f in findings)


def test_unknown_action_in_an_environment_rule(shortdir: Path) -> None:
    policy_dir = copy_valid(shortdir)
    substitute(
        policy_dir, "00-company.yaml", "deny: [truncate, ddl.drop]", "deny: [truncat, ddl.*]"
    )
    errors = messages(lint(policy_dir), "error")
    assert errors == [
        "error: 00-company.yaml: environments.test.sql.deny[0]: unknown action 'truncat'"
    ]


def test_wildcards_and_risk_classes_are_known_actions(shortdir: Path) -> None:
    findings = lint(copy_valid(shortdir))
    assert messages(findings, "error") == []  # scale/*, read, write, delete/pods


def test_unknown_action_in_a_target_rule(shortdir: Path) -> None:
    policy_dir = copy_valid(shortdir)
    substitute(policy_dir, "50-targets.yaml", "deny: [write]", "deny: [wipe]")
    errors = messages(lint(policy_dir), "error")
    assert errors == ["error: targets.cbsl-stage.sql.deny[0]: unknown action 'wipe'"]


def test_unknown_action_in_the_guard(shortdir: Path) -> None:
    policy_dir = copy_valid(shortdir)
    substitute(policy_dir, "00-company.yaml", "sql:user.*", "sql:nothing.*")
    errors = messages(lint(policy_dir), "error")
    assert errors == ["error: 00-company.yaml: guard.forbid[1]: unknown action 'nothing.*' for sql"]


def test_unknown_connector_type_in_the_guard_and_environments(shortdir: Path) -> None:
    policy_dir = copy_valid(shortdir)
    substitute(policy_dir, "00-company.yaml", "sql:grant", "ssh:grant")
    substitute(
        policy_dir,
        "00-company.yaml",
        "  prod:\n    ceiling: read\n",
        "  prod:\n    ceiling: read\n    sqll:\n      allow: [read]\n",
    )
    errors = messages(lint(policy_dir), "error")
    assert "error: 00-company.yaml: guard.forbid[0]: unknown connector type 'ssh'" in errors
    assert "error: 00-company.yaml: environments.prod.sqll: unknown connector type 'sqll'" in errors


def test_constraint_not_supported_for_the_action(shortdir: Path) -> None:
    policy_dir = copy_valid(shortdir)
    substitute(
        policy_dir,
        "00-company.yaml",
        "      allow: [write]\n    kubectl:\n      allow: [read, rollout/restart]\n",
        "      allow: [write]\n      constraints:\n        select: { requireWhere: true }\n"
        "    kubectl:\n      allow: [read, rollout/restart]\n",
    )
    errors = messages(lint(policy_dir), "error")
    assert errors == [
        "error: 00-company.yaml: environments.stage.sql.constraints.select.requireWhere: "
        "constraint 'requireWhere' is not supported for action 'select'"
    ]


def test_unknown_constraint_name_and_unknown_constraint_action(shortdir: Path) -> None:
    policy_dir = copy_valid(shortdir)
    substitute(
        policy_dir,
        "00-company.yaml",
        "update: { requireWhere: true,",
        "update: { requireWere: true,",
    )
    substitute(
        policy_dir,
        "00-company.yaml",
        "        delete: { requireWhere",
        "        remove: { requireWhere",
    )
    errors = messages(lint(policy_dir), "error")
    assert any("constraints.update.requireWere" in e and "not supported" in e for e in errors)
    assert any("constraints.remove: unknown action 'remove'" in e for e in errors)


def test_a_constraint_wildcard_must_be_supported_for_every_matched_action(shortdir: Path) -> None:
    policy_dir = copy_valid(shortdir)
    # `requireName` is supported for delete/* only; get/* would match actions it does not cover.
    substitute(
        policy_dir,
        "00-company.yaml",
        '"delete/*": { requireName: true }',
        '"*/pods": { requireName: true }',
    )
    errors = messages(lint(policy_dir), "error")
    assert any("constraint 'requireName' is not supported for action '*/pods'" in e for e in errors)


def test_lint_main_reports_and_exits(shortdir: Path) -> None:
    policy_dir = copy_valid(shortdir)
    out, err = io.StringIO(), io.StringIO()
    code = lint_main(
        ["--policy-dir", str(policy_dir)],
        fake_registry(),
        out=out,
        err=err,
        uid=ME,
        fstat=fake_fstat(policy_dir, {"00-company.yaml": 0}),
    )
    assert code == 0
    assert "pins not checked (store locked)" in out.getvalue()


def test_lint_main_exits_78_on_errors(shortdir: Path) -> None:
    out = io.StringIO()
    code = lint_main(["--policy-dir", str(shortdir / "missing")], fake_registry(), out=out)
    assert code == 78
    assert "does not exist" in out.getvalue()


def test_lint_main_usage_error(shortdir: Path) -> None:
    err = io.StringIO()
    assert lint_main(["--bogus"], fake_registry(), err=err) == 64
    assert "usage: modgudr-broker lint" in err.getvalue()


def test_lint_main_defaults_to_policy_d_under_modgudr_home(shortdir: Path) -> None:
    out = io.StringIO()
    code = lint_main([], fake_registry(), environ={"MODGUDR_HOME": str(shortdir)}, out=out)
    assert code == 78
    assert str(shortdir / "policy.d") in out.getvalue()
    assert lint_module.EXIT_CONFIG == 78
