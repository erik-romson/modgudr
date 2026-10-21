"""The decision order of §7.5 (M11), case by case."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from modgudr.broker.engine.decide import Scope, after_run, decide, scope_for
from modgudr.broker.engine.explain import explain
from modgudr.broker.policy.load import Policy, load_policy
from modgudr.broker.policy.resolve import resolve_target
from modgudr.spi import CEILINGS, Action, Decision, Fact, Layer, Risk, Rule, RuleSet
from tests.support.enginefx import FakePlugin, kubectl_plugin, sql_plugin
from tests.support.policyfx import ME, copy_valid, fake_registry, root_company_fstat


def make_scope(
    *,
    ceiling: Risk = Risk.DESTRUCTIVE,
    target_rules: Mapping[str, RuleSet] | None = None,
    env_rules: Mapping[str, RuleSet] | None = None,
    guard: Sequence[str] = (),
    plugin: FakePlugin | None = None,
    env: str = "test",
) -> Scope:
    plugin = sql_plugin() if plugin is None else plugin
    return Scope(
        target="db",
        type=plugin.type,
        env=env,
        ceiling=ceiling,
        guard=tuple(Rule(p) for p in guard),
        invariants=tuple(plugin.invariants()),
        target_rules={} if target_rules is None else target_rules,
        env_rules={} if env_rules is None else env_rules,
        defaults=plugin.default_rules(),
        checks=plugin.constraint_checks(),
    )


def rules(
    allow: Sequence[str] = (),
    deny: Sequence[str] = (),
    constraints: Mapping[str, Mapping[str, bool | int | str | tuple[str, ...]]] | None = None,
) -> RuleSet:
    return RuleSet(
        tuple(Rule(p) for p in allow),
        tuple(Rule(p) for p in deny),
        {} if constraints is None else constraints,
    )


def act(name: str, risk: Risk, **facts: Fact) -> Action:
    return Action(name, risk, facts)


EVERYTHING = rules(allow=["*", "unknown", "secret", "admin", "read", "write", "destructive"])


def assert_decided(decision: Decision, verdict: str, layer: Layer, rule: str) -> None:
    got = (decision.verdict, decision.layer, decision.rule)
    assert got == (verdict, layer, rule), explain(decision)


# --- unknown and secret --------------------------------------------------------------------------


def test_unknown_is_denied_first_where_everything_is_allowed() -> None:
    scope = make_scope(
        ceiling=Risk.ADMIN,
        target_rules={"sql": EVERYTHING},
        env_rules={"all": EVERYTHING},
        guard=["sql:*"],
    )
    action = Action("sql:unknown", Risk.UNKNOWN, invariant_hits=("--x",), detail="parse error.")
    decision = decide(action, scope)
    assert_decided(decision, "deny", Layer.INVARIANT, "unknown")
    assert decision.message == "Cannot classify this call: parse error"
    assert "cannot classify" in explain(decision).lower()


def test_the_risk_decides_not_the_name() -> None:
    scope = make_scope(ceiling=Risk.ADMIN, env_rules={"sql": EVERYTHING})
    decision = decide(Action("sql:select", Risk.UNKNOWN), scope)
    assert_decided(decision, "deny", Layer.INVARIANT, "unknown")
    assert decision.message == "Cannot classify this call"


def test_secret_is_denied_under_allow_read() -> None:
    scope = make_scope(env_rules={"sql": rules(allow=["read"])})
    decision = decide(act("sql:select", Risk.SECRET, tables=("dba_users",)), scope)
    assert_decided(decision, "deny", Layer.INVARIANT, "secret")
    assert "would reveal a secret" in decision.message


def test_a_rule_naming_the_class_secret_cannot_allow_it() -> None:
    scope = make_scope(ceiling=Risk.ADMIN, target_rules={"sql": rules(allow=["secret"])})
    decision = decide(act("sql:select", Risk.SECRET), scope)
    assert_decided(decision, "deny", Layer.INVARIANT, "secret")


# --- invariants, guard, ceiling ------------------------------------------------------------------


def test_ceiling_beats_a_target_allow() -> None:
    scope = make_scope(ceiling=Risk.READ, target_rules={"sql": rules(allow=["write"])})
    decision = decide(act("sql:update", Risk.WRITE, where="column"), scope)
    assert_decided(decision, "deny", Layer.CEILING, "read")


def test_guard_beats_ceiling_admin_and_every_allow() -> None:
    scope = make_scope(
        ceiling=Risk.ADMIN,
        target_rules={"sql": rules(allow=["grant"])},
        env_rules={"sql": EVERYTHING},
        guard=["sql:grant", "sql:user.*"],
    )
    assert_decided(decide(act("sql:grant", Risk.ADMIN), scope), "deny", Layer.GUARD, "sql:grant")
    decision = decide(act("sql:user.create", Risk.ADMIN), scope)
    assert_decided(decision, "deny", Layer.GUARD, "sql:user.*")


def test_a_guard_entry_names_one_connector_type() -> None:
    scope = make_scope(
        plugin=kubectl_plugin(),
        env_rules={"kubectl": rules(allow=["delete/*"])},
        guard=["sql:*"],
    )
    action = act("kubectl:delete/pods", Risk.DESTRUCTIVE, names=("web-1",), namespace="a")
    assert_decided(decide(action, scope), "allow", Layer.ENVIRONMENT, "delete/*")


def test_invariant_beats_an_environment_allow() -> None:
    scope = make_scope(ceiling=Risk.ADMIN, env_rules={"sql": rules(allow=["session", "admin"])})
    decision = decide(act("sql:session", Risk.ADMIN), scope)
    assert_decided(decision, "deny", Layer.INVARIANT, "session")
    assert "session state belongs to the broker" in decision.message


def test_an_invariant_hit_found_by_the_classifier_is_refused() -> None:
    scope = make_scope(plugin=kubectl_plugin(), env_rules={"kubectl": rules(allow=["read"])})
    action = Action("kubectl:get/pods", Risk.READ, invariant_hits=("--as", "--token"))
    assert_decided(decide(action, scope), "deny", Layer.INVARIANT, "--as")


def test_invariant_comes_before_guard_and_guard_before_ceiling() -> None:
    scope = make_scope(ceiling=Risk.READ, guard=["sql:*"])
    assert decide(act("sql:session", Risk.ADMIN), scope).layer is Layer.INVARIANT
    assert decide(act("sql:grant", Risk.ADMIN), scope).layer is Layer.GUARD


# --- the overridable layers ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("layer_rules", "rule"),
    [
        ({"sql": rules(allow=["delete"], deny=["delete"])}, "delete"),
        ({"sql": rules(allow=["destructive"]), "all": rules(deny=["delete"])}, "delete"),
        ({"sql": rules(deny=["destructive"]), "all": rules(allow=["*"])}, "destructive"),
    ],
    ids=["same-block", "all-block-denies", "connector-block-denies"],
)
def test_deny_beats_allow_in_the_same_layer(layer_rules: Mapping[str, RuleSet], rule: str) -> None:
    action = act("sql:delete", Risk.DESTRUCTIVE, where="column")
    assert_decided(decide(action, make_scope(target_rules=layer_rules)), "deny", Layer.TARGET, rule)
    assert_decided(
        decide(action, make_scope(env_rules=layer_rules)), "deny", Layer.ENVIRONMENT, rule
    )


def test_target_overrides_environment() -> None:
    env = {"sql": rules(allow=["write"], deny=["truncate"])}
    scope = make_scope(
        target_rules={"sql": rules(allow=["truncate"], deny=["write"])}, env_rules=env
    )
    truncate = decide(act("sql:truncate", Risk.DESTRUCTIVE), scope)
    assert_decided(truncate, "allow", Layer.TARGET, "truncate")
    update = decide(act("sql:update", Risk.WRITE, where="column"), scope)
    assert_decided(update, "deny", Layer.TARGET, "write")


def test_environment_overrides_plugin_default() -> None:
    scope = make_scope(env_rules={"sql": rules(allow=["write"])})
    update = decide(act("sql:update", Risk.WRITE, where="column"), scope)
    assert_decided(update, "allow", Layer.ENVIRONMENT, "write")
    blind = make_scope(env_rules={"sql": rules(deny=["read"])})
    assert_decided(decide(act("sql:select", Risk.READ), blind), "deny", Layer.ENVIRONMENT, "read")


def test_a_silent_layer_passes_the_question_down() -> None:
    scope = make_scope(target_rules={"sql": rules(deny=["truncate"])})
    decision = decide(act("sql:select", Risk.READ), scope)
    assert_decided(decision, "allow", Layer.PLUGIN_DEFAULT, "read")
    assert decision.message == "The sql plugin defaults allow read"


def test_no_rule_means_deny() -> None:
    scope = make_scope(ceiling=Risk.WRITE)
    decision = decide(act("sql:insert", Risk.WRITE), scope)
    assert_decided(decision, "deny", Layer.NO_RULE, "none")
    assert decision.message.startswith("No rule allows this")


def test_rules_of_another_connector_type_do_not_apply() -> None:
    scope = make_scope(env_rules={"kubectl": rules(allow=["*"])})
    assert_decided(decide(act("sql:insert", Risk.WRITE), scope), "deny", Layer.NO_RULE, "none")


# --- wildcards and classes -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "name", "risk", "expected"),
    [
        ("kubectl:delete/*", "kubectl:delete/pods", Risk.DESTRUCTIVE, True),
        ("kubectl:delete/*", "kubectl:delete/jobs", Risk.DESTRUCTIVE, True),
        ("kubectl:delete/*", "kubectl:get/pods", Risk.READ, False),
        ("kubectl:delete/*", "sql:delete", Risk.DESTRUCTIVE, False),
        ("delete/*", "kubectl:delete/pods", Risk.DESTRUCTIVE, True),
        ("kubectl:*/secrets", "kubectl:get/secrets", Risk.SECRET, True),
        ("kubectl:*/secrets", "kubectl:get/pods", Risk.READ, False),
        ("sql:ddl.*", "sql:ddl.drop", Risk.DESTRUCTIVE, True),
        ("sql:ddl.*", "sql:ddl.create", Risk.ADMIN, True),
        ("sql:ddl.*", "sql:delete", Risk.DESTRUCTIVE, False),
        ("ddl.*", "sql:ddl.alter", Risk.ADMIN, True),
        ("sql:user.*", "sql:user.create", Risk.ADMIN, True),
        ("sql:user.*", "sql:update", Risk.WRITE, False),
        ("write", "sql:update", Risk.WRITE, True),
        ("write", "kubectl:scale/deployments", Risk.WRITE, True),
        ("write", "sql:select", Risk.READ, False),
        ("write", "sql:delete", Risk.DESTRUCTIVE, False),
        ("delete", "sql:delete", Risk.DESTRUCTIVE, True),
        ("delete", "kubectl:delete/pods", Risk.DESTRUCTIVE, False),
        ("Delete", "sql:delete", Risk.DESTRUCTIVE, False),
        ("*", "sql:anything", Risk.READ, True),
    ],
)
def test_wildcards_and_classes_match_as_7_1(
    pattern: str, name: str, risk: Risk, expected: bool
) -> None:
    assert Rule(pattern).matches(Action(name, risk)) is expected


# --- explanations, phases, the run ---------------------------------------------------------------


def test_explain_text_for_a_ceiling_denial() -> None:
    scope = Scope(target="prod-ro", type="sql", env="prod", ceiling=Risk.READ)
    decision = decide(act("sql:delete", Risk.DESTRUCTIVE, where="column"), scope)
    assert explain(decision) == (
        "denied: sql:delete (destructive) on prod-ro. Environment prod allows read only (ceiling)."
    )


def test_a_ceiling_above_read_says_up_to() -> None:
    scope = make_scope(ceiling=Risk.WRITE, env="stage")
    decision = decide(act("sql:delete", Risk.DESTRUCTIVE), scope)
    assert decision.message == "Environment stage allows up to write"


def test_phase_two_decides_with_the_effective_environment() -> None:
    action = act("sql:delete", Risk.DESTRUCTIVE, where="column")
    env_rules = {"sql": rules(allow=["delete"])}
    declared = decide(action, make_scope(env_rules=env_rules))
    effective = decide(action, make_scope(ceiling=Risk.READ, env="prod"))
    assert (declared.allowed, declared.env) == (True, "test")
    assert (effective.allowed, effective.env, effective.layer) == (False, "prod", Layer.CEILING)


def test_after_run_holds_an_allowed_call_to_its_constraints() -> None:
    scope = make_scope(
        env_rules={"sql": rules(allow=["delete"], constraints={"delete": {"maxAffectedRows": 10}})}
    )
    decision = decide(act("sql:delete", Risk.DESTRUCTIVE, where="column"), scope)
    assert decision.allowed
    assert after_run(decision, scope.checks, {"affectedRows": 10}) is decision
    over = after_run(decision, scope.checks, {"affectedRows": 11})
    assert_decided(over, "deny", Layer.CONSTRAINT, "maxAffectedRows")
    assert over.message == (
        "Constraint maxAffectedRows from environment test is not met: 11 rows, limit 10"
    )
    unknown = after_run(decision, scope.checks, {"affectedRows": None})
    assert unknown.message.endswith("row count unavailable")


def test_after_run_leaves_a_denial_alone() -> None:
    scope = make_scope(ceiling=Risk.READ)
    denied = decide(act("sql:delete", Risk.DESTRUCTIVE), scope)
    assert after_run(denied, scope.checks, {"affectedRows": 1}) is denied


# --- the SPI types the engine relies on ----------------------------------------------------------


def test_risk_order_puts_secret_and_unknown_above_every_ceiling() -> None:
    assert sorted([Risk.UNKNOWN, Risk.ADMIN, Risk.READ, Risk.SECRET, Risk.WRITE]) == [
        Risk.READ,
        Risk.WRITE,
        Risk.ADMIN,
        Risk.SECRET,
        Risk.UNKNOWN,
    ]
    assert Risk.READ < Risk.WRITE < Risk.DESTRUCTIVE < Risk.ADMIN < Risk.SECRET < Risk.UNKNOWN
    assert max(Risk.READ, Risk.ADMIN, Risk.WRITE) is Risk.ADMIN
    assert all(r > c for r in (Risk.SECRET, Risk.UNKNOWN) for c in CEILINGS)
    assert [r for r in Risk if r.is_ceiling] == list(CEILINGS)


def test_action_names() -> None:
    action = Action("kubectl:delete/pods", Risk.DESTRUCTIVE)
    assert (action.type, action.local_name) == ("kubectl", "delete/pods")
    unknown = Action.unknown("kubectl", "resource 'x' is not in the catalogue")
    assert (unknown.name, unknown.risk) == ("kubectl:unknown", Risk.UNKNOWN)


# --- scopes from a loaded policy -----------------------------------------------------------------


@pytest.fixture
def policy(shortdir: Path) -> Policy:
    policy_dir = copy_valid(shortdir)
    return load_policy(policy_dir, fake_registry(), uid=ME, fstat=root_company_fstat(policy_dir))


def policy_decide(policy: Policy, name: str, action: Action, env: str | None = None) -> Decision:
    resolved = resolve_target(policy, name)
    plugin = {"sql": sql_plugin(), "kubectl": kubectl_plugin()}[resolved.target.type]
    scope = scope_for(policy, resolved.target, resolved.env if env is None else env, plugin)
    return decide(action, scope)


def test_scope_for_a_loaded_policy(policy: Policy) -> None:
    update = act("sql:update", Risk.WRITE, where="column")
    assert_decided(policy_decide(policy, "cbsl-stage", update), "deny", Layer.TARGET, "write")
    delete = act("sql:delete", Risk.DESTRUCTIVE, where="column")
    allowed = policy_decide(policy, "cbsl-test", delete)
    assert_decided(allowed, "allow", Layer.ENVIRONMENT, "delete")
    assert {n: c.value for n, c in allowed.constraints.items()} == {
        "requireWhere": True,
        "maxAffectedRows": 1000,
    }
    assert_decided(policy_decide(policy, "cbsl-prod", delete), "deny", Layer.CEILING, "read")
    assert_decided(
        policy_decide(policy, "sf", act("sql:grant", Risk.ADMIN)), "deny", Layer.GUARD, "sql:grant"
    )


def test_scope_for_a_target_declared_with_an_alias(policy: Policy) -> None:
    pods = act("kubectl:delete/pods", Risk.DESTRUCTIVE, names=("web-1",))
    decision = policy_decide(policy, "aks-test", pods)
    assert_decided(decision, "allow", Layer.ENVIRONMENT, "delete/pods")
    assert decision.env == "test"


def test_scope_for_the_effective_environment(policy: Policy) -> None:
    delete = act("sql:delete", Risk.DESTRUCTIVE, where="column")
    decision = policy_decide(policy, "cbsl-test", delete, env="prod")
    assert_decided(decision, "deny", Layer.CEILING, "read")
    assert explain(decision) == (
        "denied: sql:delete (destructive) on cbsl-test. Environment prod allows read only "
        "(ceiling)."
    )
