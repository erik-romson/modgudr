"""Isolation detection (M22): the merge, `required_settings`, and every requirement.

Settings files live in short temporary directories; a root owner is injected through `fstat`,
so no test reads or writes a system path.
"""

from __future__ import annotations

import copy
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from modgudr.client.agent.isolation import (
    CREDENTIAL_VARS,
    KUBECTL_DENY_HOSTS,
    L0_WARNING,
    Facts,
    Isolation,
    detect,
    merge_settings,
    persistence_paths,
    required_settings,
    settings_signature,
)
from tests.support.brokerfx import RootFstat

Doc = dict[str, Any]

HOSTS = ("acme-example.snowflakecomputing.com", "db-test.example.net", *KUBECTL_DENY_HOSTS)


class Layout:
    def __init__(self, root: Path, platform: str = "darwin", home: str | None = None) -> None:
        self.root = root
        self.user_home = str(root / "u")
        (root / "u").mkdir(exist_ok=True)
        self.base = root / "ms" / "managed-settings.json"
        self.dropins = root / "ms" / "managed-settings.d"
        self.dropins.mkdir(parents=True, exist_ok=True)
        modgudr_home = home or f"{self.user_home}/.modgudr"
        self.facts = Facts(
            platform=platform,
            home=modgudr_home,
            agent_socket=f"{self.user_home}/Library/Caches/modgudr/run/agent.sock",
            human_socket=f"{modgudr_home}/run/human.sock",
            deny_hosts=HOSTS,
        )

    def required(self, facts: Facts | None = None) -> Doc:
        return required_settings(facts or self.facts, user_home=self.user_home)

    def write(self, name: str, doc: Doc, mode: int = 0o644) -> Path:
        path = self.base if name == "base" else self.dropins / name
        path.write_text(json.dumps(doc))
        path.chmod(mode)
        return path

    def detect(
        self, facts: Facts | None = None, fstat: Callable[[int], Any] | None = None
    ) -> Isolation:
        return detect(
            facts or self.facts,
            user_home=self.user_home,
            base=self.base,
            dropin_dir=self.dropins,
            fstat=fstat or RootFstat(),
        )


@pytest.fixture
def layout(shortdir: Path) -> Layout:
    return Layout(shortdir)


def test_no_file_is_none(layout: Layout) -> None:
    result = layout.detect()
    assert result.label == "none"
    assert "no managed settings" in result.reasons[0]


def test_file_without_sandbox_enabled_is_none(layout: Layout) -> None:
    doc = layout.required()
    del doc["sandbox"]["enabled"]
    layout.write("base", doc)
    result = layout.detect()
    assert result.label == "none"
    assert any("sandbox.enabled" in r for r in result.reasons)


@pytest.mark.parametrize("entry", ["human.sock", "its directory"])
def test_allow_unix_sockets_listing_human_sock_is_none(layout: Layout, entry: str) -> None:
    doc = layout.required()
    human = layout.facts.human_socket
    listed = human if entry == "human.sock" else str(Path(human).parent)
    doc["sandbox"]["network"]["allowUnixSockets"].append(listed)
    layout.write("50-modgudr.json", doc)
    result = layout.detect()
    assert result.label == "none"
    assert any("covers human.sock" in r for r in result.reasons)


def test_correct_base_with_a_dropin_that_disables_the_sandbox_is_none(layout: Layout) -> None:
    layout.write("base", layout.required())
    layout.write("60-company.json", {"sandbox": {"enabled": False}})
    result = layout.detect()
    assert result.label == "none"
    assert result.reasons == ("sandbox.enabled must be true (found false)",)


def test_correct_dropin_only_is_managed_settings(layout: Layout) -> None:
    layout.write("50-modgudr.json", layout.required())
    result = layout.detect()
    assert (result.label, result.reasons) == ("managed-settings", ())
    assert result.isolated
    assert result.files == (str(layout.dropins / "50-modgudr.json"),)


def test_correct_base_only_is_managed_settings(layout: Layout) -> None:
    layout.write("base", layout.required())
    assert layout.detect().label == "managed-settings"


def test_dropins_merge_after_the_base_in_name_order(layout: Layout) -> None:
    doc = layout.required()
    doc["sandbox"]["enabled"] = False
    layout.write("base", doc)
    layout.write("10-a.json", {"sandbox": {"enabled": False}})
    layout.write("20-b.json", {"sandbox": {"enabled": True}})
    # Hidden files and other names are ignored.
    layout.write(".90-hidden.json", {"sandbox": {"enabled": False}})
    layout.write("95-notes.txt", {"sandbox": {"enabled": False}})
    result = layout.detect()
    assert result.label == "managed-settings", result.reasons
    assert [Path(f).name for f in result.files] == [
        "managed-settings.json",
        "10-a.json",
        "20-b.json",
    ]


def test_merge_combines_lists_and_overwrites_scalars() -> None:
    merged = merge_settings(
        [
            {"a": {"x": 1, "l": ["p", "q"]}, "s": "one"},
            {"a": {"y": 2, "l": ["q", "r"]}, "s": "two"},
        ]
    )
    assert merged == {"a": {"x": 1, "y": 2, "l": ["p", "q", "r"]}, "s": "two"}


def test_merged_lists_from_several_files_count(layout: Layout) -> None:
    doc = layout.required()
    deny = doc["permissions"]["deny"]
    half = len(deny) // 2
    first, second = copy.deepcopy(doc), {"permissions": {"deny": deny[half:]}}
    first["permissions"]["deny"] = deny[:half]
    layout.write("base", first)
    layout.write("50-modgudr.json", second)
    assert layout.detect().label == "managed-settings"


def test_a_settings_file_not_owned_by_root_is_none(layout: Layout) -> None:
    layout.write("50-modgudr.json", layout.required())
    result = layout.detect(fstat=os.fstat)
    assert result.label == "none"
    assert any("must be owned by root" in r for r in result.reasons)


def test_a_symlinked_settings_file_is_none(layout: Layout) -> None:
    real = layout.root / "elsewhere.json"
    real.write_text(json.dumps(layout.required()))
    (layout.dropins / "50-modgudr.json").symlink_to(real)
    result = layout.detect()
    assert result.label == "none"
    assert any("is a symlink" in r for r in result.reasons)


def test_invalid_json_is_none(layout: Layout) -> None:
    layout.write("base", layout.required())
    (layout.dropins / "50-modgudr.json").write_text("{not json")
    result = layout.detect()
    assert result.label == "none"
    assert any("not valid JSON" in r for r in result.reasons)


# --- mutations: every M22 requirement --------------------------------------------------------

Mutation = Callable[[Doc], None]


def _delete(*keys: str) -> Mutation:
    def mutate(doc: Doc) -> None:
        node = doc
        for key in keys[:-1]:
            node = node[key]
        del node[keys[-1]]

    return mutate


def _set(value: object, *keys: str) -> Mutation:
    def mutate(doc: Doc) -> None:
        node = doc
        for key in keys[:-1]:
            node = node[key]
        node[keys[-1]] = value

    return mutate


def _drop_file(path: str) -> Mutation:
    def mutate(doc: Doc) -> None:
        files = doc["sandbox"]["credentials"]["files"]
        doc["sandbox"]["credentials"]["files"] = [f for f in files if f["path"] != path]

    return mutate


def _drop_var(name: str) -> Mutation:
    def mutate(doc: Doc) -> None:
        env = doc["sandbox"]["credentials"]["envVars"]
        doc["sandbox"]["credentials"]["envVars"] = [e for e in env if e["name"] != name]

    return mutate


def _drop_rule(rule: str) -> Mutation:
    def mutate(doc: Doc) -> None:
        deny = doc["permissions"]["deny"]
        assert rule in deny, rule
        doc["permissions"]["deny"] = [r for r in deny if r != rule]

    return mutate


def _drop_domain(host: str) -> Mutation:
    def mutate(doc: Doc) -> None:
        domains = doc["sandbox"]["network"]["deniedDomains"]
        doc["sandbox"]["network"]["deniedDomains"] = [d for d in domains if d != host]

    return mutate


def _add_socket(path: str) -> Mutation:
    def mutate(doc: Doc) -> None:
        doc["sandbox"]["network"]["allowUnixSockets"].append(path)

    return mutate


def _mutations() -> list[tuple[str, Mutation, str]]:
    """(id, mutation, text the reason must contain), for the default macOS layout."""
    sandbox_flags = [
        ("enabled", True),
        ("failIfUnavailable", True),
        ("allowUnsandboxedCommands", False),
    ]
    out: list[tuple[str, Mutation, str]] = []
    for key, wanted in sandbox_flags:
        name = f"sandbox.{key}"
        out.append((f"{name}-deleted", _delete("sandbox", key), name))
        out.append((f"{name}-flipped", _set(not wanted, "sandbox", key), name))
    for key in ("enableWeakerNestedSandbox", "enableWeakerNetworkIsolation", "allowAppleEvents"):
        name = f"sandbox.{key}"
        out.append((f"{name}-true", _set(True, "sandbox", key), name))
    name = "sandbox.filesystem.allowManagedReadPathsOnly"
    out.append(
        (f"{name}-deleted", _delete("sandbox", "filesystem", "allowManagedReadPathsOnly"), name)
    )
    out.append(
        (f"{name}-flipped", _set(False, "sandbox", "filesystem", "allowManagedReadPathsOnly"), name)
    )
    for key, wanted in (
        ("allowManagedDomainsOnly", True),
        ("strictAllowlist", True),
        ("allowLocalBinding", False),
    ):
        name = f"sandbox.network.{key}"
        out.append((f"{name}-deleted", _delete("sandbox", "network", key), name))
        out.append((f"{name}-flipped", _set(not wanted, "sandbox", "network", key), name))
    name = "sandbox.network.allowUnixSockets"
    out.append((f"{name}-deleted", _delete("sandbox", "network", "allowUnixSockets"), name))
    out.append((f"{name}-extra", _add_socket("/var/run/docker.sock"), f"{name} must list exactly"))
    name = "sandbox.network.allowAllUnixSockets"
    out.append((f"{name}-true", _set(True, "sandbox", "network", "allowAllUnixSockets"), name))
    name = "permissions.disableBypassPermissionsMode"
    out.append((f"{name}-deleted", _delete("permissions", "disableBypassPermissionsMode"), name))
    out.append(
        (f"{name}-weakened", _set("enable", "permissions", "disableBypassPermissionsMode"), name)
    )
    return out


def _list_mutations(layout: Layout) -> list[tuple[str, Mutation, str]]:
    """One mutation per credential path, variable, persistence path and deny host."""
    out: list[tuple[str, Mutation, str]] = []
    doc = layout.required()
    for entry in doc["sandbox"]["credentials"]["files"]:
        path = entry["path"]
        out.append(
            (f"files:{path}", _drop_file(path), f"sandbox.credentials.files must deny {path}")
        )
    for rule in doc["permissions"]["deny"]:
        if rule.startswith("Read("):
            path = rule[5:-1].removesuffix("/**")
            out.append((rule, _drop_rule(rule), f"Read(...) rule covering {path}"))
    for name in CREDENTIAL_VARS:
        out.append(
            (f"env:{name}", _drop_var(name), f"sandbox.credentials.envVars must deny {name}")
        )
    for path in persistence_paths(layout.facts, layout.user_home):
        rule = f"Edit({path})"
        out.append((rule, _drop_rule(rule), f"Edit(...) rule covering {path}"))
    for host in HOSTS:
        out.append((f"domain:{host}", _drop_domain(host), f"deniedDomains must list {host}"))
        rule = f"WebFetch(domain:{host})"
        out.append((rule, _drop_rule(rule), f"permissions.deny must hold {rule}"))
    return out


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [(m, r) for _, m, r in _mutations()],
    ids=[i for i, _, _ in _mutations()],
)
def test_each_requirement_deleted_or_weakened_is_none(
    layout: Layout, mutation: Mutation, reason: str
) -> None:
    doc = layout.required()
    mutation(doc)
    layout.write("50-modgudr.json", doc)
    result = layout.detect()
    assert result.label == "none"
    assert any(reason in r for r in result.reasons), result.reasons


def test_each_list_entry_removed_is_none(shortdir: Path) -> None:
    layout = Layout(shortdir)
    mutations = _list_mutations(layout)
    assert len(mutations) > 40
    for ident, mutation, reason in mutations:
        doc = layout.required()
        mutation(doc)
        layout.write("50-modgudr.json", doc)
        result = layout.detect()
        assert result.label == "none", ident
        assert any(reason in r for r in result.reasons), (ident, result.reasons)


def test_a_group_writable_file_is_none(layout: Layout) -> None:
    layout.write("50-modgudr.json", layout.required(), mode=0o664)
    result = layout.detect()
    assert result.label == "none"
    assert any("must not be writable by group or others (mode 0664)" in r for r in result.reasons)


def test_linux_has_no_unix_socket_or_apple_event_requirements(shortdir: Path) -> None:
    layout = Layout(shortdir, platform="linux")
    doc = layout.required()
    network = doc["sandbox"]["network"]
    assert network["allowAllUnixSockets"] is True
    assert "allowUnixSockets" not in network
    assert "allowAppleEvents" not in doc["sandbox"]
    paths = [f["path"] for f in doc["sandbox"]["credentials"]["files"]]
    assert not [p for p in paths if "Library" in p]
    assert not [r for r in doc["permissions"]["deny"] if "Library" in r]
    layout.write("50-modgudr.json", doc)
    assert layout.detect().label == "managed-settings"


def test_required_settings_spell_every_key(layout: Layout) -> None:
    doc = layout.required()
    sandbox = doc["sandbox"]
    assert sandbox["filesystem"] == {"allowManagedReadPathsOnly": True}
    assert "allowManagedReadPathsOnly" not in doc
    assert sandbox["network"]["allowUnixSockets"] == [layout.facts.agent_socket]
    assert sandbox["network"]["allowAllUnixSockets"] is False
    assert sorted(sandbox["network"]["deniedDomains"]) == sorted(HOSTS)
    assert doc["permissions"]["disableBypassPermissionsMode"] == "disable"
    files = [f["path"] for f in sandbox["credentials"]["files"]]
    assert files == [
        "~/.azure",
        "~/.kube",
        "~/.pgpass",
        "~/.netrc",
        "~/.config/gh",
        "~/Library/DBeaverData",
        "~/.sqldeveloper",
        "~/.modgudr",
        "~/.config/bws",
    ]
    assert {f["mode"] for f in sandbox["credentials"]["files"]} == {"deny"}
    deny = doc["permissions"]["deny"]
    assert "Read(~/.pgpass)" in deny and "Read(~/.kube/**)" in deny
    assert "Read(~/.modgudr/**)" in deny and "Edit(~/.modgudr/**)" in deny
    assert "Edit(.claude/**)" in deny and "Edit(~/.local/share/uv/**)" in deny
    assert "WebFetch(domain:*.azmk8s.io)" in deny
    # Steering keys are not boundary: not required.
    assert "hooks" not in doc and "allow" not in doc["permissions"]
    assert not [r for r in deny if r.startswith("Bash(")]


# --- a non-default MODGUDR_HOME ----------------------------------------------------------------


@pytest.mark.parametrize("platform", ["darwin", "linux"])
def test_non_default_home(shortdir: Path, platform: str) -> None:
    (shortdir / "h2").mkdir()
    canonical = os.path.realpath(shortdir / "h2")
    default = Layout(shortdir, platform)
    moved = Layout(shortdir, platform, home=canonical)
    assert moved.facts.home == canonical
    assert moved.facts.human_socket == f"{canonical}/run/human.sock"

    # Settings that deny only ~/.modgudr.
    default.write("50-modgudr.json", default.required())
    result = moved.detect()
    assert result.label == "none"
    assert any(
        f"sandbox.credentials.files must deny {canonical} (MODGUDR_HOME)" in r
        for r in result.reasons
    )
    human_reasons = [r for r in result.reasons if r.startswith("human.sock")]
    assert len(human_reasons) == 1
    if platform == "linux":
        assert "on Linux that is its only protection" in human_reasons[0]

    # Settings that deny the canonical path, written absolute (`//` in permission rules).
    doc = moved.required()
    assert {"path": canonical, "mode": "deny"} in doc["sandbox"]["credentials"]["files"]
    assert f"Read(/{canonical}/**)" in doc["permissions"]["deny"]
    moved.write("50-modgudr.json", doc)
    assert moved.detect().label == "managed-settings"

    # Settings that deny a symlink to the home but not its canonical path.
    link = shortdir / "link-h2"
    link.symlink_to(canonical)
    linked = Layout(shortdir, platform, home=str(link))
    moved.write("50-modgudr.json", linked.required())
    result = moved.detect()
    assert result.label == "none"
    assert any(canonical in r for r in result.reasons)


def test_home_matching_tilde_is_written_with_tilde(layout: Layout) -> None:
    files = [f["path"] for f in layout.required()["sandbox"]["credentials"]["files"]]
    assert "~/.modgudr" in files


def test_a_new_deny_host_needs_setup_again(layout: Layout) -> None:
    layout.write("50-modgudr.json", layout.required())
    more = Facts(
        platform=layout.facts.platform,
        home=layout.facts.home,
        agent_socket=layout.facts.agent_socket,
        human_socket=layout.facts.human_socket,
        deny_hosts=(*HOSTS, "db-new.example.net"),
    )
    result = layout.detect(more)
    assert result.label == "none"
    assert "sandbox.network.deniedDomains must list db-new.example.net" in result.reasons
    assert "permissions.deny must hold WebFetch(domain:db-new.example.net)" in result.reasons


# --- facts, signature, warning --------------------------------------------------------------


def test_facts_round_trip_through_status_json(layout: Layout) -> None:
    data = layout.facts.to_json()
    assert set(data) == {"platform", "home", "agentSocket", "humanSocket", "denyHosts"}
    assert Facts.from_json(json.loads(json.dumps(data))) == layout.facts
    with pytest.raises(ValueError, match="home"):
        Facts.from_json({k: v for k, v in data.items() if k != "home"})


def test_unsupported_platform_is_refused() -> None:
    with pytest.raises(ValueError, match="unsupported platform"):
        Facts("win32", "/h", "/a.sock", "/h/run/human.sock")


def test_signature_changes_on_edit_chmod_and_new_dropin(layout: Layout) -> None:
    path = layout.write("50-modgudr.json", layout.required())
    first = settings_signature(layout.base, layout.dropins)
    assert settings_signature(layout.base, layout.dropins) == first
    path.chmod(0o664)
    second = settings_signature(layout.base, layout.dropins)
    assert second != first
    layout.write("60-more.json", {})
    assert settings_signature(layout.base, layout.dropins) != second


def test_the_l0_warning_says_modgudr() -> None:
    assert "modgudr agent-setup claude" in L0_WARNING
    assert "`mg " not in L0_WARNING
    assert L0_WARNING.splitlines()[0] == (
        "WARNING: modgudr runs as your own user and no agent isolation is configured."
    )
    assert len(L0_WARNING.splitlines()) == 4
