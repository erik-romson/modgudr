"""`modgudr agent-setup claude` (M20): the generated drop-in, its refusals and `INSTALL.txt`.

The broker is a stub server on `agent.sock` answering `status` and `targets`. Output goes to short
temporary directories; the generated drop-in is checked with step 06's detection predicate through
an injected root owner. Nothing here touches a system path.
"""

from __future__ import annotations

import ast
import json
import os
import sys
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from modgudr.client import cli
from modgudr.client.agent import hook, setup
from modgudr.client.agent.isolation import KUBECTL_DENY_HOSTS, Facts, Isolation, detect
from modgudr.client.agent.setup import (
    DEFAULT_ALLOWED_DOMAINS,
    DROPIN_DIR,
    DROPIN_FILE,
    HOOK_FILE,
    INSTALL_FILE,
    MARKER_KEY,
    run_setup,
)
from modgudr.client.errors import BrokerUnavailable, UsageError
from tests.support.brokerfx import RootFstat
from tests.support.stubbroker import StubBroker

Doc = dict[str, Any]

SNOWFLAKE_HOST = "acme-example.snowflakecomputing.com"
ORACLE_HOST = "db-test.example.net"
TARGETS = [
    {
        "name": "snow-test",
        "type": "sql",
        "system": "snow",
        "env": "test",
        "destinations": [f"{SNOWFLAKE_HOST}:443"],
    },
    {
        "name": "ora-test",
        "type": "sql",
        "system": "ora",
        "env": "test",
        "destinations": [f"{ORACLE_HOST}:1521"],
    },
    {"name": "aks-test", "type": "kubectl", "system": "aks", "env": "test", "destinations": []},
]
HOSTS = (ORACLE_HOST, SNOWFLAKE_HOST, *KUBECTL_DENY_HOSTS)


class World:
    """A temporary home, the facts a broker would report and the stub that reports them."""

    def __init__(self, root: Path, platform: str = "darwin", home: str | None = None) -> None:
        self.root = root
        self.user_home = str(root / "u")
        (root / "u").mkdir()
        self.platform = platform
        modgudr_home = home or f"{self.user_home}/.modgudr"
        self.facts = Facts(
            platform=platform,
            home=modgudr_home,
            agent_socket=str(root / "agent.sock"),
            human_socket=f"{modgudr_home}/run/human.sock",
            deny_hosts=HOSTS,
        )
        self.out = root / "out"
        self.dropin = self.out / DROPIN_DIR / DROPIN_FILE

    def answers(self) -> dict[str, object]:
        return {
            "status": {**self.facts.to_json(), "isolation": "none"},
            "targets": {"targets": TARGETS},
        }

    def broker(self) -> StubBroker:
        return StubBroker(Path(self.facts.agent_socket), self.answers())

    def run(
        self,
        *allow: str,
        force: bool = False,
        uid: int = 1000,
        remove: Sequence[str] = (),
        **env: str,
    ) -> str:
        return run_setup(
            self.out,
            allow,
            force=force,
            remove_domains=remove,
            platform=self.platform,
            uid=uid,
            user_home=self.user_home,
            environ=env,
        )

    def settings(self) -> Doc:
        return json.loads(self.dropin.read_text())


@pytest.fixture
def world(shortdir: Path, monkeypatch: pytest.MonkeyPatch) -> World:
    w = World(shortdir)
    monkeypatch.setenv("MODGUDR_SOCKET", w.facts.agent_socket)
    return w


def generate(w: World, *allow: str) -> Doc:
    with w.broker():
        w.run(*allow)
    return w.settings()


def test_the_dropin_has_every_m20_key(world: World) -> None:
    doc = generate(world)
    assert doc[MARKER_KEY]
    sandbox = doc["sandbox"]
    for key, value in {
        "enabled": True,
        "failIfUnavailable": True,
        "allowUnsandboxedCommands": False,
        "enableWeakerNestedSandbox": False,
        "enableWeakerNetworkIsolation": False,
        "allowAppleEvents": False,
    }.items():
        assert sandbox[key] is value, key
    assert sandbox["filesystem"] == {"allowManagedReadPathsOnly": True}
    assert "allowManagedReadPathsOnly" not in doc
    credentials = sandbox["credentials"]
    assert all(entry["mode"] == "deny" for entry in credentials["files"])
    paths = [entry["path"] for entry in credentials["files"]]
    for wanted in (
        "~/.azure",
        "~/.kube",
        "~/.pgpass",
        "~/.netrc",
        "~/.config/gh",
        "~/Library/DBeaverData",
        "~/.sqldeveloper",
        "~/.ssh",
        "~/.modgudr",
        "~/.config/bws",
    ):
        assert wanted in paths
    assert all(entry["mode"] == "deny" for entry in credentials["envVars"])
    assert [e["name"] for e in credentials["envVars"]] == [
        "PGPASSWORD",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "JIRA_API_TOKEN",
        "SNOWFLAKE_PASSWORD",
        "SNOWFLAKE_PRIVATE_KEY",
        "AZURE_CLIENT_SECRET",
        "BW_SESSION",
        "BWS_ACCESS_TOKEN",
    ]
    network = sandbox["network"]
    assert network["allowedDomains"] == list(DEFAULT_ALLOWED_DOMAINS)
    assert network["allowManagedDomainsOnly"] is True
    assert network["strictAllowlist"] is True
    assert network["allowLocalBinding"] is False
    permissions = doc["permissions"]
    assert permissions["disableBypassPermissionsMode"] == "disable"
    deny = permissions["deny"]
    for tool in (
        "kubectl",
        "kubelogin",
        "az",
        "sqlplus",
        "sql",
        "snowsql",
        "snow",
        "bw",
        "bws",
        "security",
    ):
        assert f"Bash({tool}:*)" in deny
    assert "Read(~/.kube/**)" in deny
    assert "Read(~/.pgpass)" in deny
    assert "Edit(~/.zshrc)" in deny
    assert "Edit(~/.local/share/uv/**)" in deny
    assert "Edit(.claude/**)" in deny
    assert "Edit(~/.modgudr/**)" in deny
    assert "Edit(~/Library/LaunchAgents/**)" in deny
    assert "Edit(~/.gradle/**)" in deny
    assert "Edit(~/.m2/**)" in deny


def test_allow_domains_without_an_installed_dropin_replace_the_defaults(world: World) -> None:
    doc = generate(world, "pypi.org", "*.example.net")
    assert doc["sandbox"]["network"]["allowedDomains"] == ["pypi.org", "*.example.net"]


@pytest.mark.parametrize("domain", ["", "https://pypi.org", "a b", "pypi.org/simple", "-x"])
def test_a_malformed_allow_domain_is_refused(world: World, domain: str) -> None:
    with world.broker(), pytest.raises(UsageError):
        world.run(domain)
    assert not world.out.exists()


def test_unix_sockets_on_macos(world: World) -> None:
    doc = generate(world)
    network = doc["sandbox"]["network"]
    assert network["allowUnixSockets"] == [world.facts.agent_socket]
    assert network["allowAllUnixSockets"] is False
    human = world.facts.human_socket
    assert not any(human.startswith(entry) for entry in network["allowUnixSockets"])


def test_deny_lists_name_every_destination_and_the_azure_domains(world: World) -> None:
    doc = generate(world)
    denied = doc["sandbox"]["network"]["deniedDomains"]
    for host in (SNOWFLAKE_HOST, ORACLE_HOST, *KUBECTL_DENY_HOSTS):
        assert host in denied
        assert f"WebFetch(domain:{host})" in doc["permissions"]["deny"]


def test_a_target_host_the_status_lacks_is_denied_too(world: World) -> None:
    world.facts = replace(world.facts, deny_hosts=(SNOWFLAKE_HOST,))
    doc = generate(world)
    assert ORACLE_HOST in doc["sandbox"]["network"]["deniedDomains"]
    assert f"WebFetch(domain:{ORACLE_HOST})" in doc["permissions"]["deny"]


def test_linux_variant(shortdir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    w = World(shortdir, platform="linux")
    monkeypatch.setenv("MODGUDR_SOCKET", w.facts.agent_socket)
    doc = generate(w)
    network = doc["sandbox"]["network"]
    assert network["allowAllUnixSockets"] is True
    assert "allowUnixSockets" not in network
    assert "allowAppleEvents" not in doc["sandbox"]
    assert "Library" not in json.dumps(doc)
    with w.broker():
        text = w.run(force=True)
    assert "/etc/claude-code/managed-settings.d/50-modgudr.json" in text
    assert "/Library/Application Support" not in text


@pytest.mark.parametrize("platform", ["darwin", "linux"])
def test_a_non_default_home_is_denied_by_its_absolute_path(
    shortdir: Path, monkeypatch: pytest.MonkeyPatch, platform: str
) -> None:
    home = str(shortdir / "h2")
    w = World(shortdir, platform=platform, home=home)
    monkeypatch.setenv("MODGUDR_SOCKET", w.facts.agent_socket)
    doc = generate(w)
    paths = [entry["path"] for entry in doc["sandbox"]["credentials"]["files"]]
    assert home in paths
    assert "~/.modgudr" not in paths
    deny = doc["permissions"]["deny"]
    assert f"Read(/{home}/**)" in deny
    assert f"Edit(/{home}/**)" in deny
    assert all("~/.modgudr" not in rule for rule in deny)
    assert w.facts.human_socket.startswith(home + "/")


def detect_in(w: World, facts: Facts | None = None) -> Isolation:
    base = w.root / "ms" / "managed-settings.json"
    dropins = w.root / "ms" / DROPIN_DIR
    dropins.mkdir(parents=True, exist_ok=True)
    target = dropins / DROPIN_FILE
    target.write_text(w.dropin.read_text())
    target.chmod(0o644)
    return detect(
        facts or w.facts,
        user_home=w.user_home,
        base=base,
        dropin_dir=dropins,
        fstat=RootFstat(),
    )


@pytest.mark.parametrize(
    ("platform", "custom_home"),
    [("darwin", False), ("linux", False), ("darwin", True), ("linux", True)],
)
def test_round_trip_through_detection(
    shortdir: Path, monkeypatch: pytest.MonkeyPatch, platform: str, custom_home: bool
) -> None:
    home = str(shortdir / "h2") if custom_home else None
    w = World(shortdir, platform=platform, home=home)
    monkeypatch.setenv("MODGUDR_SOCKET", w.facts.agent_socket)
    generate(w)
    result = detect_in(w)
    assert result.label == "managed-settings", result.reasons

    more = replace(w.facts, deny_hosts=(*w.facts.deny_hosts, "new-db.example.net"))
    added = detect_in(w, more)
    assert added.label == "none"
    assert any("new-db.example.net" in reason for reason in added.reasons)

    moved_home = str(shortdir / "elsewhere")
    moved = replace(w.facts, home=moved_home, human_socket=f"{moved_home}/run/human.sock")
    gone = detect_in(w, moved)
    assert gone.label == "none"
    assert any(moved_home in reason for reason in gone.reasons)


def test_the_hook_entry(world: World) -> None:
    doc = generate(world)
    entries = doc["hooks"]["PreToolUse"]
    assert len(entries) == 1 and entries[0]["matcher"] == "Bash"
    assert entries[0]["hooks"] == [
        {
            "type": "command",
            "command": "/usr/bin/python3",
            "args": ["-I", "/opt/modgudr/bin/mg-hook"],
            "timeout": 10,
            "onFailure": "block",
        }
    ]
    assert doc["permissions"]["allow"] == ["Bash(modgudr:*)"]


def listing(root: Path) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*"))


def test_it_writes_three_files(world: World) -> None:
    generate(world)
    assert listing(world.out) == sorted(
        [INSTALL_FILE, HOOK_FILE, DROPIN_DIR, f"{DROPIN_DIR}/{DROPIN_FILE}"]
    )
    assert (world.out / HOOK_FILE).read_text() == Path(hook.__file__).read_text()
    assert (world.out / HOOK_FILE).stat().st_mode & 0o111


def test_root_is_refused(world: World) -> None:
    with world.broker(), pytest.raises(UsageError, match="root or under sudo"):
        world.run(uid=0)
    assert not world.out.exists()


def test_sudo_is_refused(world: World) -> None:
    with world.broker(), pytest.raises(UsageError, match="root or under sudo"):
        world.run(SUDO_USER="someone")
    assert not world.out.exists()


def test_existing_output_needs_force(world: World) -> None:
    generate(world)
    world.dropin.write_text(json.dumps({MARKER_KEY: "old"}))
    with world.broker(), pytest.raises(UsageError, match="--force"):
        world.run()
    assert json.loads(world.dropin.read_text()) == {MARKER_KEY: "old"}
    with world.broker():
        world.run(force=True)
    assert world.settings()["sandbox"]["enabled"] is True


@pytest.mark.parametrize("force", [False, True])
def test_a_dropin_without_the_marker_is_never_replaced(world: World, force: bool) -> None:
    world.dropin.parent.mkdir(parents=True)
    world.dropin.write_text('{"sandbox": {"enabled": false}}')
    with world.broker(), pytest.raises(UsageError, match="not written by modgudr"):
        world.run(force=force)
    assert world.dropin.read_text() == '{"sandbox": {"enabled": false}}'
    assert listing(world.out) == [DROPIN_DIR, f"{DROPIN_DIR}/{DROPIN_FILE}"]


def test_the_install_text(world: World) -> None:
    with world.broker():
        text = world.run()
    assert (world.out / INSTALL_FILE).read_text() == text
    assert (
        "sudo install -d -m 0755 -o root -g wheel "
        "'/Library/Application Support/ClaudeCode/managed-settings.d'" in text
    )
    assert (
        f"sudo install -m 0644 -o root -g wheel {world.out / DROPIN_DIR / DROPIN_FILE} "
        "'/Library/Application Support/ClaudeCode/managed-settings.d/50-modgudr.json'"
    ) in text
    assert (
        f"sudo install -m 0755 -o root -g wheel {world.out / HOOK_FILE} /opt/modgudr/bin/mg-hook"
    ) in text
    assert (
        "sudo rm -f "
        "'/Library/Application Support/ClaudeCode/managed-settings.d/50-modgudr.json' "
        "/opt/modgudr/bin/mg-hook" in text
    )
    assert "claude doctor" in text and "/status" in text
    assert MARKER_KEY in text  # the check before installing over a foreign file
    for name in ("snow-test", "ora-test", "aks-test"):
        assert name in text
    assert text.endswith("\n")


def test_the_hook_source_is_python39_stdlib_only() -> None:
    source = Path(hook.__file__).read_text()
    tree = ast.parse(source, feature_version=(3, 9))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0
            imported.add((node.module or "").split(".")[0])
    assert "modgudr" not in imported
    assert imported <= set(sys.stdlib_module_names)


def test_the_broker_being_down_is_exit_6(world: World, shortdir: Path) -> None:
    with pytest.raises(BrokerUnavailable):
        world.run()
    assert not world.out.exists()


def test_the_cli_writes_and_prints(world: World, capsys: pytest.CaptureFixture[str]) -> None:
    with world.broker():
        code = cli.main(
            ["agent-setup", "claude", "--out", str(world.out), "--allow-domain", "pypi.org"]
        )
    captured = capsys.readouterr()
    assert code == 0
    assert "sudo install" in captured.out
    assert world.settings()["sandbox"]["network"]["allowedDomains"] == ["pypi.org"]
    with world.broker():
        assert cli.main(["agent-setup", "claude", "--out", str(world.out)]) == 64
    assert "--force" in capsys.readouterr().err


def test_the_cli_exits_6_when_the_broker_is_down(
    world: World, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["agent-setup", "claude", "--out", str(world.out)]) == 6
    assert "broker not running" in capsys.readouterr().err
    assert not world.out.exists()


def test_the_cli_needs_an_agent(world: World) -> None:
    assert cli.main(["agent-setup"]) == 64
    assert cli.main(["agent-setup", "codex"]) == 64


# --- the installed domains -----------------------------------------------------------------------

Install = Callable[[object], Path]


def point_at(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    def installed_dropin(platform: str) -> Path:
        return path

    monkeypatch.setattr(setup, "installed_dropin", installed_dropin)


def dropin_with(allowed: object) -> dict[str, Any]:
    return {MARKER_KEY: "old", "sandbox": {"network": {"allowedDomains": allowed}}}


@pytest.fixture
def install(world: World, monkeypatch: pytest.MonkeyPatch) -> Install:
    """Writes the installed drop-in (a JSON value, or text) and points `installed_dropin` at it."""
    path = world.root / "installed.json"

    def write(document: object) -> Path:
        path.write_text(document if isinstance(document, str) else json.dumps(document))
        point_at(monkeypatch, path)
        return path

    return write


def allowed(w: World) -> list[str]:
    return w.settings()["sandbox"]["network"]["allowedDomains"]


def run_with(w: World, *allow: str, remove: Sequence[str] = (), force: bool = False) -> str:
    with w.broker():
        return w.run(*allow, remove=remove, force=force)


def refused(w: World, *allow: str, remove: Sequence[str] = (), match: str) -> None:
    with w.broker(), pytest.raises(UsageError, match=match):
        w.run(*allow, remove=remove)
    assert not w.out.exists()


def test_nothing_installed_gives_the_defaults(world: World) -> None:
    text = run_with(world)
    assert allowed(world) == list(DEFAULT_ALLOWED_DOMAINS)
    assert "no drop-in installed" in text
    assert "added:" not in text


def test_nothing_installed_with_an_allow_domain_gives_only_that(world: World) -> None:
    run_with(world, "Example.NET")
    assert allowed(world) == ["example.net"]


def test_nothing_installed_cannot_remove(world: World) -> None:
    refused(world, remove=["a.org"], match="nothing to remove from")


def test_a_reinstall_with_no_flags_changes_nothing(world: World, install: Install) -> None:
    install(dropin_with(["B.org", "a.org"]))
    text = run_with(world)
    assert allowed(world) == ["B.org", "a.org"]
    assert "added: none" in text and "removed: none" in text
    assert "no drop-in installed" not in text


def test_additions_follow_the_installed_order_and_are_stable(
    world: World, install: Install
) -> None:
    install(dropin_with(["b.org", "a.org"]))
    run_with(world, "c.org")
    assert allowed(world) == ["b.org", "a.org", "c.org"]
    # The installed file is unchanged, so the second run still adds c.org to it.
    text = run_with(world, "c.org", force=True)
    assert allowed(world) == ["b.org", "a.org", "c.org"]
    assert "added: c.org" in text


def test_a_removal(world: World, install: Install) -> None:
    install(dropin_with(["a.org", "b.org"]))
    text = run_with(world, remove=["a.org"])
    assert allowed(world) == ["b.org"]
    assert "removed: a.org" in text and "added: none" in text


def test_an_allow_and_a_remove_together(world: World, install: Install) -> None:
    install(dropin_with(["a.org", "b.org"]))
    text = run_with(world, "c.org", remove=["a.org"])
    assert allowed(world) == ["b.org", "c.org"]
    assert "added: c.org" in text and "removed: a.org" in text


def test_removing_a_domain_that_is_not_installed_is_refused(world: World, install: Install) -> None:
    install(dropin_with(["a.org", "b.org"]))
    with world.broker(), pytest.raises(UsageError) as caught:
        world.run(remove=["z.org"])
    message = str(caught.value)
    assert "a.org, b.org" in message and "Only 50-modgudr.json" in message
    assert not world.out.exists()


def test_removing_the_last_domain_leaves_none(world: World, install: Install) -> None:
    install(dropin_with(["a.org"]))
    text = run_with(world, remove=["a.org"])
    assert allowed(world) == []
    assert "allowed domains: none" in text


def test_an_empty_installed_list_stays_empty(world: World, install: Install) -> None:
    install(dropin_with([]))
    run_with(world)
    assert allowed(world) == []


def test_domains_compare_case_insensitively(world: World, install: Install) -> None:
    install(dropin_with(["pypi.org"]))
    text = run_with(world, "Pypi.org")
    assert allowed(world) == ["pypi.org"]
    assert "added: none" in text
    run_with(world, remove=["PYPI.ORG"], force=True)
    assert allowed(world) == []


def test_allow_and_remove_of_the_same_domain_is_refused_before_reading(
    world: World, install: Install
) -> None:
    install("not json")
    refused(world, "x.org", remove=["X.org"], match="'x.org'")


def test_a_wildcard_and_its_apex_are_different_entries(world: World, install: Install) -> None:
    install(dropin_with(["example.net"]))
    refused(world, remove=["*.example.net"], match="not in the installed drop-in")
    run_with(world, "*.example.net")
    assert allowed(world) == ["example.net", "*.example.net"]


def test_a_malformed_installed_entry_is_refused_but_can_be_removed(
    world: World, install: Install
) -> None:
    install(dropin_with(["pypi.org", "https://x.com"]))
    refused(world, match="https://x.com")
    run_with(world, remove=["https://x.com"])
    assert allowed(world) == ["pypi.org"]


def test_an_absent_file_or_parent_gives_the_defaults(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    point_at(monkeypatch, world.root / "none.json")
    run_with(world)
    assert allowed(world) == list(DEFAULT_ALLOWED_DOMAINS)
    point_at(monkeypatch, world.root / "no" / "x.json")
    run_with(world, force=True)
    assert allowed(world) == list(DEFAULT_ALLOWED_DOMAINS)


def test_a_directory_at_the_path_is_refused(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    path = world.root / "installed.json"
    path.mkdir()
    point_at(monkeypatch, path)
    refused(world, match=str(path))


@pytest.mark.skipif(os.getuid() == 0, reason="root reads a mode 000 file")
def test_an_unreadable_file_is_refused(world: World, install: Install) -> None:
    path = install(dropin_with(["a.org"]))
    path.chmod(0)
    try:
        refused(world, match=str(path))
    finally:
        path.chmod(0o600)


@pytest.mark.parametrize(
    "document",
    [
        "not json",
        "[]",
        {"sandbox": {"network": {"allowedDomains": ["a.org"]}}},
        dropin_with("a.org"),
        dropin_with(["a.org", 5]),
        {MARKER_KEY: "old", "sandbox": {"network": {}}},
        {MARKER_KEY: "old"},
    ],
)
def test_an_unusable_installed_file_is_refused(
    world: World, install: Install, document: object
) -> None:
    path = install(document)
    refused(world, match=str(path))


def test_an_unparseable_file_is_exit_64_even_with_the_broker_down(
    world: World, install: Install, capsys: pytest.CaptureFixture[str]
) -> None:
    install("not json")
    assert cli.main(["agent-setup", "claude", "--out", str(world.out)]) == 64
    assert "not JSON" in capsys.readouterr().err
    assert not world.out.exists()


def test_the_cli_removes_a_domain(
    world: World, install: Install, capsys: pytest.CaptureFixture[str]
) -> None:
    install(dropin_with(["a.org", "b.org"]))
    with world.broker():
        code = cli.main(
            ["agent-setup", "claude", "--out", str(world.out), "--remove-domain", "a.org"]
        )
    assert code == 0
    assert "removed: a.org" in capsys.readouterr().out
    assert allowed(world) == ["b.org"]
    with world.broker():
        args = ["agent-setup", "claude", "--out", str(world.out), "--remove-domain", "z.org"]
        assert cli.main([*args, "--force"]) == 64
    assert "not in the installed drop-in" in capsys.readouterr().err


def test_the_installed_dropin_is_never_under_the_system_path_in_tests(
    world: World, install: Install
) -> None:
    assert not str(setup.installed_dropin("darwin")).startswith("/Library")
    install(dropin_with([]))
    assert not str(setup.installed_dropin("darwin")).startswith("/Library")


def test_the_real_installed_path_is_the_install_target() -> None:
    assert setup.install_target("darwin").endswith(f"{DROPIN_DIR}/{DROPIN_FILE}")
