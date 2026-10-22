"""`modgudr doctor` (M22): every check, against a temporary home, managed-settings directory and
hook path. The status answer is built by hand; nothing here touches a system path."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
from typing import Any

import pytest

from modgudr.client.agent.doctor import (
    FAIL,
    INFO,
    OK,
    WARN,
    Context,
    Line,
    collect_lines,
    run_doctor,
)
from modgudr.client.agent.isolation import Facts, required_settings
from modgudr.client.errors import BrokerUnavailable
from tests.support.brokerfx import RootFstat


class Stat:
    """A stat that reports a chosen owner and the real mode."""

    def __init__(self, uid: int) -> None:
        self.uid = uid

    def __call__(self, path: str) -> os.stat_result:
        values = list(os.stat(path))  # noqa: PTH116
        values[4] = self.uid
        return os.stat_result(values)


class World:
    def __init__(self, root: Path, home: str | None = None) -> None:
        self.root = root
        self.user = root / "u"
        self.user.mkdir()
        self.home = home or str(self.user / ".modgudr")
        self.facts = Facts(
            platform="darwin",
            home=self.home,
            agent_socket=str(root / "c" / "agent.sock"),
            human_socket=f"{self.home}/run/human.sock",
            deny_hosts=("db.example.net",),
        )
        self.managed = root / "ms"
        self.hook = root / "mg-hook"
        self.hook.write_text("#!/usr/bin/python3\n")
        self.hook.chmod(0o755)
        self.python = root / "python3"
        self.python.write_text("")
        self.python.chmod(0o755)
        self.plist = root / "claudecode.plist"

    def context(self, **overrides: object) -> Context:
        values: dict[str, Any] = {
            "user_home": str(self.user),
            "uid": os.getuid(),
            "managed_base": self.managed / "managed-settings.json",
            "managed_dir": self.managed / "managed-settings.d",
            "hook": self.hook,
            "python": self.python,
            "mdm_plist": self.plist,
            "fstat": RootFstat(),
            "stat": Stat(0),
            "editable_dirs": list,
            "writable": lambda _path: False,
            "which": lambda _name: None,
        }
        values.update(overrides)
        return Context(**values)

    def status(self, **overrides: object) -> dict[str, Any]:
        data: dict[str, Any] = {
            **self.facts.to_json(),
            "version": "0.1.0",
            "protocol": {"broker": [1]},
            "state": "locked",
            "dev": False,
            "isolation": "none",
            "policy": {
                "files": [
                    {"name": "00-company.yaml", "uid": 0, "mode": "0644"},
                    {"name": "50-targets.yaml", "uid": os.getuid(), "mode": "0644"},
                ]
            },
        }
        data.update(overrides)
        return data

    def install(self, settings: dict[str, Any] | None = None) -> Path:
        document = (
            settings
            if settings is not None
            else required_settings(self.facts, user_home=str(self.user))
        )
        path = self.managed / "managed-settings.d" / "50-modgudr.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document))
        return path


@pytest.fixture
def world(shortdir: Path) -> World:
    return World(shortdir)


def levels(lines: list[Line], needle: str) -> list[str]:
    return [line.level for line in lines if needle in line.text]


def texts(lines: list[Line], level: str) -> list[str]:
    return [line.text for line in lines if line.level == level]


def test_no_settings_and_a_readable_credential_path_fail(world: World) -> None:
    (world.user / ".azure").mkdir()
    lines, none = collect_lines(world.context(), world.status())
    assert none
    assert any("~/.azure exists and is not denied" in t for t in texts(lines, FAIL))
    assert any(t.startswith("isolation: none; no managed settings") for t in texts(lines, FAIL))
    out = io.StringIO()
    code = run_doctor(world.context(), status_fn=world.status, out=out)
    assert code == 1
    assert "FAIL" in out.getvalue()


def test_a_matching_dropin_is_ok(world: World) -> None:
    (world.user / ".azure").mkdir()
    world.install()
    lines, none = collect_lines(world.context(), world.status())
    assert not none
    assert not texts(lines, FAIL), texts(lines, FAIL)
    assert any(t.startswith("isolation: managed-settings") for t in texts(lines, OK))
    assert any("~/.azure exists and the managed settings deny it" in t for t in texts(lines, OK))
    assert any(f"MODGUDR_HOME {world.home} exists" in t for t in texts(lines, OK))
    assert run_doctor(world.context(), status_fn=world.status, out=io.StringIO()) == 0


def test_a_dropin_without_fail_if_unavailable_fails_naming_it(world: World) -> None:
    settings = required_settings(world.facts, user_home=str(world.user))
    del settings["sandbox"]["failIfUnavailable"]  # type: ignore[attr-defined,index]
    world.install(settings)
    lines, none = collect_lines(world.context(), world.status())
    assert none
    assert any("sandbox.failIfUnavailable must be true" in t for t in texts(lines, FAIL))
    code = run_doctor(world.context(), status_fn=world.status, out=io.StringIO())
    assert code == 1


def test_a_dropin_for_the_default_home_fails_when_the_broker_reports_another(
    shortdir: Path,
) -> None:
    other_home = str(shortdir / "elsewhere")
    world = World(shortdir, home=other_home)
    Path(other_home).mkdir()
    default = Facts(
        platform="darwin",
        home=str(world.user / ".modgudr"),
        agent_socket=world.facts.agent_socket,
        human_socket=str(world.user / ".modgudr" / "run" / "human.sock"),
        deny_hosts=world.facts.deny_hosts,
    )
    world.install(required_settings(default, user_home=str(world.user)))
    lines, none = collect_lines(world.context(), world.status())
    assert none
    failed = texts(lines, FAIL)
    assert any(f"MODGUDR_HOME {other_home} exists and is not denied" in t for t in failed)
    assert any(other_home in t and t.startswith("isolation: none") for t in failed)


def test_an_mdm_profile_warns(world: World) -> None:
    world.plist.write_text("<plist/>")
    lines, _ = collect_lines(world.context(), world.status())
    assert any("MDM profile" in t and "may be skipped" in t for t in texts(lines, WARN))


def test_a_hook_the_user_can_write_fails(world: World) -> None:
    world.hook.chmod(0o666)
    lines, _ = collect_lines(world.context(), world.status())
    assert any("hook" in t and "writable by group or others" in t for t in texts(lines, FAIL))
    world.hook.chmod(0o755)
    lines, _ = collect_lines(world.context(stat=Stat(os.getuid() + 1)), world.status())
    assert any("not by root" in t for t in texts(lines, FAIL))
    lines, _ = collect_lines(world.context(hook=world.root / "absent"), world.status())
    assert any("absent does not exist" in t for t in texts(lines, FAIL))


def test_allow_unix_sockets_covering_human_sock_fails(world: World) -> None:
    settings = required_settings(world.facts, user_home=str(world.user))
    settings["sandbox"]["network"]["allowUnixSockets"] = [  # type: ignore[index]
        world.facts.agent_socket,
        f"{world.home}/run",
    ]
    world.install(settings)
    lines, _ = collect_lines(world.context(), world.status())
    assert any("covers human.sock" in t for t in texts(lines, FAIL))


def test_directory_and_socket_modes(world: World) -> None:
    home = Path(world.home)
    (home / "run").mkdir(parents=True)
    home.chmod(0o755)
    (home / "run").chmod(0o700)
    lines, _ = collect_lines(world.context(), world.status())
    assert any(f"state directory {home} has mode 0755" in t for t in texts(lines, FAIL))
    assert any(f"run directory {home / 'run'} is private" in t for t in texts(lines, OK))
    assert any("audit directory" in t and "does not exist" in t for t in texts(lines, WARN))


def test_policy_file_owners(world: World) -> None:
    status = world.status(
        policy={
            "files": [
                {"name": "00-company.yaml", "uid": os.getuid(), "mode": "0644"},
                {"name": "50-targets.yaml", "uid": 4242, "mode": "0644"},
                {"name": "60-more.yaml", "uid": 0, "mode": "0666"},
            ]
        }
    )
    lines, _ = collect_lines(world.context(), status)
    failed = texts(lines, FAIL)
    assert any("00-company.yaml" in t for t in failed)  # not dev: a user-owned company file
    assert any("50-targets.yaml" in t for t in failed)
    assert any("60-more.yaml" in t and "writable" in t for t in failed)
    dev = world.status(dev=True, policy={"files": [world.status()["policy"]["files"][0]]})
    dev["policy"]["files"][0]["uid"] = os.getuid()
    lines, _ = collect_lines(world.context(), dev)
    assert any("dev mode" in t for t in texts(lines, WARN))


def test_an_editable_install_in_a_writable_directory_warns(world: World) -> None:
    lines, _ = collect_lines(
        world.context(editable_dirs=lambda: ["/src/modgudr"], writable=lambda _p: True),
        world.status(),
    )
    assert any("editable install in /src/modgudr" in t for t in texts(lines, WARN))
    lines, _ = collect_lines(world.context(editable_dirs=lambda: ["/src/modgudr"]), world.status())
    assert not any("editable" in t for t in texts(lines, WARN))


def test_the_mg_name_is_an_info_line(world: World) -> None:
    lines, _ = collect_lines(world.context(which=lambda _n: "/usr/bin/mg"), world.status())
    assert any("/usr/bin/mg" in t for t in texts(lines, INFO))
    lines, _ = collect_lines(world.context(), world.status())
    assert any("no `mg` on PATH" in t for t in texts(lines, INFO))


def test_a_broker_that_is_down_fails_and_the_rest_still_runs(world: World) -> None:
    def down() -> dict[str, Any]:
        raise BrokerUnavailable("broker not running; start it in your own terminal")

    out = io.StringIO()
    assert run_doctor(world.context(), status_fn=down, out=out) == 1
    text = out.getvalue()
    assert "FAIL broker not reachable: broker not running" in text
    assert "hook" in text and "MDM profile" in text


def test_the_broker_version_is_reported(world: World) -> None:
    lines, _ = collect_lines(world.context(), world.status())
    assert any("modgudr-broker 0.1.0" in t and "v1" in t for t in texts(lines, OK))
