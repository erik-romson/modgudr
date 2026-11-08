"""`modgudr agent-setup claude`: the managed settings, the hook and the install steps (M20).

The generator reads `status --json` (the M22 facts) and `targets --json` from the broker over
`agent.sock`. The boundary-bearing keys come from `required_settings(facts)` in
`modgudr.client.agent.isolation`, the function isolation detection checks against; this module
adds only the steering keys: `permissions.allow`, the `Bash(<tool>:*)` denies, the allowed
domains and the hook. It writes into an output directory and never to a system path.
"""

import ast
import importlib.resources
import json
import os
import pwd
import re
import shlex
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from modgudr.client import paths
from modgudr.client.agent.hook import BLOCKED_TOOLS, FILE_TOOLS
from modgudr.client.agent.isolation import (
    SETTINGS_DIRS,
    Facts,
    check_settings,
    merge_settings,
    required_settings,
)
from modgudr.client.errors import Error, UsageError
from modgudr.client.protocol import Result
from modgudr.client.transport import client_info, client_version, open_call

MARKER_KEY = "_modgudrGenerated"
DROPIN_FILE = "50-modgudr.json"
DROPIN_DIR = "managed-settings.d"
HOOK_FILE = "mg-hook"
INSTALL_FILE = "INSTALL.txt"

#: Where the printed steps install the hook; root-owned, outside the home (A17, Q5).
HOOK_INSTALL_DIR = "/opt/modgudr/bin"
HOOK_INSTALL_PATH = f"{HOOK_INSTALL_DIR}/{HOOK_FILE}"
HOOK_INTERPRETER = "/usr/bin/python3"

DEFAULT_ALLOWED_DOMAINS = ("pypi.org", "files.pythonhosted.org", "registry.npmjs.org")

_DOMAIN = re.compile(r"(\*\.)?[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?")


@dataclass(frozen=True)
class BrokerFacts:
    """What the generator learns from the broker."""

    facts: Facts
    #: (name, system, env, type) of every target, for the install notes.
    targets: tuple[tuple[str, str, str, str], ...]
    #: Every host a target contacts.
    hosts: tuple[str, ...]


# --- the broker ----------------------------------------------------------------------------------


def _meta(op: str) -> Any:  # noqa: ANN401
    call = open_call(paths.agent_socket(), op, client=client_info("agent-setup"))
    try:
        data: Any = None
        for frame in call.frames():
            if isinstance(frame, Result):
                data = frame.data
        return data
    finally:
        call.close()


def _host_of(destination: str) -> str:
    """The host of a `host:port` destination (IPv6 literals in brackets)."""
    if destination.startswith("["):
        return destination[1:].split("]", 1)[0].lower()
    return destination.rpartition(":")[0].lower() if ":" in destination else destination.lower()


def _as_dict(value: object) -> dict[str, Any] | None:
    return cast("dict[str, Any]", value) if isinstance(value, dict) else None


def _as_list(value: object) -> list[Any] | None:
    return cast("list[Any]", value) if isinstance(value, list) else None


def read_broker_facts(status: object, targets: object, *, platform: str) -> BrokerFacts:
    """The facts from the answers of `status` and `targets`. The platform is the one the variant
    is generated for. Raises `Error` when an answer is malformed."""
    status_doc = _as_dict(status)
    if status_doc is None:
        raise Error("the broker's status answer is malformed")
    try:
        facts = Facts.from_json({**status_doc, "platform": platform})
    except ValueError as exc:
        raise Error(f"the broker's status answer is incomplete: {exc}") from None
    targets_doc = _as_dict(targets)
    entries = _as_list(targets_doc.get("targets")) if targets_doc is not None else None
    if entries is None:
        raise Error("the broker's targets answer is malformed")
    summary: list[tuple[str, str, str, str]] = []
    hosts: set[str] = set()
    for entry in entries:
        item = _as_dict(entry)
        destinations = _as_list(item.get("destinations", [])) if item is not None else None
        if item is None or destinations is None:
            raise Error("the broker's targets answer is malformed")
        values = [item.get(key) for key in ("name", "system", "env", "type")]
        if not all(isinstance(v, str) for v in values):
            raise Error("the broker's targets answer is malformed")
        name, system, env, kind = (str(v) for v in values)
        summary.append((name, system, env, kind))
        hosts.update(_host_of(d) for d in destinations if isinstance(d, str))
    return BrokerFacts(facts, tuple(summary), tuple(sorted(hosts)))


# --- the settings --------------------------------------------------------------------------------


def hook_entry(matcher: str) -> dict[str, Any]:
    return {
        "matcher": matcher,
        "hooks": [
            {
                "type": "command",
                "command": HOOK_INTERPRETER,
                "args": ["-I", HOOK_INSTALL_PATH],
                "timeout": 10,
                "onFailure": "block",
            }
        ],
    }


def build_settings(
    broker: BrokerFacts, *, user_home: str, allow_domains: Sequence[str], version: str
) -> dict[str, object]:
    """The drop-in: the required boundary keys plus the steering keys."""
    # Hosts the facts do not list (a target the status answer lags behind) are denied as well.
    hosts = tuple(sorted({*broker.facts.deny_hosts, *broker.hosts}))
    facts = Facts(
        platform=broker.facts.platform,
        home=broker.facts.home,
        agent_socket=broker.facts.agent_socket,
        human_socket=broker.facts.human_socket,
        deny_hosts=hosts,
    )
    settings: dict[str, object] = {MARKER_KEY: version}
    settings.update(required_settings(facts, user_home=user_home))
    sandbox: dict[str, Any] = settings["sandbox"]  # pyright: ignore[reportAssignmentType]
    sandbox["network"]["allowedDomains"] = list(allow_domains)
    permissions: dict[str, Any] = settings["permissions"]  # pyright: ignore[reportAssignmentType]
    permissions["allow"] = ["Bash(modgudr:*)"]
    permissions["deny"] = [*permissions["deny"], *(f"Bash({tool}:*)" for tool in BLOCKED_TOOLS)]
    settings["hooks"] = {"PreToolUse": [hook_entry("Bash"), hook_entry("|".join(FILE_TOOLS))]}
    return settings


def validate_settings(
    text: str, facts: Facts, *, user_home: str, version: str
) -> dict[str, object]:
    """Parse the generated JSON and check it against the detection predicate. Raises `Error`."""
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise Error(f"internal: the generated settings are not valid JSON: {exc}") from None
    if not isinstance(document, dict) or document.get(MARKER_KEY) != version:  # pyright: ignore[reportUnknownMemberType]
        raise Error("internal: the generated settings lack the generation marker")
    merged = merge_settings([document])  # pyright: ignore[reportUnknownArgumentType]
    problems = check_settings(merged, facts, user_home=user_home)
    if problems:
        raise Error(
            "internal: the generated settings fail isolation detection: " + "; ".join(problems)
        )
    return merged


def hook_source() -> str:
    """The text of `hook.py`, which is installed unchanged as `mg-hook`."""
    text = importlib.resources.files("modgudr.client.agent").joinpath("hook.py").read_text("utf-8")
    ast.parse(text, feature_version=(3, 9))  # the macOS Command Line Tools Python
    return text


def install_target(platform: str) -> str:
    return f"{SETTINGS_DIRS[platform]}/{DROPIN_DIR}/{DROPIN_FILE}"


def installed_dropin(platform: str) -> Path:
    """The drop-in an earlier install left. There is no environment override: the reason is in
    the docstring of `modgudr.client.agent.isolation`."""
    return Path(install_target(platform))


def installed_domains(path: Path) -> tuple[str, ...] | None:
    """The `allowedDomains` of the installed drop-in, or `None` when there is no such file.

    Raises `UsageError` for anything else that is wrong with it: a foreign file must not donate
    domains, and a broken one must not be mistaken for an empty one."""
    try:
        text = path.read_text("utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise UsageError(
            f"cannot read the installed drop-in {path}: {exc.strerror or exc}"
        ) from None
    except ValueError:
        raise UsageError(f"the installed drop-in {path} is not UTF-8 text") from None
    try:
        document = json.loads(text)
    except ValueError:
        raise UsageError(f"the installed drop-in {path} is not JSON") from None
    if not isinstance(document, dict):
        raise UsageError(f"the installed drop-in {path} is not a JSON object")
    fields = cast("dict[str, Any]", document)
    if MARKER_KEY not in fields:
        raise UsageError(
            f"the installed drop-in {path} has no {MARKER_KEY} marker, so modgudr did not write it"
        )
    sandbox = _as_dict(fields.get("sandbox"))
    network = _as_dict(sandbox.get("network")) if sandbox is not None else None
    listed = _as_list(network.get("allowedDomains")) if network is not None else None
    if listed is None:
        raise UsageError(f"the installed drop-in {path} has no sandbox.network.allowedDomains list")
    domains: list[str] = []
    for entry in listed:
        if not isinstance(entry, str):
            raise UsageError(f"the installed drop-in {path} lists a domain that is not a string")
        domains.append(entry)
    return tuple(domains)


def install_text(
    broker: BrokerFacts,
    *,
    out: Path,
    version: str,
    allow_domains: Sequence[str],
    installed: Sequence[str] | None,
) -> str:
    """`INSTALL.txt`: the `sudo` steps, how to undo them and how to verify them."""
    facts = broker.facts
    target = install_target(facts.platform)
    target_dir = f"{SETTINGS_DIRS[facts.platform]}/{DROPIN_DIR}"
    group = "wheel" if facts.platform == "darwin" else "root"
    q = shlex.quote
    source = out / DROPIN_DIR / DROPIN_FILE
    hook = out / HOOK_FILE
    lines = [
        f"modgudr agent-setup claude (modgudr {version}): install steps",
        "",
        "Review the files in this directory, then run the lines below in your own terminal.",
        "Nothing here was installed. The drop-in never replaces the company's",
        "managed-settings.json; the hook is root-owned so that the agent cannot edit it.",
        "",
        "Generated for:",
        f"  platform:       {facts.platform}",
        f"  MODGUDR_HOME:   {facts.home}",
        f"  agent socket:   {facts.agent_socket}",
        f"  human socket:   {facts.human_socket} (denied to the sandbox)",
        f"  allowed domains: {', '.join(allow_domains) or 'none'}",
    ]
    if installed is None:
        lines.append("    no drop-in installed")
    else:
        kept = {d.lower() for d in allow_domains}
        known = {d.lower() for d in installed}
        added = [d for d in allow_domains if d.lower() not in known]
        removed = [d for d in installed if d.lower() not in kept]
        lines.append(f"    added: {', '.join(added) or 'none'}")
        lines.append(f"    removed: {', '.join(removed) or 'none'}")
    if broker.targets:
        lines.append("  targets:")
        lines += [
            f"    {name} ({kind}, {system}@{env})" for name, system, env, kind in broker.targets
        ]
    else:
        lines.append("  targets:        none")
    lines += [
        "",
        "1. Install. First make sure no drop-in of this name exists that modgudr did not write;",
        "   this prints a message and stops when one does:",
        "",
        f"  [ ! -e {q(target)} ] || sudo grep -q {MARKER_KEY} {q(target)} \\",
        f"    || {{ echo 'refusing: {target} exists and was not written by modgudr'; false; }}",
        "",
        "   Then:",
        "",
        f"  sudo install -d -m 0755 -o root -g {group} {q(target_dir)}",
        f"  sudo install -m 0644 -o root -g {group} {q(str(source))} {q(target)}",
        f"  sudo install -d -m 0755 -o root -g {group} /opt/modgudr {q(HOOK_INSTALL_DIR)}",
        f"  sudo install -m 0755 -o root -g {group} {q(str(hook))} {q(HOOK_INSTALL_PATH)}",
        "",
        "2. Uninstall:",
        "",
        f"  sudo rm -f {q(target)} {q(HOOK_INSTALL_PATH)}",
        "",
        "3. Verify. Start a new Claude Code session, then:",
        "",
        "  claude doctor            the managed settings are listed, with no error",
        "  /status                  inside Claude Code: the managed settings source is shown",
        "  modgudr status           isolation: managed-settings",
        "",
        "Re-run `modgudr agent-setup claude --force` and install again whenever you add a target",
        "or move MODGUDR_HOME: the isolation label drops to none until you do.",
        "",
    ]
    return "\n".join(lines)


# --- the command ---------------------------------------------------------------------------------


def _check_domains(domains: Sequence[str], *, what: str) -> tuple[str, ...]:
    for domain in domains:
        if not _DOMAIN.fullmatch(domain):
            raise UsageError(
                f"{what} {domain!r} is not a domain; give a host name such as "
                "pypi.org or *.example.net"
            )
    return tuple(dict.fromkeys(domains))


def _check_flags(allow: Sequence[str], remove: Sequence[str]) -> tuple[str, ...]:
    """The flags alone, before the installed file is read. Returns the new entries, lower-case."""
    both = {d.lower() for d in allow} & {d.lower() for d in remove}
    if both:
        raise UsageError(f"--allow-domain and --remove-domain both name {sorted(both)[0]!r}")
    return _check_domains([d.lower() for d in allow], what="--allow-domain")


def _merge_domains(
    installed: tuple[str, ...] | None,
    added: Sequence[str],
    remove: Sequence[str],
    *,
    path: Path,
) -> tuple[str, ...]:
    """The allowed domains of the new drop-in. Domains compare case-insensitively."""
    if installed is None:
        if remove:
            raise UsageError(
                f"--remove-domain needs an installed drop-in, and {path} does not exist: "
                "there is nothing to remove from"
            )
        return tuple(added) or DEFAULT_ALLOWED_DOMAINS
    gone = {d.lower() for d in remove}
    missing = gone - {d.lower() for d in installed}
    if missing:
        raise UsageError(
            f"--remove-domain {sorted(missing)[0]!r} is not in the installed drop-in. "
            f"Installed domains: {', '.join(installed) or 'none'}. "
            f"Only {DROPIN_FILE} ({path}) is read; other files in {DROPIN_DIR} are not"
        )
    kept = [d for d in installed if d.lower() not in gone]
    seen: set[str] = set()
    merged: list[str] = []
    for domain in (*kept, *added):
        if domain.lower() not in seen:
            seen.add(domain.lower())
            merged.append(domain)
    return _check_domains(merged, what="allowed domain")


def _has_marker(path: Path) -> bool:
    try:
        document = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(document, dict) and MARKER_KEY in document


def current_platform() -> str:
    return "darwin" if sys.platform == "darwin" else "linux"


def run_setup(
    out: Path,
    allow_domains: Sequence[str],
    *,
    force: bool,
    remove_domains: Sequence[str] = (),
    platform: str | None = None,
    uid: int | None = None,
    user_home: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> str:
    """Generate the three files into `out` and return the text of `INSTALL.txt`.

    Raises `BrokerUnavailable` (exit 6) when the broker is down and `UsageError` for a refusal;
    a refusal writes nothing.
    """
    env = os.environ if environ is None else environ
    if (os.getuid() if uid is None else uid) == 0 or env.get("SUDO_USER"):
        raise UsageError(
            "agent-setup refuses to run as root or under sudo: the paths would be root's. "
            "Run it as yourself; only the printed install lines use sudo"
        )
    where = platform or current_platform()
    installed_path = installed_dropin(where)
    added = _check_flags(allow_domains, remove_domains)
    installed = installed_domains(installed_path)
    domains = _merge_domains(installed, added, remove_domains, path=installed_path)
    out = out.absolute()
    dropin = out / DROPIN_DIR / DROPIN_FILE
    if dropin.exists() and not _has_marker(dropin):
        raise UsageError(
            f"{dropin} exists and was not written by modgudr (no {MARKER_KEY} marker); "
            "it is never replaced. Choose another --out directory"
        )
    existing = [p for p in (dropin, out / HOOK_FILE, out / INSTALL_FILE) if p.exists()]
    if existing and not force:
        raise UsageError(
            f"{', '.join(str(p) for p in existing)} already exist(s); use --force to overwrite"
        )
    broker = read_broker_facts(_meta("status"), _meta("targets"), platform=where)
    home = user_home if user_home is not None else pwd.getpwuid(os.getuid()).pw_dir
    version = client_version()
    settings = build_settings(broker, user_home=home, allow_domains=domains, version=version)
    text = json.dumps(settings, indent=2) + "\n"
    validate_settings(text, broker.facts, user_home=home, version=version)
    hook = hook_source()
    instructions = install_text(
        broker, out=out, version=version, allow_domains=domains, installed=installed
    )
    dropin.parent.mkdir(parents=True, exist_ok=True)
    dropin.write_text(text, "utf-8")
    hook_path = out / HOOK_FILE
    hook_path.write_text(hook, "utf-8")
    hook_path.chmod(0o755)
    (out / INSTALL_FILE).write_text(instructions, "utf-8")
    return instructions
