"""Agent isolation detection (M22): one security-critical predicate, stdlib only.

The broker, `agent-setup` and `doctor` all use this module:

- **Facts** are computed by the broker and reported in `status --json`: the platform, the
  canonical `MODGUDR_HOME`, `agent.sock` and `human.sock` paths, and the deny-host set.
- **`required_settings(facts)`** returns every boundary-bearing setting of the managed-settings
  drop-in (M20). `agent-setup` writes exactly these plus the steering keys (the hook,
  `permissions.allow` and the `Bash(<tool>:*)` denies), which are not required here.
- **`detect`** merges `managed-settings.json` and `managed-settings.d/*.json` the way Claude Code
  does and checks the result against the M22 requirements. The result is `managed-settings`, or
  `none` with the list of failed requirements.

The managed-settings paths and the platform are parameters. There is no environment override:
one would let any same-uid process fake `isolation: managed-settings`.
"""

from __future__ import annotations

import copy
import errno
import json
import os
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, cast

IsolationLabel = Literal["none", "managed-settings"]
NONE: IsolationLabel = "none"
MANAGED_SETTINGS: IsolationLabel = "managed-settings"

PLATFORMS = ("darwin", "linux")

#: Where Claude Code reads file-based managed settings, per platform.
SETTINGS_DIRS: Mapping[str, str] = {
    "darwin": "/Library/Application Support/ClaudeCode",
    "linux": "/etc/claude-code",
}
BASE_FILE = "managed-settings.json"
DROPIN_DIR = "managed-settings.d"

#: Deny hosts every kubectl target brings: the AKS API servers, ARM and the Entra login.
KUBECTL_DENY_HOSTS = ("*.azmk8s.io", "management.azure.com", "login.microsoftonline.com")

#: The §4.8 credential paths without `MODGUDR_HOME`: (path, is a directory, macOS only).
_CREDENTIAL_PATHS: tuple[tuple[str, bool, bool], ...] = (
    ("~/.azure", True, False),
    ("~/.kube", True, False),
    ("~/.pgpass", False, False),
    ("~/.netrc", False, False),
    ("~/.config/gh", True, False),
    ("~/Library/DBeaverData", True, True),
    ("~/.sqldeveloper", True, False),
)
#: The developer's own `bws` config and state (M20).
BWS_CONFIG = "~/.config/bws"

#: The §4.8 credential variables plus M20's.
CREDENTIAL_VARS = (
    "PGPASSWORD",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "JIRA_API_TOKEN",
    "SNOWFLAKE_PASSWORD",
    "SNOWFLAKE_PRIVATE_KEY",
    "AZURE_CLIENT_SECRET",
    "BW_SESSION",
    "BWS_ACCESS_TOKEN",
)

#: The §4.8 persistence paths (`Edit(...)` denies) before `MODGUDR_HOME`: (path, macOS only).
_PERSISTENCE_PATHS: tuple[tuple[str, bool], ...] = (
    ("~/.zshrc", False),
    ("~/.zprofile", False),
    ("~/.zshenv", False),
    ("~/.bashrc", False),
    ("~/.bash_profile", False),
    ("~/.profile", False),
    ("~/bin/**", False),
    ("~/.local/bin/**", False),
    ("~/Library/LaunchAgents/**", True),
    ("~/.config/systemd/user/**", False),
    ("~/.claude/**", False),
    ("~/.srt-settings.json", False),
    ("~/.ssh/**", False),
    ("~/.gitconfig", False),
)
#: The repository's own `.claude/` (a relative rule, kept as written) and the broker's venv.
REPO_CLAUDE = ".claude/**"
UV_SHARE = "~/.local/share/uv/**"

#: The §4.9 text, on stderr of `status`, `targets` and `doctor` when isolation is `none`.
L0_WARNING = (
    "WARNING: modgudr runs as your own user and no agent isolation is configured.\n"
    "         Both sockets, the policy and the unlock are reachable by anything you run,\n"
    "         including coding agents. This set-up protects against accidents only.\n"
    "         Run `modgudr agent-setup claude` and install the managed settings, "
    "or install at L1."
)

_MISSING = object()


@dataclass(frozen=True)
class Facts:
    """What the broker knows about the boundary it needs (`status --json`)."""

    platform: str
    #: The canonical `MODGUDR_HOME` (realpath).
    home: str
    agent_socket: str
    human_socket: str
    #: Every statically known target destination host, plus the Azure hosts for kubectl.
    deny_hosts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.platform not in PLATFORMS:
            raise ValueError(
                f"unsupported platform {self.platform!r}; supported: {', '.join(PLATFORMS)}"
            )

    def to_json(self) -> dict[str, object]:
        return {
            "platform": self.platform,
            "home": self.home,
            "agentSocket": self.agent_socket,
            "humanSocket": self.human_socket,
            "denyHosts": list(self.deny_hosts),
        }

    @classmethod
    def from_json(cls, data: Mapping[str, object]) -> Facts:
        """The facts from `status --json`. Raises ValueError when one is missing or malformed."""
        values: dict[str, str] = {}
        for key in ("platform", "home", "agentSocket", "humanSocket"):
            value = data.get(key)
            if not isinstance(value, str) or not value:
                raise ValueError(f"status is missing {key!r}")
            values[key] = value
        hosts = data.get("denyHosts")
        if not isinstance(hosts, list):
            raise ValueError("status is missing 'denyHosts'")
        host_list = cast("list[object]", hosts)
        if not all(isinstance(h, str) for h in host_list):
            raise ValueError("status has a malformed 'denyHosts'")
        return cls(
            platform=values["platform"],
            home=values["home"],
            agent_socket=values["agentSocket"],
            human_socket=values["humanSocket"],
            deny_hosts=tuple(cast("list[str]", host_list)),
        )


@dataclass(frozen=True)
class Isolation:
    """The detection result. `reasons` lists every failed requirement when `label` is `none`."""

    label: IsolationLabel
    reasons: tuple[str, ...] = ()
    #: The settings files that were read, in merge order.
    files: tuple[str, ...] = ()

    @property
    def isolated(self) -> bool:
        return self.label == MANAGED_SETTINGS


def settings_locations(platform: str) -> tuple[Path, Path]:
    """The production `managed-settings.json` and `managed-settings.d/` for a platform."""
    directory = SETTINGS_DIRS.get(platform)
    if directory is None:
        raise ValueError(f"unsupported platform {platform!r}; supported: {', '.join(PLATFORMS)}")
    return Path(directory) / BASE_FILE, Path(directory) / DROPIN_DIR


# --- paths ---------------------------------------------------------------------------------------


def _expand(path: str, user_home: str) -> str | None:
    """A settings path as an absolute path (`~` from the `pwd` home), or None when relative.

    `~/x` is the home, `//x` and `/x` are absolute. A trailing `/**` or `/` is stripped, as the
    sandbox does. Symlinks are not resolved.
    """
    if path == "~":
        expanded = user_home
    elif path.startswith("~/"):
        expanded = user_home.rstrip("/") + path[1:]
    elif path.startswith("/"):
        expanded = "/" + path.lstrip("/")
    else:
        return None
    while expanded.endswith("/**"):
        expanded = expanded[:-3]
    expanded = os.path.normpath(expanded)
    return expanded


def _covers(entry: str, path: str) -> bool:
    """Whether an absolute `entry` equals `path` or is a parent directory of it."""
    if entry == "/":
        return True
    return path == entry or path.startswith(entry + "/")


def _home_entry(facts: Facts, user_home: str) -> str:
    """`~/.modgudr` when that expands to exactly the canonical home, else the canonical path."""
    if _expand("~/.modgudr", user_home) == os.path.normpath(facts.home):
        return "~/.modgudr"
    return os.path.normpath(facts.home)


def _rule_path(path: str) -> str:
    """A path as a permission rule writes it: `~/…` stays, an absolute path is `//abs/path`."""
    if path.startswith("/"):
        return "//" + path.lstrip("/")
    return path


def credential_paths(facts: Facts, user_home: str) -> tuple[tuple[str, bool], ...]:
    """Every M20 credential path in written form, with whether it is a directory."""
    darwin = facts.platform == "darwin"
    out = [(path, is_dir) for path, is_dir, mac_only in _CREDENTIAL_PATHS if darwin or not mac_only]
    out.append((_home_entry(facts, user_home), True))
    out.append((BWS_CONFIG, True))
    return tuple(out)


def persistence_paths(facts: Facts, user_home: str) -> tuple[str, ...]:
    """Every path that needs an `Edit(...)` deny, in written form (D13)."""
    darwin = facts.platform == "darwin"
    out = [path for path, mac_only in _PERSISTENCE_PATHS if darwin or not mac_only]
    out.append(_home_entry(facts, user_home).rstrip("/") + "/**")
    out.append(REPO_CLAUDE)
    out.append(UV_SHARE)
    return tuple(out)


def _read_rule(path: str, is_dir: bool) -> str:
    return f"Read({_rule_path(path)}{'/**' if is_dir else ''})"


def _edit_rule(path: str) -> str:
    return f"Edit({_rule_path(path)})"


def _webfetch_rule(host: str) -> str:
    return f"WebFetch(domain:{host})"


# --- required settings ---------------------------------------------------------------------------


def required_settings(facts: Facts, *, user_home: str) -> dict[str, object]:
    """Every boundary-bearing M20 setting for these facts, as managed-settings JSON."""
    darwin = facts.platform == "darwin"
    creds = credential_paths(facts, user_home)
    sandbox: dict[str, object] = {
        "enabled": True,
        "failIfUnavailable": True,
        "allowUnsandboxedCommands": False,
        "enableWeakerNestedSandbox": False,
        "enableWeakerNetworkIsolation": False,
    }
    if darwin:
        sandbox["allowAppleEvents"] = False
    sandbox["credentials"] = {
        "files": [{"path": path, "mode": "deny"} for path, _ in creds],
        "envVars": [{"name": name, "mode": "deny"} for name in CREDENTIAL_VARS],
    }
    sandbox["filesystem"] = {"allowManagedReadPathsOnly": True}
    network: dict[str, object] = {
        "deniedDomains": list(facts.deny_hosts),
        "allowManagedDomainsOnly": True,
        "strictAllowlist": True,
        "allowLocalBinding": False,
    }
    if darwin:
        network["allowUnixSockets"] = [facts.agent_socket]
        network["allowAllUnixSockets"] = False
    else:
        network["allowAllUnixSockets"] = True
    sandbox["network"] = network
    deny = [_read_rule(path, is_dir) for path, is_dir in creds]
    deny += [_edit_rule(path) for path in persistence_paths(facts, user_home)]
    deny += [_webfetch_rule(host) for host in facts.deny_hosts]
    permissions: dict[str, object] = {"disableBypassPermissionsMode": "disable", "deny": deny}
    return {"sandbox": sandbox, "permissions": permissions}


# --- merging and loading -------------------------------------------------------------------------


def merge_settings(documents: Sequence[Mapping[str, object]]) -> dict[str, object]:
    """Merge settings the way Claude Code merges managed settings: base first, then drop-ins.

    Nested blocks merge key by key, lists combine without duplicates, and for single values the
    later file wins.
    """
    merged: dict[str, object] = {}
    for document in documents:
        _merge_into(merged, document)
    return merged


def _merge_into(target: dict[str, object], source: Mapping[str, object]) -> None:
    for key, value in source.items():
        current = target.get(key, _MISSING)
        if isinstance(current, dict) and isinstance(value, Mapping):
            _merge_into(cast("dict[str, object]", current), cast("Mapping[str, object]", value))
        elif isinstance(current, list) and isinstance(value, list):
            combined = list(cast("list[object]", current))
            for item in cast("list[object]", value):
                if item not in combined:
                    combined.append(copy.deepcopy(item))
            target[key] = combined
        else:
            target[key] = copy.deepcopy(value)


class StatLike(Protocol):
    @property
    def st_uid(self) -> int: ...

    @property
    def st_mode(self) -> int: ...


Fstat = Callable[[int], StatLike]


@dataclass(frozen=True)
class LoadedSettings:
    settings: dict[str, object]
    files: tuple[str, ...]
    #: Files that could not be read, parsed or trusted (owner, mode).
    problems: tuple[str, ...]


def settings_files(base: Path, dropin_dir: Path) -> list[Path]:
    """The managed-settings files Claude Code reads, in merge order.

    The base file first, then every `*.json` in the drop-in directory in alphabetical order;
    hidden files and other names are ignored.
    """
    files: list[Path] = []
    if os.path.lexists(base):
        files.append(base)
    files.extend(_dropin_files(dropin_dir))
    return files


def _dropin_files(dropin_dir: Path) -> list[Path]:
    if not dropin_dir.is_dir():
        return []
    names = sorted(
        p.name
        for p in dropin_dir.iterdir()
        if p.name.endswith(".json") and not p.name.startswith(".")
    )
    return [dropin_dir / name for name in names]


def load_managed_settings(
    base: Path, dropin_dir: Path, *, fstat: Fstat = os.fstat
) -> LoadedSettings:
    """Read and merge the managed settings. Every file must be root-owned and not writable by
    group or others; symlinks are refused."""
    documents: list[Mapping[str, object]] = []
    problems: list[str] = []
    files = settings_files(base, dropin_dir)
    for path in files:
        document = _read_settings_file(path, fstat, problems)
        if document is not None:
            documents.append(document)
    return LoadedSettings(merge_settings(documents), tuple(str(p) for p in files), tuple(problems))


def _read_settings_file(
    path: Path, fstat: Fstat, problems: list[str]
) -> Mapping[str, object] | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            problems.append(f"{path}: is a symlink; managed settings must be regular files")
        else:
            problems.append(f"{path}: cannot be read: {exc.strerror}")
        return None
    try:
        st = fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            problems.append(f"{path}: is not a regular file")
            return None
        if st.st_uid != 0:
            problems.append(f"{path}: must be owned by root (owner uid {st.st_uid})")
        if st.st_mode & 0o022:
            problems.append(
                f"{path}: must not be writable by group or others "
                f"(mode {stat.S_IMODE(st.st_mode):04o})"
            )
        with os.fdopen(fd, "rb", closefd=False) as handle:
            raw = handle.read()
    finally:
        os.close(fd)
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        problems.append(f"{path}: is not valid JSON")
        return None
    if not isinstance(document, dict):
        problems.append(f"{path}: must hold a JSON object")
        return None
    return cast("dict[str, object]", document)


def settings_signature(base: Path, dropin_dir: Path) -> tuple[object, ...]:
    """What changes when a managed-settings file is added, removed, edited, chowned or chmodded."""
    entries: list[object] = [_stat_key(base), _stat_key(dropin_dir)]
    entries.extend((path.name, _stat_key(path)) for path in _dropin_files(dropin_dir))
    return tuple(entries)


def _stat_key(path: Path) -> tuple[int, ...] | None:
    try:
        st = os.lstat(path)
    except OSError:
        return None
    return (st.st_ino, st.st_mtime_ns, st.st_ctime_ns, st.st_size, st.st_mode, st.st_uid)


# --- detection -----------------------------------------------------------------------------------


def detect(
    facts: Facts,
    *,
    user_home: str,
    base: Path,
    dropin_dir: Path,
    fstat: Fstat = os.fstat,
) -> Isolation:
    """Isolation detection: `managed-settings`, or `none` with every failed requirement."""
    loaded = load_managed_settings(base, dropin_dir, fstat=fstat)
    if not loaded.files:
        return Isolation(
            NONE, (f"no managed settings: neither {base} nor {dropin_dir}/*.json exists",)
        )
    reasons = [*loaded.problems, *check_settings(loaded.settings, facts, user_home=user_home)]
    return Isolation(MANAGED_SETTINGS if not reasons else NONE, tuple(reasons), loaded.files)


def _get(settings: Mapping[str, object], dotted: str) -> object:
    head, _, rest = dotted.partition(".")
    value = settings.get(head, _MISSING)
    if not rest:
        return value
    if not isinstance(value, Mapping):
        return _MISSING
    return _get(cast("Mapping[str, object]", value), rest)


def _found(value: object) -> str:
    if value is _MISSING:
        return "missing"
    try:
        return json.dumps(value)
    except (TypeError, ValueError):
        return repr(value)


def _entries(settings: Mapping[str, object], dotted: str) -> list[Mapping[str, object]]:
    value = _get(settings, dotted)
    if not isinstance(value, list):
        return []
    return [
        cast("Mapping[str, object]", item)
        for item in cast("list[object]", value)
        if isinstance(item, Mapping)
    ]


def _strings(settings: Mapping[str, object], dotted: str) -> list[str]:
    value = _get(settings, dotted)
    if not isinstance(value, list):
        return []
    return [item for item in cast("list[object]", value) if isinstance(item, str)]


def _denied_files(settings: Mapping[str, object], user_home: str) -> list[str]:
    out: list[str] = []
    for entry in _entries(settings, "sandbox.credentials.files"):
        path = entry.get("path")
        if entry.get("mode") == "deny" and isinstance(path, str):
            expanded = _expand(path, user_home)
            if expanded is not None:
                out.append(expanded)
    return out


@dataclass(frozen=True)
class _Rule:
    tool: str
    #: The absolute path for `~/` and `//` rules; the literal text for relative ones.
    path: str
    recursive: bool
    relative: bool


def _parse_rules(settings: Mapping[str, object], user_home: str) -> list[_Rule]:
    rules: list[_Rule] = []
    for text in _strings(settings, "permissions.deny"):
        if not text.endswith(")") or "(" not in text:
            continue
        tool, _, inner = text[:-1].partition("(")
        if tool not in ("Read", "Edit"):
            continue
        recursive = inner.endswith("/**")
        if inner.startswith("~") or inner.startswith("//"):
            expanded = _expand(inner, user_home)
            if expanded is not None:
                rules.append(_Rule(tool, expanded, recursive, relative=False))
        elif not inner.startswith("/"):
            # A relative rule (`.claude/**`) is compared as written. A single leading `/` means
            # "relative to the settings source" and never counts in managed settings.
            rules.append(_Rule(tool, inner, recursive, relative=True))
    return rules


def _rule_covers(rules: Sequence[_Rule], tool: str, path: str, user_home: str) -> bool:
    """Whether a `tool(...)` deny covers `path` (written form, `/**` marking a directory)."""
    if not (path.startswith("~") or path.startswith("/")):
        return any(r.tool == tool and r.relative and r.path == path for r in rules)
    wanted = _expand(path, user_home)
    if wanted is None:
        return False
    wanted_recursive = path.endswith("/**")
    for rule in rules:
        if rule.tool != tool or rule.relative:
            continue
        if rule.recursive and _covers(rule.path, wanted):
            return True
        if not rule.recursive and not wanted_recursive and rule.path == wanted:
            return True
    return False


def _socket_entries(value: object, user_home: str) -> list[tuple[str, str]]:
    """`allowUnixSockets` entries as (written, expanded)."""
    if not isinstance(value, list):
        return []
    out: list[tuple[str, str]] = []
    for item in cast("list[object]", value):
        if isinstance(item, str):
            expanded = _expand(item, user_home)
            out.append((item, expanded if expanded is not None else item))
    return out


def covering_socket_entries(
    settings: Mapping[str, object], human_socket: str, *, user_home: str
) -> list[str]:
    """The `allowUnixSockets` entries (as written) that equal or contain `human.sock`."""
    human = os.path.normpath(human_socket)
    value = _get(settings, "sandbox.network.allowUnixSockets")
    out: list[str] = []
    for written, expanded in _socket_entries(value, user_home):
        real = os.path.realpath(expanded)
        if _covers(expanded, human) or _covers(real, human):
            out.append(written)
    return out


def absolute_path(written: str, user_home: str) -> str | None:
    """A settings path (`~/x`, `//x`, `/x`) as an absolute path, or None for a relative one."""
    return _expand(written, user_home)


def credential_denials(
    settings: Mapping[str, object], path: str, is_dir: bool, *, user_home: str
) -> tuple[bool, bool]:
    """Whether the settings deny a credential path (written form) in `sandbox.credentials.files`
    and with a `Read(...)` rule, the two layers `check_settings` requires."""
    expanded = _expand(path, user_home)
    in_sandbox = expanded is not None and any(
        _covers(entry, expanded) for entry in _denied_files(settings, user_home)
    )
    rule_path = path.rstrip("/") + "/**" if is_dir else path
    in_rules = _rule_covers(_parse_rules(settings, user_home), "Read", rule_path, user_home)
    return in_sandbox, in_rules


def check_settings(settings: Mapping[str, object], facts: Facts, *, user_home: str) -> list[str]:
    """The failed M22 requirements of merged settings, each naming its key. Empty means isolated."""
    reasons: list[str] = []
    darwin = facts.platform == "darwin"

    def must_be(dotted: str, wanted: bool) -> None:
        value = _get(settings, dotted)
        if value is not wanted:
            reasons.append(
                f"{dotted} must be {'true' if wanted else 'false'} (found {_found(value)})"
            )

    def must_not_be_true(dotted: str) -> None:
        value = _get(settings, dotted)
        if value is True:
            reasons.append(f"{dotted} must not be true")

    # Sandbox switches and weakeners.
    must_be("sandbox.enabled", True)
    must_be("sandbox.failIfUnavailable", True)
    must_be("sandbox.allowUnsandboxedCommands", False)
    must_not_be_true("sandbox.enableWeakerNestedSandbox")
    must_not_be_true("sandbox.enableWeakerNetworkIsolation")
    if darwin:
        must_not_be_true("sandbox.allowAppleEvents")

    # Credentials.
    must_be("sandbox.filesystem.allowManagedReadPathsOnly", True)
    denied = _denied_files(settings, user_home)
    rules = _parse_rules(settings, user_home)
    home_entry = _home_entry(facts, user_home)
    for path, is_dir in credential_paths(facts, user_home):
        label = f"{path} (MODGUDR_HOME)" if path == home_entry else path
        expanded = _expand(path, user_home)
        if expanded is None or not any(_covers(entry, expanded) for entry in denied):
            reasons.append(f"sandbox.credentials.files must deny {label}")
        rule_path = path.rstrip("/") + "/**" if is_dir else path
        if not _rule_covers(rules, "Read", rule_path, user_home):
            reasons.append(f"permissions.deny must hold a Read(...) rule covering {label}")
    env_denied = {
        entry.get("name")
        for entry in _entries(settings, "sandbox.credentials.envVars")
        if entry.get("mode") == "deny"
    }
    for name in CREDENTIAL_VARS:
        if name not in env_denied:
            reasons.append(f"sandbox.credentials.envVars must deny {name}")

    # Persistence (D13).
    for path in persistence_paths(facts, user_home):
        if not _rule_covers(rules, "Edit", path, user_home):
            reasons.append(f"permissions.deny must hold an Edit(...) rule covering {path}")

    # Network.
    must_be("sandbox.network.allowManagedDomainsOnly", True)
    must_be("sandbox.network.strictAllowlist", True)
    must_be("sandbox.network.allowLocalBinding", False)
    denied_domains = {d.lower() for d in _strings(settings, "sandbox.network.deniedDomains")}
    deny_rules = set(_strings(settings, "permissions.deny"))
    for host in facts.deny_hosts:
        if host.lower() not in denied_domains:
            reasons.append(f"sandbox.network.deniedDomains must list {host}")
        if _webfetch_rule(host) not in deny_rules:
            reasons.append(f"permissions.deny must hold {_webfetch_rule(host)}")

    # Unix sockets.
    human = os.path.normpath(facts.human_socket)
    if darwin:
        value = _get(settings, "sandbox.network.allowUnixSockets")
        found = _found(value)
        listed = cast("list[object]", value) if isinstance(value, list) else None
        if listed != [facts.agent_socket]:
            reasons.append(
                f"sandbox.network.allowUnixSockets must list exactly {facts.agent_socket} "
                f"(found {found})"
            )
        for written in covering_socket_entries(settings, facts.human_socket, user_home=user_home):
            reasons.append(
                f"sandbox.network.allowUnixSockets entry {written} covers human.sock ({human})"
            )
        must_not_be_true("sandbox.network.allowAllUnixSockets")
    if not any(_covers(entry, human) for entry in denied):
        detail = "; on Linux that is its only protection" if not darwin else ""
        reasons.append(
            f"human.sock ({human}) is not inside a path denied by sandbox.credentials.files{detail}"
        )

    # Permission mode.
    mode = _get(settings, "permissions.disableBypassPermissionsMode")
    if mode != "disable":
        reasons.append(
            f'permissions.disableBypassPermissionsMode must be "disable" (found {_found(mode)})'
        )
    return reasons
