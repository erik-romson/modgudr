"""The kubectl argv parser (M17): the command path, every flag and the positional arguments.

kubectl parses with cobra and pflag. This parser follows them closely enough that it finds the
verb and the flag values kubectl would, and it refuses whatever it cannot place (`ParseError`,
which the classifier turns into `kubectl:unknown`). It never runs kubectl.

- **The command path.** The first positional argument is the verb, and verbs with subcommands
  (`rollout restart`, `create secret generic`, `top pod`) take the next ones. Before the verb, and
  between a verb and its subcommand, only global flags are accepted. Cobra accepts a command's own
  flags there too; refusing them is stricter, never looser.
- **Long flags:** `--name=value`, `--name value`; a boolean `--name` or `--name=false`; a flag with
  an optional value (`--dry-run`) never takes the next argument. kubectl normalises `_` in a flag
  name to `-`, and so does this parser.
- **Short flags:** `-n value`, `-nvalue`, `-n=value`, and combined booleans such as `-it`.
- A flag that needs a value takes the next argument even when it starts with `-`, as pflag does.
- `--` ends the flags: everything after it is positional (`Parsed.dash` marks where it was).
- A flag the command does not know is a `ParseError`.

Each flag carries a `Role` for the classifier: identity and connection flags, path-taking flags,
debug output flags, verbosity and the output format (M17 invariants).
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum


class Arity(Enum):
    """How a flag takes its value."""

    #: No value; `--name=false` sets it false. A bare flag is `true`.
    BOOL = "bool"
    #: A required value: `--name=value`, `--name value`, `-nvalue`, `-n value`.
    VALUE = "value"
    #: An optional value with a default (pflag's NoOptDefVal): only `--name=value` sets one.
    OPTIONAL = "optional"


class Role(Enum):
    """What a flag means to the classifier."""

    NONE = "none"
    #: Identity and connection flags: the broker fixes the cluster and the user (M17).
    IDENTITY = "identity"
    #: Path-taking flags: kubectl would read a file, or a raw API path, as the developer (M17).
    PATH = "path"
    #: Debug output flags that print or write request details (M17).
    DEBUG = "debug"
    #: `-v`/`--v`: a debug flag from level 6 on.
    VERBOSITY = "verbosity"
    #: `-o`/`--output`: some formats read a template file.
    OUTPUT = "output"


@dataclass(frozen=True)
class Flag:
    """One flag a command accepts."""

    #: The long name without dashes: `namespace`, `as-group`, `v`.
    name: str
    #: The one-letter shorthand, or "".
    short: str = ""
    arity: Arity = Arity.VALUE
    role: Role = Role.NONE
    #: The value of a bare `OPTIONAL` flag.
    default: str = ""


def _b(name: str, short: str = "", role: Role = Role.NONE) -> Flag:
    return Flag(name, short, Arity.BOOL, role)


def _v(name: str, short: str = "", role: Role = Role.NONE) -> Flag:
    return Flag(name, short, Arity.VALUE, role)


def _o(name: str, default: str) -> Flag:
    return Flag(name, "", Arity.OPTIONAL, Role.NONE, default)


@dataclass(frozen=True)
class Command:
    """A kubectl command: its own flags and its subcommands (cobra's command tree)."""

    name: str
    flags: tuple[Flag, ...] = ()
    subs: tuple[Command, ...] = ()
    aliases: tuple[str, ...] = ()
    #: Whether it runs without a subcommand (`create -f`); else one is required (`rollout`).
    runs: bool = True
    #: The resource a `create` subcommand makes (a catalogue plural), or "".
    resource: str = ""

    def find(self, word: str) -> Command | None:
        """The subcommand `word` names, by name or alias (cobra matches exactly)."""
        for sub in self.subs:
            if word == sub.name or word in sub.aliases:
                return sub
        return None


@dataclass(frozen=True)
class FlagUse:
    """One flag as the call used it."""

    #: The long name without dashes (after `_` to `-` normalisation).
    name: str
    #: The value: a boolean is `true` or `false`, a bare optional flag its default.
    value: str
    #: The flag as written, without its value: `-n`, `--namespace`.
    spelled: str
    role: Role


@dataclass(frozen=True)
class Parsed:
    """A parsed kubectl argv."""

    #: The canonical command path: `("get",)`, `("rollout", "restart")`, `("create", "configmap")`.
    path: tuple[str, ...]
    #: Every flag use, in argv order.
    flags: tuple[FlagUse, ...]
    #: The positional arguments, before and after `--`.
    args: tuple[str, ...]
    #: How many of `args` came before `--` (all of them when there was none).
    dash: int
    #: The command the path names.
    command: Command

    @property
    def verb(self) -> str:
        return self.path[0]

    def last(self, name: str) -> str | None:
        """The value of the last use of a flag (kubectl's "last wins"), or None."""
        for use in reversed(self.flags):
            if use.name == name:
                return use.value
        return None

    def has(self, name: str) -> bool:
        return any(use.name == name for use in self.flags)

    def boolean(self, name: str, default: bool = False) -> bool:
        """A boolean flag's value; the parser has validated it."""
        value = self.last(name)
        return default if value is None else value == "true"


class ParseError(Exception):
    """kubectl would refuse this argv, or the parser cannot place it.

    `flags` holds the flags parsed before the error, so that the classifier still records the
    invariants they break.
    """

    def __init__(self, detail: str, flags: Sequence[FlagUse] = ()) -> None:
        super().__init__(detail)
        self.detail = detail
        self.flags = tuple(flags)


# --- the command tree ------------------------------------------------------------------------

#: kubectl's global (persistent) flags. Every command accepts them, before or after the verb.
GLOBAL: tuple[Flag, ...] = (
    _v("namespace", "n"),
    _v("as", role=Role.IDENTITY),
    _v("as-group", role=Role.IDENTITY),
    _v("as-uid", role=Role.IDENTITY),
    _v("cache-dir", role=Role.IDENTITY),
    _v("certificate-authority", role=Role.IDENTITY),
    _v("client-certificate", role=Role.IDENTITY),
    _v("client-key", role=Role.IDENTITY),
    _v("cluster", role=Role.IDENTITY),
    _v("context", role=Role.IDENTITY),
    _b("insecure-skip-tls-verify", role=Role.IDENTITY),
    _v("kubeconfig", role=Role.IDENTITY),
    _v("password", role=Role.IDENTITY),
    _v("server", "s", Role.IDENTITY),
    _v("tls-server-name", role=Role.IDENTITY),
    _v("token", role=Role.IDENTITY),
    # `create rolebinding --user` is a local flag of the same name; it counts as the identity
    # flag too, which refuses that form (stricter, never looser).
    _v("user", role=Role.IDENTITY),
    _v("username", role=Role.IDENTITY),
    _v("v", "v", Role.VERBOSITY),
    # `--vmodule` raises the verbosity per source file, which would get around the `-v` limit.
    _v("vmodule", role=Role.DEBUG),
    _v("log-file", role=Role.DEBUG),
    _v("profile-output", role=Role.DEBUG),
    _v("request-timeout"),
    _b("disable-compression"),
    _b("match-server-version"),
    _b("warnings-as-errors"),
)

_FILES = (
    _v("filename", "f", Role.PATH),
    _v("kustomize", "k", Role.PATH),
    _b("recursive", "R"),
)
_PRINT = (
    _v("output", "o", Role.OUTPUT),
    _v("template"),
    _b("allow-missing-template-keys"),
    _b("show-managed-fields"),
)
_DRY_RUN = _o("dry-run", "unchanged")
_VALIDATE = _o("validate", "strict")
_CASCADE = _o("cascade", "background")
_ALL_NAMESPACES = _b("all-namespaces", "A")
_SELECTOR = _v("selector", "l")
_FIELD_SELECTOR = _v("field-selector")
_FIELD_MANAGER = _v("field-manager")
_RAW_PATH = _v("raw", role=Role.PATH)
#: The flags every `create <resource>` subcommand has.
_CREATE = (*_PRINT, _DRY_RUN, _FIELD_MANAGER, _b("save-config"), _VALIDATE)
_FROM_FILES = (_v("from-file", role=Role.PATH), _v("from-env-file", role=Role.PATH))


def _create(name: str, resource: str, *flags: Flag, aliases: tuple[str, ...] = ()) -> Command:
    return Command(name, (*_CREATE, *flags), aliases=aliases, resource=resource)


def _service(name: str, *flags: Flag) -> Command:
    return _create(name, "services", _v("tcp"), *flags)


def _secret(name: str, *flags: Flag) -> Command:
    return _create(name, "secrets", _b("append-hash"), *flags)


_ROLLOUT_SELECT = (*_FILES, _SELECTOR)

_GET = Command(
    "get",
    (
        *_FILES,
        *_PRINT,
        _ALL_NAMESPACES,
        _v("chunk-size"),
        _FIELD_SELECTOR,
        _b("ignore-not-found"),
        _v("label-columns", "L"),
        _b("no-headers"),
        _b("output-watch-events"),
        _RAW_PATH,
        _SELECTOR,
        _b("server-print"),
        _b("show-kind"),
        _b("show-labels"),
        _v("sort-by"),
        _v("subresource"),
        _b("watch", "w"),
        _b("watch-only"),
    ),
)
_DESCRIBE = Command(
    "describe",
    (*_FILES, _ALL_NAMESPACES, _v("chunk-size"), _SELECTOR, _b("show-events")),
)
_LOGS = Command(
    "logs",
    (
        _b("all-containers"),
        _b("all-pods"),
        _v("container", "c"),
        # `logs -f` is follow, not a file name (M17).
        _b("follow", "f"),
        _b("ignore-errors"),
        _v("limit-bytes"),
        _v("max-log-requests"),
        _v("pod-running-timeout"),
        _b("prefix"),
        _b("previous", "p"),
        _SELECTOR,
        _v("since"),
        _v("since-time"),
        _v("tail"),
        _b("timestamps"),
    ),
)
_TOP = Command(
    "top",
    subs=(
        Command(
            "pod",
            (
                _ALL_NAMESPACES,
                _b("containers"),
                _FIELD_SELECTOR,
                _b("no-headers"),
                _SELECTOR,
                _v("sort-by"),
                _b("sum"),
                _b("use-protocol-buffers"),
            ),
            aliases=("pods", "po"),
            resource="pods",
        ),
        Command(
            "node",
            (
                _b("no-headers"),
                _SELECTOR,
                _b("show-capacity"),
                _v("sort-by"),
                _b("use-protocol-buffers"),
            ),
            aliases=("nodes", "no"),
            resource="nodes",
        ),
    ),
    runs=False,
)
_EXPLAIN = Command("explain", (_v("api-version"), _v("output", "o", Role.OUTPUT), _b("recursive")))
_DELETE = Command(
    "delete",
    (
        *_FILES,
        _b("all"),
        _ALL_NAMESPACES,
        _CASCADE,
        _DRY_RUN,
        _FIELD_SELECTOR,
        _b("force"),
        _v("grace-period"),
        _b("ignore-not-found"),
        _b("now"),
        _v("output", "o", Role.OUTPUT),
        _RAW_PATH,
        _SELECTOR,
        _v("timeout"),
        _b("wait"),
    ),
)
_APPLY = Command(
    "apply",
    (
        *_FILES,
        *_PRINT,
        _DRY_RUN,
        _b("all"),
        _CASCADE,
        _FIELD_MANAGER,
        _b("force"),
        _b("force-conflicts"),
        _v("grace-period"),
        _b("openapi-patch"),
        _b("overwrite"),
        _b("prune"),
        _v("prune-allowlist"),
        _SELECTOR,
        _b("server-side"),
        _v("timeout"),
        _VALIDATE,
        _b("wait"),
    ),
)
_CREATE_CMD = Command(
    "create",
    (
        *_FILES,
        *_PRINT,
        _DRY_RUN,
        _FIELD_MANAGER,
        _RAW_PATH,
        _b("save-config"),
        _SELECTOR,
        _VALIDATE,
    ),
    subs=(
        _create(
            "configmap",
            "configmaps",
            _b("append-hash"),
            *_FROM_FILES,
            _v("from-literal"),
            aliases=("cm",),
        ),
        Command(
            "secret",
            subs=(
                _secret("generic", *_FROM_FILES, _v("from-literal"), _v("type")),
                _secret("tls", _v("cert", role=Role.PATH), _v("key", role=Role.PATH)),
                _secret(
                    "docker-registry",
                    _v("docker-email"),
                    _v("docker-password"),
                    _v("docker-server"),
                    _v("docker-username"),
                    _v("from-file", role=Role.PATH),
                ),
            ),
            runs=False,
        ),
        _create("namespace", "namespaces", aliases=("ns",)),
        _create("serviceaccount", "serviceaccounts", aliases=("sa",)),
        Command(
            "token",
            (
                *_PRINT,
                _v("audience"),
                _v("bound-object-kind"),
                _v("bound-object-name"),
                _v("bound-object-uid"),
                _v("duration"),
            ),
            resource="serviceaccounts",
        ),
        _create(
            "deployment",
            "deployments",
            _v("image"),
            _v("port"),
            _v("replicas", "r"),
            aliases=("deploy",),
        ),
        _create("job", "jobs", _v("from"), _v("image")),
        _create("cronjob", "cronjobs", _v("image"), _v("restart"), _v("schedule"), aliases=("cj",)),
        _create("role", "roles", _v("resource"), _v("resource-name"), _v("verb")),
        _create(
            "clusterrole",
            "clusterroles",
            _v("aggregation-rule"),
            _v("non-resource-url"),
            _v("resource"),
            _v("resource-name"),
            _v("verb"),
        ),
        _create(
            "rolebinding",
            "rolebindings",
            _v("clusterrole"),
            _v("group"),
            _v("role"),
            _v("serviceaccount"),
        ),
        _create(
            "clusterrolebinding",
            "clusterrolebindings",
            _v("clusterrole"),
            _v("group"),
            _v("serviceaccount"),
        ),
        _create(
            "ingress",
            "ingresses",
            _v("annotation"),
            _v("class"),
            _v("default-backend"),
            _v("rule"),
            aliases=("ing",),
        ),
        _create(
            "poddisruptionbudget",
            "poddisruptionbudgets",
            _v("max-unavailable"),
            _v("min-available"),
            _v("selector"),
            aliases=("pdb",),
        ),
        _create("quota", "resourcequotas", _v("hard"), _v("scopes"), aliases=("resourcequota",)),
        Command(
            "service",
            subs=(
                _service("clusterip", _v("clusterip")),
                _service("externalname", _v("external-name")),
                _service("loadbalancer"),
                _service("nodeport", _v("node-port")),
            ),
            aliases=("svc",),
            runs=False,
        ),
    ),
)
_REPLACE = Command(
    "replace",
    (
        *_FILES,
        *_PRINT,
        _DRY_RUN,
        _CASCADE,
        _FIELD_MANAGER,
        _b("force"),
        _v("grace-period"),
        _RAW_PATH,
        _b("save-config"),
        _v("subresource"),
        _v("timeout"),
        _VALIDATE,
        _b("wait"),
    ),
)
_PATCH = Command(
    "patch",
    (
        *_FILES,
        *_PRINT,
        _DRY_RUN,
        _FIELD_MANAGER,
        _b("local"),
        _v("patch", "p"),
        _v("patch-file", role=Role.PATH),
        _v("subresource"),
        _v("type"),
    ),
)
_SCALE = Command(
    "scale",
    (
        *_FILES,
        *_PRINT,
        _DRY_RUN,
        _b("all"),
        _v("current-replicas"),
        _v("replicas"),
        _v("resource-version"),
        _SELECTOR,
        _v("timeout"),
    ),
)
_METADATA = (
    *_FILES,
    *_PRINT,
    _DRY_RUN,
    _b("all"),
    _ALL_NAMESPACES,
    _FIELD_MANAGER,
    _FIELD_SELECTOR,
    _b("list"),
    _b("local"),
    _b("overwrite"),
    _v("resource-version"),
    _SELECTOR,
)
_ROLLOUT = Command(
    "rollout",
    subs=(
        Command("history", (*_ROLLOUT_SELECT, *_PRINT, _v("revision"))),
        Command("pause", (*_ROLLOUT_SELECT, *_PRINT, _FIELD_MANAGER)),
        Command("restart", (*_ROLLOUT_SELECT, *_PRINT, _FIELD_MANAGER)),
        Command("resume", (*_ROLLOUT_SELECT, *_PRINT, _FIELD_MANAGER)),
        Command(
            "status",
            (*_ROLLOUT_SELECT, _v("revision"), _v("timeout"), _b("watch", "w")),
        ),
        Command("undo", (*_ROLLOUT_SELECT, *_PRINT, _DRY_RUN, _v("to-revision"))),
    ),
    runs=False,
)
_STREAMS = (_b("quiet", "q"), _b("stdin", "i"), _b("tty", "t"))
_EXEC = Command(
    "exec",
    (
        _v("container", "c"),
        _v("filename", "f", Role.PATH),
        _v("pod-running-timeout"),
        *_STREAMS,
    ),
)
_ATTACH = Command("attach", (_v("container", "c"), _v("pod-running-timeout"), *_STREAMS))
_PORT_FORWARD = Command("port-forward", (_v("address"), _v("pod-running-timeout")))
_CP = Command("cp", (_v("container", "c"), _b("no-preserve"), _v("retries")))
_DEBUG = Command(
    "debug",
    (
        _b("arguments-only"),
        _b("attach"),
        _v("container", "c"),
        _v("copy-to"),
        _v("custom", role=Role.PATH),
        _v("env"),
        _v("filename", "f", Role.PATH),
        _v("image"),
        _v("image-pull-policy"),
        # debug's own `--profile` (legacy, general, baseline, …), not the global profiler flag.
        _v("profile"),
        _b("replace"),
        _b("same-node"),
        _v("set-image"),
        _b("share-processes"),
        _v("target"),
        *_STREAMS,
    ),
)
_AUTH = Command(
    "auth",
    subs=(
        Command(
            "can-i",
            (
                _ALL_NAMESPACES,
                _b("list"),
                _b("no-headers"),
                _b("quiet", "q"),
                _v("subresource"),
            ),
        ),
    ),
    runs=False,
)
_CONFIG = Command(
    "config",
    subs=(
        Command(
            "view",
            (
                *_PRINT,
                _b("flatten"),
                _b("merge"),
                _b("minify"),
                # `config view --raw` is a boolean: print the credentials too.
                _b("raw"),
            ),
        ),
    ),
    runs=False,
)

#: The verbs the classifier knows.
VERBS: tuple[Command, ...] = (
    _GET,
    _DESCRIBE,
    _LOGS,
    _TOP,
    _EXPLAIN,
    _DELETE,
    _APPLY,
    _CREATE_CMD,
    _REPLACE,
    _PATCH,
    _SCALE,
    Command("label", _METADATA),
    Command("annotate", _METADATA),
    _ROLLOUT,
    _EXEC,
    _CP,
    _ATTACH,
    _PORT_FORWARD,
    _DEBUG,
    _AUTH,
    _CONFIG,
)

ROOT = Command("kubectl", subs=VERBS, runs=False)

#: kubectl's own verbs that the broker does not run: an unknown verb is a plugin otherwise.
UNSUPPORTED = frozenset(
    {
        "alpha",
        "api-resources",
        "api-versions",
        "autoscale",
        "certificate",
        "cluster-info",
        "completion",
        "cordon",
        "diff",
        "drain",
        "edit",
        "events",
        "expose",
        "help",
        "kustomize",
        "options",
        "plugin",
        "proxy",
        "run",
        "set",
        "taint",
        "uncordon",
        "version",
        "wait",
    }
)


# --- parsing ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Table:
    long: Mapping[str, Flag]
    short: Mapping[str, Flag]


def _table(*groups: tuple[Flag, ...]) -> _Table:
    """A lookup table; a later group shadows an earlier one, as a local flag shadows a global."""
    long: dict[str, Flag] = {}
    short: dict[str, Flag] = {}
    for group in groups:
        for flag in group:
            long[flag.name] = flag
            if flag.short:
                short[flag.short] = flag
    return _Table(long, short)


_GLOBAL_TABLE = _table(GLOBAL)
_GLOBAL_NAMES = frozenset(flag.name for flag in GLOBAL)

#: The values Go's `strconv.ParseBool` accepts.
_TRUE = frozenset({"1", "t", "T", "TRUE", "true", "True"})
_FALSE = frozenset({"0", "f", "F", "FALSE", "false", "False"})
#: A klog verbosity level, as `strconv.ParseInt` reads it.
_LEVEL = re.compile(r"[+-]?[0-9]+")


def _is_flag(arg: str) -> bool:
    """pflag: an argument is a flag when it starts with `-` and is longer than one character."""
    return len(arg) > 1 and arg[0] == "-"


class _Parser:
    def __init__(self, argv: Sequence[str]) -> None:
        self.argv = argv
        self.i = 0
        self.uses: list[FlagUse] = []

    def fail(self, detail: str) -> ParseError:
        return ParseError(detail, self.uses)

    def _use(self, flag: Flag, value: str, spelled: str) -> None:
        if flag.arity is Arity.BOOL:
            if value in _TRUE:
                value = "true"
            elif value in _FALSE:
                value = "false"
            else:
                raise self.fail(f"{spelled} takes true or false, not {value!r}")
        if flag.role is Role.VERBOSITY and not _LEVEL.fullmatch(value):
            raise self.fail(f"{spelled} takes a number, not {value!r}")
        self.uses.append(FlagUse(flag.name, value, spelled, flag.role))

    def _next_value(self, spelled: str) -> str:
        if self.i + 1 >= len(self.argv):
            raise self.fail(f"{spelled} needs a value")
        self.i += 1
        return self.argv[self.i]

    def flag(self, table: _Table) -> None:
        """Parse the flag at `argv[i]` (one argument, or two with its value)."""
        arg = self.argv[self.i]
        if arg.startswith("--"):
            body, eq, value = arg[2:].partition("=")
            if not body or body[0] in "-=":
                raise self.fail(f"bad flag syntax {arg!r}")
            name = body.replace("_", "-")
            spelled = f"--{name}"
            flag = table.long.get(name)
            if flag is None:
                raise self.fail(f"unknown flag {spelled}")
            if not eq:
                if flag.arity is Arity.BOOL:
                    value = "true"
                elif flag.arity is Arity.OPTIONAL:
                    value = flag.default
                else:
                    value = self._next_value(spelled)
            self._use(flag, value, spelled)
        else:
            shorts = arg[1:]
            while shorts:
                spelled = f"-{shorts[0]}"
                flag = table.short.get(shorts[0])
                if flag is None:
                    raise self.fail(f"unknown flag {spelled}")
                if len(shorts) > 2 and shorts[1] == "=":
                    value, shorts = shorts[2:], ""
                elif flag.arity is Arity.BOOL:
                    value, shorts = "true", shorts[1:]
                elif flag.arity is Arity.OPTIONAL:
                    value, shorts = flag.default, shorts[1:]
                elif len(shorts) > 1:
                    value, shorts = shorts[1:], ""
                else:
                    value, shorts = self._next_value(spelled), ""
                self._use(flag, value, spelled)
        self.i += 1

    def command(self) -> tuple[tuple[str, ...], Command]:
        """Walk the command tree to the command the argv names."""
        node = ROOT
        path: list[str] = []
        while node.subs:
            own = node.runs and node is not ROOT
            table = _table(GLOBAL, node.flags) if own else _GLOBAL_TABLE
            local: list[str] = []
            while self.i < len(self.argv) and _is_flag(self.argv[self.i]):
                if self.argv[self.i] == "--":
                    break
                before = len(self.uses)
                self.flag(table)
                local += [u.spelled for u in self.uses[before:] if u.name not in _GLOBAL_NAMES]
            at_end = self.i >= len(self.argv) or self.argv[self.i] == "--"
            if at_end and own:
                break
            if at_end:
                what = f"kubectl {' '.join(path)} needs a subcommand" if path else "no kubectl verb"
                if self.i < len(self.argv):
                    what += " before --"
                raise self.fail(what)
            word = self.argv[self.i]
            sub = node.find(word)
            if sub is None:
                raise self.fail(_unknown_command(path, word))
            if local:
                raise self.fail(
                    f"{local[0]} must come after 'kubectl {' '.join([*path, sub.name])}'"
                )
            path.append(sub.name)
            node = sub
            self.i += 1
        return tuple(path), node

    def parse(self) -> Parsed:
        path, command = self.command()
        table = _table(GLOBAL, command.flags)
        args: list[str] = []
        dash: int | None = None
        while self.i < len(self.argv):
            arg = self.argv[self.i]
            if arg == "--":
                dash = len(args)
                args.extend(self.argv[self.i + 1 :])
                break
            if _is_flag(arg):
                self.flag(table)
            else:
                args.append(arg)
                self.i += 1
        return Parsed(
            path, tuple(self.uses), tuple(args), len(args) if dash is None else dash, command
        )


def _unknown_command(path: Sequence[str], word: str) -> str:
    if not path:
        if word in UNSUPPORTED:
            return f"kubectl {word} is not supported through the broker"
        return f"unknown verb {word!r}: kubectl plugins are not run"
    return f"kubectl {' '.join(path)} {word} is not supported through the broker"


def parse(argv: Sequence[str]) -> Parsed:
    """Parse the arguments after `kubectl`. Raises `ParseError` for anything it cannot place."""
    return _Parser(argv).parse()
