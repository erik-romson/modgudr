"""kubectl classification (§7.1 to §7.3, §7.6, §7.8, M17): actions, risk, invariants and facts.

`classify(argv, default_namespace)` turns the arguments after `kubectl` into an `Action`. It never
raises: whatever it cannot place is `kubectl:unknown`, with the reason in `detail`.

- **Actions** are `kubectl:<verb>/<plural>` (`kubectl:delete/pods`), `kubectl:rollout/<sub>`,
  `kubectl:create/<plural>`, `kubectl:top/<plural>`, `kubectl:auth/can-i`, `kubectl:config/view`
  and `kubectl:create/token`. More than one resource type gives `kubectl:<verb>/multiple`. A call
  that takes its objects from a file or a raw path names no resource: `kubectl:apply`,
  `kubectl:get`. The `resources` fact lists the types either way.
  A policy that allows `delete/*` and denies one resource must deny `delete/multiple` too.
- **Risk** follows §7.2: `exec`, `cp`, `attach`, `port-forward` and `debug` are admin; any call that
  names `secrets`, `config view --raw` and `create token` are secret; `proxy`, `edit`, other
  `config` commands, plugins, resources outside the catalogue and unparseable input are unknown.
- **Invariant hits** (§7.3, extended): identity and connection flags, path-taking flags (and
  output formats that read a template file), and debug output flags (`-v` from 6 on). The hit is
  the flag's long name (`--as`, `--server` for `-s`, `--filename` for `-f`); `detail` explains the
  first one. `INVARIANTS` adds `kubectl:cp/*`, which always reads or writes the broker's files.
- **Facts:** `namespace` (the last `-n`; else the target's `defaultNamespace`; else `default`),
  `allNamespaces`, `names`, `selector`, `all`, `follow`, `resources` and, when the call names its
  resource types, `clusterScoped`.

`RequireName` and `Namespaces` are the constraint checks for these facts (§7.6, M17).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from modgudr.spi import Action, ConstraintCheck, ConstraintValue, Fact, Measured, Risk, Rule

from .catalogue import SECRETS, Kind, by_plural, lookup
from .parse import FlagUse, Parsed, ParseError, Role, parse

TYPE = "kubectl"

#: The namespace kubectl uses when neither the call nor the target names one.
DEFAULT_NAMESPACE = "default"

#: The plugin invariants with a name of their own (§7.3). The flag invariants are hits.
INVARIANTS: tuple[Rule, ...] = (
    Rule(
        "kubectl:cp/*",
        "cp copies files to and from the broker's machine, as the developer",
    ),
)

#: Output formats that read a template file named by the format or by `--template` (M17).
_FILE_FORMATS = frozenset(
    {"go-template-file", "templatefile", "jsonpath-file", "custom-columns-file"}
)
#: Every other output format the classifier accepts; an unknown one is unknown.
_FORMATS = frozenset(
    {
        "json",
        "yaml",
        "name",
        "wide",
        "go-template",
        "template",
        "jsonpath",
        "jsonpath-as-json",
        "custom-columns",
        "plaintext",
        "plaintext-openapiv2",
    }
)

#: Flags that name a command's objects instead of its arguments (all path-taking).
_SOURCES = ("filename", "kustomize", "raw")

_HIT_DETAIL: Mapping[Role, str] = {
    Role.IDENTITY: "the broker sets the cluster, the user and the kubeconfig itself",
    Role.PATH: "kubectl would read a file on the broker's machine, as the developer",
    Role.DEBUG: "it prints or writes request details, which can hold the token",
    Role.VERBOSITY: "-v 6 and above prints request details, which can hold the token",
    Role.OUTPUT: "this output format reads a template file on the broker's machine, as the "
    "developer",
}
_RAW_DETAIL = "a raw API path is not classified, so it would get around the rules"


class _Unknown(Exception):
    """The call cannot be classified; the message is the `detail`."""


@dataclass(frozen=True)
class _Hit:
    name: str
    detail: str


def _hits(flags: Sequence[FlagUse]) -> list[_Hit]:
    """The invariant hits of the flags, in argv order, each once."""
    hits: dict[str, _Hit] = {}
    for use in flags:
        name = ""
        if use.role in (Role.IDENTITY, Role.PATH, Role.DEBUG):
            name = f"--{use.name}"
        elif use.role is Role.VERBOSITY and int(use.value) >= 6:
            name = "--v"
        elif use.role is Role.OUTPUT:
            output = _format(use.value)
            if output in _FILE_FORMATS:
                name = f"--output={output}"
        if name and name not in hits:
            detail = _RAW_DETAIL if use.name == "raw" else _HIT_DETAIL[use.role]
            hits[name] = _Hit(name, detail)
    return list(hits.values())


def _format(value: str) -> str:
    """The format of an `-o` value: `jsonpath={.items}` is `jsonpath`."""
    return value.partition("=")[0].lower()


def _check_formats(parsed: Parsed) -> None:
    for use in parsed.flags:
        if use.role is Role.OUTPUT:
            output = _format(use.value)
            if output not in _FORMATS and output not in _FILE_FORMATS:
                raise _Unknown(f"unknown output format {output!r}")


# --- resources -------------------------------------------------------------------------------


def _kind(name: str) -> Kind:
    found = lookup(name)
    if found is None:
        raise _Unknown(f"resource {name!r} is not in the catalogue")
    return found


def _type_name(arg: str) -> tuple[Kind, str]:
    """`type/name`, as kubectl splits it: one slash, both parts set, a single type."""
    parts = arg.split("/")
    if len(parts) != 2 or not parts[0] or not parts[1] or "," in parts[0]:
        raise _Unknown(f"{arg!r} is not in type/name form")
    return _kind(parts[0]), parts[1]


def _builder(args: Sequence[str]) -> tuple[tuple[Kind, ...], tuple[str, ...]]:
    """Resource types and names as kubectl's resource builder reads them.

    Either every argument is `type/name`, or the first is a type or a comma list of types and the
    rest are names of each.
    """
    if not args:
        return (), ()
    slashed = sum("/" in arg for arg in args)
    if slashed:
        if slashed != len(args):
            raise _Unknown("mixes type/name arguments with a separate resource type")
        pairs = [_type_name(arg) for arg in args]
        return tuple(kind for kind, _ in pairs), tuple(name for _, name in pairs)
    types = args[0].split(",")
    if not all(types):
        raise _Unknown(f"{args[0]!r} has an empty resource type")
    names = tuple(args[1:])
    if not all(names):
        raise _Unknown("a resource name is empty")
    return tuple(_kind(t) for t in types), names


def _pod_target(arg: str) -> tuple[Kind, str]:
    """A pod name, or `type/name` for a pod owner (`deploy/web`), as `logs` and `exec` take it."""
    if not arg:
        raise _Unknown("the pod name is empty")
    if "/" in arg:
        return _type_name(arg)
    return by_plural("pods"), arg


def _plurals(kinds: Sequence[Kind]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(kind.plural for kind in kinds))


def _action_name(verb: str, kinds: Sequence[Kind]) -> str:
    plurals = _plurals(kinds)
    if not plurals:
        return verb
    if len(plurals) == 1:
        return f"{verb}/{plurals[0]}"
    return f"{verb}/multiple"


# --- facts -----------------------------------------------------------------------------------


def _namespace(parsed: Parsed, default_namespace: str) -> str:
    value = parsed.last("namespace")
    if value is None:
        return default_namespace
    if not value:
        raise _Unknown("-n needs a namespace name")
    return value


def _facts(
    parsed: Parsed,
    default_namespace: str,
    kinds: Sequence[Kind],
    names: Sequence[str],
    *,
    namespace: str = "",
    follow: bool = False,
    cluster_scoped: bool | None = None,
    selector: bool = True,
) -> dict[str, Fact]:
    facts: dict[str, Fact] = {
        "namespace": namespace or _namespace(parsed, default_namespace),
        "allNamespaces": parsed.boolean("all-namespaces"),
        "names": tuple(names),
        "selector": parsed.last("selector") if selector else None,
        "all": parsed.boolean("all"),
        "follow": follow,
        "resources": _plurals(kinds),
    }
    if cluster_scoped is None and kinds:
        cluster_scoped = any(not kind.namespaced for kind in kinds)
    if cluster_scoped is not None:
        facts["clusterScoped"] = cluster_scoped
    return facts


@dataclass(frozen=True)
class _Classified:
    name: str
    risk: Risk
    facts: dict[str, Fact]


# --- verbs -----------------------------------------------------------------------------------

#: The risk of each verb that takes resource types (secrets aside, which are always `secret`).
RESOURCE_RISK: Mapping[str, Risk] = {
    "get": Risk.READ,
    "describe": Risk.READ,
    "delete": Risk.DESTRUCTIVE,
    "scale": Risk.WRITE,
    "patch": Risk.WRITE,
    "label": Risk.WRITE,
    "annotate": Risk.WRITE,
}
#: The risk of each `rollout` subcommand.
ROLLOUT_RISK: Mapping[str, Risk] = {
    "history": Risk.READ,
    "status": Risk.READ,
    "pause": Risk.WRITE,
    "restart": Risk.WRITE,
    "resume": Risk.WRITE,
    "undo": Risk.WRITE,
}


def _without_pairs(args: Sequence[str], verb: str) -> tuple[str, ...]:
    """The resource arguments of `label`/`annotate`: those before the first `key=value`/`key-`."""
    resources: list[str] = []
    pairs = False
    for arg in args:
        is_pair = ("=" in arg and arg[0] != "=") or (arg.endswith("-") and arg != "-")
        if is_pair:
            pairs = True
        elif pairs:
            raise _Unknown(f"kubectl {verb} needs every resource before the changes: {arg!r}")
        else:
            resources.append(arg)
    return tuple(resources)


def _sourced(parsed: Parsed) -> bool:
    return any(parsed.has(name) for name in _SOURCES)


def _resource_verb(parsed: Parsed, default_namespace: str) -> _Classified:
    verb = parsed.verb
    args = _without_pairs(parsed.args, verb) if verb in ("label", "annotate") else parsed.args
    kinds, names = _builder(args)
    if not kinds and not _sourced(parsed):
        raise _Unknown(f"kubectl {verb} needs a resource type, such as pods")
    if verb == "rollout":
        sub = parsed.path[1]
        name, risk = f"rollout/{sub}", ROLLOUT_RISK[sub]
        follow = sub == "status" and parsed.boolean("watch", default=True)
    else:
        name, risk = _action_name(verb, kinds), RESOURCE_RISK[verb]
        follow = verb == "get" and (parsed.boolean("watch") or parsed.boolean("watch-only"))
    return _Classified(name, risk, _facts(parsed, default_namespace, kinds, names, follow=follow))


def _file_verb(parsed: Parsed, default_namespace: str) -> _Classified:
    """`apply`, `replace` and `create` without a subcommand: the objects come from -f or -k."""
    verb = parsed.verb
    if parsed.args:
        raise _Unknown(f"kubectl {verb} takes its objects from -f or -k, not from arguments")
    if not _sourced(parsed):
        raise _Unknown(f"kubectl {verb} needs -f or -k")
    risk = Risk.WRITE
    if (verb == "apply" and parsed.boolean("prune")) or (
        verb == "replace" and parsed.boolean("force")
    ):
        risk = Risk.DESTRUCTIVE
    return _Classified(verb, risk, _facts(parsed, default_namespace, (), ()))


#: The `create` subcommands that take a command after `--`.
_CREATE_COMMANDS = frozenset({"deployment", "job", "cronjob"})


def _create(parsed: Parsed, default_namespace: str) -> _Classified:
    if len(parsed.path) == 1:
        return _file_verb(parsed, default_namespace)
    sub = parsed.command.name
    shown = " ".join(parsed.path)
    before, after = parsed.args[: parsed.dash], parsed.args[parsed.dash :]
    if len(before) != 1 or not before[0]:
        raise _Unknown(f"kubectl {shown} takes one name")
    if after and sub not in _CREATE_COMMANDS:
        raise _Unknown(f"kubectl {shown} takes no command after --")
    kind = by_plural(parsed.command.resource)
    if sub == "token":
        name, risk = "create/token", Risk.SECRET
    else:
        name, risk = f"create/{kind.plural}", Risk.WRITE
    facts = _facts(parsed, default_namespace, (kind,), before, selector=False)
    return _Classified(name, risk, facts)


def _pod_verb(parsed: Parsed, default_namespace: str) -> _Classified:
    """`logs`, `exec`, `attach`, `port-forward` and `debug`: one pod, or `type/name` of an owner."""
    verb = parsed.verb
    before = parsed.args[: parsed.dash]
    if verb == "logs":
        if len(parsed.args) > 2:
            raise _Unknown("kubectl logs takes a pod and at most a container")
        if not parsed.args and parsed.last("selector") is None:
            raise _Unknown("kubectl logs needs a pod name or -l")
        target = parsed.args[:1]
    elif verb in ("exec", "debug"):
        if len(before) > 1 or (not before and not parsed.has("filename")):
            raise _Unknown(f"kubectl {verb} takes one pod, then -- and the command")
        target = before
    elif verb == "attach":
        if len(parsed.args) != 1:
            raise _Unknown("kubectl attach takes one pod")
        target = parsed.args
    else:
        if len(parsed.args) < 2:
            raise _Unknown("kubectl port-forward takes a pod and at least one port")
        target = parsed.args[:1]
    if target:
        kind, pod = _pod_target(target[0])
        kinds, names = (kind,), (pod,)
    elif verb == "logs":
        kinds, names = (by_plural("pods"),), ()
    else:
        kinds, names = (), ()
    risk = Risk.READ if verb == "logs" else Risk.ADMIN
    follow = verb == "logs" and parsed.boolean("follow")
    facts = _facts(parsed, default_namespace, kinds, names, follow=follow)
    return _Classified(_action_name(verb, kinds), risk, facts)


def _file_spec(arg: str) -> tuple[str, str] | None:
    """kubectl cp's `[namespace/]pod:path` as (namespace, pod); None for a local path."""
    colon = arg.find(":")
    if colon == -1:
        return None
    pod = arg[:colon].split("/")
    if colon == 0 or len(pod) > 2 or not pod[-1]:
        raise _Unknown(f"{arg!r} is not a [namespace/]pod:path")
    return (pod[0] if len(pod) == 2 else ""), pod[-1]


def _cp(parsed: Parsed, default_namespace: str) -> _Classified:
    if len(parsed.args) != 2:
        raise _Unknown("kubectl cp takes a source and a destination")
    remote = [spec for spec in map(_file_spec, parsed.args) if spec is not None]
    if len(remote) != 1:
        raise _Unknown("kubectl cp copies between one pod path and one local path")
    namespace, pod = remote[0]
    facts = _facts(parsed, default_namespace, (by_plural("pods"),), (pod,), namespace=namespace)
    return _Classified("cp/pods", Risk.ADMIN, facts)


def _top(parsed: Parsed, default_namespace: str) -> _Classified:
    if len(parsed.args) > 1:
        raise _Unknown(f"kubectl top {parsed.command.name} takes at most one name")
    kind = by_plural(parsed.command.resource)
    facts = _facts(parsed, default_namespace, (kind,), parsed.args)
    return _Classified(f"top/{kind.plural}", Risk.READ, facts)


def _explain(parsed: Parsed, default_namespace: str) -> _Classified:
    if len(parsed.args) != 1:
        raise _Unknown("kubectl explain takes one resource, such as pods.spec")
    kind = _kind(parsed.args[0].split(".", 1)[0])
    facts = _facts(parsed, default_namespace, (kind,), ())
    return _Classified(f"explain/{kind.plural}", Risk.READ, facts)


def _auth(parsed: Parsed, default_namespace: str) -> _Classified:
    """`auth can-i`: a question about the caller's rights in a namespace, no object access."""
    if len(parsed.args) > 3:
        raise _Unknown("kubectl auth can-i takes a verb, a resource and a name")
    if not parsed.args and not parsed.boolean("list"):
        raise _Unknown("kubectl auth can-i needs a verb and a resource, or --list")
    facts = _facts(parsed, default_namespace, (), (), cluster_scoped=False)
    return _Classified("auth/can-i", Risk.READ, facts)


def _config(parsed: Parsed, default_namespace: str) -> _Classified:
    if parsed.args or not parsed.boolean("raw"):
        raise _Unknown("kubectl config is not supported through the broker")
    return _Classified("config/view", Risk.SECRET, _facts(parsed, default_namespace, (), ()))


_Handler = Callable[[Parsed, str], _Classified]

_HANDLERS: Mapping[str, _Handler] = {
    "get": _resource_verb,
    "describe": _resource_verb,
    "delete": _resource_verb,
    "scale": _resource_verb,
    "patch": _resource_verb,
    "label": _resource_verb,
    "annotate": _resource_verb,
    "rollout": _resource_verb,
    "apply": _file_verb,
    "replace": _file_verb,
    "create": _create,
    "logs": _pod_verb,
    "exec": _pod_verb,
    "attach": _pod_verb,
    "port-forward": _pod_verb,
    "debug": _pod_verb,
    "cp": _cp,
    "top": _top,
    "explain": _explain,
    "auth": _auth,
    "config": _config,
}


# --- classify --------------------------------------------------------------------------------


def _unknown(detail: str, hits: Sequence[_Hit]) -> Action:
    return Action(
        f"{TYPE}:unknown", Risk.UNKNOWN, invariant_hits=tuple(h.name for h in hits), detail=detail
    )


def _classify(argv: Sequence[str], default_namespace: str) -> Action:
    try:
        parsed = parse(argv)
    except ParseError as exc:
        return _unknown(exc.detail, _hits(exc.flags))
    hits = _hits(parsed.flags)
    try:
        _check_formats(parsed)
        classified = _HANDLERS[parsed.verb](parsed, default_namespace)
    except _Unknown as exc:
        return _unknown(str(exc), hits)
    risk = classified.risk
    resources = classified.facts.get("resources")
    if isinstance(resources, tuple) and SECRETS in resources:
        risk = Risk.SECRET
    return Action(
        f"{TYPE}:{classified.name}",
        risk,
        classified.facts,
        tuple(hit.name for hit in hits),
        hits[0].detail if hits else "",
    )


def classify(argv: Sequence[object], default_namespace: str | None = None) -> Action:
    """Classify the arguments after `kubectl` (M17). Never raises.

    `default_namespace` is the target's `defaultNamespace`; without it the namespace a call names
    no `-n` for is `default`.
    """
    try:
        if isinstance(argv, str):
            return Action.unknown(TYPE, "the arguments must be a list of words, not one string")
        words: list[str] = []
        for word in argv:
            if not isinstance(word, str):
                return Action.unknown(TYPE, "every argument must be a string")
            words.append(word)
        return _classify(words, default_namespace or DEFAULT_NAMESPACE)
    except Exception as exc:
        return Action.unknown(TYPE, f"the kubectl classifier failed: {type(exc).__name__}")


# --- constraints -----------------------------------------------------------------------------


def _listed(values: Sequence[str]) -> str:
    return ", ".join(values)


class RequireName:
    """`requireName` (§7.6, M17): refuses `--all`, selector-only and nameless forms."""

    def before(self, action: Action, value: ConstraintValue) -> str | None:
        if value is False:
            return None
        if value is not True:
            return f"requireName is true or false, not {value!r}"
        every = action.facts.get("all")
        if every is True:
            return "--all is refused; name the objects"
        if every is not False:
            return "the call does not say whether it acts on --all"
        names = action.facts.get("names")
        if isinstance(names, tuple) and names:
            return None
        if action.facts.get("selector"):
            return "a selector is refused; name the objects"
        return "name the objects to act on"

    def after(self, action: Action, value: ConstraintValue, measured: Measured) -> str | None:
        return None


class Namespaces:
    """`namespaces` (§7.6, M17): the call's namespace must be listed.

    `-A` never matches, and a cluster-scoped resource is denied. A call whose facts do not say
    either (no resource type, a missing fact) is denied too.
    """

    def before(self, action: Action, value: ConstraintValue) -> str | None:
        if not isinstance(value, tuple) or not value:
            return f"namespaces is a list of namespaces, not {value!r}"
        allowed = f"allowed: {_listed(value)}; add -n {value[0]}"
        facts = action.facts
        spans = facts.get("allNamespaces")
        if spans is True:
            return f"-A (all namespaces) never matches namespaces; {allowed}"
        if spans is not False:
            return "the call does not say whether it spans all namespaces"
        scoped = facts.get("clusterScoped")
        if scoped is True:
            resources = facts.get("resources")
            shown = _listed(resources) if isinstance(resources, tuple) else "the resource"
            return f"{shown}: cluster-scoped resources are denied under namespaces"
        if scoped is not False:
            return "the call names no resource type, so its namespace cannot be checked"
        namespace = facts.get("namespace")
        if not isinstance(namespace, str) or namespace not in value:
            return f"namespace {namespace!r} is not allowed; {allowed}"
        return None

    def after(self, action: Action, value: ConstraintValue, measured: Measured) -> str | None:
        return None


#: The constraint checks of the kubectl connector, by name.
CHECKS: Mapping[str, ConstraintCheck] = {
    "namespaces": Namespaces(),
    "requireName": RequireName(),
}
