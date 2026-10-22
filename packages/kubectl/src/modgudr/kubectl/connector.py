"""The `kubectl` connector (§7.8, §8.4, M17, M18): config, the passthrough op, the action
catalogue, and execution through a broker-owned kubeconfig.

A target names an AKS cluster by its Azure coordinates and takes `provider: azure-cli`; the
cluster's server comes from Azure, never from the policy, so there is no `server:` key.

**Per call** (M6 step 9, after the decision record):

1. the endpoint, then a token, from the provider (stages `provider.endpoint`, `provider.token`);
2. a fresh `$MODGUDR_HOME/run/k-<16 hex>/` (0700) with a kubeconfig whose user is the exec plugin
   of `modgudr.kubectl.exec_credential`, and `cred.sock`, which hands this call's token to that
   plugin only;
3. `kubectl --kubeconfig <file> --cache-dir <dir>/cache <argv…>`: an argv array, no shell, stdin
   closed, its own process group, the environment `PATH`, `HOME=<dir>`, `KUBECONFIG=<file>`;
4. stdout streams as `text` frames through the sink; stderr is captured (64 KiB) and goes out
   scrubbed after it. A non-zero exit is `upstream` with the raw code; "Unable to connect to the
   server" adds "is your VPN up?";
5. timeout, lock and disconnect kill the process group (SIGTERM, SIGKILL after 2 s); the socket
   and the directory are removed whatever happened.

The token never touches disk, argv or a child's environment.
"""

from __future__ import annotations

import asyncio
import codecs
import contextlib
import os
import re
import shutil
import signal
from collections.abc import Mapping, Sequence
from pathlib import Path
from secrets import token_hex
from typing import cast

from pydantic import BaseModel, ConfigDict, field_validator

from modgudr.broker.server import MAX_SOCKET_PATH_BYTES
from modgudr.spi import (
    Action,
    ActionSpec,
    Call,
    ConstraintCheck,
    Credentials,
    Destination,
    Endpoint,
    OperationSpec,
    ResultSink,
    Risk,
    Rule,
    RuleSet,
    Secrets,
    TargetContext,
    UpstreamFailure,
)

from .catalogue import KINDS, SECRETS
from .classify import (
    CHECKS,
    DEFAULT_NAMESPACE,
    INVARIANTS,
    RESOURCE_RISK,
    ROLLOUT_RISK,
    TYPE,
    classify,
)
from .exec_credential import SOCKET_NAME, CredentialServer
from .kubeconfig import write_kubeconfig
from .parse import ROOT, Command

#: The AKS server application: the audience of every AKS token (Bitwarden/AKS report §4.3).
AKS_SERVER_APP = "6dae42f8-4368-4678-94ff-3960e28e3630"
#: What `targets`, `describe` and `explain` show before a call has fetched the endpoint.
NOT_FETCHED = "not fetched"
#: The most of kubectl's stderr that is kept.
STDERR_LIMIT = 64 * 1024
#: Seconds between SIGTERM and SIGKILL to kubectl's process group.
KILL_GRACE = 2.0
READ_CHUNK = 65536
#: The per-call directory: `$MODGUDR_HOME/run/k-<16 hex>/`.
CALL_DIR_PREFIX = "k-"
VPN_HINT = "is your VPN up?"
_UNREACHABLE = "unable to connect to the server"

# --- config ---------------------------------------------------------------------------------------

_SUBSCRIPTION = re.compile(r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}")
#: Azure resource group names: 1 to 90 characters, not ending in a period (ASCII only here).
_RESOURCE_GROUP = re.compile(r"[A-Za-z0-9_.()-]{0,89}[A-Za-z0-9_()-]")
#: AKS cluster names: 1 to 63 characters, letters and digits at both ends.
_CLUSTER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?")
#: A Kubernetes namespace: a DNS label.
_NAMESPACE = re.compile(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?")


class ClusterConfig(BaseModel):
    """An AKS cluster by its Azure coordinates (M18)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    subscription: str
    resourceGroup: str
    name: str

    @field_validator("subscription")
    @classmethod
    def _subscription(cls, value: str) -> str:
        if not _SUBSCRIPTION.fullmatch(value):
            raise ValueError("subscription must be a subscription id (a GUID)")
        return value

    @field_validator("resourceGroup")
    @classmethod
    def _resource_group(cls, value: str) -> str:
        if not _RESOURCE_GROUP.fullmatch(value):
            raise ValueError(
                "resourceGroup must be 1 to 90 letters, digits, '_', '-', '.', '(' or ')', "
                "not ending in '.'"
            )
        return value

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        if not _CLUSTER.fullmatch(value):
            raise ValueError(
                "name must be 1 to 63 letters, digits, '_' or '-', starting and ending with a "
                "letter or digit"
            )
        return value


class KubectlConfig(BaseModel):
    """`type: kubectl` target keys: `cluster` and `defaultNamespace`. There is no `server:` key:
    the endpoint comes from Azure (M18)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cluster: ClusterConfig
    defaultNamespace: str | None = None

    @field_validator("defaultNamespace")
    @classmethod
    def _namespace(cls, value: str | None) -> str | None:
        if value is not None and not _NAMESPACE.fullmatch(value):
            raise ValueError("defaultNamespace must be a namespace name (a DNS label)")
        return value

    def cluster_keys(self) -> dict[str, str]:
        return {
            "subscription": self.cluster.subscription,
            "resourceGroup": self.cluster.resourceGroup,
            "name": self.cluster.name,
        }


def _kubectl_config(config: BaseModel) -> KubectlConfig:
    if not isinstance(config, KubectlConfig):
        raise TypeError(f"not a kubectl target config: {type(config).__name__}")
    return config


# --- operations and actions -----------------------------------------------------------------------

OPERATIONS: tuple[OperationSpec, ...] = (
    OperationSpec(
        "kubectl",
        "run kubectl with the arguments that follow, verbatim (the broker sets the cluster, the "
        "user and the kubeconfig)",
        rows=False,
        passthrough=True,
    ),
)

#: Both kubectl constraints apply to every action (§7.6, M17).
CONSTRAINTS = frozenset(CHECKS)

#: Verbs that take one pod, or `type/name` of a pod's owner.
_POD_VERBS: Mapping[str, Risk] = {
    "logs": Risk.READ,
    "exec": Risk.ADMIN,
    "attach": Risk.ADMIN,
    "port-forward": Risk.ADMIN,
    "debug": Risk.ADMIN,
}


def _command(name: str) -> Command:
    found = ROOT.find(name)
    if found is None:
        raise KeyError(name)
    return found


def _created(command: Command) -> list[str]:
    """The catalogue plurals the `create` subcommands make (the nested `secret` ones too)."""
    out: list[str] = []
    for sub in command.subs:
        if sub.resource:
            out.append(sub.resource)
        out.extend(_created(sub))
    return out


def _catalogue() -> tuple[ActionSpec, ...]:
    """Every action name the classifier gives, for `modgudr actions kubectl` and policy lint."""
    specs: dict[str, ActionSpec] = {}

    def add(name: str, risk: Risk, summary: str) -> None:
        specs.setdefault(name, ActionSpec(name, risk, CONSTRAINTS, summary))

    def per_kind(verb: str, risk: Risk) -> None:
        for kind in KINDS:
            add(
                f"{verb}/{kind.plural}",
                Risk.SECRET if kind.plural == SECRETS else risk,
                f"kubectl {verb} {kind.plural}",
            )

    for verb, risk in RESOURCE_RISK.items():
        add(verb, risk, f"kubectl {verb} -f (objects from a file; refused as a path flag)")
        per_kind(verb, risk)
        add(f"{verb}/multiple", risk, f"kubectl {verb} with more than one resource type")
    for sub, risk in ROLLOUT_RISK.items():
        add(f"rollout/{sub}", risk, f"kubectl rollout {sub}")
    for verb in ("apply", "replace", "create"):
        add(verb, Risk.WRITE, f"kubectl {verb} -f (refused as a path flag)")
    for plural in _created(_command("create")):
        risk = Risk.SECRET if plural == SECRETS else Risk.WRITE
        add(f"create/{plural}", risk, f"kubectl create {plural}")
    add("create/token", Risk.SECRET, "kubectl create token (a service account token)")
    for verb, risk in _POD_VERBS.items():
        add(verb, risk, f"kubectl {verb} without a pod (-f; refused as a path flag)")
        per_kind(verb, risk)
    add("cp/pods", Risk.ADMIN, "kubectl cp (an invariant: never allowed)")
    for sub in _command("top").subs:
        add(f"top/{sub.resource}", Risk.READ, f"kubectl top {sub.name}")
    per_kind("explain", Risk.READ)
    add("auth/can-i", Risk.READ, "kubectl auth can-i")
    add("config/view", Risk.SECRET, "kubectl config view --raw")
    return tuple(specs.values())


ACTIONS: tuple[ActionSpec, ...] = _catalogue()


class KubectlConnector:
    """`type: kubectl`."""

    @property
    def type(self) -> str:
        return TYPE

    @property
    def config_model(self) -> type[BaseModel]:
        return KubectlConfig

    def operations(self) -> Sequence[OperationSpec]:
        return OPERATIONS

    def actions(self) -> Sequence[ActionSpec]:
        return ACTIONS

    def invariants(self) -> Sequence[Rule]:
        return INVARIANTS

    def default_rules(self) -> RuleSet:
        return RuleSet(allow=(Rule("read"),))

    def constraint_checks(self) -> Mapping[str, ConstraintCheck]:
        return CHECKS

    def validate(self, call: Call, config: BaseModel, *, max_rows: int) -> None:
        """The op contract is the argv list the core has checked; the classifier does the rest."""

    def classify(self, call: Call, config: BaseModel) -> Action:
        try:
            namespace = _kubectl_config(config).defaultNamespace
        except TypeError as exc:
            return Action.unknown(TYPE, str(exc))
        argv = call.args.get("argv", ())
        if not isinstance(argv, list | tuple):
            return Action.unknown(TYPE, "the arguments must be a list of words")
        return classify(cast("Sequence[object]", argv), namespace)

    async def open(
        self, name: str, config: BaseModel, secrets: Secrets | None, *, context: TargetContext
    ) -> KubectlTarget:
        if secrets is not None or context.credentials is None:
            raise ValueError(
                f"kubectl target {name} takes a credential provider (provider: azure-cli), "
                "not a secret"
            )
        probe = context.home / "run" / f"{CALL_DIR_PREFIX}{'0' * 16}" / SOCKET_NAME
        if len(os.fsencode(probe)) > MAX_SOCKET_PATH_BYTES:
            raise ValueError(
                f"MODGUDR_HOME {context.home} is too long for the per-call credential socket "
                f"({len(os.fsencode(probe))} bytes, limit {MAX_SOCKET_PATH_BYTES})"
            )
        return KubectlTarget(name, _kubectl_config(config), context, context.credentials)


# --- the target -----------------------------------------------------------------------------------


class KubectlTarget:
    """One kubectl target: its `kubectl`, its provider and the endpoint of this session."""

    def __init__(
        self,
        name: str,
        config: KubectlConfig,
        context: TargetContext,
        credentials: Credentials,
    ) -> None:
        self.name = name
        self._config = config
        self._credentials = credentials
        self._path = context.path
        self._run_dir = context.home / "run"
        self._uid = os.getuid()
        found = shutil.which("kubectl", path=context.path) if context.path else None
        #: Resolved at broker start (M18); None when it is not on the broker's `PATH`.
        self.kubectl: str | None = str(Path(found).absolute()) if found else None
        #: The endpoint the first call of this session fetched; dropped on lock (`aclose`).
        self._endpoint: Endpoint | None = None

    @property
    def default_port(self) -> int:
        return 443

    @property
    def namespace(self) -> str:
        return self._config.defaultNamespace or DEFAULT_NAMESPACE

    def destinations(self) -> frozenset[Destination]:
        endpoint = self._endpoint
        return frozenset() if endpoint is None else frozenset({endpoint.destination})

    def facts(self) -> Mapping[str, object]:
        endpoint = self._endpoint
        facts: dict[str, object] = {
            "endpoint": NOT_FETCHED if endpoint is None else endpoint.server,
            "kubectl": self.kubectl,
        }
        if self.kubectl is None:
            facts["problem"] = "kubectl is not on the broker's PATH; calls fail"
        return facts

    async def aclose(self) -> None:
        """Lock or shutdown: the next call fetches the endpoint again. Running kubectl processes
        end with their calls, which the broker cancels first (M7)."""
        self._endpoint = None

    async def execute(self, call: Call, sink: ResultSink) -> None:
        kubectl = self.kubectl
        if kubectl is None:
            raise UpstreamFailure(
                "kubectl is not on the broker's PATH; install it, or start the broker with it on "
                "PATH"
            )
        argv = call.args.get("argv", [])
        if not isinstance(argv, list):
            raise TypeError("the kubectl arguments are not a list")
        words = [str(word) for word in cast("list[object]", argv)]
        endpoint = await self._credentials.endpoint(self._config.cluster_keys())
        self._endpoint = endpoint
        sink.report(destination=str(endpoint.destination))
        token = await self._credentials.token(AKS_SERVER_APP)
        workdir = self._call_dir()
        server: CredentialServer | None = None
        try:
            socket_path = workdir / SOCKET_NAME
            kubeconfig = write_kubeconfig(workdir, endpoint, socket_path, self.namespace)
            server = CredentialServer(socket_path, token.value, token.expires_at, uid=self._uid)
            await server.start()
            await self._run(kubectl, kubeconfig, workdir, words, sink)
        finally:
            if server is not None:
                server.close()
            shutil.rmtree(workdir, ignore_errors=True)

    def _call_dir(self) -> Path:
        """A new `run/k-<16 hex>/`, 0700."""
        path = self._run_dir / f"{CALL_DIR_PREFIX}{token_hex(8)}"
        path.mkdir(mode=0o700)
        path.chmod(0o700)
        return path

    async def _run(
        self,
        kubectl: str,
        kubeconfig: Path,
        workdir: Path,
        argv: Sequence[str],
        sink: ResultSink,
    ) -> None:
        env = {"PATH": self._path, "HOME": str(workdir), "KUBECONFIG": str(kubeconfig)}
        command = [
            kubectl,
            "--kubeconfig",
            str(kubeconfig),
            "--cache-dir",
            str(workdir / "cache"),
            *argv,
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                cwd=str(workdir),
                start_new_session=True,
            )
        except OSError as exc:
            raise UpstreamFailure(f"kubectl cannot be started: {exc.strerror or exc}") from None
        assert proc.stdout is not None and proc.stderr is not None
        errors = asyncio.ensure_future(_capture(proc.stderr))
        ended = False
        try:
            await _stream(proc.stdout, sink)
            code = await proc.wait()
            stderr = await errors
            ended = True
        finally:
            if not ended:
                errors.cancel()
                await _stop(proc)
        # Whatever kubectl left running in its group goes too.
        _signal(proc.pid, signal.SIGKILL)
        sink.report(exit_code=code)
        text = stderr.decode("utf-8", "replace")
        if text:
            await sink.text("stderr", text)
        if code != 0:
            raise UpstreamFailure(_failure(code, text))


async def _stream(stdout: asyncio.StreamReader, sink: ResultSink) -> None:
    """kubectl's stdout as `text` frames, decoded across chunk boundaries."""
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    while chunk := await stdout.read(READ_CHUNK):
        text = decoder.decode(chunk)
        if text:
            await sink.text("stdout", text)
    tail = decoder.decode(b"", final=True)
    if tail:
        await sink.text("stdout", tail)


async def _capture(stderr: asyncio.StreamReader) -> bytes:
    """kubectl's stderr, of which the first `STDERR_LIMIT` bytes are kept; the rest is read and
    dropped, so kubectl never blocks on a full pipe."""
    kept = bytearray()
    while chunk := await stderr.read(READ_CHUNK):
        room = STDERR_LIMIT - len(kept)
        if room > 0:
            kept += chunk[:room]
    return bytes(kept)


def _failure(code: int, stderr: str) -> str:
    line = next((x.strip() for x in stderr.splitlines() if x.strip()), "")
    message = f"kubectl exited with code {code}"
    if line:
        message += f": {line[:300]}"
    if _UNREACHABLE in stderr.lower():
        message += f"; {VPN_HINT}"
    return message


def _signal(pgid: int, sig: signal.Signals) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pgid, sig)


def _group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


async def _stop(proc: asyncio.subprocess.Process) -> None:
    """End kubectl and everything it started: SIGTERM to its process group, SIGKILL after 2 s
    (M18). The SIGKILL is scheduled before the wait, so a second cancellation cannot skip it."""
    pgid = proc.pid
    _signal(pgid, signal.SIGTERM)
    timer = asyncio.get_running_loop().call_later(KILL_GRACE, _signal, pgid, signal.SIGKILL)
    try:
        async with asyncio.timeout(KILL_GRACE):
            await proc.wait()
            while _group_alive(pgid):
                await asyncio.sleep(0.02)
    except TimeoutError:
        _signal(pgid, signal.SIGKILL)
        await proc.wait()
    timer.cancel()
