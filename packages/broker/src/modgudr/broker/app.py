"""The broker as an object: `build(config)` and the `Broker` it returns (M3).

`build` loads the policy through the registry and prepares the audit writer and the store; it
never runs the process hardening (that is the daemon's, M23), and nothing in it reads the
broker's environment: the config carries every path, the `pwd` home and the managed-settings
locations. `Broker.start` walks the M1 flow to LISTENING(LOCKED):

    POLICY_LOADED -> AUDIT_READY -> BOUND (flock, sockets) -> LISTENING(LOCKED)

Any failure before LISTENING raises `StartError` (exit 78) with nothing listening and no socket
left behind.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import importlib.metadata
import logging
import os
import pwd
import sys
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO, cast

from modgudr.client import paths
from modgudr.client.agent.isolation import (
    KUBECTL_DENY_HOSTS,
    L0_WARNING,
    Facts,
    Isolation,
    detect,
    settings_locations,
    settings_signature,
)
from modgudr.client.errors import UsageError

from ..spi import (
    Action,
    Connector,
    Decision,
    Destination,
    OperationSpec,
    ResolvedSecret,
    SecretRef,
    SecretStore,
    StoreConfigError,
    StoreContext,
    StoreError,
    StoreFactory,
    Target,
)
from .audit import AuditUnavailable, AuditWriter
from .engine.decide import Scope, decide, scope_for
from .limits import Limits, Slots, defaults_limits, effective_limits
from .ops import (
    PROTOCOL_VERSIONS,
    UNKNOWN_LOCKED,
    ClientGone,
    Connection,
    Dispatcher,
    Flight,
    Request,
)
from .policy.load import Policy, PolicyError, load_policy
from .policy.model import TargetConfig
from .registry import PluginError, PluginRegistry
from .scrub import MIN_DATA_LENGTH, Scrubber
from .server import (
    LOCK_FILE,
    Channel,
    ChannelServer,
    StartError,
    SupportsGetsockopt,
    acquire_lock,
    check_socket_path,
    ensure_private_dir,
    peer_uid,
    release_lock,
)

log = logging.getLogger("modgudr.broker")

DEV_BANNER = (
    "modgudr-broker: DEV MODE. The file store is enabled and every audit line is marked "
    "dev: true. Never put real secrets in the secrets file."
)

#: How long shutdown waits for connections and servers to close.
SHUTDOWN_GRACE = 5.0


def _pwd_home() -> Path:
    return Path(pwd.getpwuid(os.getuid()).pw_dir)


def _utcnow() -> datetime:
    return datetime.now(UTC)


PeerUid = Callable[[SupportsGetsockopt], int]


@dataclass(frozen=True)
class BrokerConfig:
    """Everything the broker needs, so the factory never reads the environment (M3)."""

    #: `MODGUDR_HOME` as given; the broker canonicalises it at start (M1).
    home: Path
    agent_socket: Path
    policy_dir: Path
    audit_dir: Path
    secrets_file: Path | None = None
    dev: bool = False
    #: The `pwd` home: `~` in managed settings, the default `MODGUDR_HOME`.
    user_home: Path = field(default_factory=_pwd_home)
    #: The managed-settings base file and drop-in directory; None means the production location.
    managed_settings: Path | None = None
    managed_settings_dir: Path | None = None
    platform: str = sys.platform
    clock: Callable[[], datetime] = _utcnow
    #: Discovered from the entry points when None. Tests register the echo connector by hand.
    registry: PluginRegistry | None = None
    stderr: TextIO | None = None
    #: Test seams: how the peer uid is read; the request-line deadline; the socket watchdog.
    peer_uid: PeerUid | None = None
    request_idle_timeout: float = 10.0
    watchdog_interval: float = 5.0
    #: How managed-settings files are stat'ed after opening (tests inject a root owner).
    settings_fstat: Callable[[int], os.stat_result] | None = None

    @property
    def human_socket(self) -> Path:
        """`$MODGUDR_HOME/run/human.sock` on both platforms (M1)."""
        return self.home / "run" / "human.sock"

    def settings_paths(self) -> tuple[Path, Path]:
        base, dropin = settings_locations(self.platform)
        return (self.managed_settings or base, self.managed_settings_dir or dropin)

    @classmethod
    def from_environment(
        cls,
        environ: Mapping[str, str],
        *,
        dev: bool = False,
        policy_dir: Path | None = None,
        audit_dir: Path | None = None,
        secrets_file: Path | None = None,
    ) -> BrokerConfig:
        """The daemon's config: `MODGUDR_HOME` and `MODGUDR_SOCKET` from the environment, the
        home from `pwd`, the production managed-settings locations."""
        user_home = _pwd_home()
        try:
            home = paths.modgudr_home(env=environ, home_dir=str(user_home))
            agent = paths.agent_socket(env=environ, home_dir=str(user_home))
        except UsageError as exc:
            raise StartError(str(exc)) from exc
        return cls(
            home=home,
            agent_socket=agent,
            policy_dir=policy_dir or home / "policy.d",
            audit_dir=audit_dir or home / "audit",
            secrets_file=secrets_file,
            dev=dev,
            user_home=user_home,
        )


@dataclass(eq=False)
class OpenTarget:
    """A configured target, opened at start without contacting anything."""

    config: TargetConfig
    connector: Connector
    target: Target
    limits: Limits
    slots: Slots
    destinations: tuple[Destination, ...]
    operations: Mapping[str, OperationSpec]
    _scopes: dict[str, Scope] = field(default_factory=dict[str, Scope])

    def scope(self, policy: Policy, env: str) -> Scope:
        scope = self._scopes.get(env)
        if scope is None:
            scope = self._scopes[env] = scope_for(policy, self.config, env, self.connector)
        return scope

    def destination_text(self) -> str:
        return ",".join(str(d) for d in self.destinations)


class PassThroughSecrets:
    """M6 step 7 until the secret service exists: resolve through the store on every login, no
    pins, no cache, and register the value with the scrubber."""

    def __init__(self, broker: Broker, ref: str) -> None:
        self._broker = broker
        self._ref = ref

    async def login[T](self, connect: Callable[[ResolvedSecret], Awaitable[T]]) -> T:
        secret = await self._broker.resolve_secret(self._ref)
        return await connect(secret)


def build(config: BrokerConfig) -> Broker:
    """Load the policy and check the store configuration. Raises `StartError` (exit 78)."""
    try:
        registry = config.registry if config.registry is not None else PluginRegistry.discover()
    except PluginError as exc:
        raise StartError(str(exc)) from exc
    try:
        policy = load_policy(config.policy_dir, registry, dev=config.dev)
    except PolicyError as exc:
        raise StartError(f"the policy cannot be loaded:\n{exc}") from exc
    scheme = policy.company.store.default
    _check_store_config(config, policy, scheme)
    factory = registry.store_factory(scheme)
    if factory is None:
        known = ", ".join(registry.store_schemes()) or "none"
        raise StartError(f"no secret store {scheme!r} is installed; installed: {known}")
    for target in policy.targets.values():
        if registry.connector_plugin(target.type) is None:
            raise StartError(f"no connector for type {target.type!r} (target {target.name})")
        if target.provider is not None and registry.provider(target.provider) is None:
            raise StartError(
                f"target {target.name} names the credential provider {target.provider!r}, "
                "which is not installed"
            )
    return Broker(config, registry, policy, scheme, factory)


def _check_store_config(config: BrokerConfig, policy: Policy, scheme: str) -> None:
    store = policy.company.store
    bws = (
        scheme == "bws"
        or "bws" in store.stores
        or any(
            t.secret is not None and SecretRef.parse(t.secret).store == "bws"
            for t in policy.targets.values()
        )
    )
    if config.dev and bws:
        raise StartError("dev mode refuses the bws store: use the file store with --dev")
    if scheme == "file" and not config.dev:
        raise StartError("the file store is for development only; start with --dev")
    for target in policy.targets.values():
        if target.secret is None:
            continue
        ref = SecretRef.parse(target.secret)
        if ref.store != scheme:
            raise StartError(
                f"target {target.name} uses the store {ref.store!r}, but the configured store "
                f"is {scheme!r}"
            )


def _broker_version() -> str:
    try:
        return importlib.metadata.version("modgudr-broker")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def deny_hosts(targets: Mapping[str, tuple[str, tuple[Destination, ...]]]) -> tuple[str, ...]:
    """Every statically known destination host, plus the Azure hosts when a kubectl target
    exists (M22). `targets` maps a name to (connector type, destinations)."""
    hosts = {d.host.lower() for _, destinations in targets.values() for d in destinations}
    if any(type_name == "kubectl" for type_name, _ in targets.values()):
        hosts.update(KUBECTL_DENY_HOSTS)
    return tuple(sorted(hosts))


class Broker:
    """A broker that can serve both channels and shut down."""

    def __init__(
        self,
        config: BrokerConfig,
        registry: PluginRegistry,
        policy: Policy,
        store_scheme: str,
        store_factory: StoreFactory,
    ) -> None:
        self.config = config
        self.registry = registry
        self.policy = policy
        self.store_scheme = store_scheme
        self._store_factory = store_factory
        self.uid = os.getuid()
        self.version = _broker_version()
        self.limits = defaults_limits(policy.company.defaults)
        self.scrubber = Scrubber()
        self.audit = AuditWriter(
            config.audit_dir,
            self.scrubber,
            clock=config.clock,
            stamp={"isolation": "none", "store": store_scheme, "dev": config.dev},
        )
        self.targets: dict[str, OpenTarget] = {}
        self.flights: set[Flight] = set()
        self.stopping = False
        self.dispatcher = Dispatcher(self)
        self._store: SecretStore | None = None
        self._servers: list[ChannelServer] = []
        self._lock_fd: int | None = None
        self._conns: dict[asyncio.Task[None], Connection] = {}
        self._watchdog: asyncio.Task[None] | None = None
        self._stopped = asyncio.Event()
        self._shutdown_task: asyncio.Task[None] | None = None
        self._secret_lengths: dict[str, int] = {}
        self._replaced_warned: set[Path] = set()
        self._facts: Facts | None = None
        self._isolation = Isolation("none", ("isolation not checked yet",))
        self._isolation_signature: tuple[object, ...] | None = None
        self._audit_started = False

    # --- start ------------------------------------------------------------------------------

    @property
    def store(self) -> SecretStore:
        if self._store is None:
            raise RuntimeError("the broker has not started")
        return self._store

    @property
    def facts(self) -> Facts:
        if self._facts is None:
            raise RuntimeError("the broker has not started")
        return self._facts

    @property
    def isolation(self) -> Isolation:
        return self._isolation

    def _warn(self, message: str) -> None:
        print(f"modgudr-broker: warning: {message}", file=self.config.stderr or sys.stderr)

    async def start(self) -> None:
        """Walk to LISTENING(LOCKED). On failure nothing listens and no socket is left."""
        try:
            await self._start()
        except BaseException:
            await self._abort()
            raise

    async def _start(self) -> None:
        config = self.config
        if config.dev:
            print(DEV_BANNER, file=config.stderr or sys.stderr)
        check_socket_path(config.agent_socket)
        check_socket_path(config.human_socket)
        ensure_private_dir(config.home, uid=self.uid, warn=self._warn)
        run_dir = config.home / "run"
        ensure_private_dir(run_dir, uid=self.uid, warn=self._warn)
        ensure_private_dir(config.agent_socket.parent, uid=self.uid, warn=self._warn)
        home = Path(os.path.realpath(config.home))
        agent = Path(os.path.realpath(config.agent_socket.parent)) / config.agent_socket.name
        human = Path(os.path.realpath(run_dir)) / config.human_socket.name
        check_socket_path(agent)
        check_socket_path(human)
        self._store = self._make_store(home)
        # AUDIT_READY.
        try:
            await self.audit.start()
        except AuditUnavailable as exc:
            raise StartError(str(exc)) from exc
        self._audit_started = True
        await self._open_targets()
        self._facts = Facts(
            platform=config.platform,
            home=str(home),
            agent_socket=str(agent),
            human_socket=str(human),
            deny_hosts=deny_hosts(
                {n: (t.config.type, t.destinations) for n, t in self.targets.items()}
            ),
        )
        self._recheck_isolation()
        self.audit.set_stamp(isolation=self._isolation.label)
        # BOUND: the lock first, then both sockets.
        self._lock_fd = acquire_lock(run_dir / LOCK_FILE)
        for channel, path in (
            (Channel.AGENT, config.agent_socket),
            (Channel.HUMAN, config.human_socket),
        ):
            server = ChannelServer(channel, path, self._handle)
            self._servers.append(server)
            await server.open(uid=self.uid)
        started = await self.audit.event("broker.start", None, **self._start_record())
        if not started:
            raise StartError(f"the audit directory {config.audit_dir} is not writable")
        # LISTENING(LOCKED).
        for server in self._servers:
            await server.start_serving()
        self._watchdog = asyncio.get_running_loop().create_task(self._watch())

    def _make_store(self, home: Path) -> SecretStore:
        settings = self.policy.company.store.stores.get(self.store_scheme, {})
        context = StoreContext(
            scheme=self.store_scheme,
            home=home,
            dev=self.config.dev,
            settings=dict(settings),
            secrets_file=self.config.secrets_file,
        )
        try:
            store = self._store_factory(context)
        except StoreConfigError as exc:
            raise StartError(f"the {self.store_scheme} store cannot start: {exc}") from exc
        if store.is_unlocked():
            raise StartError(f"the {self.store_scheme} store must start locked (M7)")
        return store

    async def _open_targets(self) -> None:
        for name, config in self.policy.targets.items():
            connector = cast("Connector", self.registry.connector_plugin(config.type))
            secrets = PassThroughSecrets(self, config.secret) if config.secret else None
            try:
                target = await connector.open(name, config.config, secrets)
            except Exception as exc:
                raise StartError(f"target {name} cannot be opened: {exc}") from exc
            limits = effective_limits(self.policy.company.defaults, config)
            self.targets[name] = OpenTarget(
                config=config,
                connector=connector,
                target=target,
                limits=limits,
                slots=Slots(limits.max_concurrent),
                destinations=tuple(sorted(target.destinations(), key=str)),
                operations={spec.name: spec for spec in connector.operations()},
            )

    def _start_record(self) -> dict[str, object]:
        return {
            **self.facts.to_json(),
            "version": self.version,
            "pid": os.getpid(),
            "isolationReasons": list(self._isolation.reasons),
            "policy": [
                {"name": f.name, "sha256": f.sha256, "uid": f.uid, "mode": f"{f.mode:04o}"}
                for f in self.policy.files
            ],
            "plugins": [origin.to_json() for origin in self.registry.origins()],
        }

    async def _abort(self) -> None:
        for server in self._servers:
            server.close()
            server.unlink()
        for server in self._servers:
            await server.wait_closed(SHUTDOWN_GRACE)
        self._servers.clear()
        if self._lock_fd is not None:
            release_lock(self._lock_fd)
            self._lock_fd = None
        await self._close_targets()
        if self._audit_started:
            await self.audit.close()
            self._audit_started = False
        if self._store is not None:
            with contextlib.suppress(Exception):
                await self._store.lock()
        self._stopped.set()

    async def _close_targets(self) -> None:
        for target in self.targets.values():
            try:
                await target.target.aclose()
            except Exception as exc:
                log.warning("target %s did not close: %s", target.config.name, type(exc).__name__)
        self.targets.clear()

    # --- serving ----------------------------------------------------------------------------

    async def _handle(
        self, channel: Channel, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = cast("asyncio.Task[None]", asyncio.current_task())
        sock = writer.get_extra_info("socket")
        try:
            uid = (self.config.peer_uid or peer_uid)(sock)
        except OSError:
            uid = -1
        conn = Connection(channel, uid, reader, writer)
        self._conns[task] = conn
        try:
            if uid != self.uid:
                conn.phase = "working"
                await self.dispatcher.refuse_peer(conn)
            else:
                await self.dispatcher.serve(conn)
        except ClientGone:
            pass
        except Exception as exc:
            log.warning(
                "connection on %s failed: %s: %s",
                channel.value,
                type(exc).__name__,
                self.scrubber.error(str(exc)),
            )
            with contextlib.suppress(Exception):
                await self.dispatcher.send_error(conn, "internal", "internal broker error", None)
        finally:
            del self._conns[task]
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    def is_unlocked(self) -> bool:
        return self.store.is_unlocked()

    async def unlock_for_tests(self, credential: str = "test") -> None:
        """Test-only seam until the real `unlock` exists (step 07). No socket reaches it."""
        await self.store.unlock(credential)

    async def resolve_secret(self, ref_text: str) -> ResolvedSecret:
        """Fetch a secret from the store and register it with the scrubber."""
        ref = SecretRef.parse(ref_text)
        secret = await self.store.resolve(ref)
        if not secret.value:
            raise StoreError(f"secret {ref} is empty")
        self.scrubber.add(secret.value)
        self._secret_lengths[str(ref)] = len(secret.value)
        return secret

    def decide(self, target: OpenTarget, action: Action, env: str) -> Decision:
        return decide(action, target.scope(self.policy, env))

    # --- facts for the metadata ops ---------------------------------------------------------

    def pin_fact(self, target: OpenTarget) -> object:
        """Pin-dependent facts: unknown while locked (M6)."""
        if target.config.secret is None:
            return target.config.env
        if not self.is_unlocked():
            return UNKNOWN_LOCKED
        return "not checked"

    def scrub_fact(self, target: OpenTarget) -> str:
        """`partial` when a known secret is shorter than the scrubber's data minimum (D21)."""
        if target.config.secret is None:
            return "full"
        if not self.is_unlocked():
            return UNKNOWN_LOCKED
        length = self._secret_lengths.get(str(SecretRef.parse(target.config.secret)))
        if length is None:
            return "unknown (secret not resolved yet)"
        return "partial" if length < MIN_DATA_LENGTH else "full"

    def l0_warning(self) -> str | None:
        """The §4.9 warning when isolation is `none` and the broker runs as the caller's uid."""
        return L0_WARNING if not self._isolation.isolated else None

    def target_summary(self, target: OpenTarget) -> dict[str, object]:
        config = target.config
        return {
            "name": config.name,
            "type": config.type,
            "system": config.system,
            "env": config.env,
            "tier": config.credential.tier,
            "mode": "attended",
            "credential": "provider" if config.provider is not None else "secret",
            "provider": config.provider,
            "ops": list(target.operations),
            "destinations": [str(d) for d in target.destinations],
            "limits": target.limits.to_json(),
            "pins": self.pin_fact(target),
        }

    def status(self, conn: Connection, req: Request) -> dict[str, object]:
        unlocked = self.is_unlocked()
        data: dict[str, object] = {
            "version": self.version,
            "protocol": {
                "broker": list(PROTOCOL_VERSIONS),
                "client": req.v,
                "clientVersion": req.client.version,
            },
            "state": "unlocked" if unlocked else "locked",
            "locked": not unlocked,
            "dev": self.config.dev,
            "store": self.store_scheme,
            "channel": conn.channel.value,
            **self.facts.to_json(),
            "isolation": self._isolation.label,
            "isolationReasons": list(self._isolation.reasons),
            "managedSettings": list(self._isolation.files),
            "auditDegraded": self.audit.degraded,
            "defaultEnv": {"env": self.policy.default_env, "source": "defaults.env"},
            "policy": self.policy_status(),
        }
        warning = self.l0_warning()
        if warning is not None:
            data["warning"] = warning
        return data

    def policy_status(self) -> dict[str, object]:
        """The load-time hashes against the files on disk: "restart to apply" when they differ."""
        loaded = {f.name: f for f in self.policy.files}
        try:
            on_disk = {p.name for p in self.config.policy_dir.iterdir() if p.name.endswith(".yaml")}
        except OSError:
            on_disk = set[str]()
        changed: list[str] = []
        for name in sorted(loaded.keys() | on_disk):
            if name not in on_disk:
                changed.append(f"{name} (removed)")
            elif name not in loaded:
                changed.append(f"{name} (added)")
            elif _file_sha256(self.config.policy_dir / name) != loaded[name].sha256:
                changed.append(name)
        return {
            "dir": str(self.config.policy_dir),
            "files": [
                {"name": f.name, "sha256": f.sha256, "uid": f.uid, "mode": f"{f.mode:04o}"}
                for f in self.policy.files
            ],
            "changed": changed,
            "restartToApply": bool(changed),
            "message": (
                "policy files changed on disk since the broker started: restart to apply"
                if changed
                else None
            ),
        }

    # --- isolation and the watchdog ---------------------------------------------------------

    def _recheck_isolation(self) -> tuple[Isolation, Isolation] | None:
        """Detect again when a managed-settings file changed. Returns (old, new) on a flip."""
        base, dropin = self.config.settings_paths()
        signature = settings_signature(base, dropin)
        if signature == self._isolation_signature:
            return None
        self._isolation_signature = signature
        old = self._isolation
        new = detect(
            self.facts,
            user_home=str(self.config.user_home),
            base=base,
            dropin_dir=dropin,
            fstat=self.config.settings_fstat or os.fstat,
        )
        self._isolation = new
        return (old, new) if old.label != new.label else None

    async def check_isolation(self) -> Isolation:
        """Re-check on mtime change; write `isolation.changed` when the label flips."""
        if self.stopping:
            return self._isolation
        flipped = self._recheck_isolation()
        if flipped is not None:
            old, new = flipped
            self.audit.set_stamp(isolation=new.label)
            await self.audit.event(
                "isolation.changed",
                previous=old.label,
                current=new.label,
                reasons=list(new.reasons),
            )
        return self._isolation

    async def _watch(self) -> None:
        """Every few seconds: rebind a deleted socket file, and re-check isolation."""
        while True:
            await asyncio.sleep(self.config.watchdog_interval)
            for server in self._servers:
                bound = server.bound
                if bound is None:
                    continue
                state = bound.state()
                if state == "missing":
                    try:
                        await server.rebind(uid=self.uid)
                    except StartError as exc:
                        log.warning("cannot rebind %s: %s", server.path, exc)
                    else:
                        self._warn(f"{server.path} was deleted; bound it again")
                elif state == "replaced" and server.path not in self._replaced_warned:
                    self._replaced_warned.add(server.path)
                    self._warn(f"{server.path} was replaced by another file; not touching it")
            await self.check_isolation()

    # --- shutdown ---------------------------------------------------------------------------

    def request_shutdown(self) -> None:
        """For signal handlers: start draining once."""
        if self._shutdown_task is None:
            self._shutdown_task = asyncio.get_running_loop().create_task(self.shutdown())

    async def wait_stopped(self) -> None:
        await self._stopped.wait()

    async def shutdown(self) -> None:
        """DRAINING -> STOPPED: in-flight calls end `cancelled: shutdown`, the sockets are
        unlinked, then `broker.stop`."""
        if self.stopping:
            await self._stopped.wait()
            return
        self.stopping = True
        if self._watchdog is not None:
            self._watchdog.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._watchdog
        for server in self._servers:
            server.close()
        for flight in list(self.flights):
            flight.cancel("shutdown")
        for task, conn in list(self._conns.items()):
            if conn.phase == "reading":
                task.cancel()
        pending = set(self._conns)
        if pending:
            await asyncio.wait(pending, timeout=SHUTDOWN_GRACE)
        for server in self._servers:
            server.unlink()
        for server in self._servers:
            await server.wait_closed(SHUTDOWN_GRACE)
        await self._close_targets()
        if self._store is not None:
            with contextlib.suppress(Exception):
                await self._store.lock()
        self.scrubber.clear()
        await self.audit.event("broker.stop", reason="shutdown")
        await self.audit.close()
        self._audit_started = False
        if self._lock_fd is not None:
            release_lock(self._lock_fd)
            self._lock_fd = None
        self._servers.clear()
        self._stopped.set()


def _file_sha256(path: Path) -> str | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb", closefd=False) as handle:
            return hashlib.sha256(handle.read()).hexdigest()
    finally:
        os.close(fd)
