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
from collections.abc import Callable, Mapping
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
    CredentialProvider,
    Decision,
    Destination,
    OperationSpec,
    ProviderContext,
    ProviderFactory,
    ProviderTarget,
    ReportingStore,
    ReportingTarget,
    SecretRef,
    SecretStore,
    StoreConfigError,
    StoreContext,
    StoreError,
    StoreFactory,
    Target,
    TargetContext,
    UnlockRefused,
    UpstreamFailure,
)
from .audit import AuditUnavailable, AuditWriter, new_audit_id
from .engine.decide import Scope, decide, scope_for
from .harden import NOT_APPLIED, Hardening
from .limits import Limits, Slots, defaults_limits, effective_limits
from .ops import (
    LOCKED_MESSAGE,
    PROTOCOL_VERSIONS,
    UNKNOWN_LOCKED,
    ClientGone,
    Connection,
    Dispatcher,
    Flight,
    Refused,
    Request,
)
from .policy.load import Fstat, Policy, PolicyError, load_policy
from .policy.model import TargetConfig
from .providers import TargetCredentials
from .registry import PluginError, PluginRegistry
from .scrub import MIN_DATA_LENGTH, Scrubber
from .secrets import SecretService, TargetSecrets
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
from .session import FAILED_UNLOCK_LIMIT, FAILED_UNLOCK_WINDOW, LockReason, Session

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
    #: The scrubber the daemon's log filter shares with the broker; a fresh one when None.
    scrubber: Scrubber | None = None
    #: The hardening facts of the daemon (M23); None for a factory-built broker.
    hardening: Hardening | None = None
    #: The broker's `PATH`, where a store looks for its executable (`bws`, M19).
    path: str = ""
    #: How policy files are stat'ed after opening: tests inject a root-owned company file, because
    #: `--dev` is refused with the `bws` store (step 03's owner-check seam).
    policy_fstat: Fstat | None = None
    #: `LANG` and `LC_*` of the broker's environment, for children that get a locale (`az`, M18).
    locale: Mapping[str, str] = field(default_factory=dict[str, str])

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
            path=environ.get("PATH", ""),
            locale={k: v for k, v in environ.items() if k == "LANG" or k.startswith("LC_")},
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
    #: The target's view of the secret service; None for a `provider:` target.
    secrets: TargetSecrets | None = None
    _scopes: dict[str, Scope] = field(default_factory=dict[str, Scope])

    def scope(self, policy: Policy, env: str) -> Scope:
        scope = self._scopes.get(env)
        if scope is None:
            scope = self._scopes[env] = scope_for(policy, self.config, env, self.connector)
        return scope

    def live_destinations(self) -> list[str]:
        """What the target contacts now: a `provider:` target knows its endpoint only once a
        call has fetched it (M18)."""
        return sorted(str(d) for d in self.target.destinations())

    def destination_text(self) -> str:
        return ",".join(self.live_destinations())

    def facts(self) -> dict[str, object]:
        target = self.target
        return dict(target.facts()) if isinstance(target, ReportingTarget) else {}


@dataclass(frozen=True)
class LockOutcome:
    #: False when the broker was locked already (`lock` is idempotent).
    locked: bool
    #: In-flight calls this lock cancelled.
    cancelled: int = 0
    #: The `lock` record's audit id.
    audit_id: str | None = None


@dataclass(frozen=True)
class UnlockOutcome:
    #: A concurrent `unlock` won while this one waited: nothing was tested.
    already: bool = False
    #: The broker was unlocked already and the store accepted the credential again.
    reauthenticated: bool = False


def build(config: BrokerConfig) -> Broker:
    """Load the policy and check the store configuration. Raises `StartError` (exit 78)."""
    try:
        registry = config.registry if config.registry is not None else PluginRegistry.discover()
    except PluginError as exc:
        raise StartError(str(exc)) from exc
    try:
        if config.policy_fstat is not None:
            policy = load_policy(
                config.policy_dir, registry, dev=config.dev, fstat=config.policy_fstat
            )
        else:
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
        if target.provider is not None and registry.provider_factory(target.provider) is None:
            known = ", ".join(registry.provider_names()) or "none"
            raise StartError(
                f"target {target.name} names the credential provider {target.provider!r}, "
                f"which is not installed; installed: {known}"
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


def broker_version() -> str:
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
        self.version = broker_version()
        self.limits = defaults_limits(policy.company.defaults)
        self.scrubber = config.scrubber if config.scrubber is not None else Scrubber()
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
        defaults = policy.company.defaults
        self.session = Session(
            clock=config.clock, idle_lock=defaults.idleLock, absolute_lock=defaults.absoluteLock
        )
        self._store: SecretStore | None = None
        self._secrets: SecretService | None = None
        #: The credential providers the targets name, created at start (M18).
        self.providers: dict[str, CredentialProvider] = {}
        self._unlocking = asyncio.Lock()
        self._locking: asyncio.Task[LockOutcome] | None = None
        self._servers: list[ChannelServer] = []
        self._lock_fd: int | None = None
        self._conns: dict[asyncio.Task[None], Connection] = {}
        self._watchdog: asyncio.Task[None] | None = None
        self._stopped = asyncio.Event()
        self._shutdown_task: asyncio.Task[None] | None = None
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
    def secrets(self) -> SecretService:
        if self._secrets is None:
            raise RuntimeError("the broker has not started")
        return self._secrets

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
        self.providers = self._make_providers(home)
        self._secrets = SecretService(
            self._store,
            self.scrubber,
            self.session,
            on_store_invalid=lambda: self.begin_lock(LockReason.STORE_INVALID),
        )
        # AUDIT_READY.
        try:
            await self.audit.start()
        except AuditUnavailable as exc:
            raise StartError(str(exc)) from exc
        self._audit_started = True
        await self._open_targets(home)
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
            path=self.config.path,
        )
        try:
            store = self._store_factory(context)
        except StoreConfigError as exc:
            raise StartError(f"the {self.store_scheme} store cannot start: {exc}") from exc
        if store.is_unlocked():
            raise StartError(f"the {self.store_scheme} store must start locked (M7)")
        if isinstance(store, ReportingStore):
            for warning in store.warnings():
                self._warn(warning)
        return store

    def _make_providers(self, home: Path) -> dict[str, CredentialProvider]:
        """One instance of every credential provider a target names (M18)."""
        context = ProviderContext(
            home=home,
            user_home=self.config.user_home,
            path=self.config.path,
            locale=dict(self.config.locale),
        )
        providers: dict[str, CredentialProvider] = {}
        for name in sorted({t.provider for t in self.policy.targets.values() if t.provider}):
            factory = cast("ProviderFactory", self.registry.provider_factory(name))
            try:
                providers[name] = factory(context)
            except Exception as exc:
                raise StartError(f"the credential provider {name} cannot start: {exc}") from exc
        return providers

    def _credentials(self, config: TargetConfig) -> TargetCredentials:
        provider = self.providers[cast("str", config.provider)]
        tier = config.credential.tier
        if tier not in provider.tiers:
            raise StartError(
                f"target {config.name}: the credential provider {provider.name} serves the tiers "
                f"{', '.join(sorted(provider.tiers))}, not {tier}"
            )
        who = ProviderTarget(config.name, config.system or config.name, tier)
        return TargetCredentials(provider, who, scrubber=self.scrubber, session=self.session)

    async def _open_targets(self, home: Path) -> None:
        for name, config in self.policy.targets.items():
            connector = cast("Connector", self.registry.connector_plugin(config.type))
            secrets: TargetSecrets | None = None
            credentials: TargetCredentials | None = None
            if config.secret is not None:
                secrets = TargetSecrets(
                    self.secrets,
                    self.policy,
                    target=name,
                    declared_env=config.env,
                    ref=SecretRef.parse(config.secret),
                )
            else:
                credentials = self._credentials(config)
            context = TargetContext(home=home, path=self.config.path, credentials=credentials)
            try:
                target = await connector.open(name, config.config, secrets, context=context)
            except Exception as exc:
                raise StartError(f"target {name} cannot be opened: {exc}") from exc
            if secrets is not None:
                secrets.attach(target)
            limits = effective_limits(self.policy.company.defaults, config)
            self.targets[name] = OpenTarget(
                config=config,
                connector=connector,
                target=target,
                limits=limits,
                slots=Slots(limits.max_concurrent),
                destinations=tuple(sorted(target.destinations(), key=str)),
                operations={spec.name: spec for spec in connector.operations()},
                secrets=secrets,
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
        return self.session.unlocked

    def locked_message(self) -> str:
        """What a call refused at the lock gate (or cancelled by a lock) is told."""
        reason = self.session.reason
        if reason is LockReason.STORE_INVALID:
            return (
                "the store session expired (store-invalid); run `modgudr unlock` in your own "
                "terminal"
            )
        if reason is None:
            return LOCKED_MESSAGE
        return f"the broker is locked ({reason}); run `modgudr unlock` in your own terminal"

    # --- the store session (M7) -------------------------------------------------------------

    async def check_session(self) -> None:
        """At every request entry and on the timer: lock when a deadline has passed."""
        if self.stopping:
            return
        expiry = self.session.expiry()
        if expiry is not None:
            await self.lock(expiry.reason, detail=expiry.detail)

    def begin_lock(
        self,
        reason: LockReason,
        *,
        detail: str | None = None,
        fields: Mapping[str, object] | None = None,
    ) -> asyncio.Task[LockOutcome] | None:
        """Lock now. Before this returns, new calls get `locked` (1) and every in-flight call is
        cancelled (2); a task closes pools and sessions (3), then drops the secret cache, minted
        tokens, the store session and the scrubber's set (4), then writes the `lock` record.

        Returns None when the broker was locked already."""
        if not self.session.lock(reason):
            return None
        flights = list(self.flights)
        for flight in flights:
            flight.cancel("lock")
        record: dict[str, object] = {**(fields or {}), "reason": str(reason)}
        record["cancelled"] = len(flights)
        if detail is not None:
            record["detail"] = detail
        task = asyncio.get_running_loop().create_task(self._finish_lock(len(flights), record))
        self._locking = task
        return task

    async def lock(
        self,
        reason: LockReason,
        *,
        detail: str | None = None,
        fields: Mapping[str, object] | None = None,
    ) -> LockOutcome:
        """`begin_lock`, then wait for its task. Idempotent."""
        task = self.begin_lock(reason, detail=detail, fields=fields)
        if task is None:
            await self._lock_finished()
            return LockOutcome(locked=False)
        return await asyncio.shield(task)

    async def _lock_finished(self) -> None:
        pending = self._locking
        if pending is not None and not pending.done():
            await asyncio.shield(pending)

    async def _finish_lock(self, cancelled: int, record: Mapping[str, object]) -> LockOutcome:
        # 3. Pools and sessions close.
        for target in list(self.targets.values()):
            try:
                await target.target.aclose()
            except Exception as exc:
                log.warning("target %s did not close: %s", target.config.name, type(exc).__name__)
        # 4. The secret cache and latches, minted tokens, the store session, the scrubber's set.
        self.secrets.drop()
        for provider in self._providers():
            try:
                await provider.lock()
            except Exception as exc:
                log.warning("provider %s did not lock: %s", provider.name, type(exc).__name__)
        try:
            await self.store.lock()
        except Exception as exc:
            log.warning("the %s store did not lock: %s", self.store_scheme, type(exc).__name__)
        self.scrubber.clear()
        audit_id = new_audit_id()
        await self.audit.event("lock", audit_id, **record)
        return LockOutcome(locked=True, cancelled=cancelled, audit_id=audit_id)

    def _providers(self) -> list[CredentialProvider]:
        return list(self.providers.values())

    async def unlock(
        self, credential: str, audit_id: str, fields: Mapping[str, object]
    ) -> UnlockOutcome:
        """`unlock` on `human.sock` (M7): serialised; every attempt is audited without its
        input. Raises `Refused` (already audited under `audit_id`)."""
        session = self.session
        seen = session.unlocks
        async with self._unlocking:
            if session.unlocked and session.unlocks != seen:
                await self.audit.event("unlock", audit_id, **fields, alreadyUnlocked=True)
                return UnlockOutcome(already=True)
            retry = session.unlock_retry_after()
            if retry is not None:
                await self.audit.event("unlock.throttled", audit_id, **fields, retryAfter=retry)
                raise Refused(
                    "throttled",
                    f"{FAILED_UNLOCK_LIMIT} failed unlocks within {FAILED_UNLOCK_WINDOW:g} s; "
                    f"the next attempt is refused untested for {retry:g} s",
                    record=None,
                    retry_after=retry,
                    audited=True,
                )
            await self._lock_finished()
            epoch = session.epoch
            state = "unlocked" if session.unlocked else "locked"
            try:
                await self.store.unlock(credential)
            except UnlockRefused as exc:
                session.unlock_failed()
                await self.audit.event("unlock.failed", audit_id, **fields, code="denied")
                raise Refused(
                    "denied",
                    f"the {self.store_scheme} store refused the credential "
                    f"({_withheld(exc, credential)}); the broker stays {state}",
                    record=None,
                    audited=True,
                ) from None
            except StoreError as exc:
                await self.audit.event("unlock.failed", audit_id, **fields, code="upstream")
                raise Refused(
                    "upstream",
                    f"the {self.store_scheme} store cannot be unlocked: "
                    f"{_withheld(exc, credential)}",
                    record=None,
                    audited=True,
                ) from None
            except Exception as exc:
                await self.audit.event("unlock.failed", audit_id, **fields, code="internal")
                raise Refused(
                    "internal",
                    f"the {self.store_scheme} store failed to unlock ({type(exc).__name__})",
                    record=None,
                    audited=True,
                ) from None
            if session.epoch != epoch:
                # A lock arrived while a re-authentication was running: it wins.
                with contextlib.suppress(Exception):
                    await self.store.lock()
                await self.audit.event("unlock.failed", audit_id, **fields, code="locked")
                raise Refused(
                    "locked",
                    "the broker was locked while the store was unlocking; run `modgudr unlock` "
                    "again",
                    record=None,
                    audited=True,
                )
            again = session.unlocked_now()
            self.secrets.on_unlock()
            await self.audit.event("unlock", audit_id, **fields, reauthenticated=again)
            return UnlockOutcome(reauthenticated=again)

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
        length = self.secrets.length(SecretRef.parse(target.config.secret))
        if length is None:
            return "unknown (secret not resolved yet)"
        return "partial" if length < MIN_DATA_LENGTH else "full"

    def l0_warning(self) -> str | None:
        """The §4.9 warning when isolation is `none` and the broker runs as the caller's uid."""
        return L0_WARNING if not self._isolation.isolated else None

    def target_problems(self, target: OpenTarget) -> list[str]:
        """Why calls of this target will fail before they start: a missing executable."""
        problems: list[str] = []
        problem = target.facts().get("problem")
        if isinstance(problem, str):
            problems.append(problem)
        provider = self.providers.get(target.config.provider or "")
        if provider is not None:
            problem = provider.facts().get("problem")
            if isinstance(problem, str):
                problems.append(problem)
        return problems

    def target_summary(self, target: OpenTarget) -> dict[str, object]:
        """A target for the metadata ops; nothing is contacted (M6, M18)."""
        config = target.config
        data: dict[str, object] = {
            "name": config.name,
            "type": config.type,
            "system": config.system,
            "env": config.env,
            "tier": config.credential.tier,
            "mode": "attended",
            "credential": "provider" if config.provider is not None else "secret",
            "provider": config.provider,
            "ops": list(target.operations),
            "destinations": target.live_destinations(),
            "limits": target.limits.to_json(),
            "pins": self.pin_fact(target),
        }
        facts = target.facts()
        if facts:
            data["facts"] = facts
        problems = self.target_problems(target)
        if problems:
            data["problems"] = problems
        return data

    def problems(self) -> list[str]:
        """Every target problem, for `status`."""
        return [
            f"target {name}: {problem}"
            for name, target in self.targets.items()
            for problem in self.target_problems(target)
        ]

    def login_info(self, target: OpenTarget) -> dict[str, object]:
        """Where the custody login of a `provider:` target lives (`modgudr login`, M18).
        Raises `Refused` for a target without a custody login."""
        config = target.config
        provider = self.providers.get(config.provider or "")
        if provider is None:
            raise Refused(
                "bad_request",
                f"target {config.name} has no credential provider; there is nothing to log in to",
                record=None,
            )
        who = ProviderTarget(config.name, config.system or config.name, config.credential.tier)
        try:
            state_dir = provider.state_dir(who)
        except UpstreamFailure as exc:
            raise Refused("internal", str(exc), record=None) from None
        if state_dir is None:
            raise Refused(
                "bad_request",
                f"target {config.name} uses the {config.credential.tier} tier: the broker uses "
                "your own login, so there is no custody login; log in with the provider's own "
                "tool in your own terminal (for azure-cli: `az login`)",
                record=None,
            )
        return {
            "target": config.name,
            "system": who.system,
            "provider": provider.name,
            "tier": config.credential.tier,
            "stateDir": str(state_dir),
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
            "storeInfo": (
                dict(self.store.facts()) if isinstance(self.store, ReportingStore) else {}
            ),
            "hardening": (
                self.config.hardening.to_json()
                if self.config.hardening is not None
                else NOT_APPLIED
            ),
            "channel": conn.channel.value,
            **self.facts.to_json(),
            "isolation": self._isolation.label,
            "isolationReasons": list(self._isolation.reasons),
            "managedSettings": list(self._isolation.files),
            "auditDegraded": self.audit.degraded,
            "providers": {name: dict(p.facts()) for name, p in self.providers.items()},
            "problems": self.problems(),
            "defaultEnv": {"env": self.policy.default_env, "source": "defaults.env"},
            "environments": [
                {"name": name, "aliases": list(env.aliases)}
                for name, env in self.policy.company.environments.items()
            ],
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
        """Every few seconds: rebind a deleted socket file, re-check isolation, and check the
        session's deadlines (the timer of M7)."""
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
            await self.check_session()

    # --- shutdown ---------------------------------------------------------------------------

    def request_shutdown(self) -> None:
        """For signal handlers: start draining once."""
        if self._shutdown_task is None:
            self._shutdown_task = asyncio.get_running_loop().create_task(self.shutdown())

    async def wait_stopped(self) -> None:
        await self._stopped.wait()

    async def shutdown(self) -> None:
        """DRAINING -> STOPPED: in-flight calls end `cancelled: shutdown`, the sockets are
        unlinked, an unlocked session locks (reason `shutdown`), then `broker.stop`."""
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
        task = self.begin_lock(LockReason.SHUTDOWN)
        if task is not None:
            await task
        await self._lock_finished()
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


def _withheld(exc: Exception, credential: str) -> str:
    """A store's message at unlock, unless it holds the input."""
    text = str(exc)
    if credential and credential in text:
        return "its message held the input and is withheld"
    return text


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
