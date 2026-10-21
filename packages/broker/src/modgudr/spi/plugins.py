"""Plugin interfaces (§9.2, §8.4): what connectors, stores, dialects and providers implement.

The core, not the plugin, does policy, limits, scrubbing, audit and pinning. The plugin classifies;
the core decides (§7.5). A plugin never sees a call the policy refused.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol

from pydantic import BaseModel

from .calls import Call, OperationSpec, ResultSink, TypedParam
from .credentials import (
    Destination,
    MintedToken,
    ResolvedSecret,
    SecretRef,
    TokenRequest,
)
from .risk import Risk
from .rules import Action, ActionSpec, ConstraintCheck, Rule, RuleSet

#: How a dialect's driver binds parameters: by name (Oracle) or by position (`:1…:n`, Snowflake).
BindStyle = Literal["named", "numeric"]


class AuthFailed(Exception):
    """Raised by a connector's login callback when the server refused the credential (M8).

    `final` marks failures that must never be retried (account locked or expired).
    """

    def __init__(self, message: str, *, final: bool = False) -> None:
        super().__init__(message)
        self.final = final


class UpstreamFailure(Exception):
    """Raised by a connector when the backend failed (driver error, process exit ≠ 0).

    The wire code is `upstream` (exit 5). The broker scrubs the message before it leaves.
    """


class BadArguments(Exception):
    """Raised by a connector's `validate` when the arguments of an op are wrong: a bad identifier,
    a bind that matches no placeholder, a number out of range.

    The wire code is `bad_request` (exit 64); the message says what is valid.
    """


class ConstraintBreach(Exception):
    """Raised by a connector when a constraint that is measured after the run is not met.

    The connector has rolled back before it raises. The wire code is `denied`, layer `constraint`
    (exit 2), with `rule` naming the constraint (M5, M14).
    """

    def __init__(self, message: str, *, rule: str) -> None:
        super().__init__(message)
        self.rule = rule


class StoreError(Exception):
    """Raised by a store that cannot resolve a reference (item missing, store unreachable).

    The wire code is `upstream` (exit 5).
    """


class StoreConfigError(Exception):
    """Raised by a store factory that cannot start with its configuration: the broker refuses
    to start (exit 78)."""


class UnlockRefused(Exception):
    """Raised by a store's `unlock` when the credential is wrong (M7).

    The broker records `unlock.failed` without the input and applies its failed-unlock limit. The
    message must not contain the credential.
    """


class StoreSessionInvalid(Exception):
    """Raised by a store whose session was rejected mid-session (a revoked or expired token).

    The broker locks with reason `store-invalid` (M7), and the call ends `locked`, not
    `upstream`.
    """


@dataclass(frozen=True)
class StoreContext:
    """What a store factory gets at broker start."""

    scheme: str
    #: The canonical `MODGUDR_HOME` (M1); store state lives under it (M2).
    home: Path
    #: `modgudr-broker --dev` (argv only, M3).
    dev: bool
    #: The company file's `store.<scheme>` block; the store validates it and refuses unknown keys.
    settings: Mapping[str, object] = field(default_factory=dict[str, object])
    #: `modgudr-broker --secrets-file` (the `file` store).
    secrets_file: Path | None = None


class Secrets(Protocol):
    """The core's secret service as one target sees it (M8)."""

    async def login[T](self, connect: Callable[[ResolvedSecret], Awaitable[T]]) -> T:
        """Run `connect` with the target's secret, single-flight per target.

        Only while a call executes: the secret handed to `connect` has passed the target's
        destination and environment pins. `connect` opens a session or pool and returns it; it
        raises `AuthFailed` when the server refuses the credential, and only then
        (`final=True` for an account that is locked or expired).

        When `connect` raises `AuthFailed`, the service drops its cached value and refetches,
        and retries once only if the value changed; otherwise the target is latched for five
        minutes and later logins fail at once without calling `connect`. Exceptions raised by
        `login` itself (a latched target, a pin refusal, a lock) must propagate unchanged.
        """
        ...


class Target(Protocol):
    """One configured, open target. Owns pools or sessions."""

    @property
    def default_port(self) -> int:
        """The port a destination pin without one means (M8): Oracle 1521, Snowflake 443,
        Kubernetes 443."""
        ...

    def destinations(self) -> frozenset[Destination]:
        """Every host:port the target will contact, for the destination pin (M8)."""
        ...

    async def execute(self, call: Call, sink: ResultSink) -> None: ...

    async def aclose(self) -> None:
        """Close pools and sessions without waiting for work in flight. The broker calls it on
        every lock (M7) and at shutdown, so it may run more than once; after a lock the target
        opens again lazily, through `Secrets.login`, on its next call."""
        ...


class Connector(Protocol):
    """A kind of backend: `sql`, `kubectl`."""

    @property
    def type(self) -> str: ...

    @property
    def config_model(self) -> type[BaseModel]:
        """Validates the target keys the core does not know; must set `extra="forbid"`."""
        ...

    def operations(self) -> Sequence[OperationSpec]: ...

    def actions(self) -> Sequence[ActionSpec]: ...

    def invariants(self) -> Sequence[Rule]:
        """Rules no environment or target can override (§7.3)."""
        ...

    def default_rules(self) -> RuleSet:
        """The plugin defaults: overridden by environment and target rules (§7.3)."""
        ...

    def constraint_checks(self) -> Mapping[str, ConstraintCheck]:
        """The checks of the constraints this connector supports, by constraint name."""
        ...

    def validate(self, call: Call, config: BaseModel, *, max_rows: int) -> None:
        """Check the arguments of an op beyond its `OperationSpec` (M6 step 3): identifiers,
        ranges, bind names against placeholders. `max_rows` is the call's effective `maxRows`.
        Raises `BadArguments`; runs before classification and touches nothing."""
        ...

    def classify(self, call: Call, config: BaseModel) -> Action:
        """Name, risk and facts of a call. Never raises: what it cannot place is `unknown`."""
        ...

    async def open(self, name: str, config: BaseModel, secrets: Secrets | None) -> Target:
        """Build the target without contacting it: nothing is contacted before the decision
        record (M6). `secrets` is None for a `provider:` target."""
        ...


class SecretStore(Protocol):
    """Where secrets come from: `file`, `bws`."""

    @property
    def scheme(self) -> str: ...

    async def unlock(self, credential: str) -> None:
        """Open a store session. Raises `UnlockRefused` for a wrong credential and
        `StoreError` when the store cannot be reached."""
        ...

    async def resolve(self, ref: SecretRef) -> ResolvedSecret:
        """The value and the pins the store holds for it. Raises `StoreError` (`upstream`), or
        `StoreSessionInvalid` when the store rejected its session."""
        ...

    async def lock(self) -> None: ...

    def is_unlocked(self) -> bool: ...


#: What a `modgudr.secret_stores` entry point names: a class or function taking the context.
StoreFactory = Callable[[StoreContext], SecretStore]


class SqlDialect(Protocol):
    """The database-specific part of the `sql` connector: catalogues and binding."""

    @property
    def name(self) -> str: ...

    @property
    def sqlglot_dialect(self) -> str: ...

    @property
    def default_port(self) -> int:
        """The port a pin without one means (M8): Oracle 1521, Snowflake 443."""
        ...

    @property
    def bind_style(self) -> BindStyle: ...

    def function_catalogue(self) -> Mapping[str, Risk]:
        """Function names (normalised) to their class: `UTL_HTTP.*` is admin (§7.2)."""
        ...

    def object_catalogue(self) -> Mapping[str, Risk]:
        """Object names (normalised) to their class: `DBA_USERS` is secret (§7.2)."""
        ...

    def bind_value(self, param: TypedParam) -> object:
        """A typed parameter as the driver takes it."""
        ...

    def tables_query(self) -> str:
        """The `tables` op's statement, with one named bind `:pattern` (a LIKE pattern)."""
        ...

    def describe_query(self) -> str:
        """The `describe` op's statement; `{table}` stands for the validated identifier."""
        ...

    def sample_query(self) -> str:
        """The `sample` op's statement; `{table}` and `{n}` stand for the validated identifier
        and row count."""
        ...


class CredentialProvider(Protocol):
    """Mints short-lived tokens for `provider:` targets (§8.4): `azure-cli`."""

    @property
    def name(self) -> str: ...

    async def mint(self, request: TokenRequest) -> MintedToken: ...

    async def lock(self) -> None:
        """Drop every cached token and endpoint (M7)."""
        ...
