"""Plugin interfaces (§9.2, §8.4): what connectors, stores, dialects and providers implement.

The core, not the plugin, does policy, limits, scrubbing, audit and pinning. The plugin classifies;
the core decides (§7.5). A plugin never sees a call the policy refused.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Literal, Protocol

from pydantic import BaseModel

from .calls import Call, OperationSpec, ResultSink, TypedParam
from .credentials import Destination, MintedToken, ResolvedSecret, SecretRef, TokenRequest
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


class Secrets(Protocol):
    """The core's secret service as one target sees it (M8)."""

    async def login[T](self, connect: Callable[[ResolvedSecret], Awaitable[T]]) -> T:
        """Run `connect` with the target's secret, single-flight per target.

        When `connect` raises `AuthFailed`, the service drops its cached value and refetches,
        and retries once only if the value changed; otherwise the target is latched.
        """
        ...


class Target(Protocol):
    """One configured, open target. Owns pools or sessions."""

    def destinations(self) -> frozenset[Destination]:
        """Every host:port the target will contact, for the destination pin (M8)."""
        ...

    async def execute(self, call: Call, sink: ResultSink) -> None: ...

    async def aclose(self) -> None: ...


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

    async def unlock(self, credential: str) -> None: ...

    async def resolve(self, ref: SecretRef) -> ResolvedSecret:
        """The value and the pins the store holds for it."""
        ...

    async def lock(self) -> None: ...

    def is_unlocked(self) -> bool: ...


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

    def tables_query(self) -> str | None: ...

    def describe_query(self) -> str | None: ...


class CredentialProvider(Protocol):
    """Mints short-lived tokens for `provider:` targets (§8.4): `azure-cli`."""

    @property
    def name(self) -> str: ...

    async def mint(self, request: TokenRequest) -> MintedToken: ...

    async def lock(self) -> None:
        """Drop every cached token and endpoint (M7)."""
        ...
