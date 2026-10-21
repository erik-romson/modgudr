"""A test-only connector, registered programmatically and never shipped.

Ops: `echo` (read), `put` (write), `slow` (sleeps in steps, emitting rows), `boom` (raises),
`leak` (an error containing the secret) and `auth` (an auth failure on the first open).
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence

from pydantic import BaseModel, ConfigDict

from modgudr.spi import (
    Action,
    ActionSpec,
    ArgSpec,
    AuthFailed,
    Call,
    Column,
    ConstraintCheck,
    Destination,
    OperationSpec,
    ResolvedSecret,
    ResultSink,
    Risk,
    Rule,
    RuleSet,
    Secrets,
    UpstreamFailure,
)

TYPE = "echo"

_RISKS: Mapping[str, Risk] = {
    "echo": Risk.READ,
    "put": Risk.WRITE,
    "slow": Risk.READ,
    "boom": Risk.READ,
    "leak": Risk.READ,
    "auth": Risk.READ,
}

OPERATIONS = (
    OperationSpec("echo", "return the text as one row", (ArgSpec("text", help="the text"),)),
    OperationSpec(
        "put",
        "pretend to write a value",
        (
            ArgSpec("value", help="the value"),
            ArgSpec("delayMs", "int", "wait before the commit", required=False, flag="--delay-ms"),
        ),
        dry_run=True,
        rows=False,
    ),
    OperationSpec(
        "slow",
        "emit rows with a pause before each",
        (
            ArgSpec("rows", "int", "how many rows", required=False, flag="--rows"),
            ArgSpec("delayMs", "int", "pause per row", required=False, flag="--delay-ms"),
        ),
    ),
    OperationSpec("boom", "raise an exception"),
    OperationSpec("leak", "fail with an error that contains the secret"),
    OperationSpec("auth", "log in; the first open of a target fails authentication"),
)


class EchoConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str = "echo.example.net"
    port: int = 7000


class EchoTarget:
    def __init__(self, name: str, config: EchoConfig, secrets: Secrets | None) -> None:
        self.name = name
        self.config = config
        self.secrets = secrets
        #: Logins through `secrets.login`, for the `auth` op.
        self.opens = 0
        self.executed: list[str] = []
        self.cancelled: list[str] = []
        self.closed = False

    def destinations(self) -> frozenset[Destination]:
        return frozenset({Destination(self.config.host, self.config.port)})

    async def execute(self, call: Call, sink: ResultSink) -> None:
        self.executed.append(call.op)
        try:
            await getattr(self, f"_op_{call.op}")(call, sink)
        except asyncio.CancelledError:
            self.cancelled.append(call.op)
            raise

    async def _op_echo(self, call: Call, sink: ResultSink) -> None:
        await sink.header([Column("text", "string")])
        await sink.row([str(call.args["text"])])

    async def _op_put(self, call: Call, sink: ResultSink) -> None:
        dry_run = bool(call.args.get("dryRun", False))
        sink.report(affected_rows=1, committed=False, dry_run=dry_run)
        delay = call.args.get("delayMs", 0)
        await asyncio.sleep((delay if isinstance(delay, int) else 0) / 1000)
        if not dry_run:
            sink.report(committed=True)

    async def _op_slow(self, call: Call, sink: ResultSink) -> None:
        rows = call.args.get("rows", 10)
        delay = call.args.get("delayMs", 300)
        count = rows if isinstance(rows, int) else 10
        pause = (delay if isinstance(delay, int) else 300) / 1000
        await sink.header([Column("i", "integer")])
        for i in range(count):
            await asyncio.sleep(pause)
            await sink.row([str(i)])

    async def _op_boom(self, call: Call, sink: ResultSink) -> None:
        raise RuntimeError("boom")

    async def _op_leak(self, call: Call, sink: ResultSink) -> None:
        if self.secrets is None:
            raise UpstreamFailure("no secret")

        async def connect(secret: ResolvedSecret) -> None:
            raise UpstreamFailure(
                f"connection to {self.config.host} refused for password {secret.value}"
            )

        await self.secrets.login(connect)

    async def _op_auth(self, call: Call, sink: ResultSink) -> None:
        if self.secrets is None:
            raise UpstreamFailure("no secret")

        async def connect(secret: ResolvedSecret) -> str:
            self.opens += 1
            if self.opens == 1:
                raise AuthFailed("invalid username or password")
            return "session"

        await self.secrets.login(connect)
        await sink.header([Column("opens", "integer")])
        await sink.row([str(self.opens)])

    async def aclose(self) -> None:
        self.closed = True


class EchoConnector:
    """The test connector. `targets` holds every target it opened, for assertions."""

    def __init__(self) -> None:
        self.targets: dict[str, EchoTarget] = {}

    @property
    def type(self) -> str:
        return TYPE

    @property
    def config_model(self) -> type[BaseModel]:
        return EchoConfig

    def operations(self) -> Sequence[OperationSpec]:
        return OPERATIONS

    def actions(self) -> Sequence[ActionSpec]:
        return tuple(ActionSpec(name, risk) for name, risk in _RISKS.items())

    def invariants(self) -> Sequence[Rule]:
        return ()

    def default_rules(self) -> RuleSet:
        return RuleSet(allow=(Rule("read"),))

    def constraint_checks(self) -> Mapping[str, ConstraintCheck]:
        return {}

    def classify(self, call: Call, config: BaseModel) -> Action:
        risk = _RISKS.get(call.op)
        if risk is None:
            return Action.unknown(TYPE, f"op {call.op!r} is not an echo op")
        return Action(f"{TYPE}:{call.op}", risk)

    async def open(self, name: str, config: BaseModel, secrets: Secrets | None) -> EchoTarget:
        if not isinstance(config, EchoConfig):
            raise TypeError("not an echo config")
        target = EchoTarget(name, config, secrets)
        self.targets[name] = target
        return target
