"""A second test-only connector, `probe`, for the callers' side (step 08).

Its ops have the shapes of the real ones: `query`, `write`, `tables`, `describe`, `count` and
`sample` (the argument names the Python `sql()` wrapper sends) and `argv`, a passthrough op like
kubectl's. Each op echoes what it received as rows (`name`, `value`), so a test sees exactly what
the client sent. Bind values appear in the rows (the connector is a test double); the broker never
audits them.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence

from pydantic import BaseModel, ConfigDict

from modgudr.spi import (
    Action,
    ActionSpec,
    ArgSpec,
    Call,
    Column,
    ConstraintCheck,
    Destination,
    OperationSpec,
    ResultSink,
    Risk,
    Rule,
    RuleSet,
    Secrets,
    TargetContext,
)

TYPE = "probe"
DEFAULT_PORT = 7002

_RISKS: Mapping[str, Risk] = {
    "argv": Risk.READ,
    "query": Risk.READ,
    "write": Risk.WRITE,
    "tables": Risk.READ,
    "describe": Risk.READ,
    "count": Risk.READ,
    "sample": Risk.READ,
}

OPERATIONS = (
    OperationSpec("argv", "echo the arguments as JSON", rows=False, passthrough=True),
    OperationSpec(
        "query",
        "echo the arguments as rows",
        (ArgSpec("sql", help="the statement", from_file=True),),
        params=True,
    ),
    OperationSpec(
        "write",
        "pretend to write",
        (ArgSpec("sql", help="the statement", from_file=True),),
        params=True,
        dry_run=True,
        rows=False,
    ),
    OperationSpec(
        "tables", "list", (ArgSpec("like", help="a pattern", required=False, flag="--like"),)
    ),
    OperationSpec("describe", "describe a table", (ArgSpec("table", help="the table"),)),
    OperationSpec(
        "count",
        "count rows",
        (
            ArgSpec("table", help="the table"),
            ArgSpec("where", help="a condition", required=False),
        ),
        params=True,
    ),
    OperationSpec(
        "sample",
        "sample rows",
        (ArgSpec("table", help="the table"), ArgSpec("n", "int", "how many", required=False)),
    ),
)


class ProbeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str = "probe.example.net"
    port: int = DEFAULT_PORT


class ProbeTarget:
    def __init__(self, name: str, config: ProbeConfig) -> None:
        self.name = name
        self.config = config
        #: Every call that reached the target: (op, args).
        self.calls: list[tuple[str, dict[str, object]]] = []

    @property
    def default_port(self) -> int:
        return DEFAULT_PORT

    def destinations(self) -> frozenset[Destination]:
        return frozenset({Destination(self.config.host, self.config.port)})

    async def execute(self, call: Call, sink: ResultSink) -> None:
        args = dict(call.args)
        self.calls.append((call.op, args))
        if call.op == "argv":
            await sink.text("stdout", json.dumps(args["argv"]))
            return
        if call.op == "write":
            dry = bool(args.get("dryRun", False))
            sink.report(affected_rows=1, committed=not dry, dry_run=dry)
            return
        await sink.header([Column("name", "string"), Column("value", "string")])
        for key in sorted(args):
            value = args[key]
            if key == "params":
                assert isinstance(value, dict)
                for pname in sorted(value):
                    param = value[pname]
                    await sink.row([f"param:{pname}", f"{param['t']}:{param['v']}"])
            else:
                await sink.row([key, str(value)])

    async def aclose(self) -> None:
        return None


class ProbeConnector:
    @property
    def type(self) -> str:
        return TYPE

    @property
    def config_model(self) -> type[BaseModel]:
        return ProbeConfig

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

    def validate(self, call: Call, config: BaseModel, *, max_rows: int) -> None:
        return None

    def classify(self, call: Call, config: BaseModel) -> Action:
        risk = _RISKS.get(call.op)
        if risk is None:
            return Action.unknown(TYPE, f"op {call.op!r} is not a probe op")
        return Action(f"{TYPE}:{call.op}", risk)

    async def open(
        self, name: str, config: BaseModel, secrets: Secrets | None, *, context: TargetContext
    ) -> ProbeTarget:
        if not isinstance(config, ProbeConfig):
            raise TypeError("not a probe config")
        return ProbeTarget(name, config)
