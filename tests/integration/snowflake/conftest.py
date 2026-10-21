"""Fixtures of the Snowflake integration tests: fakesnow, a spy, an unlocked in-process broker."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest

from modgudr.broker.app import Broker
from tests.support.brokerfx import BrokerEnv, running, unlock
from tests.support.snowflakefx import Spy, fake_snowflake, sf_env


@pytest.fixture
def spy() -> Iterator[Spy]:
    with fake_snowflake() as s:
        yield s


@pytest.fixture
def env(shortdir: Path) -> BrokerEnv:
    return sf_env(shortdir)


@pytest.fixture
async def broker(env: BrokerEnv, spy: Spy) -> AsyncIterator[Broker]:
    async with running(env) as b:
        await unlock(env)
        yield b
