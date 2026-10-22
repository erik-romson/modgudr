"""Fixtures of the Oracle integration tests: one disposable Oracle Free container per session,
a driver spy and an unlocked in-process broker (dev mode, `file` store).

The first thing a session does is the stop condition of step 16: Docker answers and the image is
present. When not, every test errors with "Docker or the Oracle Free image is not available (see
Before running B3)". The tests never skip and never pull another image.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest

from modgudr.broker.app import Broker
from tests.support import oraclefx
from tests.support.brokerfx import BrokerEnv, running, unlock
from tests.support.oraclefx import OracleDb, Spy


@pytest.fixture(scope="session")
def db() -> Iterator[OracleDb]:
    try:
        database = oraclefx.start()
    except RuntimeError as exc:
        pytest.fail(str(exc), pytrace=False)
    try:
        yield database
    finally:
        oraclefx.stop(database)


@pytest.fixture
def spy() -> Iterator[Spy]:
    with oraclefx.spying() as s:
        yield s


@pytest.fixture
def env(shortdir: Path, db: OracleDb) -> BrokerEnv:
    return oraclefx.ora_env(shortdir, db)


@pytest.fixture
async def broker(env: BrokerEnv, spy: Spy) -> AsyncIterator[Broker]:
    async with running(env) as b:
        await unlock(env)
        yield b
