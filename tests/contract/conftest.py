"""Fixtures of the contract tests: a broker on its own thread, the CLI as a subprocess."""

from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.support.brokerfx import BrokerEnv
from tests.support.brokerthread import BrokerThread, make_caller_env


@pytest.fixture
def served(shortdir: Path) -> Iterator[BrokerThread]:
    """A locked broker with the echo and probe targets."""
    env = make_caller_env(shortdir)
    with BrokerThread(env) as thread:
        yield thread


@pytest.fixture
def unlocked(served: BrokerThread) -> BrokerThread:
    served.unlock()
    return served


@pytest.fixture
def env(served: BrokerThread) -> BrokerEnv:
    return served.env
