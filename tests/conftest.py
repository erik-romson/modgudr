import os
from pathlib import Path

import pytest

from modgudr.client.agent import setup
from tests.support.fakebin import fakebin as fakebin
from tests.support.sandbox import pytest_report_header as pytest_report_header
from tests.support.sandbox import pytest_runtest_makereport as pytest_runtest_makereport
from tests.support.shortdir import shortdir as shortdir

_OPT_IN = {
    "kind": "MODGUDR_TEST_KIND",
    "snowflake_live": "MODGUDR_SF_LIVE",
}


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    for marker, variable in _OPT_IN.items():
        if os.environ.get(variable) == "1":
            continue
        skip = pytest.mark.skip(reason=f"set {variable}=1 to run {marker} tests")
        for item in items:
            if marker in item.keywords:
                item.add_marker(skip)


@pytest.fixture(autouse=True)
def no_installed_dropin(monkeypatch: pytest.MonkeyPatch) -> None:
    """No test reads the real system drop-in: the installed file does not exist."""

    def absent(platform: str) -> Path:
        return Path("/nonexistent/modgudr-test/50-modgudr.json")

    monkeypatch.setattr(setup, "installed_dropin", absent)
