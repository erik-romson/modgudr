import os

import pytest

from tests.support.fakebin import fakebin as fakebin
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
