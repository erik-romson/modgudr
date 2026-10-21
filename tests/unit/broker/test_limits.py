"""Effective limits and the non-blocking `maxConcurrent` slots."""

from __future__ import annotations

import pytest

from modgudr.broker.limits import MaxRowsRefused, Slots, defaults_limits, effective_limits
from modgudr.broker.policy.model import Defaults, TargetConfig
from tests.support.echo_connector import EchoConfig

DEFAULTS = Defaults.model_validate({"env": "test", "timeout": "30s", "maxBytes": "2MiB"})


def target(**keys: object) -> TargetConfig:
    return TargetConfig.model_validate(
        {
            "name": "t1",
            "type": "echo",
            "env": "test",
            "credential": {"tier": "dedicated"},
            "secret": "file:t1",
            "config": EchoConfig(),
            **keys,
        }
    )


def test_defaults_apply_without_target_overrides() -> None:
    limits = effective_limits(DEFAULTS, target())
    assert limits == defaults_limits(DEFAULTS)
    assert (limits.timeout, limits.max_rows, limits.max_rows_hard) == (30.0, 500, 50000)
    assert (limits.max_bytes, limits.max_request_bytes, limits.max_concurrent) == (
        2 * 1024**2,
        1024**2,
        4,
    )


def test_a_target_overrides_its_own_limits_but_not_the_hard_ones() -> None:
    limits = effective_limits(
        DEFAULTS, target(timeout="1s", maxRows=10, maxBytes="1KiB", maxConcurrent=2)
    )
    assert (limits.timeout, limits.max_rows, limits.max_bytes, limits.max_concurrent) == (
        1.0,
        10,
        1024,
        2,
    )
    assert (limits.max_rows_hard, limits.max_request_bytes) == (50000, 1024**2)


def test_requested_max_rows_is_refused_above_the_hard_limit_never_clamped() -> None:
    limits = defaults_limits(DEFAULTS)
    assert limits.with_max_rows(None) is limits
    assert limits.with_max_rows(50000).max_rows == 50000
    with pytest.raises(MaxRowsRefused, match="maxRowsHard 50000"):
        limits.with_max_rows(50001)


def test_slots_never_block_and_cannot_be_released_twice() -> None:
    slots = Slots(2)
    assert slots.try_acquire() and slots.try_acquire()
    assert not slots.try_acquire()
    slots.release()
    assert slots.try_acquire()
    slots.release()
    slots.release()
    with pytest.raises(RuntimeError):
        slots.release()
