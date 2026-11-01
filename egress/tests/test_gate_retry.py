"""Fast retry while the gate is closed (M24): every 20 s for 10 failures, then the interval."""

import asyncio
from collections.abc import Coroutine
from datetime import UTC, datetime
from typing import Any

import pytest

from suckerpot_egress.gate import FAST_RETRY_MAX, FAST_RETRY_S, GateStatus
from tests.helpers import fake_world, gate_for

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def status(open_: bool) -> GateStatus:
    return GateStatus(open_, "ok" if open_ else "tunnel_down", None, NOW)


def test_closed_gate_retries_fast_then_backs_off() -> None:
    gate = gate_for(fake_world())
    interval = float(gate.settings.check_interval_s)
    assert interval > FAST_RETRY_S
    delays = [gate.next_delay(status(False)) for _ in range(FAST_RETRY_MAX + 3)]
    assert delays[:FAST_RETRY_MAX] == [FAST_RETRY_S] * FAST_RETRY_MAX
    assert delays[FAST_RETRY_MAX:] == [interval] * 3


def test_open_resets_the_count() -> None:
    gate = gate_for(fake_world())
    for _ in range(FAST_RETRY_MAX + 2):
        gate.next_delay(status(False))
    assert gate.next_delay(status(True)) == float(gate.settings.check_interval_s)
    assert gate.next_delay(status(False)) == FAST_RETRY_S


def test_request_check_restarts_the_fast_window_and_wakes() -> None:
    gate = gate_for(fake_world())
    for _ in range(FAST_RETRY_MAX + 2):
        gate.next_delay(status(False))
    gate.request_check()
    assert gate._wake.is_set()
    assert gate.next_delay(status(False)) == FAST_RETRY_S


async def test_run_waits_the_fast_delay_when_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    gate = gate_for(fake_world(vpn=None))
    waits: list[float] = []

    async def spy(aw: Coroutine[Any, Any, Any], timeout: float) -> None:  # noqa: ASYNC109
        aw.close()
        waits.append(timeout)
        if len(waits) >= 2:
            raise asyncio.CancelledError
        raise TimeoutError

    monkeypatch.setattr("suckerpot_egress.gate.asyncio.wait_for", spy)
    with pytest.raises(asyncio.CancelledError):
        await gate.run()
    assert waits == [FAST_RETRY_S, FAST_RETRY_S]


async def test_a_request_during_a_check_is_not_lost() -> None:
    gate = gate_for(fake_world())
    calls = 0

    async def check() -> GateStatus:
        nonlocal calls
        calls += 1
        if calls == 1:
            gate.request_check()  # arrives while the check runs
        return status(True)

    gate.check = check  # type: ignore[method-assign]
    task = asyncio.create_task(gate.run())
    await asyncio.sleep(0.05)
    task.cancel()
    assert calls >= 2  # woke at once instead of waiting a full interval
