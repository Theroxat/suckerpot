"""The container healthcheck against a running sensor."""

from __future__ import annotations

import asyncio

from conftest import Harness

from docker_sensor import healthcheck


async def test_healthcheck_ok_and_quiet(harness: Harness, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    harness.sensor.cfg  # noqa: B018
    monkeypatch.setenv("DOCKER_PORT", str(harness.port))
    assert await asyncio.to_thread(healthcheck.main) == 0


async def test_healthcheck_fails_when_nothing_listens(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("DOCKER_PORT", "1")
    assert await asyncio.to_thread(healthcheck.main) == 1
