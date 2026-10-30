"""The container healthcheck against a running sensor."""

from __future__ import annotations

import asyncio

import pytest
from conftest import Harness

from synology_sensor import healthcheck


async def test_healthcheck_ok_and_quiet(harness: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SYNOLOGY_HTTP_PORT", str(harness.port))
    assert await asyncio.to_thread(healthcheck.main) == 0


async def test_healthcheck_fails_when_nothing_listens(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SYNOLOGY_HTTP_PORT", "1")
    assert await asyncio.to_thread(healthcheck.main) == 1
