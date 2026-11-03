from __future__ import annotations

import json

from hubproxy import healthcheck
from tests.helpers import ALLOW, exchange, running


async def test_status_reports_mode_and_allow() -> None:
    async with running() as (_, _, _, control):
        raw = await exchange(control, b"GET /status HTTP/1.1\r\nHost: hubproxy\r\n\r\n")
        head, _, body = raw.partition(b"\r\n\r\n")
        assert head.startswith(b"HTTP/1.1 200 OK") or b" 200 " in head.split(b"\r\n")[0]
        assert json.loads(body) == {"mode": "direct", "allow": [f"{ALLOW}:443"], "ok": True}


async def test_control_refuses_everything_else() -> None:
    async with running() as (_, _, _, control):
        post = await exchange(control, b"POST /status HTTP/1.1\r\nHost: x\r\n\r\n")
        assert b" 405 " in post.split(b"\r\n")[0]
        other = await exchange(control, b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
        assert b" 404 " in other.split(b"\r\n")[0]
        junk = await exchange(control, b"nonsense\r\n\r\n")
        assert b" 400 " in junk.split(b"\r\n")[0]


async def test_healthcheck_succeeds_and_fails() -> None:
    import asyncio

    async with running() as (_, _, _, control):
        assert await asyncio.to_thread(healthcheck.check, control) is True
    assert healthcheck.check(1) is False
