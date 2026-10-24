"""WebSocket backfill + live broadcast against a real, migrated TimescaleDB."""

import asyncio
import os
from datetime import UTC, datetime

import pytest
from sqlalchemy import text
from starlette.testclient import TestClient
from suckerpot_db import EventRow, create_engine, create_session_factory

from api.main import create_app

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]


async def _seed(rows: list[tuple[str, str, dict[str, object]]], truncate: bool = False) -> None:
    engine = create_engine(pool_size=1)
    factory = create_session_factory(engine)
    try:
        if truncate:
            async with engine.begin() as conn:
                await conn.execute(text("TRUNCATE events, sessions"))
        async with factory() as s, s.begin():
            for etype, ip, data in rows:
                s.add(
                    EventRow(
                        ts=datetime.now(UTC),
                        sensor="ssh",
                        session_id="live-1",
                        type=etype,
                        src_ip=ip,
                        src_port=1,
                        dst_port=2,
                        data=data,
                    )
                )
    finally:
        await engine.dispose()


def test_backfill_then_live_event() -> None:
    asyncio.run(
        _seed(
            [
                ("connect", "203.0.113.7", {}),
                (
                    "login_attempt",
                    "2001:db8::1",
                    {"username": "root", "password": "123456", "success": False},
                ),
            ],
            truncate=True,
        )
    )
    app = create_app(None)
    with TestClient(app) as client:
        recent = client.get("/api/v1/events/recent", params={"limit": 10}).json()["items"]
        assert [e["type"] for e in recent] == ["login_attempt", "connect"]
        with client.websocket_connect("/api/v1/live") as ws:
            first = ws.receive_json()
            assert first["kind"] == "backfill"
            events = first["events"]
            assert [e["summary"] for e in events] == ["login root/123456 failed", "connected"]
            assert events[0]["src_ip"] == "2001:db8::1"
            assert events[0]["country"] is None and events[0]["tags"] == []
            asyncio.run(_seed([("command", "203.0.113.9", {"input": "uname -a"})]))
            got_event = got_stats = False
            for _ in range(12):
                msg = ws.receive_json()
                if msg["kind"] == "event":
                    assert msg["event"]["summary"] == "ran `uname -a`"
                    assert msg["event"]["id"] > events[0]["id"]
                    got_event = True
                elif msg["kind"] == "stats":
                    stats = msg["stats"]
                    assert stats["window_seconds"] == 60
                    assert stats["by_sensor"]["ssh"]["events"] >= 2
                    got_stats = True
                if got_event and got_stats:
                    break
            assert got_event and got_stats
            ws.send_text("ping")
            for _ in range(12):
                if ws.receive_json()["kind"] == "pong":
                    break
            else:
                pytest.fail("no pong")
