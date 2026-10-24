"""Seeds rows directly and reads them through the API (needs POSTGRES_* and a migrated DB)."""

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import text
from suckerpot_db import EventRow, SessionRow, create_engine, create_session_factory

from api.main import create_app

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    engine = create_engine(pool_size=2)
    factory = create_session_factory(engine)
    now = datetime.now(UTC)
    async with engine.begin() as conn:
        await conn.execute(text("TRUNCATE events, sessions"))
    async with factory() as s, s.begin():
        for i, ip in enumerate(["203.0.113.7", "2001:db8::1"]):
            sid = f"api-it-{i}"
            s.add(
                SessionRow(
                    session_id=sid,
                    sensor="ssh",
                    src_ip=ip,
                    src_port=1,
                    dst_port=2,
                    started_at=now - timedelta(minutes=i),
                    last_event_at=now,
                )
            )
            s.add(
                EventRow(
                    ts=now,
                    sensor="ssh",
                    session_id=sid,
                    type="connect",
                    src_ip=ip,
                    src_port=1,
                    dst_port=2,
                    data={},
                )
            )
    app = create_app(factory)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t"
        ) as c:
            yield c
    await engine.dispose()


async def test_inet_roundtrip(client: httpx.AsyncClient) -> None:
    items = (await client.get("/api/v1/sessions")).json()["items"]
    assert [i["src_ip"] for i in items] == ["203.0.113.7", "2001:db8::1"]
    ev = (await client.get("/api/v1/sessions/api-it-1/events")).json()["items"]
    assert ev[0]["src_ip"] == "2001:db8::1"
    by_ip = (await client.get("/api/v1/sessions", params={"src_ip": "2001:db8::1"})).json()
    assert [i["session_id"] for i in by_ip["items"]] == ["api-it-1"]
