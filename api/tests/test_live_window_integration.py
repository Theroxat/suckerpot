"""GET /api/v1/live/window against a real, migrated TimescaleDB."""

import asyncio
import os
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from starlette.testclient import TestClient
from suckerpot_db import EventRow, create_engine, create_session_factory

from api.main import create_app

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

# (minutes ago, sensor, ip, country, asn, benign)
ROWS: list[tuple[float, str, str, str | None, int | None, bool | None]] = [
    (0.2, "ssh", "203.0.113.7", "NL", 64500, None),
    (0.5, "ssh", "203.0.113.7", "NL", 64500, None),
    (3, "web", "203.0.113.8", "NL", 64500, None),
    (12, "telnet", "198.51.100.4", "BR", 64501, None),  # older than the old 6-minute buffer
    (14, "web", "198.51.100.5", None, None, None),
    (14.5, "web", "198.51.100.6", "DE", 64502, True),  # research scanner
    (20, "ssh", "192.0.2.9", "FR", 64503, None),  # outside the 15-minute window
]


async def _seed() -> None:
    engine = create_engine(pool_size=1)
    factory = create_session_factory(engine)
    now = datetime.now(UTC)
    try:
        async with engine.begin() as conn:
            await conn.execute(text("TRUNCATE events, sessions"))
        async with factory() as s, s.begin():
            for ago, sensor, ip, country, asn, benign in ROWS:
                s.add(
                    EventRow(
                        ts=now - timedelta(minutes=ago),
                        sensor=sensor,
                        session_id=f"w-{ip}",
                        type="connect",
                        src_ip=ip,
                        src_port=1,
                        dst_port=2,
                        data={},
                        country=country,
                        asn=asn,
                        org=f"Net {asn}" if asn else None,
                        benign=benign,
                    )
                )
    finally:
        await engine.dispose()


def test_window_aggregates_the_whole_window() -> None:
    asyncio.run(_seed())
    with TestClient(create_app(None)) as client:
        r = client.get("/api/v1/live/window")
        assert r.status_code == 200, r.text
        w = r.json()
        assert w["window_minutes"] == 15
        assert w["events"] == 5  # research scanner and the old row are left out
        assert w["unlocated"] == 1
        assert w["events_last_minute"] == 2 and w["sessions_last_minute"] == 1
        assert w["by_sensor"] == {"ssh": 2, "web": 2, "telnet": 1}
        assert w["last_minute_by_sensor"]["ssh"] == {"events": 2, "sessions": 1}
        assert w["last_event_id"] > 0
        by_country = {c["country"]: c for c in w["countries"]}
        assert set(by_country) == {"NL", "BR"}
        assert by_country["NL"]["events"] == 3 and by_country["NL"]["ips"] == 2
        assert by_country["NL"]["top_ip"] == "203.0.113.7"
        assert by_country["NL"]["by_sensor"] == {"ssh": 2, "web": 1}
        assert w["addresses"][0]["ip"] == "203.0.113.7" and w["addresses"][0]["events"] == 2
        assert [n["asn"] for n in w["networks"]] == [64500, 64501]
        assert w["networks"][0]["ips"] == 2

        # A repeat inside a few seconds is served from the cache; other variants are not.
        assert client.get("/api/v1/live/window").json()["as_of"] == w["as_of"]

        # Research scanners come back with include_benign.
        both = client.get("/api/v1/live/window", params={"include_benign": "true"}).json()
        assert both["events"] == 6
        assert {c["country"] for c in both["countries"]} == {"NL", "BR", "DE"}

        # The sensor filter and the window length.
        only = client.get("/api/v1/live/window", params={"sensor": "web,telnet"}).json()
        assert only["events"] == 3 and only["by_sensor"] == {"web": 2, "telnet": 1}
        wide = client.get("/api/v1/live/window", params={"minutes": 30}).json()
        assert wide["events"] == 6 and "FR" in {c["country"] for c in wide["countries"]}
        short = client.get("/api/v1/live/window", params={"minutes": 1}).json()
        assert short["events"] == 2


def test_window_bounds_are_validated() -> None:
    with TestClient(create_app(None)) as client:
        for minutes in (0, 61):
            r = client.get("/api/v1/live/window", params={"minutes": minutes})
            assert r.status_code == 422
        assert client.get("/api/v1/live/window", params={"sensor": "ftp"}).status_code == 422
