"""Analytics endpoints against a real TimescaleDB with a small hand-checked dataset."""

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

import httpx
import pytest
from analytics_seed import api_engine, owner_engine, small_dataset
from suckerpot_db import create_session_factory

from api.main import create_app

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

BASE = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
WIN = {
    "since": (BASE - timedelta(hours=6)).isoformat(),
    "until": (BASE + timedelta(hours=1)).isoformat(),
}


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    async with owner_engine() as owner:
        await small_dataset(BASE).write(owner)
    engine = api_engine()
    app = create_app(create_session_factory(engine), enable_live=False)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t/api/v1"
        ) as c:
            yield c
    await engine.dispose()


async def get(c: httpx.AsyncClient, path: str, **params: str | int | None) -> dict[str, Any]:
    r = await c.get(path, params={k: v for k, v in params.items() if v is not None})
    assert r.status_code == 200, r.text
    assert r.headers["cache-control"] == "no-store"
    body: dict[str, Any] = r.json()
    return body


async def test_timeseries_zero_filled(client: httpx.AsyncClient) -> None:
    body = await get(client, "/stats/timeseries", bucket="1h", **WIN)
    pts = body["points"]
    assert body["bucket"] == "1h"
    assert len(pts) == 7
    by_ts = {p["ts"].replace("+00:00", "Z"): p for p in pts}
    hour = (BASE - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    assert by_ts[hour]["events"] == {
        "ssh": 8,
        "telnet": 0,
        "web": 4,
        "rdp": 0,
        "redis": 0,
        "docker": 0,
        "mysql": 0,
        "adb": 0,
        "mssql": 0,
        "smb": 0,
        "sip": 0,
    }
    assert by_ts[hour]["sessions"] == {
        "ssh": 1,
        "telnet": 0,
        "web": 1,
        "rdp": 0,
        "redis": 0,
        "docker": 0,
        "mysql": 0,
        "adb": 0,
        "mssql": 0,
        "smb": 0,
        "sip": 0,
    }
    five = (BASE - timedelta(hours=5)).isoformat().replace("+00:00", "Z")
    assert by_ts[five]["events"]["ssh"] == 3
    assert sum(sum(p["events"].values()) for p in pts) == 15
    assert sum(sum(p["sessions"].values()) for p in pts) == 3


async def test_timeseries_sensor_filter_and_buckets(client: httpx.AsyncClient) -> None:
    body = await get(client, "/stats/timeseries", bucket="5m", sensor="web", **WIN)
    assert len(body["points"]) == 7 * 12
    assert sum(p["events"]["web"] for p in body["points"]) == 4
    assert sum(p["events"]["ssh"] for p in body["points"]) == 0
    day = await get(client, "/stats/timeseries", bucket="1d", **WIN)
    assert sum(sum(p["events"].values()) for p in day["points"]) == 15
    assert all(p["ts"].endswith("Z") or p["ts"].endswith("+00:00") for p in day["points"])


async def test_timeseries_default_window_is_24h(client: httpx.AsyncClient) -> None:
    body = await get(client, "/stats/timeseries")
    assert 24 <= len(body["points"]) <= 25
    assert sum(sum(p["events"].values()) for p in body["points"]) == 15


@pytest.mark.parametrize(
    ("field", "expected", "total"),
    [
        ("username", [("root", 3), ("admin", 1)], 4),
        ("password", [("admin", 2), ("123456", 1), ("toor", 1)], 4),
        ("command", [("uname -a", 2)], 2),
        (
            "url",
            [("/index.php?a=1", 2), ("http://192.0.2.50/x.sh", 1), ("http://192.0.2.50/y.sh", 1)],
            4,
        ),
        ("user_agent", [("curl/8.5", 2)], 2),
        ("country", [("NL", 2), ("US", 1)], 3),
        ("asn", [("14061", 2), ("15169", 1)], 3),
        ("org", [("DigitalOcean, LLC", 2), ("Example Cloud", 1)], 3),
        ("src_ip", [("203.0.113.7", 2), ("198.51.100.9", 1)], 3),
        ("tag", [("brute-force", 1), ("crypto-miner", 1), ("php2shell", 1), ("recon", 1)], 4),
    ],
)
async def test_top_fields(
    client: httpx.AsyncClient, field: str, expected: list[tuple[str, int]], total: int
) -> None:
    body = await get(client, "/stats/top", field=field, **WIN)
    assert body["field"] == field
    assert body["total"] == total
    assert [(i["value"], i["count"]) for i in body["items"]] == expected
    first = body["items"][0]
    assert first["share"] == pytest.approx(first["count"] / total, abs=1e-3)
    assert first["first_seen"] <= first["last_seen"]


async def test_top_limit_sensor_and_empty(client: httpx.AsyncClient) -> None:
    body = await get(client, "/stats/top", field="username", limit=1, **WIN)
    assert len(body["items"]) == 1
    assert body["total"] == 4  # total covers all values, not just the page
    body = await get(client, "/stats/top", field="username", sensor="web", **WIN)
    assert body == {"field": "username", "total": 0, "items": []}


async def test_heatmap(client: httpx.AsyncClient) -> None:
    body = await get(client, "/stats/heatmap", **WIN)
    cells = body["cells"]
    assert len(cells) == 168
    assert {(c["dow"], c["hour"]) for c in cells} == {(d, h) for d in range(7) for h in range(24)}
    assert sum(c["events"] for c in cells) == 15
    t = BASE - timedelta(minutes=30)
    cell = next(c for c in cells if (c["dow"], c["hour"]) == (t.weekday(), t.hour))
    assert cell["events"] >= 8


async def test_attackers_default_order_and_shape(client: httpx.AsyncClient) -> None:
    body = await get(client, "/attackers")
    assert body["next_cursor"] is None
    assert [a["ip"] for a in body["items"]] == ["198.51.100.9", "203.0.113.7", "2001:db8::5"]
    a = body["items"][1]
    assert a["sessions"] == 2
    assert a["events"] == 11
    assert a["sensors"] == ["ssh"]
    assert (a["login_attempts"], a["login_success"], a["commands"], a["downloads"]) == (4, 1, 2, 1)
    assert (a["country"], a["city"], a["asn"], a["org"]) == (
        "NL",
        "Amsterdam",
        14061,
        "DigitalOcean, LLC",
    )
    assert a["abuse_score"] == 80
    assert a["known_scanner"] is False
    assert a["tags"] == ["brute-force", "crypto-miner", "recon"]
    assert a["first_seen"] < a["last_seen"]


@pytest.mark.parametrize("sort", ["last_seen", "first_seen", "sessions", "events"])
@pytest.mark.parametrize("order", ["asc", "desc"])
async def test_attackers_keyset_pagination_matches_full_list(
    client: httpx.AsyncClient, sort: str, order: str
) -> None:
    full = [a["ip"] for a in (await get(client, "/attackers", sort=sort, order=order))["items"]]
    assert len(full) == 3
    paged: list[str] = []
    cursor = None
    for _ in range(5):
        body = await get(client, "/attackers", sort=sort, order=order, limit=1, cursor=cursor)
        paged += [a["ip"] for a in body["items"]]
        cursor = body["next_cursor"]
        if cursor is None:
            break
    assert paged == full


async def test_attackers_sort_semantics(client: httpx.AsyncClient) -> None:

    def ips(b: dict[str, Any]) -> list[str]:
        return [a["ip"] for a in b["items"]]

    assert ips(await get(client, "/attackers", sort="sessions"))[0] == "203.0.113.7"
    assert ips(await get(client, "/attackers", sort="events", order="asc"))[-1] == "203.0.113.7"
    assert ips(await get(client, "/attackers", sort="first_seen", order="asc"))[0] == "2001:db8::5"


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ({"country": "nl"}, ["203.0.113.7", "2001:db8::5"]),
        ({"asn": 15169}, ["198.51.100.9"]),
        ({"sensor": "web"}, ["198.51.100.9"]),
        ({"sensor": "telnet"}, ["2001:db8::5"]),
        ({"tag": "mirai"}, ["2001:db8::5"]),
        ({"tag": "nope"}, []),
        ({"q": "203."}, ["203.0.113.7"]),
        ({"q": "2001:"}, ["2001:db8::5"]),
        ({"q": "1"}, ["198.51.100.9"]),
    ],
)
async def test_attackers_filters(
    client: httpx.AsyncClient, params: dict[str, str | int], expected: list[str]
) -> None:
    body = await get(client, "/attackers", sort="last_seen", **params)
    assert [a["ip"] for a in body["items"]] == expected


async def test_attacker_filters_keep_full_stats(client: httpx.AsyncClient) -> None:
    body = await get(client, "/attackers", tag="crypto-miner")
    assert body["items"][0]["sessions"] == 2  # tag only selects the attacker


async def test_attacker_detail(client: httpx.AsyncClient) -> None:
    body = await get(client, "/attackers/203.0.113.7")
    assert body["attacker"]["ip"] == "203.0.113.7"
    assert [s["session_id"] for s in body["recent_sessions"]] == ["a1", "a2"]
    assert body["recent_sessions"][0]["src_ip"] == "203.0.113.7"
    assert body["top_usernames"][:2] == [
        {"value": "root", "count": 3},
        {"value": "admin", "count": 1},
    ]
    assert body["top_commands"] == [{"value": "uname -a", "count": 2}]
    tl = body["timeline"]
    assert len(tl) == 30
    assert tl[-1]["day"] == datetime.now(UTC).date().isoformat()
    assert sum(d["events"] for d in tl) == 11
    v6 = await get(client, "/attackers/" + quote("2001:DB8:0::5"))
    assert v6["attacker"]["ip"] == "2001:db8::5"


async def test_attacker_detail_404(client: httpx.AsyncClient) -> None:
    r = await client.get("/attackers/192.0.2.250")
    assert r.status_code == 404


async def test_asns(client: httpx.AsyncClient) -> None:
    body = await get(client, "/asns")
    top = body["items"][0]
    assert top["asn"] == 14061
    assert (top["ips"], top["sessions"], top["events"]) == (2, 3, 14)
    assert (top["org"], top["country"]) == ("DigitalOcean, LLC", "NL")
    assert [i["asn"] for i in body["items"]] == [14061, 15169]
    recent = await get(client, "/asns", since=(BASE - timedelta(days=1)).isoformat())
    assert recent["items"][0]["sessions"] == 2
    by_ips = await get(client, "/asns", sort="ips", limit=1)
    assert [i["asn"] for i in by_ips["items"]] == [14061]


async def test_hostile_strings_are_truncated(client: httpx.AsyncClient) -> None:
    from sqlalchemy import insert
    from suckerpot_db import EventRow

    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            insert(EventRow),
            [
                {
                    "ts": BASE - timedelta(minutes=1),
                    "sensor": "ssh",
                    "session_id": "a1",
                    "type": "command",
                    "src_ip": "203.0.113.7",
                    "src_port": 1,
                    "dst_port": 2,
                    "data": {"input": "A" * 5000 + "'; DROP TABLE events;--"},
                }
            ],
        )
    body = await get(client, "/stats/top", field="command", **WIN)
    longest = max(len(i["value"]) for i in body["items"])
    assert longest == 256


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ({"username": "admin"}, ["a1"]),
        ({"username": "root"}, ["a1", "a2", "c1"]),
        ({"password": "toor"}, ["a2"]),
        ({"command": "uname -a"}, ["a1"]),
        ({"url": "/index.php?a=1"}, ["b1"]),
        ({"url": "http://192.0.2.50/x.sh"}, ["a1"]),
        ({"url": "http://192.0.2.50/y.sh"}, ["b1"]),
        ({"username": "root", "password": "toor"}, ["a2"]),
        ({"username": "root", "country": "NL", "command": "uname -a"}, ["a1"]),
        ({"username": "nobody"}, []),
        ({"command": "uname"}, []),  # exact match only
        ({"username": "uname -a"}, []),  # right value, wrong event type
    ],
)
async def test_sessions_value_filters(
    client: httpx.AsyncClient, params: dict[str, str], expected: list[str]
) -> None:
    body = await get(client, "/sessions", **params)
    assert sorted(s["session_id"] for s in body["items"]) == expected


@pytest.mark.parametrize("form", ["repeated", "comma"])
async def test_multi_sensor_filter(client: httpx.AsyncClient, form: str) -> None:
    sensors: list[tuple[str, str | int | float | bool | None]] = (
        [("sensor", "ssh"), ("sensor", "web")] if form == "repeated" else [("sensor", "ssh,web")]
    )
    since, until = WIN["since"], WIN["until"]
    r = await client.get("/stats/timeseries", params=[*sensors, ("since", since), ("until", until)])
    assert r.status_code == 200, r.text
    pts = r.json()["points"]
    one_ssh = await get(client, "/stats/timeseries", sensor="ssh", **WIN)
    one_web = await get(client, "/stats/timeseries", sensor="web", **WIN)
    expected = sum(p["events"]["ssh"] for p in one_ssh["points"]) + sum(
        p["events"]["web"] for p in one_web["points"]
    )
    assert expected > 0
    assert sum(p["events"]["ssh"] + p["events"]["web"] for p in pts) == expected
    assert sum(sum(p["events"].values()) for p in pts) == expected  # nothing from other sensors
    single = await get(client, "/stats/timeseries", sensor="web", **WIN)
    assert sum(p["events"]["web"] for p in single["points"]) == 4
    for path in ("/sessions", "/attackers"):
        both = await client.get(path, params=sensors)
        one = await client.get(path, params=[("sensor", "web")])
        assert both.status_code == 200 and one.status_code == 200
        assert len(both.json()["items"]) >= len(one.json()["items"])
    top = await client.get(
        "/stats/top", params=[*sensors, ("field", "username"), ("since", since), ("until", until)]
    )
    heat = await client.get("/stats/heatmap", params=[*sensors, ("since", since), ("until", until)])
    assert top.status_code == 200 and heat.status_code == 200
    assert (await client.get("/sessions", params=[("sensor", "ftp")])).status_code == 422
