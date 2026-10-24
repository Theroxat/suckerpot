"""Performance smoke test: ~25k events / 3000 sessions, every endpoint under 300 ms."""

import os
import statistics
import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import pytest_asyncio
from analytics_seed import api_engine, big_dataset, owner_engine
from suckerpot_db import create_session_factory

from api.main import create_app

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

BUDGET_S = 0.3
BASE = datetime.now(UTC)
SINCE = (BASE - timedelta(days=7)).isoformat()
UNTIL = (BASE + timedelta(minutes=1)).isoformat()
WIN = {"since": SINCE, "until": UNTIL}


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def client() -> AsyncIterator[httpx.AsyncClient]:
    seed = big_dataset(BASE)
    async with owner_engine() as owner:
        await seed.write(owner)
        async with owner.connect() as conn:
            await conn.exec_driver_sql("COMMIT")
            await conn.exec_driver_sql("ANALYZE events")
            await conn.exec_driver_sql("ANALYZE sessions")
    engine = api_engine()
    app = create_app(create_session_factory(engine), enable_live=False)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t/api/v1"
        ) as c:
            yield c
    await engine.dispose()


CASES: list[tuple[str, str, dict[str, str | int]]] = [
    ("timeseries 1h", "/stats/timeseries", {"bucket": "1h", **WIN}),
    ("timeseries 5m 24h", "/stats/timeseries", {"bucket": "5m"}),
    ("timeseries 1d", "/stats/timeseries", {"bucket": "1d", **WIN}),
    *[
        (f"top {f}", "/stats/top", {"field": f, "limit": 10, **WIN})
        for f in (
            "country",
            "asn",
            "org",
            "username",
            "password",
            "command",
            "url",
            "user_agent",
            "tag",
            "src_ip",
        )
    ],
    ("heatmap", "/stats/heatmap", dict(WIN)),
    ("attackers last_seen", "/attackers", {"limit": 50}),
    ("attackers sessions", "/attackers", {"sort": "sessions", "limit": 200}),
    ("attackers filtered", "/attackers", {"country": "NL", "tag": "mirai", "sensor": "ssh"}),
    ("attackers prefix", "/attackers", {"q": "203.0"}),
    ("asns", "/asns", {"limit": 50}),
]


@pytest.mark.parametrize(("name", "path", "params"), CASES, ids=[c[0] for c in CASES])
async def test_endpoint_under_budget(
    client: httpx.AsyncClient, name: str, path: str, params: dict[str, str | int]
) -> None:
    samples: list[float] = []
    for _ in range(6):
        t = time.perf_counter()
        r = await client.get(path, params=params)
        samples.append(time.perf_counter() - t)
        assert r.status_code == 200, r.text
    med = statistics.median(samples[1:])
    print(f"PERF {name:24s} median {med * 1000:6.1f} ms  max {max(samples[1:]) * 1000:6.1f} ms")
    assert med < BUDGET_S


async def test_attacker_detail_under_budget(client: httpx.AsyncClient) -> None:
    ip = (await client.get("/attackers", params={"sort": "events", "limit": 1})).json()["items"][0][
        "ip"
    ]
    samples: list[float] = []
    for _ in range(5):
        t = time.perf_counter()
        r = await client.get(f"/attackers/{ip}")
        samples.append(time.perf_counter() - t)
        assert r.status_code == 200
    med = statistics.median(samples[1:])
    print(f"PERF {'attacker detail':24s} median {med * 1000:6.1f} ms")
    assert med < BUDGET_S


async def test_dataset_size(client: httpx.AsyncClient) -> None:
    body = (await client.get("/stats/heatmap", params=WIN)).json()
    total = sum(c["events"] for c in body["cells"])
    assert 20000 <= total <= 32000


@pytest.mark.parametrize(
    "params",
    [{"username": "root"}, {"password": "123456"}, {"command": "uname -a"}, {"url": "/.env"}],
    ids=["username", "password", "command", "url"],
)
async def test_sessions_value_filter_under_budget(
    client: httpx.AsyncClient, params: dict[str, str]
) -> None:
    samples: list[float] = []
    for _ in range(5):
        t = time.perf_counter()
        r = await client.get("/sessions", params={**params, "limit": 50})
        samples.append(time.perf_counter() - t)
        assert r.status_code == 200, r.text
    med = statistics.median(samples[1:])
    print(f"PERF sessions filter {next(iter(params)):10s} median {med * 1000:6.1f} ms")
    assert med < BUDGET_S
