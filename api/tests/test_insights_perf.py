"""M7 endpoints on ~25k events / 3000 sessions: every endpoint under 300 ms."""

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


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def client() -> AsyncIterator[httpx.AsyncClient]:
    seed = big_dataset(BASE)
    for i in range(300):  # a realistic spread of download URLs on top of the base dataset
        seed.session(
            f"dl-{i}",
            "ssh",
            f"203.0.113.{i % 250 + 1}",
            BASE - timedelta(minutes=i * 30),
            [
                (0.0, "connect", {}),
                (
                    1.0,
                    "download_attempt",
                    {"url": f"http://192.0.2.9/p{i % 120}.sh", "tool": "wget"},
                ),
            ],
            tags=["malware-drop"],
        )
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
    ("insights 7d", "/insights", {}),
    ("insights 29d", "/insights", {"since": (BASE - timedelta(days=29)).isoformat()}),
    *[
        (f"trends new {f}", "/trends/new", {"field": f, "days": 7})
        for f in ("username", "password", "command", "url", "asn", "user_agent")
    ],
    ("trends tags 1d", "/trends/tags", {}),
    ("trends tags 1h", "/trends/tags", {"bucket": "1h"}),
    ("malware list", "/malware", {"limit": 50}),
    ("malware filtered", "/malware", {"tool": "wget", "q": "p1"}),
    ("malware detail", "/malware/detail", {"url": "http://192.0.2.9/p7.sh"}),
    ("settings site", "/settings/site", {}),
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
