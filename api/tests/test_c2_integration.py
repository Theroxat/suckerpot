"""GET /indicators/c2 against a real TimescaleDB with a hand-checked dataset."""

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from analytics_seed import api_engine, owner_engine
from sqlalchemy import text
from suckerpot_db import create_session_factory

from api.main import create_app

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

NOW = datetime.now(UTC).replace(microsecond=0)
H1 = "a1" * 32
H2 = "b2" * 32
H_OLD = "c3" * 32
TF = "https://threatfox.abuse.ch/ioc/1234/"
VT = f"https://www.virustotal.com/gui/file/{H1}/relations"

# (hash, hours since last seen, sessions linking to it)
HASHES = [(H1, 2, 3), (H2, 5, 1), (H_OLD, 24 * 60, 2)]
# (hash, address, kind, port, source, confidence, family, reference)
CONTACTS: list[tuple[str, str, str, int | None, str, str, str | None, str | None]] = [
    (H1, "203.0.113.5", "ip", 4444, "threatfox", "high", "Mirai", TF),
    (H1, "203.0.113.5", "ip", None, "virustotal", "medium", None, VT),
    (H2, "203.0.113.5", "ip", None, "virustotal", "medium", None, "https://evil.test/x"),
    (H1, "198.51.100.7", "ip", None, "virustotal", "medium", None, VT),
    (H2, "c2.badhost.ru", "domain", None, "virustotal", "medium", None, VT),
    (H_OLD, "192.0.2.50", "ip", None, "threatfox", "high", "Gafgyt", TF),
    (H1, "192.0.2.60", "ip", None, "virustotal", "low", None, None),  # never shown
]


async def seed() -> None:
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(text("TRUNCATE indicators CASCADE"))
        ids: dict[str, int] = {}
        for value, hours, sessions in HASHES:
            seen = NOW - timedelta(hours=hours)
            iid = int(
                await conn.scalar(
                    text(
                        "INSERT INTO indicators (type, value, role, first_seen, last_seen, "
                        "sightings, sensors) VALUES ('hash', :v, 'hash', :f, :l, 1, '{ssh}') "
                        "RETURNING id"
                    ),
                    {"v": value, "f": seen - timedelta(hours=1), "l": seen},
                )
                or 0
            )
            ids[value] = iid
            for n in range(sessions):
                await conn.execute(
                    text(
                        "INSERT INTO indicator_sessions VALUES (:i, :s, "
                        "CAST('203.0.113.9' AS inet), 'ssh', :t)"
                    ),
                    {"i": iid, "s": f"{value[:4]}-{n}", "t": seen},
                )
        for h, addr, kind, port, source, conf, family, ref in CONTACTS:
            await conn.execute(
                text(
                    "INSERT INTO indicator_contacts (hash_indicator_id, address, kind, port, "
                    "source, confidence, family, reference, first_seen) VALUES "
                    "(:i, :a, :k, :p, :s, :c, :f, :r, :t)"
                ),
                {"i": ids[h], "a": addr, "k": kind, "p": port, "s": source, "c": conf,
                 "f": family, "r": ref, "t": NOW - timedelta(days=1)},
            )  # fmt: skip


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    await seed()
    engine = api_engine()
    app = create_app(create_session_factory(engine), enable_live=False)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t/api/v1"
        ) as c:
            yield c
    await engine.dispose()


async def c2(client: httpx.AsyncClient, **params: Any) -> dict[str, Any]:
    r = await client.get("/indicators/c2", params=params)
    assert r.status_code == 200, r.text
    return r.json()  # type: ignore[no-any-return]


async def test_list_shape_order_and_aggregation(client: httpx.AsyncClient) -> None:
    body = await c2(client)
    assert body["next_cursor"] is None
    items = body["items"]
    # High confidence first; the 60-day-old hash is outside the default 30-day window.
    assert [i["address"] for i in items] == ["203.0.113.5", "198.51.100.7", "c2.badhost.ru"]
    top = items[0]
    assert top["defanged"] == "203[.]0[.]113[.]5" and top["kind"] == "ip"
    assert top["port"] == 4444 and top["confidence"] == "high"
    assert top["sources"] == ["threatfox", "virustotal"] and top["families"] == ["Mirai"]
    assert top["hash_count"] == 2 and top["sessions"] == 4
    assert [h["sha256"] for h in top["hashes"]] == [H1, H2]  # most recent first
    assert top["hashes"][0]["family"] == "Mirai"
    assert top["references"] == sorted([TF, VT])  # the unknown link is dropped
    assert top["first_seen"] and top["last_seen"]
    assert set(top) == {
        "address", "defanged", "kind", "port", "confidence", "sources", "families", "hashes",
        "hash_count", "sessions", "first_seen", "last_seen", "references",
    }  # fmt: skip
    medium = items[1]
    assert medium["confidence"] == "medium" and medium["sources"] == ["virustotal"]
    assert medium["port"] is None and medium["families"] == [] and medium["sessions"] == 3
    domain = items[2]
    assert domain["kind"] == "domain" and domain["defanged"] == "c2[.]badhost[.]ru"


async def test_filters(client: httpx.AsyncClient) -> None:
    high = await c2(client, min_confidence="high")
    assert [i["address"] for i in high["items"]] == ["203.0.113.5"]
    assert [i["address"] for i in (await c2(client, kind="domain"))["items"]] == ["c2.badhost.ru"]
    wide = await c2(client, hours=24 * 90)
    assert [i["address"] for i in wide["items"]] == [
        "203.0.113.5", "192.0.2.50", "198.51.100.7", "c2.badhost.ru"
    ]  # fmt: skip
    assert (await c2(client, hours=1))["items"] == []


async def test_keyset_pagination_covers_everything_once(client: httpx.AsyncClient) -> None:
    seen: list[str] = []
    cursor: str | None = None
    for _ in range(5):
        body = await c2(client, limit=1, hours=24 * 90, **({"cursor": cursor} if cursor else {}))
        assert len(body["items"]) <= 1
        seen += [i["address"] for i in body["items"]]
        cursor = body["next_cursor"]
        if cursor is None:
            break
    assert seen == ["203.0.113.5", "192.0.2.50", "198.51.100.7", "c2.badhost.ru"]


async def test_bad_parameters_are_rejected(client: httpx.AsyncClient) -> None:
    for params in (
        {"limit": 0}, {"limit": 201}, {"hours": 0}, {"hours": 24 * 91}, {"kind": "url"},
        {"min_confidence": "low"}, {"cursor": "x" * 600},
    ):  # fmt: skip
        assert (await client.get("/indicators/c2", params=params)).status_code == 422
    assert (
        await client.get("/indicators/c2", params={"cursor": "not-a-cursor"})
    ).status_code == 400
    assert (await client.post("/indicators/c2")).status_code in (403, 405)
