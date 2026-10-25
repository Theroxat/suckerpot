"""CVE endpoints against a real TimescaleDB with a small hand-checked dataset."""

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from analytics_seed import Seed, api_engine, owner_engine
from sqlalchemy import text
from suckerpot_db import create_session_factory

from api.cursor import encode_cursor
from api.main import create_app

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

NOW = datetime.now(UTC).replace(microsecond=0)

# (id, vendor, product, severity, score, kev, relevance, services, tags, days ago, rank)
ROWS: list[tuple[Any, ...]] = [
    (
        "CVE-2099-0001",
        "PHP Group",
        "PHP",
        "CRITICAL",
        9.2,
        True,
        "high",
        ["web-php"],
        ["php2shell"],
        2,
        399_920,
    ),
    ("CVE-2099-0002", "Redis", "Redis", "HIGH", 8.1, False, "high", ["redis"], [], 3, 300_810),
    (
        "CVE-2099-0003",
        "Acme",
        "Widget",
        "CRITICAL",
        9.8,
        False,
        "medium",
        ["openssh"],
        [],
        4,
        200_980,
    ),
    ("CVE-2099-0004", "Acme", "Gadget_100%", "LOW", 3.1, False, "none", [], [], 5, 310),
    ("CVE-2099-0005", "Acme", "Gizmo", None, None, True, "none", [], [], 60, 10_000),
]


async def seed() -> None:
    sessions = Seed()
    for i, ip in enumerate(["203.0.113.1", "203.0.113.2", "203.0.113.1"]):
        sessions.session(
            f"s{i}", "web", ip, NOW - timedelta(hours=i + 1), [(0.0, "http_request", {})],
            tags=["php2shell", "scanner"] if i < 2 else ["recon"],
        )  # fmt: skip
    async with owner_engine() as owner:
        await sessions.write(owner)
        async with owner.begin() as conn:
            await conn.execute(text("TRUNCATE cve, cve_sync_state, enrichment_status"))
            for r in ROWS:
                await conn.execute(
                    text(
                        "INSERT INTO cve (cve_id, vendor, product, title, description, "
                        "cvss_severity, cvss_score, in_kev, relevance, matched_services, tags, "
                        "published_at, rank_score, sources, cwes, refs, cpes) VALUES "
                        "(:id, :v, :p, :t, :d, :sev, :sc, :kev, :rel, :svc, :tags, :pub, :rank, "
                        "ARRAY['nvd'], ARRAY['CWE-94'], "
                        "ARRAY['https://example.com/a', 'javascript:alert(1)', "
                        "'https://ex\u00e4mple.com/x'], "
                        "ARRAY['php:php'])"
                    ),
                    {
                        "id": r[0], "v": r[1], "p": r[2], "t": f"{r[1]} {r[2]} flaw",
                        "d": "Long description. " * 50, "sev": r[3], "sc": r[4], "kev": r[5],
                        "rel": r[6], "svc": r[7], "tags": r[8],
                        "pub": NOW - timedelta(days=r[9]), "rank": r[10],
                    },
                )  # fmt: skip
            await conn.execute(
                text(
                    "INSERT INTO cve_sync_state (source, last_run_at, last_success_at, "
                    "items_last_run) VALUES ('kev', now(), now(), 5)"
                )
            )
            await conn.execute(
                text(
                    "INSERT INTO enrichment_status (name, detail) VALUES "
                    "('nvd', '{\"configured\": true}')"
                )
            )


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


def ids(body: dict[str, Any]) -> list[str]:
    return [i["cve_id"] for i in body["items"]]


async def test_default_order_is_rank_with_seen_counts(client: httpx.AsyncClient) -> None:
    body = (await client.get("/cves")).json()
    assert ids(body) == [
        "CVE-2099-0001",
        "CVE-2099-0002",
        "CVE-2099-0003",
        "CVE-2099-0005",
        "CVE-2099-0004",
    ]
    assert body["total"] == 5 and body["next_cursor"] is None
    first = body["items"][0]
    assert first["seen_sessions"] == 2 and first["in_kev"] and first["relevance"] == "high"
    assert len(first["description"]) <= 400
    assert body["items"][1]["seen_sessions"] == 0


async def test_filters(client: httpx.AsyncClient) -> None:
    async def get(**params: Any) -> dict[str, Any]:
        r = await client.get("/cves", params=params)
        assert r.status_code == 200, r.text
        body: dict[str, Any] = r.json()
        return body

    assert ids(await get(relevance="relevant")) == [
        "CVE-2099-0001",
        "CVE-2099-0002",
        "CVE-2099-0003",
    ]
    assert ids(await get(relevance="none", kev="true")) == ["CVE-2099-0005"]
    assert ids(await get(severity="critical")) == ["CVE-2099-0001", "CVE-2099-0003"]
    assert ids(await get(severity="none")) == ["CVE-2099-0005"]
    since = (NOW - timedelta(days=10)).date().isoformat()
    assert (await get(since=since))["total"] == 4
    assert ids(await get(q="redis")) == ["CVE-2099-0002"]
    assert ids(await get(q="100%")) == ["CVE-2099-0004"]  # LIKE wildcards are escaped
    assert (await get(q="%"))["total"] == 1


async def test_pagination_walks_every_row_once(client: httpx.AsyncClient) -> None:
    for sort in ("rank", "published"):
        seen: list[str] = []
        cursor = None
        for _ in range(10):
            params: dict[str, Any] = {"limit": 2, "sort": sort}
            if cursor:
                params["cursor"] = cursor
            body = (await client.get("/cves", params=params)).json()
            seen += ids(body)
            cursor = body["next_cursor"]
            if not cursor:
                break
        assert len(seen) == 5 and len(set(seen)) == 5, sort
    published = (await client.get("/cves", params={"sort": "published"})).json()
    assert ids(published)[0] == "CVE-2099-0001" and ids(published)[-1] == "CVE-2099-0005"


async def test_validation(client: httpx.AsyncClient) -> None:
    assert (await client.get("/cves", params={"limit": 101})).status_code == 422
    assert (await client.get("/cves", params={"cursor": "garbage"})).status_code == 422
    bad_cursors: list[list[str | int]] = [
        ["abc", "CVE-2099-0001"],
        [2**40, "CVE-2099-0001"],
        [5, "CVE-2099-0001\n"],
        [5, "x"],
    ]
    for bad in bad_cursors:
        r = await client.get("/cves", params={"cursor": encode_cursor(bad)})
        assert r.status_code == 422, bad
    ok = await client.get("/cves", params={"cursor": encode_cursor([5, "CVE-2099-0001"])})
    assert ok.status_code == 200
    assert (await client.get("/cves", params={"relevance": "x"})).status_code == 422
    assert (await client.get("/cves", params={"q": "x" * 101})).status_code == 422
    assert (await client.get("/cves/not-an-id")).status_code == 422
    assert (await client.get("/cves/CVE-2099-9999")).status_code == 404


async def test_detail_traffic(client: httpx.AsyncClient) -> None:
    body = (await client.get("/cves/CVE-2099-0001")).json()
    assert body["traffic"]["sessions"] == 2 and body["traffic"]["ips"] == 2
    assert body["traffic"]["by_tag"] == [{"tag": "php2shell", "sessions": 2}]
    assert body["traffic"]["first_seen"] and body["cwes"] == ["CWE-94"]
    assert len(body["description_full"]) > 400
    assert body["refs"] == ["https://example.com/a"]  # only safe http(s) links are returned
    none = (await client.get("/cves/CVE-2099-0002")).json()
    assert none["traffic"] == {
        "sessions": 0, "ips": 0, "first_seen": None, "last_seen": None, "by_tag": []
    }  # fmt: skip


async def test_sync_status(client: httpx.AsyncClient) -> None:
    body = (await client.get("/cves/sync")).json()
    assert [s["source"] for s in body["sources"]] == ["kev", "nvd", "github"]
    assert body["sources"][0]["items_last_run"] == 5 and body["sources"][1]["last_run_at"] is None
    assert (body["total"], body["relevant"], body["kev"]) == (5, 3, 2)
    assert body["nvd_key_configured"] is True and body["github_key_configured"] is False


async def test_api_role_cannot_write(client: httpx.AsyncClient) -> None:
    engine = api_engine()
    try:
        async with engine.begin() as conn:
            with pytest.raises(Exception, match="permission denied"):
                await conn.execute(text("DELETE FROM cve"))
    finally:
        await engine.dispose()
