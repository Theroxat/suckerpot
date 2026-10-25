"""Indicator endpoints against a real TimescaleDB with a hand-checked dataset."""

import json
import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from analytics_seed import Seed, api_engine, owner_engine
from sqlalchemy import text
from suckerpot_db import create_session_factory

from api.main import create_app

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

NOW = datetime.now(UTC).replace(microsecond=0)
SHA = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
SRC = [f"203.0.113.{i}" for i in range(1, 7)]

# (type, value, role, hours since last seen, sightings, [source index list])
INDICATORS: list[tuple[str, str, str, int, int, list[int]]] = [
    ("domain", "dl.badhost.ru", "download_host", 1, 9, [0, 1, 2, 3]),
    ("url", "http://dl.badhost.ru/bins/x86", "download_host", 2, 6, [0, 1, 2]),
    ("ip", "8.8.4.4", "contacted_host", 3, 4, [3, 4]),
    ("hash", SHA, "hash", 4, 3, [0, 1]),
    ("domain", "solo.badhost.ru", "download_host", 5, 1, [5]),
    ("domain", "old.badhost.ru", "contacted_host", 24 * 30, 2, [4]),
]


async def seed() -> None:
    s = Seed()
    for n, ip in enumerate(SRC):
        s.session(
            f"s{n}",
            "ssh",
            ip,
            NOW - timedelta(hours=1, minutes=n),
            [(0.0, "connect", {})],
            geo=("NL", "Amsterdam", 14061, "DigitalOcean, LLC"),
        )
    async with owner_engine() as owner:
        await s.write(owner)
        async with owner.begin() as conn:
            await conn.execute(text("TRUNCATE indicators CASCADE"))
            for kind, value, role, hours, sightings, sources in INDICATORS:
                seen = NOW - timedelta(hours=hours) + timedelta(minutes=10)
                iid = await conn.scalar(
                    text(
                        "INSERT INTO indicators (type, value, role, host, first_seen, last_seen, "
                        "sightings, sensors) VALUES (:t, :v, :r, :h, :f, :l, :n, ARRAY['ssh']) "
                        "RETURNING id"
                    ),
                    {
                        "t": kind, "v": value, "r": role, "n": sightings, "l": seen,
                        "f": seen - timedelta(hours=1),
                        "h": "dl.badhost.ru" if kind == "url" else None,
                    },
                )  # fmt: skip
                for i in sources:
                    await conn.execute(
                        text(
                            "INSERT INTO indicator_sessions VALUES "
                            "(:i, :s, CAST(:ip AS inet), 'ssh', :ts)"
                        ),
                        {"i": iid, "s": f"s{i}", "ip": SRC[i], "ts": seen},
                    )
            ids = {
                r.value: r.id
                for r in (await conn.execute(text("SELECT id, value FROM indicators"))).all()
            }
            intel = [
                (ids["dl.badhost.ru"], "urlhaus", True, "Mirai", "malware_download",
                 ["elf", "mirai"], "https://urlhaus.abuse.ch/host/dl.badhost.ru/"),
                (ids["dl.badhost.ru"], "threatfox", True, "Mirai", "payload_delivery", [],
                 "https://threatfox.abuse.ch/ioc/42/"),
                (ids[SHA], "virustotal", True, "trojan.gafgyt", "trojan", ["elf"],
                 "https://evil.example/not-allowed"),
                (ids["solo.badhost.ru"], "urlhaus", False, None, None, [], None),
                (ids["8.8.4.4"], "urlhaus", False, None, None, ["not-checked"], None),
            ]  # fmt: skip
            for iid, source, known, family, threat, tags, ref in intel:
                await conn.execute(
                    text(
                        "INSERT INTO indicator_intel (indicator_id, source, known, family, "
                        "threat_type, tags, reference) VALUES (:i, :s, :k, :f, :t, :tags, :r)"
                    ),
                    {"i": iid, "s": source, "k": known, "f": family, "t": threat, "tags": tags,
                     "r": ref},
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


async def listing(client: httpx.AsyncClient, **params: Any) -> list[dict[str, Any]]:
    r = await client.get("/indicators", params=params)
    assert r.status_code == 200, r.text
    return r.json()["items"]  # type: ignore[no-any-return]


async def test_list_order_counts_and_defanging(client: httpx.AsyncClient) -> None:
    items = await listing(client)
    assert [i["value"] for i in items][:5] == [
        "dl.badhost.ru",
        "http://dl.badhost.ru/bins/x86",
        "8.8.4.4",
        SHA,
        "solo.badhost.ru",
    ]
    top = items[0]
    assert top["defanged"] == "dl[.]badhost[.]ru"
    assert items[1]["defanged"] == "hxxp://dl[.]badhost[.]ru/bins/x86"
    assert (top["sightings"], top["sessions"], top["ips"]) == (9, 4, 4)
    assert top["known"] is True and top["family"] == "Mirai"
    assert top["sources"] == ["threatfox", "urlhaus"] and top["checked"] is True
    unchecked = items[1]
    assert unchecked["known"] is None and unchecked["checked"] is False
    reserved = items[2]  # only a "not-checked" marker: still unchecked
    assert reserved["known"] is None and reserved["sources"] == []
    solo = items[4]
    assert solo["known"] is False and solo["checked"] is True


async def test_filters(client: httpx.AsyncClient) -> None:
    assert [i["type"] for i in await listing(client, type="hash")] == ["hash"]
    assert {i["role"] for i in await listing(client, role="contacted_host")} == {"contacted_host"}
    assert [i["value"] for i in await listing(client, known="true")] == ["dl.badhost.ru", SHA]
    not_known = {i["value"] for i in await listing(client, known="false")}
    assert "dl.badhost.ru" not in not_known and "solo.badhost.ru" in not_known
    assert {i["value"] for i in await listing(client, family="mirai")} == {"dl.badhost.ru"}
    assert len(await listing(client, since=(NOW - timedelta(days=2)).isoformat())) == 5
    assert {i["value"] for i in await listing(client, q="BINS/x86")} == {
        "http://dl.badhost.ru/bins/x86"
    }
    assert await listing(client, q="%") == []  # no pattern matching: a literal search
    assert await listing(client, q="nothing-like-this") == []


async def test_hours_window_matches_the_graph_and_all_time_stays_available(
    client: httpx.AsyncClient,
) -> None:
    assert len(await listing(client)) == len(INDICATORS)  # no window: all time
    week = {i["value"] for i in await listing(client, hours=168)}
    assert "old.badhost.ru" not in week and len(week) == len(INDICATORS) - 1
    day = {i["value"] for i in await listing(client, hours=4)}
    assert day == {"dl.badhost.ru", "http://dl.badhost.ru/bins/x86", "8.8.4.4", SHA}
    # combined with `since`, the later bound wins
    tight = await listing(
        client, hours=168, since=(NOW - timedelta(hours=2, minutes=30)).isoformat()
    )
    assert {i["value"] for i in tight} == {"dl.badhost.ru", "http://dl.badhost.ru/bins/x86"}
    csv = (await client.get("/indicators/export", params={"hours": 4})).text
    assert "solo[.]badhost[.]ru" not in csv and "dl[.]badhost[.]ru" in csv
    assert (await client.get("/indicators", params={"hours": 0})).status_code == 422
    assert (await client.get("/indicators", params={"hours": 99999})).status_code == 422


async def test_pagination_is_stable_and_complete(client: httpx.AsyncClient) -> None:
    seen: list[int] = []
    cursor: str | None = None
    for _ in range(10):
        params: dict[str, Any] = {"limit": 2}
        if cursor:
            params["cursor"] = cursor
        body = (await client.get("/indicators", params=params)).json()
        assert len(body["items"]) <= 2
        seen += [i["id"] for i in body["items"]]
        cursor = body["next_cursor"]
        if cursor is None:
            break
    assert len(seen) == len(set(seen)) == len(INDICATORS)


@pytest.mark.parametrize(
    ("params", "status"),
    [
        ({"limit": 0}, 422),
        ({"limit": 201}, 422),
        ({"type": "nope"}, 422),
        ({"role": "nope"}, 422),
        ({"cursor": "garbage"}, 400),
        ({"since": "yesterday"}, 422),
        ({"family": "<script>"}, 422),
        ({"q": "x" * 129}, 422),
    ],
)
async def test_bad_parameters(
    client: httpx.AsyncClient, params: dict[str, Any], status: int
) -> None:
    assert (await client.get("/indicators", params=params)).status_code == status


async def test_detail(client: httpx.AsyncClient) -> None:
    top = (await listing(client))[0]
    r = await client.get(f"/indicators/{top['id']}")
    assert r.status_code == 200
    d = r.json()
    assert d["indicator"]["defanged"] == "dl[.]badhost[.]ru"
    assert [i["source"] for i in d["intel"]] == ["threatfox", "urlhaus"]
    assert d["intel"][1]["reference"] == "https://urlhaus.abuse.ch/host/dl.badhost.ru/"
    assert d["not_checked"] is False
    assert len(d["sessions"]) == 4 and {s["sensor"] for s in d["sessions"]} == {"ssh"}
    assert sorted(s["ip"] for s in d["source_ips"]) == SRC[:4]
    assert d["source_ips"][0]["country"] == "NL"
    related = {x["defanged"] for x in d["related"]}
    assert "hxxp://dl[.]badhost[.]ru/bins/x86" in related and SHA in related
    assert d["links_truncated"] is False


async def test_detail_filters_disallowed_reference_and_reserved(client: httpx.AsyncClient) -> None:
    by_value = {i["value"]: i for i in await listing(client)}
    vt = (await client.get(f"/indicators/{by_value[SHA]['id']}")).json()
    assert vt["intel"][0]["source"] == "virustotal" and vt["intel"][0]["reference"] is None
    reserved = (await client.get(f"/indicators/{by_value['8.8.4.4']['id']}")).json()
    assert reserved["intel"] == [] and reserved["not_checked"] is True


async def test_detail_not_found_and_bad_id(client: httpx.AsyncClient) -> None:
    assert (await client.get("/indicators/999999")).status_code == 404
    assert (await client.get("/indicators/abc")).status_code == 422
    assert (await client.get("/indicators/0")).status_code == 422


async def test_graph(client: httpx.AsyncClient) -> None:
    r = await client.get("/infrastructure/graph", params={"hours": 48})
    assert r.status_code == 200
    g = r.json()
    kinds = {
        k: [n for n in g["nodes"] if n["kind"] == k] for k in ("source", "indicator", "family")
    }
    assert len(kinds["source"]) == 6
    # the URL is rolled up into its host, the old indicator is outside the window
    assert {n["label"] for n in kinds["indicator"]} == {
        "dl[.]badhost[.]ru", "8[.]8[.]4[.]4", SHA, "solo[.]badhost[.]ru",
    }  # fmt: skip
    assert {n["label"] for n in kinds["family"]} == {"Mirai", "trojan.gafgyt"}
    ids = {n["id"] for n in g["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in g["edges"])
    host = next(n for n in kinds["indicator"] if n["label"] == "dl[.]badhost[.]ru")
    to_host = [e for e in g["edges"] if e["target"] == host["id"]]
    assert len(to_host) == 4 and all(e["source"].startswith("s:") for e in to_host)
    assert any(e["source"] == host["id"] and e["target"] == "f:mirai" for e in g["edges"])
    assert g["summary"]["shared_hosts"] == 1
    assert g["summary"]["sources_on_shared_hosts"] == 4
    assert g["summary"]["top_host"] == "dl[.]badhost[.]ru" and g["summary"]["top_host_sources"] == 4
    assert g["summary"]["sources"] == 6 and g["summary"]["families"] == 2
    assert g["truncated"] is False and len(g["nodes"]) <= 300
    # a wider window includes the old indicator
    wide = (await client.get("/infrastructure/graph", params={"hours": 24 * 60})).json()
    assert any(n["label"] == "old[.]badhost[.]ru" for n in wide["nodes"])
    only = (await client.get("/infrastructure/graph", params={"role": "hash"})).json()
    assert [n["label"] for n in only["nodes"] if n["kind"] == "indicator"] == [SHA]


async def test_graph_is_bounded(client: httpx.AsyncClient) -> None:
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text(
                """
                INSERT INTO indicators (type, value, role, first_seen, last_seen)
                SELECT 'domain', 'bulk' || g || '.badhost.ru', 'download_host', now(), now()
                FROM generate_series(1, 150) g
                """
            )
        )
        await conn.execute(
            text(
                """
                INSERT INTO indicator_sessions
                SELECT i.id, 'x' || g, CAST('198.51.100.' || (g % 250 + 1) AS inet), 'ssh', now()
                FROM indicators i, generate_series(1, 40) g WHERE i.value LIKE 'bulk%'
                """
            )
        )
    g = (await client.get("/infrastructure/graph")).json()
    assert len(g["nodes"]) <= 300
    assert len([n for n in g["nodes"] if n["kind"] == "indicator"]) <= 60
    assert g["truncated"] is True


async def test_graph_parameters(client: httpx.AsyncClient) -> None:
    assert (await client.get("/infrastructure/graph", params={"hours": 0})).status_code == 422
    assert (await client.get("/infrastructure/graph", params={"hours": 99999})).status_code == 422


async def test_export_csv(client: httpx.AsyncClient) -> None:
    r = await client.get("/indicators/export", params={"format": "csv", "role": "download_host"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert r.headers["content-disposition"].startswith('attachment; filename="suckerpot-')
    lines = r.text.strip().split("\n")
    assert lines[0].startswith("type,value,defanged,role")
    assert len(lines) == 1 + 3  # domain, url and solo; the old one is a contacted host
    assert "hxxp://dl[.]badhost[.]ru/bins/x86" in r.text


async def test_export_stix(client: httpx.AsyncClient) -> None:
    r = await client.get("/indicators/export", params={"format": "stix", "known": "true"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/stix+json")
    bundle = json.loads(r.text)
    assert bundle["type"] == "bundle"
    patterns = sorted(o["pattern"] for o in bundle["objects"])
    assert patterns == sorted(
        ["[domain-name:value = 'dl.badhost.ru']", f"[file:hashes.'SHA-256' = '{SHA}']"]
    )
    assert (await client.get("/indicators/export", params={"format": "xml"})).status_code == 422


async def test_api_role_cannot_write(client: httpx.AsyncClient) -> None:
    engine = api_engine()
    try:
        async with engine.begin() as conn:
            with pytest.raises(Exception, match="permission denied"):
                await conn.execute(text("DELETE FROM indicators"))
    finally:
        await engine.dispose()
