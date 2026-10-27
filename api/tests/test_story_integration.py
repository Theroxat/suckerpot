"""GET /api/v1/story against a real, migrated TimescaleDB."""

import asyncio
import os
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from starlette.testclient import TestClient
from suckerpot_db import EventRow, SessionRow, create_engine, create_session_factory

from api.main import create_app
from api.story import classify_stage

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

# (id, sensor, ip, country, attempts, success, commands, downloads, tags, benign, minutes ago)
SESSIONS: list[tuple[str, str, str, str | None, int, bool, int, int, list[str], bool, int]] = [
    ("st-look", "web", "203.0.113.1", "NL", 0, False, 0, 0, [], False, 30),
    ("st-guess", "ssh", "203.0.113.2", "NL", 37, False, 0, 0, [], False, 60),
    ("st-in", "ssh", "203.0.113.3", "DE", 3, True, 0, 0, [], False, 90),
    ("st-cmd", "telnet", "203.0.113.4", "DE", 2, True, 4, 0, ["mirai"], False, 120),
    ("st-dl", "telnet", "198.51.100.5", "BR", 2, True, 4, 1, ["mirai"], False, 150),
    ("st-exp", "web", "198.51.100.6", None, 0, False, 0, 0, ["php2shell"], False, 180),
    ("st-benign", "web", "198.51.100.7", "FR", 0, False, 0, 0, [], True, 10),
    ("st-old", "ssh", "192.0.2.8", "FR", 1, False, 0, 0, [], False, 60 * 30),
]


async def _seed() -> None:
    engine = create_engine(pool_size=1)
    factory = create_session_factory(engine)
    now = datetime.now(UTC)
    try:
        async with engine.begin() as conn:
            await conn.execute(text("TRUNCATE events, sessions"))
        async with factory() as s, s.begin():
            for sid, sensor, ip, cc, att, ok, cmd, dl, tags, benign, ago in SESSIONS:
                started = now - timedelta(minutes=ago)
                s.add(
                    SessionRow(
                        session_id=sid,
                        sensor=sensor,
                        src_ip=ip,
                        src_port=1,
                        dst_port=2,
                        started_at=started,
                        last_event_at=started + timedelta(seconds=30),
                        event_count=att + cmd + dl + 2,
                        login_attempts=att,
                        login_success=ok,
                        commands=cmd,
                        downloads=dl,
                        country=cc,
                        tags=tags,
                        benign=benign,
                    )
                )
                s.add(
                    EventRow(
                        ts=started,
                        sensor=sensor,
                        session_id=sid,
                        type="connect",
                        src_ip=ip,
                        src_port=1,
                        dst_port=2,
                        data={},
                        country=cc,
                    )
                )
    finally:
        await engine.dispose()


def test_story_funnel_conserves_sessions() -> None:
    asyncio.run(_seed())
    with TestClient(create_app(None)) as client:
        r = client.get("/api/v1/story")
        assert r.status_code == 200, r.text
        body: dict[str, Any] = r.json()
        totals = body["totals"]
        assert totals["sessions"] == 6  # the research scanner and the old session are left out
        assert totals["sources"] == 6 and totals["exploits"] == 1 and totals["downloads"] == 1
        nodes = {n["id"]: n for n in body["flow"]["nodes"]}
        for column in ("origin", "door", "stage"):
            assert sum(n["sessions"] for n in nodes.values() if n["column"] == column) == 6
        assert nodes["stage:exploit"]["sessions"] == 1
        assert nodes["stage:download"]["sessions"] == 1
        assert nodes["origin:NL"]["href"] == "/attacks?country=NL"
        assert nodes["stage:download"]["href"] == "/attacks?stage=download"
        assert nodes["origin:NL"]["label"] == "Netherlands"
        for node_id, node in nodes.items():
            if node["column"] == "stage":
                into = sum(
                    link["value"] for link in body["flow"]["links"] if link["target"] == node_id
                )
                assert into == node["sessions"]
        assert sum(b["sessions"] for b in body["timeline"]) == 6
        assert 3 <= len(body["stories"]) <= 5
        assert body["stories"][0]["stage"] == "exploit"
        assert body["stories"][1]["stage"] == "download"
        assert body["stories"][1]["steps"][0]["kind"] == "connect"
        assert body["headline"].startswith("In the last 24 hours, 6 machines")


def test_story_with_benign_and_hours() -> None:
    asyncio.run(_seed())
    with TestClient(create_app(None)) as client:
        r = client.get("/api/v1/story", params={"hours": 168, "include_benign": "true"})
        assert r.status_code == 200
        assert r.json()["totals"]["sessions"] == 8
        assert client.get("/api/v1/story", params={"hours": 0}).status_code == 422
        assert client.get("/api/v1/story", params={"hours": 169}).status_code == 422


def test_sql_and_python_classifiers_agree() -> None:
    asyncio.run(_seed())
    with TestClient(create_app(None)) as client:
        r = client.get("/api/v1/story", params={"hours": 168, "include_benign": "true"})
        nodes = r.json()["flow"]["nodes"]
        stages = {n["key"]: n["sessions"] for n in nodes if n["column"] == "stage"}
    expected: dict[str, int] = {}
    for _, _, _, _, att, ok, cmd, dl, tags, _, _ in SESSIONS:
        st = classify_stage(
            login_attempts=att, login_success=ok, commands=cmd, downloads=dl, tags=tags
        )
        expected[st] = expected.get(st, 0) + 1
    assert stages == expected


def test_download_step_survives_hundreds_of_login_attempts() -> None:
    async def seed() -> None:
        engine = create_engine(pool_size=1)
        factory = create_session_factory(engine)
        now = datetime.now(UTC)
        start = now - timedelta(minutes=20)
        try:
            async with engine.begin() as conn:
                await conn.execute(text("TRUNCATE events, sessions"))
            async with factory() as s, s.begin():
                s.add(
                    SessionRow(
                        session_id="st-mirai",
                        sensor="telnet",
                        src_ip="203.0.113.50",
                        src_port=1,
                        dst_port=2,
                        started_at=start,
                        last_event_at=now,
                        event_count=605,
                        login_attempts=600,
                        login_success=True,
                        commands=2,
                        downloads=1,
                        country="NL",
                        tags=["mirai"],
                    )
                )

                def ev(sec: int, type_: str, data: dict[str, Any]) -> EventRow:
                    return EventRow(
                        ts=start + timedelta(seconds=sec),
                        sensor="telnet",
                        session_id="st-mirai",
                        type=type_,
                        src_ip="203.0.113.50",
                        src_port=1,
                        dst_port=2,
                        data=data,
                    )

                s.add(ev(0, "connect", {}))
                for i in range(600):
                    data = {"username": "root", "password": f"pw{i % 7}", "success": False}
                    s.add(ev(1 + i // 10, "login_attempt", data))
                ok = {"username": "root", "password": "x", "success": True}
                s.add(ev(100, "login_attempt", ok))
                s.add(ev(101, "command", {"input": "busybox"}))
                s.add(ev(102, "download_attempt", {"url": "http://198.51.100.2/m"}))
        finally:
            await engine.dispose()

    asyncio.run(seed())
    with TestClient(create_app(None)) as client:
        story = client.get("/api/v1/story").json()["stories"][0]
        kinds = [st["kind"] for st in story["steps"]]
        assert kinds == ["connect", "guess", "login", "command", "download"]
        guess = story["steps"][1]
        assert guess["count"] == 600 and "root/pw" in guess["technical"]


def test_sessions_can_be_filtered_by_stage() -> None:
    asyncio.run(_seed())
    with TestClient(create_app(None)) as client:
        for stage, ids in {
            "looked": {"st-look"},
            "guessed": {"st-guess", "st-old"},
            "got_in": {"st-in"},
            "commands": {"st-cmd"},
            "download": {"st-dl"},
            "exploit": {"st-exp"},
        }.items():
            r = client.get("/api/v1/sessions", params={"stage": stage})
            assert r.status_code == 200, r.text
            assert {i["session_id"] for i in r.json()["items"]} == ids
