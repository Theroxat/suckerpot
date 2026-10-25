"""Search planning, Today sentences and the benign filters (M19), without a database."""

from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Any

import pytest
from sqlalchemy import Select
from sqlalchemy.dialects import postgresql

from api import analytics_queries as q
from api import search, today
from api.benign import visible_events, visible_sessions

T0 = datetime(2026, 10, 24, 12, 0, tzinfo=UTC)


def sql(stmt: Select[Any]) -> str:
    return str(stmt.compile(dialect=postgresql.dialect()))  # type: ignore[no-untyped-call]


# --------------------------------------------------------------------------- search


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("  203.0.113.7  ", "203.0.113.7"),
        ("evil[.]example", "evil.example"),
        ("hxxp://evil[.]example/a.sh", "http://evil.example/a.sh"),
        ("a\x00b\x07c", "abc"),
        ("x" * 500, "x" * search.MAX_QUERY),
    ],
)
def test_normalise(raw: str, expected: str) -> None:
    assert search.normalise(raw) == expected


@pytest.mark.parametrize(
    ("query", "low", "high"),
    [
        ("203.0.113.7", "203.0.113.7", "203.0.113.7"),
        ("203.0.113.", "203.0.113.0", "203.0.113.255"),
        ("203.0.113", "203.0.113.0", "203.0.113.255"),
        ("203.0.", "203.0.0.0", "203.0.255.255"),
        ("203.", "203.0.0.0", "203.255.255.255"),
        ("2001:db8::7", "2001:db8::7", "2001:db8::7"),
    ],
)
def test_ip_bounds(query: str, low: str, high: str) -> None:
    assert search.ip_bounds(query) == (ip_address(low), ip_address(high))


@pytest.mark.parametrize(
    "query", ["203.0.11", "203", "256.1.1.", "1.2.3.4.5", "abc", "203.0.113.999"]
)
def test_ip_bounds_refuses_what_is_not_an_unambiguous_address_or_prefix(query: str) -> None:
    assert search.ip_bounds(query) is None


@pytest.mark.parametrize(
    ("query", "kinds"),
    [
        ("203.0.113.7", ["ip"]),
        ("203.0.113.", ["ip"]),
        ("CVE-2026-109618", ["cve", "campaign"]),
        ("d41d8cd98f00b204e9800998ecf8427e", ["hash"]),
        ("evil.example", ["domain"]),
        ("http://evil.example/a.sh", ["domain"]),
        ("mirai", ["campaign"]),
        ("mirai loader #4", ["campaign"]),
        ("a.b", ["domain"]),
    ],
)
def test_plan_only_queries_the_groups_a_query_can_match(query: str, kinds: list[str]) -> None:
    assert search.plan(query) == kinds


def test_like_prefix_escapes_wildcards() -> None:
    assert search.like_prefix("50%_off\\") == "50\\%\\_off\\\\%"


# --------------------------------------------------------------------------- benign filters


def test_visible_filters_use_the_partial_index_shape() -> None:
    assert [str(c) for c in visible_sessions(False)] == ["NOT sessions.benign"]
    assert [str(c) for c in visible_events(False)] == ["events.benign IS NOT true"]
    assert visible_sessions(True) == [] and visible_events(True) == []


def test_every_analytics_statement_can_leave_scanners_out() -> None:
    w = q.Window(T0 - timedelta(hours=1), T0)
    hidden = [
        q.events_bucket_stmt("1h", w, None, False),
        q.sessions_bucket_stmt("1h", w, None, False),
        q.top_stmt("username", w, None, 5, include_benign=False),
        q.top_stmt("country", w, None, 5, include_benign=False),
        q.heatmap_stmt(w, None, False),
        q.attackers_stmt(sort="sessions", order="desc", limit=5, include_benign=False),
        q.asns_stmt("sessions", 5, None, False),
    ]
    for stmt in hidden:
        assert "benign" in sql(stmt)
    shown = [
        q.events_bucket_stmt("1h", w, None),
        q.top_stmt("country", w, None, 5),
        q.heatmap_stmt(w, None),
        q.attackers_stmt(sort="sessions", order="desc", limit=5),
        q.asns_stmt("sessions", 5, None),
    ]
    for stmt in shown:
        assert "benign" not in sql(stmt)


# --------------------------------------------------------------------------- Today sentences


def test_happened_sentence() -> None:
    assert today.happened_sentence(0, 0, 0, 0) == (
        "No attacks reached the honeypot in the last 24 hours."
    )
    assert today.happened_sentence(1204, 312, 41, 870) == (
        "1,204 attacks came from 312 addresses in the last 24 hours, 38% more than the day before. "
        "41 sessions ran commands on a fake shell."
    )
    assert today.happened_sentence(1, 1, 0, 0) == (
        "1 attack came from 1 address in the last 24 hours. None of them got as far as a shell."
    )


def test_trend_phrase_stays_quiet_on_small_or_flat_numbers() -> None:
    assert today.trend_phrase(9, 100) == ""
    assert today.trend_phrase(100, 90) == ""
    assert today.trend_phrase(50, 100) == ", 50% fewer than the day before"


def test_campaign_and_act_sentences() -> None:
    assert today.campaigns_sentence(2, 0).startswith("2 new campaigns formed")
    assert (
        today.campaigns_sentence(0, 1) == "No new campaigns today, but 1 campaign is still active."
    )
    assert "No campaign has been spotted" in today.campaigns_sentence(0, 0)
    assert today.act_sentence(3, 0, 0).startswith("3 servers tried to hand malware")
    assert "also scored high enough" in today.act_sentence(1, 0, 4)
    assert (
        today.act_sentence(0, 0, 0)
        == "Nothing urgent today: no malware downloads and no exploit payloads."
    )
    assert "but no download server was seen" in today.act_sentence(0, 2, 0)


def test_new_week_and_exposure_sentences() -> None:
    assert today.new_week_sentence({}).startswith("Nothing new this week")
    assert today.new_week_sentence({"asn": 1, "url": 2, "command": 3}) == (
        "6 things showed up for the first time this week: 1 network, 2 URLs and 3 commands."
    )
    assert today.new_week_sentence({"url": 1}) == (
        "1 thing showed up for the first time this week: 1 URL."
    )
    assert (
        today.exposure_sentence(3, 0, 0) == "None of the 3 services you listed was targeted today."
    )
    assert today.exposure_sentence(3, 2, 40) == (
        "Attackers went after 2 of the 3 services you listed today, 40 attacks in all."
    )
