"""M29 links: local abuse reports skip what the network handles; the blocklist gets +2."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ingest.abuse.candidates import Seed, without_network
from ingest.blocklist.scoring import REASONS, Scored, network_bonus
from ingest.blocklist.worker import Candidate, apply_network

T = datetime(2026, 11, 2, tzinfo=UTC)


class FakeSession:
    def __init__(self, values: list[str]) -> None:
        self.values = values
        self.sql = ""

    async def execute(self, stmt: Any = None, *_: Any, **__: Any) -> list[tuple[str]]:
        self.sql = str(stmt)
        return [(v,) for v in self.values]


def seed(value: str, typ: str = "ip") -> Seed:
    return Seed("attack_source", typ, value, T, T, 1, 1)  # type: ignore[arg-type]


async def test_subjects_the_network_handles_are_skipped() -> None:
    seeds = [seed("198.51.100.23"), seed("198.51.100.24"), seed("Dropper.Example.org", "domain")]
    session: Any = FakeSession(["198.51.100.23", "dropper.example.org"])
    left = await without_network(session, seeds)
    assert [s.value for s in left] == ["198.51.100.24"]


async def test_a_c2_value_with_a_port_matches_its_host() -> None:
    session: Any = FakeSession(["198.51.100.50:23", "[2001:db8::5]:443"])
    left = await without_network(session, [seed("198.51.100.50"), seed("2001:db8::5"), seed("a")])
    assert [s.value for s in left] == ["a"]


async def test_a_non_member_keeps_every_subject() -> None:
    seeds = [seed("198.51.100.23")]
    session: Any = FakeSession([])  # the query joins on state = 'member': no rows
    assert await without_network(session, seeds) == seeds


def test_network_bonus_is_two_points_with_its_reason() -> None:
    assert "network-confirmed" in REASONS
    out = network_bonus(Scored(40, ["ran-commands"]))
    assert out.score == 42 and out.reasons == ["ran-commands", "network-confirmed"]
    assert network_bonus(Scored(99, [])).score == 100
    assert network_bonus(out) == out  # idempotent


def test_apply_network_only_touches_confirmed_candidates() -> None:
    a = Candidate("ip", "198.51.100.23", 40, ["ran-commands"], T, T)
    b = Candidate("ip", "198.51.100.24", 40, ["ran-commands"], T, T)
    apply_network([a, b], {("ip", "198.51.100.23")})
    assert (a.score, b.score) == (42, 40) and "network-confirmed" in a.reasons


async def test_a_merely_confirmed_target_does_not_cancel_the_local_report() -> None:
    session = FakeSession([])
    await without_network(session, [seed("198.51.100.23")])  # type: ignore[arg-type]
    assert "'reported'" in session.sql and "'taken_down'" in session.sql
    assert "'confirmed'" not in session.sql


async def test_the_window_runs_on_the_report_or_takedown_date() -> None:
    session = FakeSession([])
    await without_network(session, [seed("198.51.100.23")])  # type: ignore[arg-type]
    assert "t.reported_day IS NOT NULL" in session.sql
    assert "coalesce(t.taken_down_day, t.reported_day)" in session.sql
    assert "last_day" not in session.sql
    assert ":days" in session.sql  # still a bound parameter
