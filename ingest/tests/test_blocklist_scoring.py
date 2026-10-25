"""Scoring of blocklist candidates, and the override and cut-off rules (pure code)."""

from datetime import UTC, datetime, timedelta

from ingest.blocklist.scoring import (
    KNOWN_SCANNER_CAP,
    REASONS,
    IndicatorFacts,
    IpFacts,
    score_indicator,
    score_ip,
)
from ingest.blocklist.worker import Candidate, apply_overrides, select_top

NOW = datetime(2026, 10, 1, tzinfo=UTC)


def ip(**kw: object) -> IpFacts:
    base: dict[str, object] = {
        "sessions": 1, "sensors": 1, "login_attempts": 0, "login_success": False, "commands": 0,
        "downloads": 0, "max_abuse": None, "known_scanner": False, "in_campaign": False,
    }  # fmt: skip
    return IpFacts(**{**base, **kw})  # type: ignore[arg-type]


def test_a_lone_connection_scores_low_and_a_dropper_scores_high() -> None:
    assert score_ip(ip()).score < 10
    dropper = score_ip(ip(commands=4, downloads=1, login_success=True, login_attempts=3))
    assert dropper.score >= 60
    assert {"ran-commands", "dropped-malware", "login-succeeded"} <= set(dropper.reasons)


def test_a_heavy_brute_forcer_with_reports_reaches_the_default_feed_threshold() -> None:
    r = score_ip(ip(login_attempts=60, max_abuse=100))
    assert r.score >= 50
    assert "brute-force" in r.reasons and "reported-abusive" in r.reasons


def test_a_mass_scanner_is_capped_unless_it_did_harm() -> None:
    quiet = score_ip(ip(sessions=30, login_attempts=40, max_abuse=100, known_scanner=True))
    assert quiet.score == KNOWN_SCANNER_CAP and "mass-scanner" in quiet.reasons
    harmful = score_ip(ip(sessions=30, commands=3, max_abuse=100, known_scanner=True))
    assert harmful.score > KNOWN_SCANNER_CAP


def test_scores_stay_within_bounds_and_reasons_are_known_codes() -> None:
    r = score_ip(
        ip(sessions=99, sensors=4, login_attempts=999, login_success=True, commands=9,
           downloads=9, max_abuse=100, in_campaign=True,
           tags=frozenset({"php2shell", "mirai", "weak-credentials"}))
    )  # fmt: skip
    assert r.score == 100
    assert set(r.reasons) <= set(REASONS)


def test_indicators_score_by_role_intel_and_spread() -> None:
    def facts(**kw: object) -> IndicatorFacts:
        base: dict[str, object] = {
            "kind": "url", "role": "download_host", "sessions": 1, "sources": 1, "sightings": 1,
            "trusted": False, "known": False, "family": None, "in_campaign": False,
        }  # fmt: skip
        return IndicatorFacts(**{**base, **kw})  # type: ignore[arg-type]

    plain = score_indicator(facts())
    contacted = score_indicator(facts(role="contacted_host"))
    known = score_indicator(facts(known=True, family="mirai", sources=4))
    assert contacted.score < plain.score < known.score <= 100
    assert "known-malware" in known.reasons and "seen-from-many-sources" in known.reasons
    assert "file-hash" in score_indicator(facts(kind="hash", role="hash", trusted=True)).reasons


def cand(kind: str, value: str, score: int, last: int = 0) -> Candidate:
    t = NOW - timedelta(hours=last)
    return Candidate(kind, value, score, ["brute-force"], t, t)


def test_allow_removes_and_block_adds_or_raises() -> None:
    base = [cand("ip", "203.0.113.1", 70), cand("ip", "203.0.113.2", 20)]
    out = apply_overrides(
        base,
        [
            {"kind": "ip", "value": "203.0.113.1", "action": "allow", "created_at": NOW},
            {"kind": "ip", "value": "203.0.113.2", "action": "block", "created_at": NOW},
            {"kind": "ip", "value": "198.51.100.9", "action": "block", "created_at": NOW},
            {
                "kind": "ip",
                "value": ".".join(("10", "0", "0", "1")),
                "action": "block",
                "created_at": NOW,
            },
            {"kind": "domain", "value": "github.com", "action": "block", "created_at": NOW},
        ],
    )
    by = {c.value: c for c in out}
    assert set(by) == {"203.0.113.2", "198.51.100.9"}
    assert by["203.0.113.2"].score == 100 and by["203.0.113.2"].reasons[0] == "manual-block"
    assert by["198.51.100.9"].sessions == 0


def test_select_top_drops_noise_orders_by_score_and_caps() -> None:
    items = [
        cand("ip", "203.0.113.1", 9),
        cand("ip", "203.0.113.2", 40, last=5),
        cand("ip", "203.0.113.3", 40, last=1),
        cand("ip", "203.0.113.4", 90),
    ]
    top = select_top(items, 3)
    assert [c.value for c in top] == ["203.0.113.4", "203.0.113.3", "203.0.113.2"]


def test_one_source_typing_a_download_five_times_stays_below_the_feed_threshold() -> None:
    planted = IndicatorFacts(
        kind="url", role="download_host", sessions=1, sources=1, sightings=5, trusted=False,
        known=False, family=None, in_campaign=False,
    )  # fmt: skip
    assert score_indicator(planted).score < 50
    spread = IndicatorFacts(
        kind="url", role="download_host", sessions=3, sources=3, sightings=3, trusted=False,
        known=False, family=None, in_campaign=False,
    )  # fmt: skip
    assert score_indicator(spread).score >= 50
    confirmed = IndicatorFacts(
        kind="url", role="download_host", sessions=1, sources=1, sightings=1, trusted=False,
        known=True, family="mirai", in_campaign=False,
    )  # fmt: skip
    assert score_indicator(confirmed).score >= 50
    typed_hash = IndicatorFacts(
        kind="hash", role="hash", sessions=1, sources=1, sightings=1, trusted=False,
        known=False, family=None, in_campaign=False,
    )  # fmt: skip
    assert score_indicator(typed_hash).score < 50
