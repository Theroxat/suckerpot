"""``decide``: every row of the state table of the design (M27 section 5), on fixed clocks."""

from datetime import UTC, datetime, timedelta

from ingest.takedown.state import (
    CHANGED,
    DOWN,
    UNKNOWN,
    UP,
    Check,
    ChildView,
    TargetView,
    decide,
)

REPORTED = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
BASE = "a" * 64
OTHER = "b" * 64


def at(hours: float) -> datetime:
    return REPORTED + timedelta(hours=hours)


def http(hours: float, outcome: str, sha: str | None = None) -> Check:
    return Check(at(hours), "http", outcome, sha)


def url(**kw: object) -> TargetView:
    base: dict[str, object] = {
        "kind": "url", "role": "payload_url", "reported_at": REPORTED, "http_eligible": True,
        "baseline_sha256": BASE,
    }  # fmt: skip
    base.update(kw)
    return TargetView(**base)  # type: ignore[arg-type]


def test_same_file_is_up() -> None:
    d = decide(url(), [http(0, "same", BASE)], at(1))
    assert (d.state, d.source, d.last_up_at) == (UP, "http", at(0))
    assert decide(url(), [http(0, "up_unhashed")], at(1)).state == UP


def test_a_different_file_is_changed_but_the_baseline_coming_back_is_up() -> None:
    assert decide(url(), [http(0, "changed", OTHER)], at(1)).state == CHANGED
    assert decide(url(), [http(0, "changed_not_stored", OTHER)], at(1)).state == CHANGED
    assert decide(url(), [http(0, "changed", BASE)], at(1)).state == UP


def test_one_failing_check_never_turns_up_into_down() -> None:
    d = decide(url(state=UP), [http(0, "same"), http(2, "http_404")], at(3))
    assert d.state == UP and d.first_down_at is None
    d = decide(url(state=UNKNOWN), [http(2, "http_404")], at(3))
    assert d.state == UNKNOWN


def test_two_strong_codes_an_hour_apart_confirm_the_takedown() -> None:
    checks = [http(0, "same"), http(1, "http_404"), http(2.5, "http_410")]
    d = decide(url(state=UP), checks, at(3))
    assert d.state == DOWN and d.source == "http"
    assert d.first_down_at == at(1)  # first check of the down streak
    assert d.state_since == at(3)


def test_strong_codes_less_than_an_hour_apart_do_not_confirm() -> None:
    checks = [http(1, "http_404"), http(1.5, "empty")]
    assert decide(url(state=UP), checks, at(2)).state == UP


def test_weak_codes_need_six_hours() -> None:
    weak = [http(1, "unreachable"), http(5, "timeout")]
    assert decide(url(state=UP), weak, at(6)).state == UP
    assert decide(url(state=UP), [http(1, "unreachable"), http(8, "http_5xx")], at(9)).state == DOWN
    mixed = [http(1, "http_404"), http(5, "timeout")]
    assert decide(url(state=UP), mixed, at(6)).state == UP  # one weak code: six hours


def test_suspended_page_and_empty_are_strong() -> None:
    checks = [http(1, "suspended_page"), http(3, "empty")]
    assert decide(url(state=UP), checks, at(4)).state == DOWN


def test_refused_and_redirect_codes_say_nothing() -> None:
    d = decide(
        url(state=UP), [http(0, "same"), http(2, "refused"), http(3, "redirect_limit")], at(4)
    )
    assert d.state == UP


def test_resurrection_counts_and_keeps_the_first_down() -> None:
    checks = [http(1, "http_404"), http(3, "http_404"), http(30, "same", BASE)]
    d = decide(
        url(state=DOWN, first_down_at=at(1), last_up_at=at(0), resurrections=0), checks, at(31)
    )
    assert d.state == UP and d.resurrections == 1
    assert d.first_down_at == at(1)  # TTD is the first streak
    assert d.last_up_at == at(30)


def test_a_down_target_stays_down_while_checks_stay_down() -> None:
    checks = [http(1, "http_404"), http(3, "http_404"), http(80, "http_404")]
    d = decide(url(state=DOWN, first_down_at=at(1), state_since=at(3)), checks, at(81))
    assert d.state == DOWN and d.state_since == at(3) and d.resurrections == 0


def test_down_before_report_is_flagged_from_the_baseline() -> None:
    checks = [http(0.2, "http_404"), http(2, "http_404")]
    d = decide(url(), checks, at(3))
    assert d.state == DOWN and d.down_before_report is True
    late = [http(9, "http_404"), http(12, "http_404")]  # first look long after the report
    assert decide(url(), late, at(13)).down_before_report is False
    ok = [http(0.2, "same"), http(2, "http_404"), http(5, "http_404")]
    assert decide(url(), ok, at(6)).down_before_report is False


def test_url_without_http_uses_urlhaus() -> None:
    t = url(http_eligible=False)
    on = Check(at(0), "urlhaus", "online")
    off = Check(at(24), "urlhaus", "offline")
    assert decide(t, [on], at(1)).state == UP
    d = decide(t, [on, off], at(25))
    assert d.state == DOWN and d.source == "urlhaus" and d.first_down_at == at(24)
    assert decide(t, [Check(at(0), "urlhaus", "not_listed")], at(1)).state == UNKNOWN
    assert decide(t, [Check(at(0), "urlhaus", "unknown_status")], at(1)).state == UNKNOWN


def host(**kw: object) -> TargetView:
    base: dict[str, object] = {
        "kind": "ip", "role": "payload_host", "reported_at": REPORTED, "http_eligible": False,
    }  # fmt: skip
    base.update(kw)
    return TargetView(**base)  # type: ignore[arg-type]


def test_host_follows_its_children() -> None:
    up = ChildView(UP, at(5), None)
    changed = ChildView(CHANGED, at(6), None)
    gone = ChildView(DOWN, at(1), at(4))
    gone2 = ChildView(DOWN, at(2), at(9))
    assert decide(host(), [], at(10), children=[up, gone]).state == UP
    assert decide(host(), [], at(10), children=[changed, gone]).state == UP
    d = decide(host(), [], at(10), children=[gone, gone2])
    assert d.state == DOWN and d.source == "children" and d.first_down_at == at(9)
    assert decide(host(), [], at(10), children=[gone, ChildView(UNKNOWN, None, None)]).state == (
        UNKNOWN
    )


def test_host_without_children_uses_the_urlhaus_host_answer() -> None:
    assert decide(host(), [Check(at(0), "urlhaus", "offline")], at(1)).state == DOWN
    assert decide(host(), [Check(at(0), "urlhaus", "online")], at(1)).state == UP
    assert decide(host(), [], at(1)).state == UNKNOWN


def c2(**kw: object) -> TargetView:
    base: dict[str, object] = {
        "kind": "ip", "role": "c2", "reported_at": REPORTED, "http_eligible": False,
    }  # fmt: skip
    base.update(kw)
    return TargetView(**base)  # type: ignore[arg-type]


def test_c2_is_never_down() -> None:
    quiet = [Check(at(i * 24), "threatfox", "not_listed") for i in range(5)]
    quiet += [Check(at(i * 24), "samples", "none") for i in range(5)]
    assert decide(c2(), quiet, at(200)).state == UNKNOWN
    assert decide(c2(state=UP), quiet, at(200)).state == UP  # undecided: unchanged, not down
    d = decide(c2(), [Check(at(30), "samples", "new_sample")], at(31))
    assert d.state == UP and d.source == "samples"
    assert decide(c2(), [Check(at(0), "threatfox", "listed")], at(1)).state == UP


def attacker(**kw: object) -> TargetView:
    base: dict[str, object] = {
        "kind": "ip", "role": "attack_source", "reported_at": REPORTED, "http_eligible": False,
    }  # fmt: skip
    base.update(kw)
    return TargetView(**base)  # type: ignore[arg-type]


def test_attack_source_active_while_seen() -> None:
    checks = [Check(at(1), "sightings", "seen")]
    d = decide(attacker(), checks, at(2))
    assert d.state == UP and d.source == "sightings"


def test_attack_source_quiet_after_seven_days_without_a_sighting() -> None:
    checks = [Check(at(1), "sightings", "seen"), Check(at(10), "sightings", "not_seen")]
    assert decide(attacker(state=UP), checks, at(24 * 3)).state == UNKNOWN  # not yet quiet
    d = decide(attacker(state=UNKNOWN), checks, at(1 + 24 * 7 + 1))
    assert d.state == DOWN and d.first_down_at is not None
    assert decide(attacker(), checks, at(1 + 24 * 7 - 2)).state == UNKNOWN


def test_attack_source_quiet_days_is_configurable() -> None:
    checks = [Check(at(0), "sightings", "not_seen")]
    assert decide(attacker(), checks, at(24 * 3), quiet_days=3).state == DOWN
    assert decide(attacker(), checks, at(24 * 3), quiet_days=7).state == UNKNOWN


def test_attack_source_reported_after_counts_as_active_for_72_hours() -> None:
    checks = [Check(at(0), "sightings", "not_seen"), Check(at(10), "abuseipdb", "reported_after")]
    assert decide(attacker(), checks, at(20)).state == UP
    assert decide(attacker(), checks, at(10 + 80)).state == UNKNOWN
    quiet = [Check(at(0), "abuseipdb", "quiet")]
    assert decide(attacker(), quiet, at(5)).state == UNKNOWN


def test_resurrection_is_not_counted_for_attacking_addresses() -> None:
    checks = [Check(at(24 * 9), "sightings", "seen")]
    d = decide(attacker(state=DOWN, first_down_at=at(24 * 8)), checks, at(24 * 9 + 1))
    assert d.state == UP and d.resurrections == 0


def test_undecided_keeps_the_previous_state_and_since() -> None:
    d = decide(url(state=UP, state_since=at(0)), [], at(5))
    assert d.state == UP and d.state_since == at(0)
