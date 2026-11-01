"""Takedown statistics: censoring, medians and the curve, on fixed clocks."""

from datetime import UTC, datetime, timedelta

from suckerpot_db.takedown_stats import (
    Fact,
    curve,
    median_ttd,
    percent,
    still_up_after_tracking,
    ttd_seconds,
    window_counts,
)

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


def fact(
    age_h: float,
    down_after_h: float | None = None,
    *,
    observed_h: float | None = None,
    **kw: object,
) -> Fact:
    reported = NOW - timedelta(hours=age_h)
    seen = age_h if observed_h is None else observed_h
    return Fact(
        role="payload_url",
        provider_key="as64500",
        reported_at=reported,
        observed_until=reported + timedelta(hours=seen),
        first_down_at=None if down_after_h is None else reported + timedelta(hours=down_after_h),
        **kw,  # type: ignore[arg-type]
    )


def test_young_targets_are_left_out_of_the_denominator() -> None:
    facts = [fact(100, 10), fact(100), fact(100, 60), fact(5), fact(20)]  # last two too young
    assert window_counts(facts, 48) == (3, 1)
    # A young target that already went down inside the window does count.
    assert window_counts([*facts, fact(5, 2)], 48) == (4, 2)


def test_half_the_targets_younger_than_the_window() -> None:
    old = [fact(200, 12 if i < 3 else None) for i in range(6)]
    young = [fact(10) for _ in range(6)]
    assert window_counts([*old, *young], 48) == (6, 3)
    assert percent(3, 6) == 50.0


def test_demo_and_down_before_report_are_not_statistics() -> None:
    facts = [fact(100, 1, demo=True), fact(100, 0.1, down_before_report=True), fact(100, 3)]
    assert window_counts(facts, 48) == (1, 1)
    assert ttd_seconds(facts[1]) is None


def test_a_stopped_target_is_observed_only_until_the_stop() -> None:
    assert window_counts([fact(300, observed_h=10)], 48) == (0, 0)


def test_median_needs_five_values() -> None:
    few = [fact(100, h) for h in (1, 2, 3, 4)]
    assert median_ttd(few) == (None, 4)
    many = [*few, fact(100, 100)]
    assert median_ttd(many) == (3 * 3600, 5)
    assert median_ttd([*many, fact(900, 800)], track_days=30)[1] == 5  # past the period: ignored


def test_still_up_after_tracking() -> None:
    facts = [fact(800, tracked_to_end=True), fact(800, 5, tracked_to_end=True), fact(50)]
    assert still_up_after_tracking(facts) == 1


def test_curve_is_cumulative_and_censored() -> None:
    facts = [fact(800, 0.5), fact(800, 5), fact(800, 40), fact(800), fact(2)]
    points = {p["hours"]: p for p in curve(facts)}
    assert points[1]["percent"] == 20.0
    assert points[1]["eligible"] == 5  # the 2-hour-old target was observed for 1 hour
    assert points[6]["percent"] == 50.0
    assert points[48]["percent"] == 75.0
    assert points[48]["eligible"] == 4
    assert curve([])[0]["percent"] is None
