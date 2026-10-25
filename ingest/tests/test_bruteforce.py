"""Per-source brute-force tracker: window, per-key isolation and the LRU bound."""

from datetime import timedelta
from pathlib import Path

import pytest

from ingest.aggregate import compute_session_deltas
from ingest.bruteforce import BruteForceTracker
from ingest.enrichment.enricher import Enricher
from ingest.enrichment.geo import GeoResolver
from ingest.tagging import load_rules
from ingest.writer import _enrich_rows, event_to_row

from .helpers import T0, make_event


def test_fires_at_threshold_only() -> None:
    t = BruteForceTracker(threshold=20)
    results = [t.record("192.0.2.1", "mysql", T0 + timedelta(seconds=i)) for i in range(20)]
    assert results == [False] * 19 + [True]


def test_slow_attempts_outside_window_do_not_count() -> None:
    t = BruteForceTracker(threshold=5, window=timedelta(minutes=10))
    assert not any(t.record("192.0.2.1", "mssql", T0 + timedelta(minutes=3 * i)) for i in range(20))


def test_keys_are_per_ip_and_per_sensor() -> None:
    t = BruteForceTracker(threshold=3)
    for i in range(2):
        t.record("192.0.2.1", "mysql", T0 + timedelta(seconds=i))
        t.record("192.0.2.1", "redis", T0 + timedelta(seconds=i))
        t.record("192.0.2.2", "mysql", T0 + timedelta(seconds=i))
    assert t.record("192.0.2.1", "mysql", T0 + timedelta(seconds=3))
    assert not t.record("192.0.2.3", "mysql", T0 + timedelta(seconds=3))


def test_lru_bound_and_eviction_order() -> None:
    t = BruteForceTracker(threshold=2, max_keys=100)
    for i in range(1000):
        t.record(f"198.51.100.{i % 250}", f"s{i}", T0)
    assert len(t) == 100
    t2 = BruteForceTracker(threshold=2, max_keys=2)
    t2.record("192.0.2.1", "a", T0)
    t2.record("192.0.2.2", "a", T0)
    t2.record("192.0.2.1", "a", T0)  # refresh: .2 is now the oldest
    t2.record("192.0.2.3", "a", T0)  # evicts .2
    assert not t2.record("192.0.2.2", "a", T0)  # forgotten, starts over
    assert len(t2) == 2


def test_per_key_memory_is_capped() -> None:
    t = BruteForceTracker(threshold=20)
    for _ in range(10_000):
        t.record("192.0.2.1", "redis", T0)
    assert len(t._seen[("192.0.2.1", "redis")]) == 20


def test_invalid_config() -> None:
    with pytest.raises(ValueError, match="positive"):
        BruteForceTracker(threshold=0)


def test_writer_tags_event_and_session_across_connections(tmp_path: Path) -> None:
    rules = load_rules(Path(__file__).resolve().parents[1] / "rules")
    enricher = Enricher(GeoResolver(tmp_path, fake_for_private=True), rules)
    events = [
        make_event("login_attempt", sid=f"c{i}", sensor="mysql", offset_s=i,
                   data={"username": "root", "success": False})
        for i in range(25)
    ]  # fmt: skip
    events.append(make_event("login_attempt", sid="other", sensor="mysql", ip="192.0.2.77"))
    rows = [event_to_row(e) for e in events]
    deltas = compute_session_deltas(events)
    _enrich_rows(events, rows, deltas, enricher, {})
    tagged = {d.session_id for d in deltas if "credential-stuffing" in d.tags}
    assert tagged == {f"c{i}" for i in range(19, 25)}
    assert (
        "credential-stuffing" in rows[24]["tags"] and "credential-stuffing" not in rows[0]["tags"]
    )
    assert "other" not in tagged
