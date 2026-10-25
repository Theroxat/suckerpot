"""Event fairness and queue-reserve behaviour (contract lesson 18)."""

from __future__ import annotations

from conftest import FakePublisher
from suckerpot_common import EventType

from smb_sensor.events import EventSink


def _scan(sink: EventSink, ip: str) -> bool:
    return sink.emit(
        session_id="s" + ip.replace(".", ""),
        src_ip=ip,
        src_port=1,
        type_=EventType.scan,
        data={"kind": "non_smb"},
    )


def _login(sink: EventSink, ip: str) -> bool:
    return sink.emit(
        session_id="l" + ip.replace(".", ""),
        src_ip=ip,
        src_port=1,
        type_=EventType.login_attempt,
        data={"username": "x", "success": False},
    )


def test_per_ip_event_bucket_isolates_sources() -> None:
    # A flooding IP exhausts only its own non-priority budget; a victim IP is unaffected.
    sink = EventSink(FakePublisher(), per_ip_events_rate=1.0, per_ip_events_burst=5.0)
    allowed_flood = sum(_scan(sink, "203.0.113.9") for _ in range(50))
    assert allowed_flood <= 6  # bounded by the per-IP burst
    # The victim's first scans still go through on its own bucket.
    assert _scan(sink, "198.51.100.7") is True


def test_queue_reserve_protects_priority_events() -> None:
    # Workers are not started, so the queue fills and the reserve logic is exercised directly.
    sink = EventSink(
        FakePublisher(),
        per_ip_events_rate=1000.0,
        per_ip_events_burst=1000.0,
        events_rate=1000.0,
        events_burst=1000.0,
        queue_size=10,
        reserve_fraction=0.2,  # reserve = 2 slots
    )
    accepted = sum(_scan(sink, "203.0.113.9") for _ in range(20))
    assert accepted == 8  # non-priority stops at size - reserve
    # A priority event from a victim still fits in the reserved tail.
    assert _login(sink, "198.51.100.7") is True
    assert _login(sink, "198.51.100.7") is True
    # Once the queue is truly full, even priority is dropped (counted, never raised).
    assert _login(sink, "198.51.100.7") is False
    assert sink.queue_full >= 1


def test_priority_events_skip_per_ip_bucket() -> None:
    sink = EventSink(FakePublisher(), per_ip_events_rate=0.01, per_ip_events_burst=1.0)
    # Non-priority quickly exhausted for this IP...
    for _ in range(5):
        _scan(sink, "203.0.113.9")
    # ...but priority events from the same IP are not gated by the per-IP non-priority bucket.
    assert _login(sink, "203.0.113.9") is True
    assert _login(sink, "203.0.113.9") is True
