from ingest.aggregate import compute_session_deltas

from .helpers import T0, make_event


def test_counters_and_times() -> None:
    events = [
        make_event("disconnect", offset_s=30),  # out of order on purpose
        make_event("connect", offset_s=0),
        make_event("login_attempt", offset_s=1, data={"success": False}),
        make_event("login_attempt", offset_s=2, data={"success": True}),
        make_event("command", offset_s=3),
        make_event("command", offset_s=4),
        make_event("download_attempt", offset_s=5),
        make_event("http_request", offset_s=6, sensor="web"),
    ]
    (d,) = compute_session_deltas(events)
    assert d.session_id == "s1"
    assert (d.event_count, d.login_attempts, d.commands, d.downloads, d.http_requests) == (
        8,
        2,
        2,
        1,
        1,
    )
    assert d.login_success is True
    assert d.started_at == T0
    assert d.last_event_at.timestamp() == T0.timestamp() + 30
    assert d.ended_at is not None and d.ended_at.timestamp() == T0.timestamp() + 30
    assert d.sensor == "ssh" and d.src_ip == "203.0.113.7"


def test_no_disconnect_means_no_end_and_no_success() -> None:
    (d,) = compute_session_deltas([make_event("login_attempt", data={"success": "yes"})])
    assert d.ended_at is None
    assert d.login_success is False


def test_multiple_sessions_sorted_by_id() -> None:
    deltas = compute_session_deltas(
        [
            make_event("connect", sid="b"),
            make_event("connect", sid="a"),
            make_event("scan", sid="b"),
        ]
    )
    assert [(d.session_id, d.event_count) for d in deltas] == [("a", 1), ("b", 2)]


def test_empty() -> None:
    assert compute_session_deltas([]) == []
