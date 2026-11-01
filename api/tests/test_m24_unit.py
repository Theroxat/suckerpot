"""Pure helpers of the M24 routes: the rate-limit window and the setup checklist."""

from datetime import UTC, datetime, timedelta

from api.setup_status import _gate_open, _names
from api.vpn_settings import CHECK_MIN_GAP, RECONNECT_MIN_GAP, _too_soon

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def test_too_soon_window() -> None:
    assert _too_soon(CHECK_MIN_GAP, NOW - timedelta(seconds=3), NOW) is not None
    assert _too_soon(CHECK_MIN_GAP, NOW - timedelta(seconds=11), NOW) is None
    assert _too_soon(CHECK_MIN_GAP, NOW + timedelta(hours=1), NOW) is None  # clock skew
    early = _too_soon(RECONNECT_MIN_GAP, NOW - timedelta(seconds=30), NOW)
    assert early is not None and early.status_code == 429
    assert early.headers["retry-after"] == "31"


def test_gate_open_needs_a_fresh_verdict() -> None:
    fresh = {"open": True, "checked_at": (NOW - timedelta(minutes=1)).isoformat()}
    assert _gate_open(fresh, NOW)
    assert not _gate_open({**fresh, "open": False}, NOW)
    assert not _gate_open({**fresh, "checked_at": (NOW - timedelta(hours=1)).isoformat()}, NOW)
    assert not _gate_open({"open": True}, NOW)
    assert not _gate_open(None, NOW)


def test_names_are_capped() -> None:
    assert _names(["a", "b"]) == "a, b"
    assert _names([str(n) for n in range(9)]).endswith("and 3 more")
