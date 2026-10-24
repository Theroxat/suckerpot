from datetime import UTC, datetime

import pytest

from api.cursor import (
    InvalidCursorError,
    decode_cursor,
    encode_cursor,
    event_cursor,
    parse_event_cursor,
    parse_session_cursor,
    session_cursor,
)


def test_roundtrip_generic() -> None:
    assert decode_cursor(encode_cursor(["a", 3])) == ["a", 3]


def test_cursor_is_urlsafe_without_padding() -> None:
    c = encode_cursor(["2026-10-24T10:00:00+00:00", "s~~?>>"])
    assert "=" not in c and "+" not in c and "/" not in c


def test_session_roundtrip() -> None:
    ts = datetime(2026, 10, 24, 10, 0, 0, 123456, tzinfo=UTC)
    assert parse_session_cursor(session_cursor(ts, "abc-1")) == (ts, "abc-1")


def test_event_roundtrip() -> None:
    ts = datetime(2026, 10, 24, 10, 0, 0, tzinfo=UTC)
    assert parse_event_cursor(event_cursor(ts, 42)) == (ts, 42)


@pytest.mark.parametrize(
    "bad",
    ["", "!!!", "bm90LWpzb24", encode_cursor([]), "x" * 600],
)
def test_invalid_cursors(bad: str) -> None:
    with pytest.raises(InvalidCursorError):
        parse_session_cursor(bad)


def test_naive_timestamp_rejected() -> None:
    with pytest.raises(InvalidCursorError):
        parse_session_cursor(encode_cursor(["2026-10-24T10:00:00", "a"]))


def test_wrong_types_rejected() -> None:
    with pytest.raises(InvalidCursorError):
        parse_event_cursor(encode_cursor(["2026-10-24T10:00:00+00:00", "nope"]))
    with pytest.raises(InvalidCursorError):
        decode_cursor(encode_cursor([True]))


@pytest.mark.parametrize("eid", [-1, 2**63])
def test_event_id_bounds(eid: int) -> None:
    with pytest.raises(InvalidCursorError):
        parse_event_cursor(encode_cursor(["2026-10-24T10:00:00+00:00", eid]))


def test_event_id_max_ok() -> None:
    ts = datetime(2026, 10, 24, tzinfo=UTC)
    assert parse_event_cursor(event_cursor(ts, 2**63 - 1)) == (ts, 2**63 - 1)
