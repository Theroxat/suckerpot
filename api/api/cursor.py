"""Opaque keyset-pagination cursors (base64url-encoded JSON)."""

from __future__ import annotations

import base64
import binascii
import json
from datetime import UTC, datetime


class InvalidCursorError(ValueError):
    """Raised when a cursor cannot be decoded."""


def encode_cursor(values: list[str | int]) -> str:
    raw = json.dumps(values, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: str) -> list[str | int]:
    if len(cursor) > 512:
        raise InvalidCursorError("cursor too long")
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        values = json.loads(raw)
    except (binascii.Error, ValueError) as exc:
        raise InvalidCursorError("malformed cursor") from exc
    if not isinstance(values, list) or not all(
        isinstance(v, str | int) and not isinstance(v, bool) for v in values
    ):
        raise InvalidCursorError("malformed cursor")
    return values


def session_cursor(started_at: datetime, session_id: str) -> str:
    return encode_cursor([started_at.isoformat(), session_id])


def parse_session_cursor(cursor: str) -> tuple[datetime, str]:
    values = decode_cursor(cursor)
    try:
        ts, sid = values
        if not isinstance(ts, str) or not isinstance(sid, str):
            raise TypeError
        parsed = _aware_utc(ts)
    except (ValueError, TypeError) as exc:
        raise InvalidCursorError("malformed cursor") from exc
    return parsed, sid


MAX_EVENT_ID = 2**63 - 1


def event_cursor(ts: datetime, event_id: int) -> str:
    return encode_cursor([ts.isoformat(), event_id])


def parse_event_cursor(cursor: str) -> tuple[datetime, int]:
    values = decode_cursor(cursor)
    try:
        ts, eid = values
        if not isinstance(ts, str) or not isinstance(eid, int) or not 0 <= eid <= MAX_EVENT_ID:
            raise TypeError
        parsed = _aware_utc(ts)
    except (ValueError, TypeError) as exc:
        raise InvalidCursorError("malformed cursor") from exc
    return parsed, eid


def _aware_utc(value: str) -> datetime:
    """Parse an ISO timestamp, require a timezone and normalise to UTC (400 on overflow)."""
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise InvalidCursorError("malformed cursor")
    try:
        return parsed.astimezone(UTC)
    except (OverflowError, ValueError) as exc:
        raise InvalidCursorError("malformed cursor") from exc
