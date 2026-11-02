"""When to ask the listing services about a target (design M27 section 4.2). Pure."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Final

LISTING_OFFSETS: Final = (
    timedelta(0),
    timedelta(hours=24),
    timedelta(days=7),
    timedelta(days=30),
)
RETRY_AFTER: Final = timedelta(minutes=15)


def first_listing_at(reported_at: datetime) -> datetime:
    """The first slot: the report time itself (due at once, a baseline)."""
    return reported_at + LISTING_OFFSETS[0]


def next_listing_at(
    step: int, reported_at: datetime, now: datetime, track_until: datetime
) -> tuple[int, datetime | None]:
    """The slot after the check of slot ``step`` ran at ``now``.

    Slots are ``reported_at + LISTING_OFFSETS[i]``; slots already in the past are skipped (a
    target created late gets one immediate baseline, then the next slot in the future). Returns
    ``(step, None)`` when no slot is left inside the tracking period.
    """
    nxt = max(step, -1) + 1
    while nxt < len(LISTING_OFFSETS):
        at = reported_at + LISTING_OFFSETS[nxt]
        if at > now:
            return (nxt, at) if at <= track_until else (len(LISTING_OFFSETS), None)
        nxt += 1
    return len(LISTING_OFFSETS), None
