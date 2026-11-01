"""Which UTC day to send and when (design M29, N5). Pure functions.

A day is sent only after it ended, plus a random wait of 2 to 20 hours, so that the moment of a
submission says nothing about the moment of an attack. At most the last two closed days are ever
sent: an older day is skipped, never back-filled.
"""

from __future__ import annotations

import random
from collections.abc import Collection
from datetime import UTC, date, datetime, time, timedelta

MAX_DAYS_BACK = 2


def utc_today(now: datetime) -> date:
    return now.astimezone(UTC).date()


def last_closed_day(now: datetime) -> date:
    """The most recent UTC day that has ended."""
    return utc_today(now) - timedelta(days=1)


def day_start(day: date) -> datetime:
    return datetime.combine(day, time.min, tzinfo=UTC)


def next_submit_at(
    now: datetime,
    min_h: float,
    max_h: float,
    rng: random.Random | None = None,
) -> datetime:
    """Midnight after the current day plus a uniform delay in [min_h, max_h] hours."""
    r = rng or random.SystemRandom()
    midnight = day_start(utc_today(now) + timedelta(days=1))
    return midnight + timedelta(hours=r.uniform(min_h, max_h))


def due_days(
    now: datetime,
    next_at: datetime | None,
    submitted: Collection[date],
    *,
    since: date | None = None,
) -> list[date]:
    """Closed days to send now, oldest first.

    Nothing is due before ``next_at`` (the random release time of the first day that closed
    after the previous submission). ``since`` (the enrolment day) keeps a new member from
    sending days that predate the enrolment.
    """
    if next_at is not None and now < next_at:
        return []
    newest = last_closed_day(now)
    days = [newest - timedelta(days=n) for n in range(MAX_DAYS_BACK - 1, -1, -1)]
    return [d for d in days if d not in submitted and (since is None or d >= since)]
