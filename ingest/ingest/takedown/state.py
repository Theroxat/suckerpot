"""The state of a target and its time to takedown (design M27 section 5). Pure.

``decide`` turns the checks of a target into ``up`` / ``down`` / ``changed`` / ``unknown``:

* a single failing check never turns ``up`` into ``down``: two down checks, far enough apart,
  are needed (1 h when both are strong signals, 6 h when one is weak);
* a command-and-control address is never ``down``: it is never contacted, so only passive
  signals (a new sample points to it, a listing was refreshed) can say it is still used;
* an attacking address is ``up`` ("active") while our own sensors keep seeing it, ``down``
  ("quiet") after ``quiet_days`` without a sighting; it is never "taken down".

When the checks do not decide, the previous state is kept.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

UP: Final = "up"
DOWN: Final = "down"
CHANGED: Final = "changed"
UNKNOWN: Final = "unknown"

STRONG_DOWN: Final = frozenset({"http_404", "http_410", "http_4xx", "suspended_page", "empty"})
WEAK_DOWN: Final = frozenset({"unreachable", "timeout", "http_5xx"})
HTTP_UP: Final = frozenset({"same", "up_unhashed"})
HTTP_CHANGED: Final = frozenset({"changed", "changed_not_stored"})
# refused / redirect_limit / bad_redirect say nothing about the host: they are skipped.
STRONG_GAP: Final = timedelta(hours=1)
WEAK_GAP: Final = timedelta(hours=6)
ACTIVE_WINDOW: Final = timedelta(hours=72)


@dataclass(frozen=True, slots=True)
class Check:
    checked_at: datetime
    method: str
    outcome: str
    sha256: str | None = None


@dataclass(frozen=True, slots=True)
class TargetView:
    kind: str
    role: str
    reported_at: datetime
    http_eligible: bool
    state: str = UNKNOWN
    state_since: datetime | None = None
    baseline_sha256: str | None = None
    last_up_at: datetime | None = None
    first_down_at: datetime | None = None
    resurrections: int = 0
    down_before_report: bool = False


@dataclass(frozen=True, slots=True)
class ChildView:
    state: str
    last_up_at: datetime | None
    first_down_at: datetime | None


@dataclass(frozen=True, slots=True)
class Decision:
    state: str
    source: str | None
    state_since: datetime | None
    last_up_at: datetime | None
    first_down_at: datetime | None
    resurrections: int
    down_before_report: bool


def _http_confirmed_down(streak: Sequence[Check]) -> bool:
    """Whether the last two informative HTTP checks are down codes far enough apart."""
    if len(streak) < 2:
        return False
    a, b = streak[-2], streak[-1]
    if a.outcome not in STRONG_DOWN | WEAK_DOWN or b.outcome not in STRONG_DOWN | WEAK_DOWN:
        return False
    both_strong = a.outcome in STRONG_DOWN and b.outcome in STRONG_DOWN
    return b.checked_at - a.checked_at >= (STRONG_GAP if both_strong else WEAK_GAP)


def _down_streak_start(informative: Sequence[Check]) -> Check:
    """First check of the trailing run of down codes."""
    start = len(informative) - 1
    while start > 0 and informative[start - 1].outcome in STRONG_DOWN | WEAK_DOWN:
        start -= 1
    return informative[start]


def _http_state(
    t: TargetView, checks: Sequence[Check]
) -> tuple[str, datetime | None, datetime | None] | None:
    """(state, down-since check time, up-at) from the HTTP checks, or None when undecided."""
    known = HTTP_UP | HTTP_CHANGED | STRONG_DOWN | WEAK_DOWN
    informative = [c for c in checks if c.method == "http" and c.outcome in known]
    if not informative:
        return None
    last = informative[-1]
    if last.outcome in HTTP_UP:
        return UP, None, last.checked_at
    if last.outcome in HTTP_CHANGED:
        if (
            last.sha256 is not None
            and t.baseline_sha256 is not None
            and last.sha256 == t.baseline_sha256
        ):
            return UP, None, last.checked_at  # the baseline file came back
        return CHANGED, None, last.checked_at
    if _http_confirmed_down(informative):
        return DOWN, _down_streak_start(informative).checked_at, None
    return None


def _listing_state(checks: Sequence[Check]) -> tuple[str, datetime | None, datetime | None] | None:
    urlhaus = [c for c in checks if c.method == "urlhaus"]
    for c in reversed(urlhaus):
        if c.outcome == "online":
            return UP, None, c.checked_at
        if c.outcome == "offline":
            return DOWN, c.checked_at, None
        if c.outcome in ("unknown_status", "not_listed"):
            return None
    return None


def decide(
    target: TargetView,
    checks: Sequence[Check],
    now: datetime,
    *,
    children: Sequence[ChildView] = (),
    quiet_days: int = 7,
) -> Decision:
    """The new state of ``target``. ``checks`` are ordered oldest first."""
    checks = sorted(checks, key=lambda c: c.checked_at)
    verdict: tuple[str, str, datetime | None, datetime | None] | None = (
        None  # state, source, down, up
    )

    if target.role == "payload_url":
        res = _http_state(target, checks) if target.http_eligible else _listing_state(checks)
        if res is not None:
            verdict = (res[0], "http" if target.http_eligible else "urlhaus", res[1], res[2])
    elif target.role == "payload_host":
        if children:
            if any(c.state in (UP, CHANGED) for c in children):
                ups = [c.last_up_at for c in children if c.last_up_at is not None]
                verdict = (UP, "children", None, max(ups) if ups else None)
            elif all(c.state == DOWN for c in children):
                downs = [c.first_down_at for c in children if c.first_down_at is not None]
                verdict = (DOWN, "children", max(downs) if downs else now, None)
        else:
            res = _listing_state(checks)
            if res is not None:
                verdict = (res[0], "urlhaus", res[1], res[2])
    elif target.role == "c2":
        # Never down: the address is never contacted.
        for c in reversed(checks):
            if (c.method == "samples" and c.outcome == "new_sample") or (
                c.method == "threatfox" and c.outcome == "listed"
            ):
                verdict = (UP, c.method, None, c.checked_at)
                break
    elif target.role == "attack_source":
        verdict = _attack_source(target, checks, now, quiet_days)

    prev = target.state
    state = verdict[0] if verdict is not None else prev
    source = verdict[1] if verdict is not None else None
    last_up = target.last_up_at
    first_down = target.first_down_at
    resurrections = target.resurrections
    if verdict is not None:
        if verdict[3] is not None and (last_up is None or verdict[3] > last_up):
            last_up = verdict[3]
        if state == DOWN and first_down is None:
            first_down = verdict[2]
    if prev == DOWN and state in (UP, CHANGED) and target.role != "attack_source":
        resurrections += 1
    since = target.state_since if state == prev else now
    return Decision(
        state=state,
        source=source,
        state_since=since,
        last_up_at=last_up,
        first_down_at=first_down,
        resurrections=resurrections,
        down_before_report=target.down_before_report
        or _down_before_report(target, checks, first_down),
    )


def _attack_source(
    target: TargetView, checks: Sequence[Check], now: datetime, quiet_days: int
) -> tuple[str, str, datetime | None, datetime | None] | None:
    sightings = [c for c in checks if c.method == "sightings"]
    if sightings and sightings[-1].outcome == "seen":
        return UP, "sightings", None, sightings[-1].checked_at
    for c in reversed(checks):
        if c.method == "abuseipdb" and c.outcome == "reported_after":
            if now - c.checked_at <= ACTIVE_WINDOW:
                return UP, "abuseipdb", None, c.checked_at
            break
    if sightings and sightings[-1].outcome == "not_seen":
        last_seen = max(
            (c.checked_at for c in sightings if c.outcome == "seen"), default=target.reported_at
        )
        quiet_since = max(target.reported_at, last_seen)
        if now - quiet_since >= timedelta(days=quiet_days):
            return DOWN, "sightings", now, None
        return UNKNOWN, "sightings", None, None  # not seen lately, but not quiet for long enough
    return None


def _down_before_report(
    target: TargetView, checks: Sequence[Check], first_down: datetime | None
) -> bool:
    """The very first HTTP check (the baseline) was already a confirmed down, within an hour of
    the report: the host was gone before anyone asked."""
    if target.role != "payload_url" or not target.http_eligible or first_down is None:
        return False
    http = [c for c in checks if c.method == "http"]
    if not http:
        return False
    baseline = http[0]
    return (
        baseline.checked_at == first_down and baseline.checked_at - target.reported_at <= STRONG_GAP
    )
