"""Pure session-delta computation for a batch of events."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from suckerpot_common import Event


@dataclass(slots=True)
class SessionDelta:
    """What a batch contributes to one session row."""

    session_id: str
    sensor: str
    src_ip: str
    src_port: int
    dst_port: int
    started_at: datetime
    last_event_at: datetime
    ended_at: datetime | None = None
    event_count: int = 0
    login_attempts: int = 0
    login_success: bool = False
    commands: int = 0
    downloads: int = 0
    http_requests: int = 0


def compute_session_deltas(events: Iterable[Event]) -> list[SessionDelta]:
    """Group events by session and compute counter deltas.

    Output is sorted by session_id so concurrent writers lock rows in a stable order.
    """
    deltas: dict[str, SessionDelta] = {}
    for ev in sorted(events, key=lambda e: e.ts):
        d = deltas.get(ev.session_id)
        if d is None:
            d = SessionDelta(
                session_id=ev.session_id,
                sensor=str(ev.sensor),
                src_ip=str(ev.src_ip),
                src_port=ev.src_port,
                dst_port=ev.dst_port,
                started_at=ev.ts,
                last_event_at=ev.ts,
            )
            deltas[ev.session_id] = d
        d.event_count += 1
        d.started_at = min(d.started_at, ev.ts)
        d.last_event_at = max(d.last_event_at, ev.ts)
        etype = str(ev.type)
        if etype == "login_attempt":
            d.login_attempts += 1
            if ev.data.get("success") is True:
                d.login_success = True
        elif etype == "command":
            d.commands += 1
        elif etype == "download_attempt":
            d.downloads += 1
        elif etype == "http_request":
            d.http_requests += 1
        elif etype == "disconnect":
            d.ended_at = ev.ts if d.ended_at is None else max(d.ended_at, ev.ts)
    return sorted(deltas.values(), key=lambda x: x.session_id)
