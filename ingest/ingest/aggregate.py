"""Pure session-delta computation for a batch of events."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
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
    tags: set[str] = field(default_factory=set)
    country: str | None = None
    city: str | None = None
    asn: int | None = None
    org: str | None = None
    abuse_score: int | None = None
    known_scanner: bool | None = None
    client_tool: str | None = None
    techniques: set[str] = field(default_factory=set)
    # A known research scanner (M19), set by the writer's enrichment step.
    benign: bool = False
    scanner_name: str | None = None


_TOOL_MAX = 24
_TOOL_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._- ")


def client_tool_of(sensor: str, data: dict[str, object]) -> str | None:
    """The sensor's client-tool guess, only from the RDP sensor and only if it looks sane."""
    tool = data.get("client_tool")
    if sensor != "rdp" or not isinstance(tool, str):
        return None
    tool = tool.strip()
    if not tool or tool == "unknown" or len(tool) > _TOOL_MAX or not set(tool) <= _TOOL_CHARS:
        return None
    return tool


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
        tool = client_tool_of(d.sensor, ev.data)
        if tool is not None:
            d.client_tool = tool
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
