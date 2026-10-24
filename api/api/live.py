"""Live feed: DB tailing poller, in-process broadcast hub and the WebSocket endpoint.

The API has no Redis access by design, so a single background task per app polls the
``events`` table (``id > last seen`` on the primary-key index, at most 500 rows per tick) and
fans the rows out to every connected WebSocket client.

WebSocket messages (JSON text frames, server to client):

* ``{"kind": "backfill", "events": [LiveEvent, ...]}``: once on connect, newest first
* ``{"kind": "event", "event": LiveEvent}``: one per new event, oldest first
* ``{"kind": "stats", "stats": {...}}``: every 5 s (and once on connect when available)
* ``{"kind": "dropped", "count": n}``: this client was too slow, n messages were skipped
* ``{"kind": "pong"}``: reply to a client text frame ``ping``
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
import time
from collections import deque
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, WebSocket
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_db.models import EventRow, SessionRow

from api.schemas import LiveEvent, LiveStats, SensorCounts

log = logging.getLogger(__name__)

MAX_CLIENTS = 50
CLIENT_QUEUE_SIZE = 200
BACKFILL_SIZE = 50
POLL_INTERVAL_S = 1.0
STATS_INTERVAL_S = 5.0
POLL_LIMIT = 500
SEND_TIMEOUT_S = 10.0
SUMMARY_MAX = 160
FIELD_MAX = 48

live_router = APIRouter()

_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _clean(value: Any, limit: int = FIELD_MAX) -> str:
    text = _CTRL.sub("?", str(value))
    return text if len(text) <= limit else text[: limit - 1] + "…"


def build_summary(etype: str, data: Mapping[str, Any] | None) -> str:
    """One short human line describing an event (attacker-controlled text is sanitised)."""
    d: Mapping[str, Any] = data or {}
    if etype == "connect":
        return "connected"
    if etype == "login_attempt":
        outcome = "succeeded" if d.get("success") is True else "failed"
        return f"login {_clean(d.get('username', ''))}/{_clean(d.get('password', ''))} {outcome}"
    if etype == "command":
        return f"ran `{_clean(d.get('input', ''), 100)}`"
    if etype == "http_request":
        status = d.get("status")
        suffix = f" → {_clean(status, 6)}" if status not in (None, "") else ""
        path = _clean(d.get("path", "/"), 100)
        return f"{_clean(d.get('method', 'GET'), 10)} {path}{suffix}"
    if etype == "download_attempt":
        tool = d.get("tool")
        via = f" via {_clean(tool, 16)}" if tool else ""
        return f"download {_clean(d.get('url', ''), 100)}{via}"
    if etype == "disconnect":
        duration = d.get("duration_s")
        if isinstance(duration, int | float) and not isinstance(duration, bool):
            return f"disconnected after {duration:.0f}s"
        return "disconnected"
    if etype == "scan":
        return "probe"
    return _clean(etype, 24)


_LIVE_COLUMNS = (
    EventRow.id,
    EventRow.ts,
    EventRow.sensor,
    EventRow.session_id,
    EventRow.type,
    EventRow.src_ip,
    EventRow.src_port,
    EventRow.dst_port,
    EventRow.data,
    EventRow.country,
    EventRow.city,
    EventRow.asn,
    EventRow.org,
    EventRow.abuse_score,
    EventRow.known_scanner,
    EventRow.tags,
)


def row_to_live(row: Any) -> LiveEvent:
    return LiveEvent(
        id=row.id,
        ts=row.ts,
        sensor=row.sensor,
        session_id=row.session_id,
        type=row.type,
        src_ip=row.src_ip,
        src_port=row.src_port,
        dst_port=row.dst_port,
        summary=build_summary(row.type, row.data),
        country=row.country,
        city=row.city,
        asn=row.asn,
        org=row.org,
        abuse_score=row.abuse_score,
        known_scanner=row.known_scanner,
        tags=list(row.tags or []),
    )


async def fetch_recent(session: AsyncSession, limit: int = BACKFILL_SIZE) -> list[LiveEvent]:
    """Newest events first."""
    stmt = select(*_LIVE_COLUMNS).order_by(EventRow.id.desc()).limit(limit)
    return [row_to_live(r) for r in (await session.execute(stmt)).all()]


async def fetch_after(session: AsyncSession, last_id: int, limit: int = POLL_LIMIT) -> list[Any]:
    """Rows with id greater than ``last_id`` (primary-key index), oldest first."""
    stmt = select(*_LIVE_COLUMNS).where(EventRow.id > last_id).order_by(EventRow.id.asc())
    return list((await session.execute(stmt.limit(limit))).all())


async def fetch_stats(session: AsyncSession) -> LiveStats:
    since = datetime.now(UTC) - timedelta(seconds=60)
    ev = (
        await session.execute(
            select(EventRow.sensor, func.count())
            .where(EventRow.ts >= since)
            .group_by(EventRow.sensor)
        )
    ).all()
    ses = (
        await session.execute(
            select(SessionRow.sensor, func.count())
            .where(SessionRow.started_at >= since)
            .group_by(SessionRow.sensor)
        )
    ).all()
    by_sensor: dict[str, SensorCounts] = {}
    for name, n in ev:
        by_sensor.setdefault(name, SensorCounts(events=0, sessions=0)).events = n
    for name, n in ses:
        by_sensor.setdefault(name, SensorCounts(events=0, sessions=0)).sessions = n
    return LiveStats(
        window_seconds=60,
        events_last_minute=sum(n for _, n in ev),
        sessions_last_minute=sum(n for _, n in ses),
        by_sensor=dict(sorted(by_sensor.items())),
    )


Item = tuple[int | None, str]


class ClientQueue:
    """Bounded per-client queue: when full the oldest message is dropped and counted."""

    def __init__(self, maxsize: int = CLIENT_QUEUE_SIZE) -> None:
        self.maxsize = maxsize
        self.items: deque[Item] = deque()
        self.dropped = 0
        self.closed = False
        self._wake = asyncio.Event()

    def put(self, item: Item) -> None:
        if len(self.items) >= self.maxsize:
            self.items.popleft()
            self.dropped += 1
        self.items.append(item)
        self._wake.set()

    def take_dropped(self) -> int:
        n, self.dropped = self.dropped, 0
        return n

    def close(self) -> None:
        self.closed = True
        self._wake.set()

    async def get(self) -> Item | None:
        """Next item, or None once the queue is closed."""
        while True:
            if self.closed:
                return None
            if self.items:
                return self.items.popleft()
            self._wake.clear()
            await self._wake.wait()


class LiveHub:
    def __init__(self, max_clients: int = MAX_CLIENTS, queue_size: int = CLIENT_QUEUE_SIZE) -> None:
        self.max_clients = max_clients
        self.queue_size = queue_size
        self.clients: set[ClientQueue] = set()
        self.latest_stats: str | None = None

    def add(self) -> ClientQueue | None:
        if len(self.clients) >= self.max_clients:
            return None
        q = ClientQueue(self.queue_size)
        self.clients.add(q)
        return q

    def remove(self, q: ClientQueue) -> None:
        self.clients.discard(q)

    def broadcast_event(self, event: LiveEvent) -> None:
        payload = json.dumps({"kind": "event", "event": event.model_dump(mode="json")})
        for q in self.clients:
            q.put((event.id, payload))

    def broadcast_stats(self, stats: LiveStats) -> None:
        payload = json.dumps({"kind": "stats", "stats": stats.model_dump(mode="json")})
        self.latest_stats = payload
        for q in self.clients:
            q.put((None, payload))

    def close_all(self) -> None:
        for q in list(self.clients):
            q.close()


class LivePoller:
    """Single background task per app: tails ``events`` and feeds the hub."""

    def __init__(
        self,
        factory: async_sessionmaker[AsyncSession],
        hub: LiveHub,
        *,
        interval: float = POLL_INTERVAL_S,
        stats_interval: float = STATS_INTERVAL_S,
    ) -> None:
        self.factory = factory
        self.hub = hub
        self.interval = interval
        self.stats_interval = stats_interval
        self.last_id: int | None = None
        self._last_error_log = 0.0

    async def poll_once(self) -> int:
        """Fetch and broadcast one page of new events. Returns how many were broadcast."""
        async with self.factory() as session:
            if self.last_id is None:
                self.last_id = (await session.scalar(select(func.max(EventRow.id)))) or 0
                return 0
            rows = await fetch_after(session, self.last_id)
        for row in rows:
            self.hub.broadcast_event(row_to_live(row))
        if rows:
            self.last_id = rows[-1].id
        return len(rows)

    async def stats_once(self) -> None:
        async with self.factory() as session:
            self.hub.broadcast_stats(await fetch_stats(session))

    def _log_error(self, what: str) -> None:
        now = time.monotonic()
        if now - self._last_error_log > 60:
            self._last_error_log = now
            log.exception("live %s failed", what)

    async def run(self) -> None:
        next_stats = 0.0
        while True:
            n = 0
            try:
                n = await self.poll_once()
            except Exception:
                self._log_error("poll")
            if time.monotonic() >= next_stats:
                next_stats = time.monotonic() + self.stats_interval
                try:
                    await self.stats_once()
                except Exception:
                    self._log_error("stats")
            if n < POLL_LIMIT:
                await asyncio.sleep(self.interval)


def _origin_ok(ws: WebSocket) -> bool:
    origin = ws.headers.get("origin")
    if not origin:
        return True  # non-browser client
    host = urlsplit(origin).netloc
    allowed = {ws.headers.get("host", "")}
    extra = os.environ.get("API_ALLOWED_ORIGINS", "")
    allowed.update(urlsplit(o.strip()).netloc for o in extra.split(",") if o.strip())
    return host in allowed


async def _sender(ws: WebSocket, q: ClientQueue, skip_up_to: int) -> None:
    while True:
        item = await q.get()
        if item is None:
            return
        dropped = q.take_dropped()
        if dropped:
            await asyncio.wait_for(
                ws.send_text(json.dumps({"kind": "dropped", "count": dropped})), SEND_TIMEOUT_S
            )
        event_id, text = item
        if event_id is not None and event_id <= skip_up_to:
            continue  # already part of the backfill
        await asyncio.wait_for(ws.send_text(text), SEND_TIMEOUT_S)


async def _receiver(ws: WebSocket, q: ClientQueue) -> None:
    while True:
        msg = await ws.receive()
        if msg["type"] == "websocket.disconnect":
            return
        if msg.get("text") == "ping":
            q.put((None, '{"kind":"pong"}'))


@live_router.websocket("/live")
async def live(ws: WebSocket) -> None:
    hub: LiveHub = ws.app.state.hub
    if not _origin_ok(ws):
        await ws.close(code=1008)
        return
    await ws.accept()
    # Register first so nothing is missed between the backfill query and the first tick.
    q = hub.add()
    if q is None:
        await ws.close(code=1013)
        return
    try:
        async with ws.app.state.session_factory() as session:
            backfill = await fetch_recent(session)
        max_id = max((e.id for e in backfill), default=0)
        await ws.send_text(
            json.dumps(
                {"kind": "backfill", "events": [e.model_dump(mode="json") for e in backfill]}
            )
        )
        if hub.latest_stats:
            await ws.send_text(hub.latest_stats)
        tasks = {
            asyncio.create_task(_sender(ws, q, max_id)),
            asyncio.create_task(_receiver(ws, q)),
        }
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for t in done:
            t.exception()  # mark retrieved; disconnects and timeouts are expected here
        code = 1001 if q.closed else 1000
    except Exception:
        log.warning("live client error", exc_info=True)
        code = 1011
    finally:
        hub.remove(q)
    with contextlib.suppress(Exception):
        await ws.close(code=code)
