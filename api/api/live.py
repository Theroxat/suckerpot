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
import time
import unicodedata
from collections import deque
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, WebSocket
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_db.models import EventRow, SessionRow

from api.schemas import LiveEvent, LiveStats, SensorCounts
from api.sensors import SENSOR_LABELS, SENSORS

log = logging.getLogger(__name__)

MAX_CLIENTS = 50
MAX_CLIENTS_PER_IP = 5
BACKFILL_CONCURRENCY = 8
CLIENT_QUEUE_SIZE = 200
BACKFILL_SIZE = 50
POLL_INTERVAL_S = 1.0
STATS_INTERVAL_S = 5.0
POLL_LIMIT = 500
SEND_TIMEOUT_S = 10.0
SUMMARY_MAX = 160
FIELD_MAX = 48
SESSION_RECHECK_S = 5.0

live_router = APIRouter()

# Format (bidi overrides, zero-width, BOM), line/paragraph separators, surrogates, private use.
_STRIPPED = frozenset({"Cf", "Zl", "Zp", "Cs", "Co"})


def _sanitize(value: str) -> str:
    out: list[str] = []
    for ch in value:
        cat = unicodedata.category(ch)
        if cat == "Cc":
            out.append("?")
        elif cat not in _STRIPPED:
            out.append(ch)
    return "".join(out)


def _clean(value: Any, limit: int = FIELD_MAX) -> str:
    text = _sanitize(str(value))
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _flags(d: Mapping[str, Any]) -> set[str]:
    flags = d.get("flags")
    if not isinstance(flags, list):
        return set()
    return {f.lower() for f in flags if isinstance(f, str)}


def _image(d: Mapping[str, Any], flags: Sequence[Any]) -> str:
    image = d.get("image")
    if isinstance(image, str) and image:
        return _clean(image, 40)
    for f in flags:
        if isinstance(f, str) and f.lower().startswith("image:"):
            return _clean(f[6:], 40)
    return ""


def _spaced(value: Any, limit: int = 24) -> str:
    return _clean(value, limit).replace("_", " ")


def _first_flag(d: Mapping[str, Any]) -> str | None:
    raw = d.get("flags")
    if isinstance(raw, list):
        return next((f for f in raw if isinstance(f, str) and f), None)
    return None


def _sip_summary(etype: str, d: Mapping[str, Any], flags: set[str]) -> str:
    kind = d.get("kind")
    if kind == "sip_summary":
        n = d.get("messages")
        return (
            f"SIP session summary ({_clean(n, 8)} messages)"
            if n is not None
            else "SIP session summary"
        )
    if kind == "sip_malformed":
        return "SIP malformed message"
    if kind in ("rate_limited", "rate_limited_aggregate"):
        return "SIP rate limited"
    method = d.get("method")
    if not (isinstance(method, str) and method):
        known = [m for m in ("invite", "register", "options") if m in flags or f"{m}_scan" in flags]
        method = known[0] if known else "request"
    name = _clean(method, 16).upper()
    if etype == "login_attempt":
        user = d.get("username")
        who = f" {_clean(user, 32)}" if user else ""
        return f"SIP {name}{who}"
    scan = " scan" if kind == "options_scan" or "options_scan" in flags else ""
    target = d.get("dialled") or d.get("to") or d.get("uri")
    tail = f" to {_clean(target, 60)}" if target else ""
    status = d.get("status", d.get("response_code"))
    code = f" {_clean(status, 6)}" if status not in (None, "") else ""
    agent = d.get("user_agent")
    ua = f" ({_clean(agent, 32)})" if scan and agent else ""
    return f"SIP {name}{scan}{tail}{code}{ua}"


def _smb_summary(etype: str, d: Mapping[str, Any], flags: set[str]) -> str:
    if flags & {"eternalblue", "ms17_010"}:
        return "SMB EternalBlue exploit attempt"
    if etype == "login_attempt":
        if d.get("anonymous") is True or "null_session" in flags:
            return "SMB null session"
        user = _clean(d.get("username") or "?", 40)
        domain = d.get("domain")
        who = f"{_clean(domain, 24)}\\{user}" if domain else user
        return f"SMB NTLM login {who}"
    if "null_session" in flags:
        return "SMB null session"
    kind = d.get("kind")
    dialect = d.get("dialect")
    version = ""
    if dialect:
        version = _clean(dialect, 16)
        if not version.upper().startswith("SMB"):
            version = f"SMB {version}"
    if kind == "smb1_negotiate":
        outcome = d.get("smb1_outcome")
        return f"SMBv1 negotiate ({_spaced(outcome)})" if outcome else "SMBv1 negotiate"
    if kind == "smb1_command":
        name = d.get("smb1_command_name")
        return f"SMBv1 {_spaced(name)}" if name else "SMBv1 probe"
    if not kind:
        if version:
            return f"SMB probe ({version})"
        return "SMBv1 probe" if "smbv1" in flags else "SMB probe"
    name = _spaced(kind)
    return f"SMB {name} ({version})" if version else f"SMB {name}"


def _adb_summary(etype: str, d: Mapping[str, Any], flags: set[str]) -> str | None:
    if etype == "command":
        text = _clean(d.get("input", ""), 100)
        if text.startswith("adb "):
            text = text[4:]
        for verb, flag in (
            ("shell", "adb_shell"),
            ("push", "adb_push"),
            ("install", "adb_install"),
        ):
            if flag in flags and not text.lower().startswith(verb):
                return f"adb {verb} {text}"
        return f"adb {text}"
    if etype == "scan":
        kind = d.get("kind")
        if kind == "adb_service":
            return f"ADB open {_clean(d.get('service', '?'), 40)}"
        if kind == "adb_auth":
            return "ADB auth probe"
    return None


def _rdp_summary(etype: str, d: Mapping[str, Any], flags: set[str]) -> str | None:
    tool = d.get("client_tool")
    tool_name = _clean(tool, 16) if isinstance(tool, str) and tool and tool != "unknown" else ""
    if etype == "login_attempt":
        method = d.get("method")
        user = _clean(d.get("username") or "?", 40)
        domain = d.get("domain")
        password = d.get("password")
        if method == "rdp-nla-off":
            who = f"{_clean(domain, 24)}\\{user}" if domain else user
            return f"RDP cleartext login {who}" + (f" ({tool_name})" if tool_name else "")
        if method == "rdp-ntlm":
            if d.get("anonymous") is True:
                return "RDP null session" + (f" ({tool_name})" if tool_name else "")
            notes = [tool_name] if tool_name else []
            if isinstance(password, str) and password:
                notes.append("weak password")
                tail = f" ({', '.join(notes)})"
                return f"RDP login {user} / {_clean(password, 40)}{tail}"
            who = f"{_clean(domain, 24)}\\{user}" if domain else user
            return f"RDP NTLM login {who}" + (f" ({tool_name})" if tool_name else "")
        if method == "rdp-cookie":
            return f"RDP connection request {user}" + (f" ({tool_name})" if tool_name else "")
        return None
    if etype in ("disconnect", "scan") and "bluekeep_probe" in flags:
        return "BlueKeep probe" + (f" ({tool_name})" if tool_name else "")
    return None


def _service_summary(sensor: str, etype: str, d: Mapping[str, Any]) -> str | None:
    """Sensor-aware one-liners for the non-shell sensors; None falls back to the generic ones."""
    flags = _flags(d)
    raw = d.get("flags")
    raw_flags: list[Any] = raw if isinstance(raw, list) else []
    if sensor == "docker" and etype in ("http_request", "command"):
        if "container_create" in flags or d.get("kind") == "container_create":
            parts = ["docker create"]
            if "privileged" in flags:
                parts.append("privileged")
            if flags & {"host_mount", "docker_sock_mount"}:
                parts.append("host-mount")
            image = _image(d, raw_flags)
            if image:
                parts.append(image)
            return " ".join(parts)
        if etype == "command" and d.get("kind") == "exec":
            return f"docker exec {_clean(d.get('input', ''), 100)}"
        return None
    if sensor in ("redis", "mysql", "mssql", "docker") and etype == "login_attempt":
        outcome = "succeeded" if d.get("success") is True else "failed"
        user = _clean(d.get("username") or ("default" if sensor == "redis" else "?"))
        return f"{sensor} login {user} {outcome}"
    if sensor in ("redis", "mysql", "mssql") and etype == "command":
        return f"{sensor} {_clean(d.get('input', ''), 100)}"
    if sensor == "adb":
        adb = _adb_summary(etype, d, flags)
        if adb is not None:
            return adb
    if sensor == "rdp":
        rdp = _rdp_summary(etype, d, flags)
        if rdp is not None:
            return rdp
    if sensor == "sip" and etype in ("scan", "command", "login_attempt"):
        return _sip_summary(etype, d, flags)
    if sensor == "smb" and etype in ("scan", "command", "login_attempt"):
        return _smb_summary(etype, d, flags)
    if sensor == "redis" and etype == "scan":
        kind = d.get("kind")
        if kind == "redis_replication":
            host, port = d.get("master_host"), d.get("master_port")
            return (
                f"Redis replication from {_clean(host, 60)}:{_clean(port, 6)}"
                if host
                else "Redis replication probe"
            )
        if kind == "cross_protocol":
            guess = d.get("protocol_guess")
            return (
                f"Redis cross-protocol ({_clean(guess, 24)})"
                if guess
                else "Redis cross-protocol probe"
            )
    if sensor in ("redis", "docker", "adb", "mysql", "mssql") and etype == "scan":
        label = SENSOR_LABELS.get(sensor, sensor)
        detail = d.get("kind") or d.get("method") or _first_flag(d)
        return f"{label} probe ({_spaced(detail)})" if detail else f"{label} probe"
    return None


def build_summary(etype: str, data: Mapping[str, Any] | None, sensor: str | None = None) -> str:
    """One short human line describing an event (attacker-controlled text is sanitised)."""
    d: Mapping[str, Any] = data or {}
    if sensor is not None:
        special = _service_summary(sensor, etype, d)
        if special is not None:
            return special
    if etype == "connect":
        return "connected"
    if etype == "login_attempt":
        outcome = "succeeded" if d.get("success") is True else "failed"
        return f"login {_clean(d.get('username', ''))}/{_clean(d.get('password', ''))} {outcome}"
    if etype == "command":
        uploads = d.get("scp_upload")
        if isinstance(uploads, list) and uploads:
            first = uploads[0] if isinstance(uploads[0], Mapping) else {}
            more = f" (+{len(uploads) - 1} more)" if len(uploads) > 1 else ""
            return f"scp upload {_clean(first.get('name', '?'), 60)}{more}"
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
        if d.get("kind") == "tcp_forward_attempt":
            host, port = _clean(d.get("host", "?"), 60), _clean(d.get("port", "?"), 6)
            return f"port-forward attempt to {host}:{port}"
        kind = d.get("kind")
        return f"probe ({_clean(kind, 24)})" if kind else "probe"
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
        summary=build_summary(row.type, row.data, row.sensor),
        country=row.country,
        city=row.city,
        asn=row.asn,
        org=row.org,
        abuse_score=row.abuse_score,
        known_scanner=row.known_scanner,
        tags=list(row.tags or []),
    )


def rows_to_live(rows: Sequence[Any]) -> list[LiveEvent]:
    """Convert rows, skipping (and logging) any row that cannot be rendered."""
    out: list[LiveEvent] = []
    for row in rows:
        try:
            out.append(row_to_live(row))
        except Exception:
            log.warning("skipping unrenderable event id=%s", getattr(row, "id", "?"), exc_info=True)
    return out


async def fetch_recent(session: AsyncSession, limit: int = BACKFILL_SIZE) -> list[LiveEvent]:
    """Newest events first."""
    stmt = select(*_LIVE_COLUMNS).order_by(EventRow.id.desc()).limit(limit)
    return rows_to_live((await session.execute(stmt)).all())


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
    by_sensor: dict[str, SensorCounts] = {s: SensorCounts(events=0, sessions=0) for s in SENSORS}
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
        self.ip = ""
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
    def __init__(
        self,
        max_clients: int = MAX_CLIENTS,
        queue_size: int = CLIENT_QUEUE_SIZE,
        max_per_ip: int = MAX_CLIENTS_PER_IP,
    ) -> None:
        self.max_clients = max_clients
        self.max_per_ip = max_per_ip
        self.queue_size = queue_size
        self.clients: set[ClientQueue] = set()
        self.per_ip: dict[str, int] = {}
        self.latest_stats: str | None = None
        self.backfill_sem = asyncio.Semaphore(BACKFILL_CONCURRENCY)

    def add(self, ip: str = "") -> ClientQueue | None:
        if len(self.clients) >= self.max_clients or self.per_ip.get(ip, 0) >= self.max_per_ip:
            return None
        q = ClientQueue(self.queue_size)
        q.ip = ip
        self.clients.add(q)
        self.per_ip[ip] = self.per_ip.get(ip, 0) + 1
        return q

    def remove(self, q: ClientQueue) -> None:
        if q in self.clients:
            self.clients.discard(q)
            left = self.per_ip.get(q.ip, 1) - 1
            if left > 0:
                self.per_ip[q.ip] = left
            else:
                self.per_ip.pop(q.ip, None)

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
        if rows:
            self.last_id = rows[-1].id  # advance even if some rows cannot be rendered
        for event in rows_to_live(rows):
            self.hub.broadcast_event(event)
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


def normalize_origin(value: str) -> str | None:
    """``scheme://host[:port]`` in canonical form, or None if not a valid http(s) origin."""
    try:
        parts = urlsplit(value.strip())
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not host or parts.path not in ("", "/"):
        return None
    if parts.query or parts.fragment or parts.username or parts.password:
        return None
    host = f"[{host}]" if ":" in host else host.lower()
    default = 80 if scheme == "http" else 443
    return f"{scheme}://{host}" + (f":{port}" if port and port != default else "")


def allowed_origins(env_value: str) -> set[str]:
    out: set[str] = set()
    for raw in env_value.split(","):
        if not raw.strip():
            continue
        norm = normalize_origin(raw)
        if norm is None:
            log.warning("ignoring malformed API_ALLOWED_ORIGINS entry")
        else:
            out.add(norm)
    return out


def _origin_ok(ws: WebSocket) -> bool:
    """Browsers always send Origin on WebSocket handshakes: it must match exactly.

    Same-origin means the scheme the request arrived with (http for ws, https for wss) plus
    the Host header. Behind a TLS-terminating proxy the public origin must be listed in
    API_ALLOWED_ORIGINS. Requests without an Origin header (non-browser clients) pass.
    """
    origin = ws.headers.get("origin")
    if origin is None:
        return True
    norm = normalize_origin(origin)  # "null" and garbage give None
    if norm is None:
        return False
    scheme = "https" if ws.url.scheme == "wss" else "http"
    own = normalize_origin(f"{scheme}://{ws.headers.get('host', '')}")
    allowed = allowed_origins(os.environ.get("API_ALLOWED_ORIGINS", ""))
    if own:
        allowed.add(own)
    return norm in allowed


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


async def _session_watch(auth: Any, token: str | None) -> None:
    """Return once the session expires or is revoked (checked every few seconds)."""
    while True:
        await asyncio.sleep(SESSION_RECHECK_S)
        if auth.validate(token) is None:
            return


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
    auth: Any = ws.app.state.auth
    session = auth.validate(auth.session_token(ws.scope))
    if session is None:
        await ws.close(code=1008)
        return
    await ws.accept()
    # Register first so nothing is missed between the backfill query and the first tick.
    q = hub.add(ws.client.host if ws.client else "")
    if q is None:
        await ws.close(code=1013)
        return
    code = 1011
    tasks: set[asyncio.Task[None]] = set()
    try:
        async with hub.backfill_sem, ws.app.state.session_factory() as session:
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
        watcher = asyncio.create_task(_session_watch(auth, auth.session_token(ws.scope)))
        tasks.add(watcher)
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        code = 1008 if watcher in done else 1001 if q.closed else 1000
    except Exception:
        log.warning("live client error", exc_info=True)
    finally:
        for t in tasks:
            t.cancel()
        # Disconnects and send timeouts are expected here; the gather also retrieves them. The
        # handler itself may be cancelled (server shutdown, test clients) while cleaning up:
        # that is fine, there is nothing left to do but release the slot.
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.gather(*tasks, return_exceptions=True)
        hub.remove(q)
    with contextlib.suppress(Exception, asyncio.CancelledError):
        await ws.close(code=code)
