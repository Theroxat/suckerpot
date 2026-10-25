"""Listener, connection handling and event emission for the Docker sensor."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
import random
import secrets
import socket
import time
from dataclasses import dataclass, field
from email.utils import formatdate
from typing import Any

from suckerpot_common import EventType

from docker_sensor import analysis
from docker_sensor.api import DockerApi, Outcome, Resp
from docker_sensor.config import Config
from docker_sensor.cpu import CpuBudget, Meter
from docker_sensor.events import EventSink, _Buckets
from docker_sensor.httpio import (
    ClientGone,
    ConnReader,
    HttpError,
    IdleTimeout,
    Request,
    SlowRequest,
    parse_head,
    to_text,
)
from docker_sensor.memguard import MemoryGuard

log = logging.getLogger("docker_sensor.server")

# Budgeted bytes per connection: parser state, StreamReader buffer (16 KiB limit, paused at
# twice that), transport buffers and the kernel socket buffers charged to the cgroup.
_CONN_COST = 96 * 1024
_BODY_FACTOR = 4  # a body kept in memory costs about this many times its size while parsed
_READER_LIMIT = 16 * 1024
_SOCK_BUF = 32 * 1024
_LOOPBACK = frozenset({"127.0.0.1", "::1"})
_MAX_HEADERS_LOGGED = 32
_REPEAT_KEEP = 3
_OUT_CHUNK = 64 * 1024  # most pending output one connection may have per write
_OUT_RESERVE = 64 * 1024  # budget reserved for a reply before it is built


def _jsonish(body: bytes) -> bool:
    return len(body) > 4096 and body.lstrip()[:1] in (b"{", b"[")


def _resp_size(resp: Resp) -> int:
    """Bytes a built reply keeps in memory (head and chunk framing included)."""
    size = len(resp.body) + len(resp.raw) + 1024
    if resp.stream is not None:
        size += sum(len(line) + 16 for line in resp.stream)
    return size


_G_HEADERS = 3000
_G_PATH = 1500
_G_BODY = 2500

_REASONS = {
    100: "Continue", 101: "UPGRADED", 200: "OK", 201: "Created", 204: "No Content",
    304: "Not Modified", 400: "Bad Request", 401: "Unauthorized", 404: "Not Found",
    408: "Request Timeout", 409: "Conflict", 413: "Request Entity Too Large",
    414: "Request-URI Too Long", 431: "Request Header Fields Too Large",
    500: "Internal Server Error", 501: "Not Implemented", 503: "Service Unavailable",
    505: "HTTP Version Not Supported",
}  # fmt: skip
_SEVERE_FLAGS = frozenset(
    {"container_create", "privileged", "host_mount", "miner", "exec", "image_pull",
     "registry_credentials", "swarm_join", "swarm_init", "image_build", "image_load",
     "image_import", "commit", "archive_put", "container_start", "docker_sock_mount"}
)  # fmt: skip


def _fit(text: str, limit: int) -> str:
    """Cut ``text`` so that its JSON encoding is at most ``limit`` bytes."""
    text = text[:limit]
    while len(json.dumps(text)) > limit and text:
        text = text[: max(0, len(text) * 3 // 4 - 1)]
    return text


def normalize_ip(raw: str) -> str:
    try:
        addr = ipaddress.ip_address(raw.split("%")[0])
    except ValueError:
        return "0.0.0.0"  # noqa: S104 - placeholder for an unparsable peer address
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return str(addr.ipv4_mapped)
    return str(addr)


class Budget:
    """Global byte budget for per-connection buffers."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.used = 0

    def acquire(self, n: int) -> bool:
        if self.used + n > self.limit:
            return False
        self.used += n
        return True

    def release(self, n: int) -> None:
        self.used = max(0, self.used - n)


class DateCache:
    def __init__(self) -> None:
        self._sec = 0
        self._val = ""

    def get(self) -> str:
        now = int(time.time())
        if now != self._sec:
            self._sec, self._val = now, formatdate(now, usegmt=True)
        return self._val


@dataclass
class Conn:
    sid: str
    ip: str
    port: int
    start: float = field(default_factory=time.monotonic)
    quiet: bool = False
    requests: int = 0
    logins: int = 0
    downloads: int = 0
    commands: int = 0
    repeats: int = 0
    seen: dict[tuple[str, str, str, str, int], int] = field(default_factory=dict)
    bytes_out: int = 0
    flags: set[str] = field(default_factory=set)
    statuses: dict[str, int] = field(default_factory=dict)
    reason: str = "closed"
    transport: asyncio.BaseTransport | None = None
    reader: asyncio.StreamReader | None = None
    cr: ConnReader | None = None
    meter: Meter | None = None
    inflight: int = 0
    cost: int = 0

    def buffered(self) -> int:
        total = self.cost + self.inflight
        if self.reader is not None:
            total += len(getattr(self.reader, "_buffer", b""))
        if self.cr is not None:
            total += len(self.cr.buf)
        t = self.transport
        if isinstance(t, asyncio.WriteTransport):
            with contextlib.suppress(Exception):
                total += t.get_write_buffer_size()
        return total

    def abort(self) -> bool:
        t = self.transport
        if not isinstance(t, asyncio.WriteTransport):
            return False
        with contextlib.suppress(Exception):
            t.abort()
        return True


class DockerSensor:
    """Process-wide state shared by all connections."""

    def __init__(
        self, cfg: Config, sink: EventSink, api: DockerApi, guard: MemoryGuard | None = None
    ) -> None:
        self.cfg = cfg
        self.sink = sink
        self.api = api
        self.budget = Budget(cfg.memory_budget)
        self.dates = DateCache()
        self.guard = guard or MemoryGuard(
            cfg.memory_limit, refuse=cfg.memory_refuse, shed=cfg.memory_shed
        )
        self.total = 0
        self.per_ip: dict[str, int] = {}
        self.live: dict[str, Conn] = {}
        self.rejected = 0
        self.connections_seen = 0
        self.requests_seen = 0
        self._limited: dict[str, int] = {}
        self._slow_close = 0
        self._rate = _Buckets(cfg.conn_rate, cfg.conn_burst)
        self.cpu = CpuBudget(cfg)
        self.held = 0  # open GET /events streams
        self.held_per_ip: dict[str, int] = {}
        self._last_sample = 0.0

    @property
    def cpu_waits(self) -> int:
        return self.cpu.waits

    # -- admission -------------------------------------------------------------------------

    def _note_limited(self, ip: str) -> None:
        if ip in self._limited or len(self._limited) < 2000:
            self._limited[ip] = self._limited.get(ip, 0) + 1

    def flush_limited(self) -> None:
        """One aggregated ``scan`` event per IP for the connections refused since last call."""
        pending, self._limited = self._limited, {}
        for ip, count in pending.items():
            if self.cfg.quiet_loopback and ip in _LOOPBACK:
                continue
            self.sink.emit(
                session_id=secrets.token_hex(8),
                src_ip=ip,
                src_port=0,
                dst_port=self.cfg.public_port,
                type_=EventType.scan,
                data={"kind": "rate_limited", "refused": count, "window_s": 60},
            )

    async def _slow_reject(self, sock: socket.socket) -> None:
        """Refuse less abruptly: read a little, wait a short random time, close."""
        loop = asyncio.get_running_loop()
        if self._slow_close >= 64:
            with contextlib.suppress(OSError):
                sock.close()
            return
        self._slow_close += 1
        try:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(loop.sock_recv(sock, 512), 0.5)
            await asyncio.sleep(random.uniform(0.1, 0.6))  # noqa: S311 - timing jitter only
        finally:
            self._slow_close -= 1
            with contextlib.suppress(OSError):
                sock.close()

    def admit(self, ip: str) -> str | None:
        """Take the slots and budget for a new connection: None if admitted, else why not."""
        cfg = self.cfg
        if cfg.quiet_loopback and ip in _LOOPBACK:
            # The container healthcheck is never refused (a local peer cannot be spoofed).
            self.budget.used += _CONN_COST
            self.total += 1
            self.per_ip[ip] = self.per_ip.get(ip, 0) + 1
            return None
        now = time.monotonic()
        if now - self._last_sample > 0.2:  # cheap: one small file read
            self._last_sample = now
            self.guard.sample()
        if not self._rate.allow(ip):
            reason = "rate"
        elif self.guard.refusing:
            self.guard.refused += 1
            reason = "memory"
        elif self.total >= cfg.max_connections or self.per_ip.get(ip, 0) >= cfg.max_per_ip:
            reason = "cap"
        elif not self.budget.acquire(_CONN_COST):
            reason = "budget"
        else:
            self.total += 1
            self.per_ip[ip] = self.per_ip.get(ip, 0) + 1
            return None
        self.rejected += 1
        return reason

    def release(self, ip: str) -> None:
        self.total = max(0, self.total - 1)
        left = self.per_ip.get(ip, 1) - 1
        if left <= 0:
            self.per_ip.pop(ip, None)
        else:
            self.per_ip[ip] = left
        self.budget.release(_CONN_COST)

    def check_memory(self) -> int:
        """One memory-guard tick: refuse above 70 %, abort the fattest connections above 85 %."""
        if not self.guard.sample():
            return 0
        self.guard.shed_events += 1
        need = max(self.guard.excess(), 1)
        ranked = sorted(self.live.values(), key=lambda c: (-c.buffered(), c.start))
        freed = aborted = 0
        for conn in ranked[: max(1, len(ranked) // 2)]:
            if freed >= need:
                break
            size = conn.buffered()
            if conn.abort():
                conn.reason = "memory-pressure"
                freed += size
                aborted += 1
        self.guard.aborted += aborted
        if aborted:
            log.warning(
                "memory %d MiB of %d MiB: aborted %d connections",
                self.guard.usage >> 20,
                self.guard.limit >> 20,
                aborted,
            )
        return aborted

    def stats(self) -> dict[str, int]:
        return {
            "connections": self.total,
            "seen": self.connections_seen,
            "requests": self.requests_seen,
            "rejected": self.rejected,
            "cpu_waits": self.cpu.waits,
            "budget_used": self.budget.used,
            "memory_used": self.guard.usage,
            "memory_peak": self.guard.peak,
            "memory_refused": self.guard.refused,
            "memory_aborted": self.guard.aborted,
            **self.sink.stats(),
        }

    # -- events ----------------------------------------------------------------------------

    def emit(
        self, conn: Conn, type_: EventType, data: dict[str, Any], *, important: bool = False
    ) -> None:
        if conn.quiet:
            return
        self.sink.emit(
            session_id=conn.sid,
            src_ip=conn.ip,
            src_port=conn.port,
            dst_port=self.cfg.public_port,
            type_=type_,
            data=data,
            important=important,
        )

    def _request_event(self, conn: Conn, req: Request, status: int, out: Outcome) -> None:
        headers: dict[str, str] = {}
        size = 0
        for k, v in req.headers:
            if len(headers) >= _MAX_HEADERS_LOGGED or size >= _G_HEADERS:
                break
            key = to_text(k.encode("latin-1"))[:128]
            val = to_text(v.encode("latin-1"))[:512]
            if key in headers:
                continue
            headers[key] = val
            size += len(json.dumps(val)) + len(json.dumps(key))
        while headers and len(json.dumps(headers)) > _G_HEADERS:
            headers.popitem()
        ctype = (req.header("content-type") or "").lower()
        binary = b"\x00" in req.body[:512] or "tar" in ctype or "octet" in ctype
        preview = "" if binary else _fit(req.body[:4096].decode("utf-8", "replace"), _G_BODY)
        data: dict[str, Any] = {
            "method": to_text(req.method.encode("latin-1"))[:32],
            "path": _fit(to_text(req.path.encode("latin-1")), _G_PATH),
            "query": _fit(to_text(req.query_raw.encode("latin-1")), _G_PATH),
            "http_version": req.version,
            "host": _fit(to_text((req.header("host") or "").encode("latin-1")), 255),
            "headers": headers,
            "user_agent": _fit(to_text((req.header("user-agent") or "").encode("latin-1")), 500),
            "body_preview": preview,
            "body_binary": binary,
            "body_sha256": req.body_sha256,
            "body_length": req.body_len,
            "body_truncated": req.body_truncated,
            "status": status,
            "route": out.route,
            "docker_api": True,
        }
        if req.chunked:
            data["chunked"] = True
        data.update(out.extra)
        data["flags"] = sorted(out.flags)[:40]
        conn.flags |= out.flags
        important = out.important or bool(out.flags & _SEVERE_FLAGS)
        if not important:
            # Identical ordinary requests (a scanner hammering /info) are counted, not repeated.
            rkey = (data["method"], data["path"], data["query"], req.body_sha256, status)
            seen = conn.seen.get(rkey)
            if seen is not None and seen >= _REPEAT_KEEP:
                conn.seen[rkey] = seen + 1
                conn.repeats += 1
                return
            if seen is not None or len(conn.seen) < 64:
                conn.seen[rkey] = (seen or 0) + 1
        self.emit(conn, EventType.http_request, data, important=important)
        for cmd in out.commands:
            conn.commands += 1
            body: dict[str, Any] = {k: v for k, v in cmd.items() if k != "flags"}
            body["flags"] = cmd.get("flags", [])[:40]
            self.emit(conn, EventType.command, body, important=True)
        for dl in out.downloads:
            conn.downloads += 1
            self.emit(conn, EventType.download_attempt, dl, important=True)
        for login in out.logins:
            conn.logins += 1
            self.emit(conn, EventType.login_attempt, login, important=True)

    # -- connection lifecycle --------------------------------------------------------------

    async def handle(self, sock: socket.socket, addr: Any) -> None:
        loop = asyncio.get_running_loop()
        ip = normalize_ip(str(addr[0]))
        port = int(addr[1])
        refused = self.admit(ip)
        if refused is not None:
            self._note_limited(ip)
            await self._slow_reject(sock)
            return
        self.connections_seen += 1
        conn = Conn(
            sid=secrets.token_hex(8),
            ip=ip,
            port=port,
            quiet=self.cfg.quiet_loopback and ip in _LOOPBACK,
            cost=_CONN_COST,
        )
        self.live[conn.sid] = conn
        writer: asyncio.StreamWriter | None = None
        try:
            reader = asyncio.StreamReader(limit=_READER_LIMIT)
            proto = asyncio.StreamReaderProtocol(reader)
            transport, _ = await loop.connect_accepted_socket(lambda: proto, sock)
            transport.set_write_buffer_limits(high=64 * 1024, low=16 * 1024)
            writer = asyncio.StreamWriter(transport, proto, reader, loop)
            conn.transport, conn.reader = transport, reader
            self.emit(conn, EventType.connect, {"transport": "tcp"})
            await self._serve(conn, reader, writer)
        except asyncio.CancelledError:
            conn.reason = "shutdown"
            raise
        except Exception:
            conn.reason = "error"
            log.exception("connection handler failed")
        finally:
            suppressed = self.sink.end_session(conn.sid)
            self.cpu.drop(conn.sid)
            self.emit(
                conn,
                EventType.disconnect,
                {
                    "duration_s": round(time.monotonic() - conn.start, 3),
                    "reason": conn.reason,
                    "requests": conn.requests,
                    "commands": conn.commands,
                    "logins": conn.logins,
                    "downloads": conn.downloads,
                    "bytes_out": conn.bytes_out,
                    "flags": sorted(conn.flags)[:32],
                    "statuses": conn.statuses,
                    "suppressed": suppressed,
                    "repeats": conn.repeats,
                },
            )
            try:
                if writer is not None:
                    await _close(writer, force=conn.reason in ("write-failed", "memory-pressure"))
                else:
                    with contextlib.suppress(OSError):
                        sock.close()
            finally:
                self.live.pop(conn.sid, None)
                self.release(ip)

    # -- wire format -----------------------------------------------------------------------

    def _head(self, resp: Resp, method: str, *, keep: bool, upgrade: bool = False) -> bytes:
        cfg = self.cfg
        status = resp.status
        if resp.hijack and upgrade:
            return (
                f"HTTP/1.1 101 UPGRADED\r\nContent-Type: {resp.ctype}\r\n"
                "Connection: Upgrade\r\nUpgrade: tcp\r\n\r\n"
            ).encode()
        hdr: dict[str, str] = {
            "Api-Version": cfg.api_version,
            "Docker-Experimental": "false",
            "Ostype": "linux",
            "Server": f"Docker/{cfg.engine_version} (linux)",
            **resp.headers,
        }
        bodyless = status in (204, 304) or 100 <= status < 200
        if not bodyless:
            hdr["Content-Type"] = resp.ctype
        lines = [f"HTTP/1.1 {status} {_REASONS.get(status, 'Status')}"]
        lines += [f"{k}: {hdr[k]}" for k in sorted(hdr)]
        lines.append(f"Date: {self.dates.get()}")
        if resp.stream is None and not bodyless and not resp.no_content_length:
            lines.append(f"Content-Length: {len(resp.body) if not resp.hijack else len(resp.raw)}")
        if not keep or resp.hijack or resp.hold > 0:
            lines.append("Connection: close")
        if resp.stream is not None:
            lines.append("Transfer-Encoding: chunked")
        return ("\r\n".join(lines) + "\r\n\r\n").encode()

    async def _write(self, conn: Conn, writer: asyncio.StreamWriter, data: bytes) -> bool:
        """Write with the pending output charged to the budget, at most 64 KiB at a time."""
        view = memoryview(data)
        try:
            for off in range(0, max(len(data), 1), _OUT_CHUNK):
                part = view[off : off + _OUT_CHUNK]
                if not self.budget.acquire(len(part)):
                    conn.reason = "budget"
                    conn.abort()
                    return False
                conn.inflight += len(part)
                try:
                    writer.write(part)
                    await asyncio.wait_for(writer.drain(), self.cfg.write_timeout)
                finally:
                    conn.inflight -= len(part)
                    self.budget.release(len(part))
        except (TimeoutError, ConnectionError, OSError):
            if conn.reason != "memory-pressure":
                conn.reason = "write-failed"
            return False
        conn.bytes_out += len(data)
        return True

    async def _write_reply(
        self, conn: Conn, writer: asyncio.StreamWriter, head: bytes, body: bytes
    ) -> bool:
        """Head and body; a large body is not copied into a second buffer."""
        if len(body) <= 16 * 1024:
            return await self._write(conn, writer, head + body)
        return await self._write(conn, writer, head) and await self._write(conn, writer, body)

    async def _send(
        self, conn: Conn, writer: asyncio.StreamWriter, req: Request, resp: Resp, keep: bool
    ) -> bool:
        """Write one response. Returns False if the connection must not be reused."""
        method = req.method
        upgrade = req.wants_upgrade()
        held = resp.stream is not None and not resp.stream and resp.hold > 0 and method != "HEAD"
        if held and (
            self.held >= self.cfg.held_streams
            or self.held_per_ip.get(conn.ip, 0) >= self.cfg.held_streams_per_ip
        ):
            resp.hold = 0.0  # too many open event streams: answer an empty stream and close
        elif held:
            self.held += 1
            self.held_per_ip[conn.ip] = self.held_per_ip.get(conn.ip, 0) + 1
            try:
                return await self._send_inner(conn, writer, req, resp, keep, upgrade)
            finally:
                self.held -= 1
                left = self.held_per_ip.get(conn.ip, 1) - 1
                if left <= 0:
                    self.held_per_ip.pop(conn.ip, None)
                else:
                    self.held_per_ip[conn.ip] = left
        return await self._send_inner(conn, writer, req, resp, keep, upgrade)

    async def _send_inner(
        self,
        conn: Conn,
        writer: asyncio.StreamWriter,
        req: Request,
        resp: Resp,
        keep: bool,
        upgrade: bool,
    ) -> bool:
        method = req.method
        head = self._head(resp, method, keep=keep, upgrade=upgrade)
        if resp.stream is not None:
            ok = await self._write(conn, writer, head)
            if method == "HEAD":
                return ok and keep
            if ok and not resp.stream and resp.hold > 0:
                # An event stream with nothing to say: open until the client leaves (bounded).
                if conn.reader is not None:
                    with contextlib.suppress(TimeoutError, ConnectionError, OSError):
                        await asyncio.wait_for(conn.reader.read(1), resp.hold)
                conn.reason = "stream-end"
                return False
            for line in resp.stream:
                if not ok:
                    return False
                chunk = f"{len(line):x}\r\n".encode() + line + b"\r\n"
                ok = await self._write(conn, writer, chunk)
                await asyncio.sleep(self.cfg.stream_delay)
            return ok and await self._write(conn, writer, b"0\r\n\r\n") and keep
        if resp.hijack:
            payload = resp.raw
            await self._write_reply(conn, writer, head, b"" if method == "HEAD" else payload)
            return False
        body = b"" if method == "HEAD" else resp.body
        ok = await self._write_reply(conn, writer, head, body)
        return ok and keep

    async def _bad_request(
        self, conn: Conn, writer: asyncio.StreamWriter, status: int, text: str
    ) -> None:
        """Go's own plain-text error, then close."""
        if status == 414:  # Go's server has no 414: it answers 431 for any oversized head
            status, text = 431, ""
        if status in (400, 431) and text in ("", "Bad Request", "Request Header Fields Too Large"):
            body = f"{status} {_REASONS[status]}".encode()
        else:
            body = (text or _REASONS.get(status, "Bad Request")).encode()
        wire = (
            f"HTTP/1.1 {status} {_REASONS.get(status, 'Status')}\r\n"
            "Content-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n"
        ).encode() + body
        conn.statuses[str(status)] = conn.statuses.get(str(status), 0) + 1
        await self._write(conn, writer, wire)

    # -- request loop ----------------------------------------------------------------------

    async def _serve(
        self, conn: Conn, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        cfg = self.cfg
        cr = ConnReader(reader, cfg)
        conn.cr = cr
        conn.meter = cr.meter = Meter(self.cpu, conn.ip, conn.sid)
        started = time.monotonic()
        while True:
            if time.monotonic() - started > cfg.max_connection_age:
                conn.reason = "max-age"
                return
            if conn.requests >= cfg.max_requests_per_conn:
                conn.reason = "max-requests"
                return
            try:
                raw = await cr.read_head(first=conn.requests == 0)
                if raw is None:
                    conn.reason = "idle" if conn.requests else "closed"
                    return
                try:
                    req = parse_head(raw, cfg)
                except HttpError as exc:
                    self._non_http(conn, raw, exc.status)
                    await self._bad_request(conn, writer, exc.status, exc.text)
                    conn.reason = "bad-request"
                    return
            except IdleTimeout:
                conn.reason = "idle" if conn.requests else "no-data"
                return
            except SlowRequest:
                self._partial(conn, cr)
                conn.reason = "timeout"
                return
            except ClientGone:
                if conn.reason != "memory-pressure":
                    conn.reason = "client-closed"
                self._partial(conn, cr)
                return
            except HttpError as exc:
                await self._bad_request(conn, writer, exc.status, exc.text)
                conn.reason = "bad-request"
                return
            conn.requests += 1
            self.requests_seen += 1
            if not await self._request(conn, cr, writer, req):
                return
            await asyncio.sleep(0)  # pipelined requests never monopolise the loop

    def _non_http(self, conn: Conn, raw: bytes, status: int) -> None:
        """Bytes that are not a valid HTTP request (TLS hello, other protocols, garbage)."""
        if conn.requests == 0:
            self.emit(
                conn,
                EventType.scan,
                {
                    "kind": "non_http",
                    "status": status,
                    "payload_preview": raw[:64].hex(),
                    "text_preview": _fit(to_text(raw[:200]), 400),
                    "tls_client_hello": raw[:2] == b"\x16\x03",
                },
            )

    def _partial(self, conn: Conn, cr: ConnReader) -> None:
        if cr.buf:
            self.emit(
                conn,
                EventType.scan,
                {
                    "kind": "incomplete_request",
                    "payload_preview": bytes(cr.buf[:64]).hex(),
                    "text_preview": _fit(to_text(bytes(cr.buf[:400])), 400),
                },
            )

    async def _request(
        self, conn: Conn, cr: ConnReader, writer: asyncio.StreamWriter, req: Request
    ) -> bool:
        cfg = self.cfg
        has_body = req.header("transfer-encoding") is not None or (
            req.header("content-length") or "0"
        ).strip() not in ("", "0")
        cost = 0
        try:
            if has_body:
                # Reserve what a declared length needs; chunked bodies grow the reservation.
                te = req.header("transfer-encoding") is not None
                declared = 0
                if not te:
                    text = (req.header("content-length") or "0").strip()
                    declared = (
                        int(text) if text.isascii() and text.isdigit() and len(text) < 12 else 0
                    )
                cost = (0 if te else min(declared, cfg.body_cap)) * _BODY_FACTOR + 4096
                if not self.budget.acquire(cost):
                    cost = 0
                    resp = Resp(503, b'{"message":"context deadline exceeded"}', close=True)
                    await self._send(conn, writer, req, resp, False)
                    conn.reason = "budget"
                    return False
                if (req.header("expect") or "").lower() == "100-continue":
                    await self._write(conn, writer, b"HTTP/1.1 100 Continue\r\n\r\n")

                def grow(n: int) -> bool:
                    nonlocal cost
                    if not te:
                        return True
                    extra = n * _BODY_FACTOR
                    if not self.budget.acquire(extra):
                        return False
                    cost += extra
                    return True

                try:
                    await cr.read_body(req, time.monotonic(), grow)
                except HttpError as exc:
                    await self._bad_request(conn, writer, exc.status, exc.text)
                    conn.reason = "bad-request"
                    return False
                except SlowRequest:
                    self._request_event(
                        conn, req, 0, Outcome(flags={"incomplete_body"}, route="timeout")
                    )
                    conn.reason = "timeout"
                    return False
                except ClientGone:
                    self._request_event(
                        conn, req, 0, Outcome(flags={"incomplete_body"}, route="client_gone")
                    )
                    conn.reason = "client-closed"
                    return False
            meter = conn.meter
            if meter is not None:
                await meter.pause()  # charge what parsing cost, wait if the buckets are empty
                if _jsonish(req.body):
                    # A big JSON body is scanned in slices, so it never blocks other connections.
                    for verdict in analysis.depth_steps(req.body, cfg.json_max_depth):
                        if verdict is None:
                            await meter.tick()
                        else:
                            req.depth_checked = verdict
            # Reserve room for the reply BEFORE building it; the real size replaces it below.
            if not self.budget.acquire(_OUT_RESERVE):
                resp = Resp(503, b'{"message":"context deadline exceeded"}', close=True)
                await self._send(conn, writer, req, resp, False)
                conn.reason = "budget"
                return False
            held = _OUT_RESERVE
            try:
                try:
                    resp, out = self.api.handle(req, conn.ip)
                except Exception:
                    log.exception("api handler failed")
                    resp, out = (
                        Resp(
                            500,
                            b'{"message":"rpc error: code = Unavailable desc = error reading from server: EOF"}',
                        ),
                        Outcome(route="error"),
                    )
                keep = req.keep_alive() and not resp.close and not req.body_truncated
                self._request_event(conn, req, resp.status, out)
                if meter is not None:
                    meter.flush()
                size = _resp_size(resp)
                if size > held:
                    self.budget.release(held)
                    held = 0
                    if not self.budget.acquire(size):
                        conn.reason = "budget"
                        conn.abort()
                        return False
                    held = size
                key = str(resp.status)
                conn.statuses[key] = conn.statuses.get(key, 0) + 1
                return await self._send(conn, writer, req, resp, keep)
            finally:
                self.budget.release(held)
        finally:
            if cost:
                self.budget.release(cost)


def _tune_socket(sock: socket.socket) -> None:
    """Small kernel buffers (charged to the container) and a bounded unacknowledged-send time."""
    with contextlib.suppress(OSError):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _SOCK_BUF)
    with contextlib.suppress(OSError):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, _SOCK_BUF)
    with contextlib.suppress(OSError):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT, 30_000)
    with contextlib.suppress(OSError):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


async def _close(writer: asyncio.StreamWriter, force: bool = False) -> None:
    """Flush briefly, then close; a peer that does not read is aborted so buffers go away."""
    transport = writer.transport
    try:
        if not force and transport.get_write_buffer_size() > 0:
            with contextlib.suppress(Exception):
                transport.set_write_buffer_limits(high=0)
                await asyncio.wait_for(writer.drain(), 5.0)
        if force or transport.get_write_buffer_size() > 0:
            transport.abort()
            return
        if writer.can_write_eof():
            with contextlib.suppress(Exception):
                writer.write_eof()
    except (TimeoutError, OSError, RuntimeError, asyncio.CancelledError):
        pass
    finally:
        with contextlib.suppress(Exception):
            if transport.get_write_buffer_size() > 0:
                transport.abort()
            else:
                writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 2.0)
        except BaseException:
            with contextlib.suppress(Exception):
                transport.abort()


class DockerServer:
    """Owns the listening socket and the accept loop."""

    def __init__(self, cfg: Config, sensor: DockerSensor) -> None:
        self.cfg = cfg
        self.sensor = sensor
        self._sock: socket.socket | None = None
        self._bg: list[asyncio.Task[None]] = []
        self._tasks: set[asyncio.Task[None]] = set()
        self.port = 0

    def _listen(self, port: int) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _tune_socket(s)
        s.bind((self.cfg.host, port))
        s.listen(512)
        s.setblocking(False)
        return s

    async def start(self) -> int:
        self.sensor.guard.sample()
        log.info(
            "memory guard: %s, limit %d MiB",
            self.sensor.guard.source,
            self.sensor.guard.limit >> 20,
        )
        self._sock = self._listen(self.cfg.port)
        self.port = int(self._sock.getsockname()[1])
        self._bg = [
            asyncio.create_task(self._accept(self._sock)),
            asyncio.create_task(self._loop(1.0, self._memory)),
            asyncio.create_task(self._loop(60.0, self._flush)),
            asyncio.create_task(self._loop(15.0, self.sensor.sink.flush_overflow)),
        ]
        return self.port

    def _memory(self) -> None:
        self.sensor.check_memory()

    def _flush(self) -> None:
        self.sensor.flush_limited()

    async def _loop(self, interval: float, fn: Any) -> None:
        while True:
            await asyncio.sleep(interval)
            try:
                fn()
            except Exception:
                log.exception("periodic task failed")

    async def _accept(self, lsock: socket.socket) -> None:
        loop = asyncio.get_running_loop()
        while True:
            try:
                conn, addr = await loop.sock_accept(lsock)
            except asyncio.CancelledError:
                raise
            except OSError:
                if lsock.fileno() == -1:
                    return
                await asyncio.sleep(0.1)
                continue
            conn.setblocking(False)
            _tune_socket(conn)
            task = asyncio.create_task(self.sensor.handle(conn, addr))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def stop(self) -> None:
        for t in self._bg:
            t.cancel()
        for t in self._bg:
            with contextlib.suppress(asyncio.CancelledError):
                await t
        if self._sock is not None:
            self._sock.close()
        for t in list(self._tasks):
            t.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
