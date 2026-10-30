"""Listeners (HTTP and HTTPS), connection handling and event emission for the Synology sensor."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
import random
import secrets
import socket
import ssl
import time
import weakref
from dataclasses import dataclass, field
from email.utils import formatdate
from typing import Any

from suckerpot_common import EventType

from synology_sensor.api import Ctx, Outcome, Resp, SynologyApi
from synology_sensor.config import Config
from synology_sensor.cpu import CpuBudget, Meter
from synology_sensor.detect import CVES
from synology_sensor.events import EventSink, _Buckets
from synology_sensor.httpio import (
    ClientGone,
    ConnReader,
    HttpError,
    IdleTimeout,
    Request,
    SlowRequest,
    parse_head,
    to_text,
)
from synology_sensor.memguard import MemoryGuard

log = logging.getLogger("synology_sensor.server")

# Budgeted bytes per connection: parser state, StreamReader buffer, transport buffers and the
# kernel socket buffers charged to the cgroup. TLS adds the SSL protocol buffers.
_CONN_COST = 96 * 1024
_TLS_COST = 224 * 1024
_BODY_FACTOR = 4  # a body kept in memory costs about this many times its size while parsed
_READER_LIMIT = 16 * 1024
_SOCK_BUF = 32 * 1024
_TLS_BUF = 32 * 1024
_LOOPBACK = frozenset({"127.0.0.1", "::1"})
_MAX_HEADERS_LOGGED = 32
_REPEAT_KEEP = 3
_OUT_CHUNK = 16 * 1024
_OUT_RESERVE = 32 * 1024  # budget reserved for a reply before it is built
_G_HEADERS = 3000
_G_PATH = 1500
_G_BODY = 2500
_G_PARAMS = 3000
_CVE_FLAGS = frozenset({"sid_forge", "scgi_injection"})
_SECRET_PARAMS = frozenset({"passwd", "password", "pass", "pwd", "__ciphertext"})

_REASONS = {
    100: "Continue", 200: "OK", 301: "Moved Permanently", 304: "Not Modified",
    400: "Bad Request", 404: "Not Found", 405: "Not Allowed", 408: "Request Time-out",
    413: "Request Entity Too Large", 414: "Request-URI Too Large",
    431: "Request Header Fields Too Large", 500: "Internal Server Error",
    501: "Not Implemented", 503: "Service Temporarily Unavailable",
    505: "HTTP Version Not Supported",
}  # fmt: skip


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


@dataclass(frozen=True)
class Listener:
    tls: bool
    port: int
    public_port: int


@dataclass
class Conn:
    sid: str
    ip: str
    port: int
    listener: Listener
    start: float = field(default_factory=time.monotonic)
    quiet: bool = False
    requests: int = 0
    logins: int = 0
    downloads: int = 0
    repeats: int = 0
    seen: dict[tuple[str, str, str, str, int], int] = field(default_factory=dict)
    bytes_out: int = 0
    flags: set[str] = field(default_factory=set)
    statuses: dict[str, int] = field(default_factory=dict)
    reason: str = "closed"
    sni: str | None = None
    tls_version: str | None = None
    cipher: str | None = None
    plain_on_tls: bool = False
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


def conn_cost(tls: bool) -> int:
    return _CONN_COST + (_TLS_COST if tls else 0)


class SynologySensor:
    """Process-wide state shared by all connections."""

    def __init__(
        self,
        cfg: Config,
        sink: EventSink,
        api: SynologyApi,
        guard: MemoryGuard | None = None,
        tls_ctx: ssl.SSLContext | None = None,
    ) -> None:
        self.cfg = cfg
        self.sink = sink
        self.api = api
        self.budget = Budget(cfg.memory_budget)
        self.dates = DateCache()
        self.guard = guard or MemoryGuard(
            cfg.memory_limit, refuse=cfg.memory_refuse, shed=cfg.memory_shed
        )
        self.tls_ctx = tls_ctx
        self.total = 0
        self.per_ip: dict[str, int] = {}
        self.live: dict[str, Conn] = {}
        self.rejected = 0
        self.connections_seen = 0
        self.requests_seen = 0
        self.requests_limited = 0
        self.handshakes = 0
        self.hs_per_ip: dict[str, int] = {}
        self._limited: dict[str, int] = {}
        self._slow_close = 0
        self._rate = _Buckets(cfg.conn_rate, cfg.conn_burst)
        self._req_rate = _Buckets(cfg.req_rate, cfg.req_burst)
        self._tls_rate = _Buckets(cfg.tls_per_sec, cfg.tls_burst, max_keys=1)
        self._tls_reserve = _Buckets(cfg.tls_reserve_rate, cfg.tls_reserve_burst, max_keys=1)
        self._tls_ip = _Buckets(cfg.tls_ip_rate, cfg.tls_ip_burst)
        self.cpu = CpuBudget(cfg)
        self._last_sample = 0.0
        self._sni: weakref.WeakKeyDictionary[ssl.SSLObject, str | None] = (
            weakref.WeakKeyDictionary()
        )

    def on_sni(self, sslobj: ssl.SSLObject, name: str | None) -> None:
        with contextlib.suppress(TypeError):
            self._sni[sslobj] = name[:255] if name else None

    # -- admission -------------------------------------------------------------------------

    def _note_limited(self, ip: str, port: int) -> None:
        key = f"{ip}|{port}"
        if key in self._limited or len(self._limited) < 2000:
            self._limited[key] = self._limited.get(key, 0) + 1

    def flush_limited(self) -> None:
        """One aggregated ``scan`` event per IP and port for connections refused since last call."""
        pending, self._limited = self._limited, {}
        for key, count in pending.items():
            ip, _, port = key.rpartition("|")
            if self.cfg.quiet_loopback and ip in _LOOPBACK:
                continue
            self.sink.emit(
                session_id=secrets.token_hex(8),
                src_ip=ip,
                src_port=0,
                dst_port=int(port),
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

    def admit(self, ip: str, tls: bool) -> str | None:
        """Take the slots and budget for a new connection: None if admitted, else why not."""
        cfg = self.cfg
        cost = conn_cost(tls)
        if cfg.quiet_loopback and ip in _LOOPBACK:
            # The container healthcheck is never refused (a local peer cannot be spoofed).
            self.budget.used += cost
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
        elif not self.budget.acquire(cost):
            reason = "budget"
        else:
            self.total += 1
            self.per_ip[ip] = self.per_ip.get(ip, 0) + 1
            return None
        self.rejected += 1
        return reason

    def release(self, ip: str, tls: bool) -> None:
        self.total = max(0, self.total - 1)
        left = self.per_ip.get(ip, 1) - 1
        if left <= 0:
            self.per_ip.pop(ip, None)
        else:
            self.per_ip[ip] = left
        self.budget.release(conn_cost(tls))

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
            "requests_limited": self.requests_limited,
            "handshakes": self.handshakes,
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
            dst_port=conn.listener.public_port,
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
        binary = b"\x00" in req.body[:512] or "octet" in ctype or "multipart" in ctype
        preview = "" if binary else _fit(req.body[:4096].decode("utf-8", "replace"), _G_BODY)
        a = out.analysis
        params: dict[str, str] = {}
        psize = 0
        for k, v in a.params:
            if k.lower() in _SECRET_PARAMS or k in params:
                continue
            if len(params) >= 24 or psize >= _G_PARAMS:
                break
            params[k[:64]] = v[:256]
            psize += len(json.dumps(k[:64])) + len(json.dumps(v[:256]))
        flags = sorted(out.flags)[:40]
        data: dict[str, Any] = {
            "method": to_text(req.method.encode("latin-1"))[:32],
            "path": _fit(to_text(req.path.encode("latin-1")), _G_PATH),
            "query": _fit(to_text(req.query_raw.encode("latin-1")), _G_PATH),
            "http_version": req.version,
            "host": _fit(to_text((req.header("host") or "").encode("latin-1")), 255),
            "sni": conn.sni,
            "tls": conn.listener.tls,
            "user_agent": _fit(to_text((req.header("user-agent") or "").encode("latin-1")), 500),
            "headers": headers,
            "body_len": req.body_len,
            "body_preview": preview,
            "body_binary": binary,
            "body_sha256": req.body_sha256,
            "body_truncated": req.body_truncated,
            "api": a.api,
            "api_method": a.api_method,
            "api_version": a.api_version,
            "params": params,
            "flags": flags,
            "status": status,
            "route": out.route,
            "dsm_version": self.cfg.dsm_version,
        }
        if a.uploads:
            data["upload_names"] = [u[:128] for u in a.uploads[:8]]
        cve = list(CVES) if out.flags & _CVE_FLAGS else []
        if cve:
            data["cve"] = cve
        conn.flags |= out.flags
        if not out.important:
            # Identical ordinary requests (a scanner hammering one URL) are counted, not repeated.
            rkey = (data["method"], data["path"], data["query"], req.body_sha256, status)
            seen = conn.seen.get(rkey)
            if seen is not None and seen >= _REPEAT_KEEP:
                conn.seen[rkey] = seen + 1
                conn.repeats += 1
                return
            if seen is not None or len(conn.seen) < 64:
                conn.seen[rkey] = (seen or 0) + 1
        self.emit(conn, EventType.http_request, data, important=out.important)
        for dl in out.downloads:
            conn.downloads += 1
            self.emit(conn, EventType.download_attempt, dl, important=True)
        for login in out.logins:
            conn.logins += 1
            self.emit(conn, EventType.login_attempt, login, important=True)

    # -- connection lifecycle --------------------------------------------------------------

    async def handle(self, sock: socket.socket, addr: Any, listener: Listener) -> None:
        loop = asyncio.get_running_loop()
        ip = normalize_ip(str(addr[0]))
        port = int(addr[1])
        refused = self.admit(ip, listener.tls)
        if refused is not None:
            self._note_limited(ip, listener.public_port)
            await self._slow_reject(sock)
            return
        self.connections_seen += 1
        conn = Conn(
            sid=secrets.token_hex(8),
            ip=ip,
            port=port,
            listener=listener,
            quiet=self.cfg.quiet_loopback and ip in _LOOPBACK,
            cost=conn_cost(listener.tls),
        )
        self.live[conn.sid] = conn
        writer: asyncio.StreamWriter | None = None
        try:
            reader: asyncio.StreamReader | None
            first = b""
            if listener.tls:
                first = await _peek(loop, sock, self.cfg.first_byte_timeout)
                if not first:
                    conn.reason = "no-data"
                    self.emit(
                        conn, EventType.connect, {"tls": True, "sni": None, "handshake": False}
                    )
                    with contextlib.suppress(OSError):
                        sock.close()
                    return
            if listener.tls and first[0] == 0x16 and self.tls_ctx is not None:
                # No handshake slot before the whole ClientHello record has arrived.
                if not await _hello_complete(loop, sock, self.cfg.tls_hello_timeout):
                    conn.reason = "tls-incomplete-hello"
                    self.emit(
                        conn, EventType.connect, {"tls": True, "sni": None, "handshake": False}
                    )
                    self.emit(conn, EventType.scan, {"kind": "tls_incomplete_hello"})
                    with contextlib.suppress(OSError):
                        sock.close()
                    return
                reader, writer = await self._start_tls(loop, sock, conn)
                if reader is None or writer is None:
                    return
                self.emit(
                    conn,
                    EventType.connect,
                    {
                        "tls": True,
                        "sni": conn.sni,
                        "tls_version": conn.tls_version,
                        "cipher": conn.cipher,
                        "handshake": True,
                    },
                )
            else:
                reader, writer = await _plain_stream(loop, sock)
                conn.transport, conn.reader = writer.transport, reader
                conn.plain_on_tls = listener.tls
                self.emit(
                    conn, EventType.connect, {"tls": listener.tls, "sni": None, "handshake": False}
                )
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
                    "login_attempts": conn.logins,
                    "downloads": conn.downloads,
                    "bytes_out": conn.bytes_out,
                    "tls": listener.tls,
                    "sni": conn.sni,
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
                self.release(ip, listener.tls)

    def _tls_allowed(self, ip: str) -> bool:
        """Handshake budget: per IP first, then the sensor-wide one.

        When the sensor-wide bucket is empty, an IP that has hardly handshaken recently may
        still use a small reserved share, so churning sources cannot lock everyone else out.
        """
        fresh = self._tls_ip.tokens(ip) >= self.cfg.tls_ip_burst - 1
        if not self._tls_ip.allow(ip):
            return False
        return self._tls_rate.allow("*") or (fresh and self._tls_reserve.allow("*"))

    async def _start_tls(
        self, loop: asyncio.AbstractEventLoop, sock: socket.socket, conn: Conn
    ) -> tuple[asyncio.StreamReader | None, asyncio.StreamWriter | None]:
        if self.tls_ctx is None:
            raise RuntimeError("TLS context missing")
        cfg = self.cfg
        if (
            self.handshakes >= cfg.tls_max_inflight
            or self.hs_per_ip.get(conn.ip, 0) >= cfg.tls_max_per_ip
            or not self._tls_allowed(conn.ip)
            or self.guard.refusing
        ):
            conn.reason = "tls-busy"
            self.emit(conn, EventType.connect, {"tls": True, "sni": None, "handshake": False})
            with contextlib.suppress(OSError):
                sock.close()
            return None, None
        reader = asyncio.StreamReader(limit=_READER_LIMIT)
        proto = asyncio.StreamReaderProtocol(reader)
        self.handshakes += 1
        self.hs_per_ip[conn.ip] = self.hs_per_ip.get(conn.ip, 0) + 1
        try:
            transport, _ = await loop.connect_accepted_socket(
                lambda: proto,
                sock,
                ssl=self.tls_ctx,
                ssl_handshake_timeout=cfg.tls_handshake_timeout,
            )
        except (OSError, ssl.SSLError, TimeoutError) as exc:
            conn.reason = "tls-handshake-failed"
            self.emit(conn, EventType.connect, {"tls": True, "sni": None, "handshake": False})
            self.emit(
                conn,
                EventType.scan,
                {
                    "kind": "tls_handshake_failed",
                    "error": type(exc).__name__,
                    "detail": str(exc)[:200],
                },
            )
            with contextlib.suppress(OSError):
                sock.close()
            return None, None
        finally:
            self.handshakes -= 1
            left = self.hs_per_ip.get(conn.ip, 1) - 1
            if left <= 0:
                self.hs_per_ip.pop(conn.ip, None)
            else:
                self.hs_per_ip[conn.ip] = left
        sslobj = transport.get_extra_info("ssl_object")
        if sslobj is not None:
            conn.sni = self._sni.pop(sslobj, None)
            conn.tls_version = sslobj.version()
            cipher = sslobj.cipher()
            conn.cipher = cipher[0] if cipher else None
        transport.set_write_buffer_limits(high=_TLS_BUF, low=_TLS_BUF // 4)
        inner = getattr(getattr(transport, "_ssl_protocol", None), "_transport", None)
        if isinstance(inner, asyncio.WriteTransport):
            inner.set_write_buffer_limits(high=_TLS_BUF, low=_TLS_BUF // 4)
        set_read_limits = getattr(transport, "set_read_buffer_limits", None)
        if set_read_limits is not None:
            set_read_limits(high=_TLS_BUF, low=_TLS_BUF // 4)
        conn.transport, conn.reader = transport, reader
        return reader, asyncio.StreamWriter(transport, proto, reader, loop)

    # -- wire format -----------------------------------------------------------------------

    def _head(self, resp: Resp, *, keep: bool, length: int) -> bytes:
        lines = [
            f"HTTP/1.1 {resp.status} {_REASONS.get(resp.status, 'Status')}",
            "Server: nginx",
            f"Date: {self.dates.get()}",
        ]
        if resp.status != 304:
            lines.append(f"Content-Type: {resp.ctype}")
            lines.append(f"Content-Length: {length}")
        lines.append("Connection: keep-alive" if keep and not resp.close else "Connection: close")
        lines += [f"{k}: {v}" for k, v in resp.headers.items()]
        if resp.status == 200:
            lines.append("X-Content-Type-Options: nosniff")
            lines.append("X-XSS-Protection: 1; mode=block")
        return ("\r\n".join(lines) + "\r\n\r\n").encode()

    async def _write(self, conn: Conn, writer: asyncio.StreamWriter, data: bytes) -> bool:
        """Write with the pending output charged to the budget, a chunk at a time."""
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

    async def _send(
        self, conn: Conn, writer: asyncio.StreamWriter, req: Request, resp: Resp, keep: bool
    ) -> bool:
        head = self._head(resp, keep=keep, length=len(resp.body))
        body = b"" if req.method == "HEAD" else resp.body
        ok = await self._write(conn, writer, head + body)
        return ok and keep and not resp.close

    async def _bad_request(
        self, conn: Conn, writer: asyncio.StreamWriter, status: int, text: str
    ) -> None:
        """nginx's own error page, then close."""
        if status == 414:
            status = 414
        reason = _REASONS.get(status, "Bad Request")
        body = (
            f"<html>\r\n<head><title>{status} {reason}</title></head>\r\n<body>\r\n"
            f"<center><h1>{status} {reason}</h1></center>\r\n<hr><center>nginx</center>\r\n"
            "</body>\r\n</html>\r\n"
        ).encode()
        wire = (
            f"HTTP/1.1 {status} {reason}\r\nServer: nginx\r\nDate: {self.dates.get()}\r\n"
            f"Content-Type: text/html\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
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
            if not conn.quiet and not self._req_rate.allow(conn.ip):
                self.requests_limited += 1
                conn.reason = "rate-limited"
                await self._bad_request(conn, writer, 503, "")
                return
            if not await self._request(conn, cr, writer, req):
                return
            await asyncio.sleep(0)  # pipelined requests never monopolise the loop

    def _non_http(self, conn: Conn, raw: bytes, status: int) -> None:
        """Bytes that are not a valid HTTP request (other protocols, garbage)."""
        if conn.requests == 0:
            self.emit(
                conn,
                EventType.scan,
                {
                    "kind": "non_http",
                    "status": status,
                    "payload_preview": raw[:64].hex(),
                    "text_preview": _fit(to_text(raw[:200]), 400),
                    "tls": conn.listener.tls,
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
                    await self._bad_request(conn, writer, 503, "")
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
                    self._request_event(conn, req, 0, _incomplete("timeout"))
                    conn.reason = "timeout"
                    return False
                except ClientGone:
                    self._request_event(conn, req, 0, _incomplete("client_gone"))
                    conn.reason = "client-closed"
                    return False
            meter = conn.meter
            if meter is not None:
                await meter.pause()  # charge what parsing cost, wait if the buckets are empty
            if not self.budget.acquire(_OUT_RESERVE):
                await self._bad_request(conn, writer, 503, "")
                conn.reason = "budget"
                return False
            held = _OUT_RESERVE
            try:
                ctx = Ctx(conn.ip, conn.listener.tls, conn.plain_on_tls)
                try:
                    resp, out = self.api.handle(req, ctx)
                except Exception:
                    log.exception("api handler failed")
                    resp, out = self.api.error_page(500), Outcome(route="error")
                keep = req.keep_alive() and not resp.close and not req.body_truncated
                if req.body_truncated:
                    out.flags.add("oversized_body")
                self._request_event(conn, req, resp.status, out)
                if meter is not None:
                    meter.flush()
                size = len(resp.body) + 1024
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


def _incomplete(route: str) -> Outcome:
    out = Outcome(route=route)
    out.flags.add("incomplete_body")
    return out


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


async def _peek(loop: asyncio.AbstractEventLoop, sock: socket.socket, wait: float) -> bytes:
    """Wait for the first bytes and look at them without consuming them."""
    fut: asyncio.Future[None] = loop.create_future()
    fd = sock.fileno()

    def ready() -> None:
        if not fut.done():
            fut.set_result(None)

    loop.add_reader(fd, ready)
    try:
        await asyncio.wait_for(fut, wait)
        return sock.recv(16, socket.MSG_PEEK)
    except (TimeoutError, OSError):
        return b""
    finally:
        loop.remove_reader(fd)


async def _hello_complete(
    loop: asyncio.AbstractEventLoop, sock: socket.socket, wait: float
) -> bool:
    """Peek until the first TLS record (header and declared length, at most 16 KiB) is in."""
    deadline = loop.time() + wait
    seen = 0
    while True:
        try:
            buf = sock.recv(5 + 16384, socket.MSG_PEEK)
        except (BlockingIOError, InterruptedError):
            buf = b""
        except OSError:
            return False
        if len(buf) >= 5:
            need = 5 + int.from_bytes(buf[3:5], "big")
            if need > 5 + 16384:
                return False  # not a TLS record this server would accept
            if len(buf) >= need:
                return True
        if buf == b"" and seen:
            return False  # peer closed
        seen = len(buf) or seen
        if loop.time() >= deadline:
            return False
        await asyncio.sleep(0.05)


async def _plain_stream(
    loop: asyncio.AbstractEventLoop, sock: socket.socket
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader = asyncio.StreamReader(limit=_READER_LIMIT)
    proto = asyncio.StreamReaderProtocol(reader)
    transport, _ = await loop.connect_accepted_socket(lambda: proto, sock)
    transport.set_write_buffer_limits(high=64 * 1024, low=16 * 1024)
    return reader, asyncio.StreamWriter(transport, proto, reader, loop)


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


class SynologyServer:
    """Owns the listening sockets and the accept loops."""

    def __init__(self, cfg: Config, sensor: SynologySensor) -> None:
        self.cfg = cfg
        self.sensor = sensor
        self._socks: list[socket.socket] = []
        self._bg: list[asyncio.Task[None]] = []
        self._tasks: set[asyncio.Task[None]] = set()
        self.http_port = 0
        self.https_port = 0

    def _listen(self, port: int) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _tune_socket(s)
        s.bind((self.cfg.host, port))
        s.listen(512)
        s.setblocking(False)
        return s

    async def start(self) -> tuple[int, int]:
        cfg = self.cfg
        self.sensor.guard.sample()
        log.info(
            "memory guard: %s, limit %d MiB",
            self.sensor.guard.source,
            self.sensor.guard.limit >> 20,
        )
        http = self._listen(cfg.http_port)
        self.http_port = int(http.getsockname()[1])
        self._socks = [http]
        self._bg = [
            asyncio.create_task(
                self._accept(http, Listener(False, self.http_port, cfg.http_public_port))
            )
        ]
        if self.sensor.tls_ctx is not None:
            https = self._listen(cfg.https_port)
            self.https_port = int(https.getsockname()[1])
            self._socks.append(https)
            self._bg.append(
                asyncio.create_task(
                    self._accept(https, Listener(True, self.https_port, cfg.https_public_port))
                )
            )
        self._bg += [
            asyncio.create_task(self._loop(1.0, self.sensor.check_memory)),
            asyncio.create_task(self._loop(60.0, self.sensor.flush_limited)),
            asyncio.create_task(self._loop(15.0, self.sensor.sink.flush_overflow)),
        ]
        return self.http_port, self.https_port

    async def _loop(self, interval: float, fn: Any) -> None:
        while True:
            await asyncio.sleep(interval)
            try:
                fn()
            except Exception:
                log.exception("periodic task failed")

    async def _accept(self, lsock: socket.socket, listener: Listener) -> None:
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
            task = asyncio.create_task(self.sensor.handle(conn, addr, listener))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def stop(self) -> None:
        for t in self._bg:
            t.cancel()
        for t in self._bg:
            with contextlib.suppress(asyncio.CancelledError):
                await t
        for s in self._socks:
            s.close()
        for t in list(self._tasks):
            t.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
