"""The MySQL listener: handshake, authentication and a canned text-protocol session.

Per connection:

1. Send an Initial Handshake v10 like a MySQL 8.0 server (random 20 byte salt, capability
   flags of an 8.0 server, ``caching_sha2_password`` as the default plugin).
2. Read the HandshakeResponse41 (or an SSLRequest, in which case TLS is negotiated first with
   the per-deployment certificate). Everything is parsed with strict bounds.
3. Authenticate against a small configurable list of weak accounts. ``mysql_native_password``
   and ``caching_sha2_password`` scrambles are *verified* against the known passwords, never
   cracked. A client that does the caching_sha2 full authentication hands over its cleartext
   password (RSA-encrypted or inside TLS), exactly as it would to a real server.
4. After a successful login, answer commands with canned data (see :mod:`responder`).

Every read has a deadline, every buffer a size cap, and the whole connection a hard time cap.
Nothing an attacker sends is executed, evaluated, written to disk or fetched.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import secrets
import socket
import ssl
import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from suckerpot_common import EventType

from mysql_sensor import auth, sqlish, wire
from mysql_sensor.config import Config
from mysql_sensor.events import Buckets, EventSink, Throttle
from mysql_sensor.identity import Identity
from mysql_sensor.memguard import MemoryGuard
from mysql_sensor.responder import Err, Ok, Responder, Result, ResultSet

log = logging.getLogger("mysql_sensor.server")

NATIVE = "mysql_native_password"
CACHING = "caching_sha2_password"
READ_CHUNK = 16 * 1024
SOCK_BUF = 32 * 1024
MAX_HANDSHAKE_RESPONSE = 8 * 1024
MAX_OVERFLOW = 64  # refused connections being answered at the same time
MAX_TLS_ROUNDS = 64
PREVIEW_BYTES = 64
OUTPUT_PREVIEW = 300
LOGIN_PREVIEW_BYTES = 8
PACKET_SEND_CHUNK = 16 * 1024
GUARD_SAMPLE_EVERY = 0.1  # seconds between memory guard samples taken on admission
STEPS_PER_SECOND = 200_000  # CPU time to steps: one step is about 5 microseconds of work
SPEND_MIN = 100  # work below this many steps (about half a millisecond) is not throttled


def normalize_ip(raw: str) -> str:
    try:
        addr = ipaddress.ip_address(raw.split("%")[0])
    except ValueError:
        return "0.0.0.0"  # noqa: S104 - placeholder for an unparsable peer address
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return str(addr.ipv4_mapped)
    return str(addr)


def is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def make_tls_context(identity: Identity) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # MySQL 8.0.28+ dropped TLS 1.0 and 1.1
    ctx.load_cert_chain(str(identity.tls_chain), str(identity.tls_key))
    ctx.options |= ssl.OP_NO_COMPRESSION | ssl.OP_NO_TICKET
    return ctx


def tune_socket(sock: Any) -> None:
    """Small kernel buffers (charged to the container) and a bounded unacknowledged-send time."""
    with contextlib.suppress(OSError, AttributeError):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCK_BUF)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCK_BUF)
    with contextlib.suppress(OSError, AttributeError):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT, 30_000)
    with contextlib.suppress(OSError, AttributeError):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


def guess_protocol(data: bytes) -> str:
    if data[:5] in (b"GET /", b"POST ", b"HEAD ", b"PUT /", b"OPTIO", b"CONNE", b"DELET", b"PROPF"):
        return "http"
    if data[:5] == b"HTTP/":
        return "http"
    if data[:2] in (b"\x16\x03", b"\x16\x01") or data[:3] == b"\x80\x2e\x01":
        return "tls"
    if data[:4] == b"SSH-":
        return "ssh"
    if data[:1] == b"*" and data[1:2].isdigit():
        return "redis"
    if data[:2] == b"\x03\x00":
        return "tpkt"
    if data[1:5] in (b"SMB\x72", b"SMB\x40") or data[:4] in (b"\xffSMB", b"\xfeSMB"):
        return "smb"
    if data[:2] in (b"\x05\x01", b"\x05\x02") or data[:2] == b"\x04\x01":
        return "socks"
    if data[:1] in (b"{", b"["):
        return "json"
    return "unknown" if data else "empty"


class _Closed(Exception):
    """The client went away or a limit was hit; ``reason`` says which."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _TooLarge(Exception):
    def __init__(self, header: bytes, length: int) -> None:
        super().__init__("packet too large")
        self.header = header
        self.length = length


class _OutOfOrder(Exception):
    """The sequence id of a packet is not the expected one (error 1156 on a real server)."""

    def __init__(self, header: bytes) -> None:
        super().__init__("packets out of order")
        self.header = header


@dataclass(slots=True)
class Packet:
    seq: int
    payload: bytes  # first ``cap`` bytes only
    length: int  # real length


class Sensor:
    """Process-wide state shared by all connections."""

    def __init__(
        self, cfg: Config, sink: EventSink, identity: Identity, guard: MemoryGuard | None = None
    ) -> None:
        self.cfg = cfg
        self.sink = sink
        self.identity = identity
        self.tls = make_tls_context(identity) if cfg.enable_tls else None
        self.guard = guard or MemoryGuard(cfg.memory_limit)
        self.total = 0
        self.per_ip: dict[str, int] = {}
        self.sessions: dict[Session, None] = {}  # insertion order = age
        self.held = 0
        self.rejected = 0
        self.evicted = 0
        self.seen = 0
        self.errors = 0
        self.overflow = 0
        self.tls_limited = 0
        self.logins = 0
        self.started = time.monotonic()
        self._conn_ids = secrets.randbelow(5000) + 40
        self.rate_limited = 0
        self.cpu_limited = 0
        self._last_sample = 0.0
        self.conn_rate = Buckets(cfg.connections_per_sec_per_ip, cfg.connections_burst_per_ip)
        self.tls_rate = Buckets(cfg.tls_per_sec_per_ip, cfg.tls_burst_per_ip)
        self.tls_global = Buckets(cfg.tls_global_per_sec, cfg.tls_global_burst, max_keys=1)
        self.tls_slots = asyncio.Semaphore(cfg.max_tls_handshakes)
        self.rsa_ip = Buckets(cfg.rsa_per_sec_per_ip, cfg.rsa_burst_per_ip)
        self.rsa_all = Buckets(cfg.rsa_per_sec, cfg.rsa_per_sec * 2, max_keys=1)
        self.cpu_ip = Throttle(cfg.cpu_steps_per_sec_ip, cfg.cpu_steps_burst_ip)
        self.cpu_all = Throttle(cfg.cpu_steps_per_sec_all, cfg.cpu_steps_burst_all, max_keys=1)

    def uptime(self) -> int:
        return self.identity.uptime_offset + int(time.monotonic() - self.started)

    def next_conn_id(self) -> int:
        self._conn_ids += 1
        return self._conn_ids

    def rsa_allowed(self, ip: str) -> bool:
        return self.rsa_ip.allow(ip) and self.rsa_all.allow("*")

    # --- admission -----------------------------------------------------------------------

    def acquire(self, ip: str) -> str | None:
        """Take a connection slot; returns the refusal kind, or None when admitted."""
        if self.per_ip.get(ip, 0) >= self.cfg.max_per_ip:
            return "per_ip"
        self._sample_guard()
        if self.guard.refusing:
            return "memory"
        if self.held + self.cfg.conn_cost > self.cfg.memory_budget:
            return "budget"
        if self.total >= self.cfg.max_connections and not self._evict_idle():
            return "global"
        self.total += 1
        self.held += self.cfg.conn_cost
        self.per_ip[ip] = self.per_ip.get(ip, 0) + 1
        return None

    def _sample_guard(self) -> None:
        """Admission also samples memory (at most 10 times a second): a burst of connections
        must not wait for the once-a-second tick to be refused."""
        now = time.monotonic()
        if now - self._last_sample >= GUARD_SAMPLE_EVERY:
            self._last_sample = now
            self.shed()

    def _evict_idle(self) -> bool:
        """At the global cap, drop the oldest connection that has not answered the handshake."""
        now = time.monotonic()
        for session in self.sessions:
            if session.stage == "handshake_sent" and now - session.started > 2.0:
                session.abort("evicted")
                self.evicted += 1
                return True
        return False

    def release(self, ip: str) -> None:
        self.total = max(0, self.total - 1)
        self.held = max(0, self.held - self.cfg.conn_cost)
        left = self.per_ip.get(ip, 1) - 1
        if left <= 0:
            self.per_ip.pop(ip, None)
        else:
            self.per_ip[ip] = left

    def shed(self) -> int:
        """Memory guard tick: above the shed threshold abort the heaviest connections."""
        if not self.guard.sample():
            return 0
        victims = sorted(self.sessions, key=lambda s: s.held_bytes(), reverse=True)
        victims = victims[: max(1, len(victims) // 4)]
        for session in victims:
            session.abort("memory_shed")
        self.guard.aborted += len(victims)
        self.guard.shed_events += 1
        return len(victims)

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)  # noqa: S104
        ip, port = normalize_ip(str(peer[0])), int(peer[1])
        tune_socket(writer.get_extra_info("socket"))
        with contextlib.suppress(Exception):
            cap = self.cfg.output_cap
            writer.transport.set_write_buffer_limits(high=cap // 2, low=cap // 8)
        self.seen += 1
        quiet = self.cfg.quiet_loopback and is_loopback(ip)
        # A per-source rate limit on new connections comes before everything that costs
        # something (slots, handshake, TLS). Over it, the answer is the real one of a source
        # that connects too often, but slow, so that retrying is no cheaper than waiting.
        refusal = "rate" if not self.conn_rate.allow(ip) else self.acquire(ip)
        if refusal is not None:
            self.rejected += 1
            if not quiet:
                self.sink.note_suppressed(ip)
            await self._refuse(writer, ip, refusal)
            return
        session: Session | None = None
        try:
            recorded = not quiet and self.sink.admit(ip)
            session = Session(self, reader, writer, ip, port, recorded, quiet)
            self.sessions[session] = None
            await session.run()
        finally:
            if session is not None:
                self.sessions.pop(session, None)
                session.settle()
            self.release(ip)

    async def _refuse(self, writer: asyncio.StreamWriter, ip: str, kind: str) -> None:
        """Over a cap: answer with the error a real server gives, then close."""
        if self.overflow >= MAX_OVERFLOW:
            writer.transport.abort()
            return
        self.overflow += 1
        try:
            if kind == "rate":
                self.rate_limited += 1
                await asyncio.sleep(self.cfg.refusal_delay)
            if kind in ("per_ip", "rate"):
                err = wire.err_payload(
                    1129,
                    "HY000",
                    f"Host '{ip}' is blocked because of many connection errors; "
                    "unblock with 'mysqladmin flush-hosts'",
                )
            else:
                err = wire.err_payload(1040, "08004", "Too many connections")
            with contextlib.suppress(Exception):
                writer.write(wire.pack(0, err))
                async with asyncio.timeout(2.0):
                    await writer.drain()
        finally:
            self.overflow -= 1
            await _close(writer)

    def stats(self) -> dict[str, int]:
        return {
            "connections": self.total,
            "seen": self.seen,
            "rejected": self.rejected,
            "evicted": self.evicted,
            "tls_limited": self.tls_limited,
            "rate_limited": self.rate_limited,
            "cpu_limited": self.cpu_limited,
            "errors": self.errors,
            "logins": self.logins,
            "held_kib": self.held // 1024,
            "memory_mib": self.guard.usage // (1024 * 1024),
            "memory_aborted": self.guard.aborted,
            **self.sink.stats(),
        }


async def _close(writer: asyncio.StreamWriter) -> None:
    """Close, but never let a peer that does not read keep our buffers: abort instead."""
    transport = writer.transport
    try:
        if transport.get_write_buffer_size() > 0:
            transport.abort()
        else:
            writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 2.0)
        except BaseException:  # timeout, reset, cancellation: make sure nothing lingers
            transport.abort()
    except Exception:
        transport.abort()


class Session:
    def __init__(
        self,
        sensor: Sensor,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        ip: str,
        port: int,
        recorded: bool,
        quiet: bool,
    ) -> None:
        self.sensor = sensor
        self.cfg = sensor.cfg
        self.reader = reader
        self.writer = writer
        self.ip = ip
        self.port = port
        self.recorded = recorded
        self.quiet = quiet
        self.session_id = uuid.uuid4().hex[:24]
        self.started = time.monotonic()
        self.started_wall = datetime.now(UTC)
        self.conn_id = sensor.next_conn_id()
        self.stage = "connected"
        self.salt = auth.new_salt()
        self.caps = 0
        self.seq = 0
        self.inbuf = bytearray()
        self.pending = 0  # bytes of the packet being assembled
        self.bytes_in = 0
        self.bytes_out = 0
        self.tls_active = False
        self.tls_obj: ssl.SSLObject | None = None
        self.tls_in: ssl.MemoryBIO | None = None
        self.tls_out: ssl.MemoryBIO | None = None
        self.auth_attempts = 0
        self.logged_in = False
        self.user = ""
        self.commands = 0
        self.responder: Responder | None = None
        self.aborted: str | None = None
        self.summary: dict[str, Any] = {}
        self._connect_sent = recorded
        self._command_events = 0
        self._important_events = 0
        self._download_events = 0
        self.suppressed_commands = 0
        self.suppressed_important = 0
        self.out_charge = 0  # pending output bytes charged to the sensor's memory budget
        self.cpu = Throttle(
            self.cfg.cpu_steps_per_sec_conn, self.cfg.cpu_steps_burst_conn, max_keys=1
        )

    # --- lifecycle helpers ---------------------------------------------------------------

    def held_bytes(self) -> int:
        return len(self.inbuf) + self.pending + self.out_charge

    def _set_out(self, size: int) -> None:
        """Charge ``size`` bytes of pending output (built, or waiting in the transport)."""
        self.sensor.held += size - self.out_charge
        self.out_charge = size

    def settle(self) -> None:
        """The connection is gone: give its output charge back."""
        self._set_out(0)

    async def _spend(self, steps: int) -> None:
        """Pay for CPU work in steps: wait for the connection's, the source's and the global
        token bucket, or give up on a connection that asks for more than it can ever get."""
        if steps < SPEND_MIN:
            return
        now = time.monotonic()
        wait = max(
            self.cpu.reserve("c", steps, now),
            self.sensor.cpu_ip.reserve(self.ip, steps, now),
            self.sensor.cpu_all.reserve("*", steps, now),
        )
        if wait > self.cfg.cpu_max_delay:
            self.sensor.cpu_limited += 1
            raise _Closed("cpu_limit")
        if wait > 0:
            await asyncio.sleep(wait)

    def abort(self, reason: str) -> None:
        self.aborted = reason
        with contextlib.suppress(Exception):
            self.writer.transport.abort()

    # --- events --------------------------------------------------------------------------

    def _emit(
        self,
        type_: EventType,
        data: dict[str, Any],
        *,
        important: bool = False,
        prelude: tuple[EventType, dict[str, Any], datetime] | None = None,
    ) -> bool:
        if self.quiet:
            return False
        return self.sensor.sink.emit(
            session_id=self.session_id,
            src_ip=self.ip,
            src_port=self.port,
            type_=type_,
            data=data,
            important=important,
            prelude=prelude,
        )

    def emit_routine(self, type_: EventType, data: dict[str, Any]) -> None:
        if self.recorded:
            self._emit(type_, data)

    def emit_important(self, type_: EventType, data: dict[str, Any]) -> bool:
        """Credentials, flagged queries, downloads: recorded even for sampled-out sessions."""
        if self._important_events >= self.cfg.session_important_events:
            self.suppressed_important += 1
            return False
        self._important_events += 1
        # A sampled-out session reports its credentials preceded by a connect event with the
        # real connection time. The sink queues it together with this event, only if the source
        # still has important-event budget, and without charging that budget for it.
        prelude = None
        if not self._connect_sent:
            prelude = (EventType.connect, {"server_version": self.cfg.version}, self.started_wall)
        sent = self._emit(type_, data, important=True, prelude=prelude)
        if sent:
            self._connect_sent = True
        return sent

    # --- I/O -----------------------------------------------------------------------------

    async def _raw_read(self, wait: float) -> bytes:
        if self.bytes_in >= self.cfg.max_input_bytes:
            raise _Closed("input_limit")
        try:
            async with asyncio.timeout(max(wait, 0.001)):
                data = await self.reader.read(READ_CHUNK)
        except TimeoutError:
            raise _Closed("timeout") from None
        except (ConnectionError, OSError):
            raise _Closed("client_reset") from None
        if not data:
            raise _Closed("client_closed")
        self.bytes_in += len(data)
        return data

    async def _recv(self, n: int, wait: float) -> bytes:
        """1..n bytes of application data (decrypted once TLS is on)."""
        if self.tls_obj is None or self.tls_in is None:
            if not self.inbuf:
                self.inbuf += await self._raw_read(wait)
            out = bytes(self.inbuf[:n])
            del self.inbuf[:n]
            return out
        deadline = time.monotonic() + wait
        for _ in range(MAX_TLS_ROUNDS):
            await asyncio.sleep(0)  # never monopolise the loop, whatever OpenSSL returns
            try:
                data = self.tls_obj.read(n)
                if data:
                    return data
                raise _Closed("client_closed")
            except ssl.SSLWantReadError:
                pass
            except ssl.SSLZeroReturnError:
                raise _Closed("client_closed") from None
            except ssl.SSLError:
                raise _Closed("tls_error") from None
            await self._flush_tls()
            self.tls_in.write(await self._raw_read(deadline - time.monotonic()))
        raise _Closed("tls_error")

    async def _read_exact(self, n: int, wait: float, reason: str = "timeout") -> bytes:
        deadline = time.monotonic() + wait
        out = bytearray()
        while len(out) < n:
            left = deadline - time.monotonic()
            if left <= 0:
                raise _Closed(reason)
            try:
                out += await self._recv(n - len(out), left)
            except _Closed as closed:
                raise _Closed(reason if closed.reason == "timeout" else closed.reason) from None
        return bytes(out)

    async def _read_packet(
        self,
        first_wait: float,
        cap: int,
        idle_reason: str = "timeout",
        limit: int | None = None,
    ) -> Packet:
        """One packet: the first ``cap`` bytes are kept, the rest is read and discarded.

        The sequence id must be the expected one (``self.seq``), as on a real server, which
        checks it before anything else. ``limit`` is the largest length accepted.
        """
        header = await self._read_exact(4, first_wait, idle_reason)
        length = int.from_bytes(header[:3], "little")
        if header[3] != self.seq & 0xFF:
            raise _OutOfOrder(header)
        if length > (self.cfg.max_packet if limit is None else limit):
            raise _TooLarge(header, length)
        kept = bytearray()
        remaining = length
        extra = min(length / self.cfg.min_rate, self.cfg.max_packet_extra)
        end = time.monotonic() + self.cfg.packet_timeout + extra
        try:
            while remaining > 0:
                left = end - time.monotonic()
                if left <= 0:
                    raise _Closed("timeout")
                chunk = await self._recv(min(remaining, READ_CHUNK), left)
                remaining -= len(chunk)
                room = cap - len(kept)
                if room > 0:
                    kept += chunk[:room]
                self.pending = len(kept)
        finally:
            self.pending = 0
        await asyncio.sleep(0)
        return Packet(header[3], bytes(kept), length)

    async def _write(self, data: bytes) -> None:
        if self.bytes_out + len(data) > self.cfg.max_output_bytes:
            raise _Closed("output_limit")
        self.bytes_out += len(data)
        transport = self.writer.transport
        try:
            # Everything not yet on the wire is charged: the bytes built here and the
            # transport's own buffer. Nothing more is built until drain() has returned.
            self._set_out(len(data) + transport.get_write_buffer_size())
            if self.tls_obj is not None and self.tls_out is not None:
                for i in range(0, len(data), PACKET_SEND_CHUNK):
                    self.tls_obj.write(data[i : i + PACKET_SEND_CHUNK])
                    self.writer.write(self.tls_out.read())
                    await self._drain()
            else:
                self.writer.write(data)
                await self._drain()
        except (ssl.SSLError, ConnectionError, OSError):
            transport.abort()
            raise _Closed("client_reset") from None
        finally:
            self._set_out(0 if transport.is_closing() else transport.get_write_buffer_size())

    async def _drain(self) -> None:
        try:
            async with asyncio.timeout(self.cfg.write_timeout):
                await self.writer.drain()
        except TimeoutError:
            self.writer.transport.abort()  # the peer does not read: free the buffers now
            raise _Closed("write_timeout") from None

    async def _flush_tls(self) -> None:
        if self.tls_out is not None:
            pending = self.tls_out.read()
            if pending:
                self.writer.write(pending)
                await self._drain()

    async def _send(self, payloads: Iterable[bytes]) -> None:
        """Send packets with consecutive sequence numbers, in bounded batches.

        ``payloads`` may be a generator: rows are built only as fast as the peer reads them.
        """
        batch = bytearray()
        for payload in payloads:
            batch += wire.pack(self.seq, payload)
            self.seq = (self.seq + 1) & 0xFF
            if len(batch) >= PACKET_SEND_CHUNK:
                await self._write(bytes(batch))
                batch.clear()
        if batch:
            await self._write(bytes(batch))

    # --- main flow -----------------------------------------------------------------------

    async def run(self) -> None:
        if self.recorded:
            self._emit(EventType.connect, {"server_version": self.cfg.version})
        reason = "server_closed"
        try:
            async with asyncio.timeout(self.cfg.max_session):
                reason = await self._serve()
        except TimeoutError:
            reason = "max_session"
        except _Closed as closed:
            reason = self.aborted or closed.reason
            if closed.reason == "cpu_limit":
                with contextlib.suppress(Exception):
                    await self._send([wire.err_payload(1105, "HY000", "Unknown error")])
        except _OutOfOrder:
            reason = self.aborted or "packet_out_of_order"
            with contextlib.suppress(Exception):
                await self._send([wire.err_payload(1156, "08S01", _OUT_OF_ORDER)])
        except asyncio.CancelledError:
            reason = "shutdown"
            raise
        except Exception as exc:
            self.sensor.errors += 1
            reason = self.aborted or "error"
            log.warning("handler error (%s) at stage %s", type(exc).__name__, self.stage)
            with contextlib.suppress(Exception):
                await self._send([wire.err_payload(1105, "HY000", "Unknown error")])
        finally:
            await _close(self.writer)
            self._finish(reason)

    def _finish(self, reason: str) -> None:
        if self.suppressed_commands or self.suppressed_important:
            self._emit(
                EventType.scan,
                {
                    "kind": "events_suppressed",
                    "suppressed_commands": self.suppressed_commands,
                    "suppressed_important": self.suppressed_important,
                },
                important=True,
            )
        data = {
            "duration_s": round(time.monotonic() - self.started, 3),
            "reason": reason,
            "stage": self.stage,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "commands": self.commands,
            "auth_attempts": self.auth_attempts,
            "logged_in": self.logged_in,
            "tls": self.tls_active,
            **self.summary,
        }
        if self.user:
            data["username"] = self.user
        if self.recorded or self._important_events:
            self._emit(EventType.disconnect, data)

    async def _serve(self) -> str:
        offered = wire.SERVER_CAPS | (wire.CLIENT_SSL if self.sensor.tls else 0)
        await self._send(
            [
                wire.handshake_payload(
                    self.cfg.version,
                    self.conn_id,
                    self.salt,
                    offered,
                    self.cfg.default_plugin,
                    wire.SERVER_STATUS_AUTOCOMMIT,
                )
            ]
        )
        self.stage = "handshake_sent"
        self.seq = 1
        try:
            pkt = await self._read_packet(
                self.cfg.handshake_timeout,
                MAX_HANDSHAKE_RESPONSE,
                limit=self.cfg.max_handshake_packet,
            )
        except _TooLarge as big:
            return await self._non_mysql(big.header, reply=False)
        except _OutOfOrder as bad:
            return await self._non_mysql(bad.header, reply=True)
        self.seq = (pkt.seq + 1) & 0xFF
        resp = await self._parse_response(pkt)
        if resp is None:
            return "bad_handshake"
        if resp.ssl_request:
            if self.sensor.tls is None:
                await self._send([wire.err_payload(1043, "08S01", "Bad handshake")])
                return "bad_handshake"
            await self._start_tls()
            try:
                pkt = await self._read_packet(
                    self.cfg.handshake_timeout,
                    MAX_HANDSHAKE_RESPONSE,
                    limit=self.cfg.max_handshake_packet,
                )
            except _TooLarge:
                await self._send([wire.err_payload(1153, "08S01", _TOO_BIG)])
                return "packet_too_large"
            self.seq = (pkt.seq + 1) & 0xFF
            resp = await self._parse_response(pkt)
            if resp is None or resp.ssl_request:
                return "bad_handshake"
        self.caps = resp.caps & offered
        self.stage = "auth"
        if not await self._authenticate(
            resp.username, resp.plugin, resp.auth_response, resp.database, resp
        ):
            return "access_denied"
        return await self._commands()

    async def _non_mysql(self, header: bytes, *, reply: bool) -> str:
        """The first four bytes are not a MySQL packet header: record what it was.

        Like a real server, which reads the header and then (a) complains about the sequence
        id (error 1156) or (b) waits for a payload of the announced length that never comes,
        until the connect timeout, without a word.
        """
        data = bytearray(header)
        with contextlib.suppress(_Closed):
            data += await self._recv(PREVIEW_BYTES - len(data), 0.3)
        self.emit_routine(EventType.scan, self._scan_data("non_mysql", bytes(data)))
        if reply:
            with contextlib.suppress(_Closed):
                await self._send([wire.err_payload(1156, "08S01", _OUT_OF_ORDER)])
            return "non_mysql"
        deadline = time.monotonic() + self.cfg.handshake_timeout
        with contextlib.suppress(_Closed):
            while (left := deadline - time.monotonic()) > 0:
                await self._recv(READ_CHUNK, left)  # read and discard
        return "non_mysql"

    @staticmethod
    def _scan_data(kind: str, data: bytes, **extra: Any) -> dict[str, Any]:
        return {
            "kind": kind,
            "protocol_guess": guess_protocol(data),
            "payload_preview": data[:PREVIEW_BYTES].hex(),
            "payload_ascii": "".join(
                chr(b) if 32 <= b < 127 else "." for b in data[:PREVIEW_BYTES]
            ),
            "bytes_received": len(data),
            **extra,
        }

    async def _parse_response(self, pkt: Packet) -> wire.HandshakeResponse | None:
        if pkt.length > MAX_HANDSHAKE_RESPONSE:
            self.emit_routine(
                EventType.scan, self._scan_data("malformed_mysql", pkt.payload, error="too_long")
            )
            await self._send([wire.err_payload(1043, "08S01", "Bad handshake")])
            return None
        try:
            return wire.parse_handshake_response(pkt.payload)
        except wire.PacketError as err:
            self.emit_routine(
                EventType.scan, self._scan_data("malformed_mysql", pkt.payload, error=err.reason)
            )
            await self._send([wire.err_payload(1043, "08S01", "Bad handshake")])
            return None

    # --- TLS -----------------------------------------------------------------------------

    async def _start_tls(self) -> None:
        sensor = self.sensor
        assert sensor.tls is not None  # noqa: S101 - checked by the caller
        if not sensor.tls_rate.allow(self.ip) or not sensor.tls_global.allow("*"):
            sensor.tls_limited += 1
            raise _Closed("tls_rate_limited")
        try:
            async with asyncio.timeout(2.0):
                await sensor.tls_slots.acquire()
        except TimeoutError:
            sensor.tls_limited += 1
            raise _Closed("tls_busy") from None
        try:
            self.stage = "tls_handshake"
            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
            obj = sensor.tls.wrap_bio(incoming, outgoing, server_side=True)
            # The ClientHello may already sit in our buffer, behind the SSLRequest.
            if self.inbuf:
                incoming.write(bytes(self.inbuf))
                self.inbuf.clear()
            deadline = time.monotonic() + self.cfg.handshake_timeout
            for _ in range(MAX_TLS_ROUNDS):
                await asyncio.sleep(0)
                try:
                    obj.do_handshake()
                    break
                except ssl.SSLWantReadError:
                    self.writer.write(outgoing.read())
                    await self._drain()
                    left = deadline - time.monotonic()
                    if left <= 0:
                        raise _Closed("timeout") from None
                    incoming.write(await self._raw_read(left))
                except ssl.SSLError as err:
                    self.summary["tls_error"] = str(err.reason or "handshake_failed")[:64]
                    with contextlib.suppress(Exception):
                        self.writer.write(outgoing.read())
                        await self._drain()
                    raise _Closed("tls_error") from None
            else:
                self.summary["tls_error"] = "too_many_rounds"
                raise _Closed("tls_error")
        finally:
            sensor.tls_slots.release()
        self.writer.write(outgoing.read())
        await self._drain()
        self.tls_obj, self.tls_in, self.tls_out = obj, incoming, outgoing
        self.tls_active = True
        cipher = obj.cipher()
        self.summary["tls_version"] = obj.version()
        self.summary["tls_cipher"] = cipher[0] if cipher else None

    # --- authentication ------------------------------------------------------------------

    async def _read_auth_packet(self, cap: int = 1024) -> Packet:
        try:
            pkt = await self._read_packet(
                self.cfg.handshake_timeout, cap, limit=self.cfg.max_handshake_packet
            )
        except _TooLarge:
            raise _Closed("packet_too_large") from None
        self.seq = (pkt.seq + 1) & 0xFF
        return pkt

    async def _exchange(
        self, user: str, plugin: str, data: bytes
    ) -> tuple[bytes | None, str | None, str]:
        """Run the plugin conversation. Returns (cleartext password, source, plugin used)."""
        known = self.cfg.accounts.get(user, ())
        if self.cfg.clear_password_switch and plugin != "mysql_clear_password":
            await self._send([wire.auth_switch_payload("mysql_clear_password", b"")])
            pkt = await self._read_auth_packet(512)
            return pkt.payload.split(b"\x00", 1)[0], "cleartext_switch", "mysql_clear_password"
        for _ in range(3):
            if plugin == "mysql_clear_password":
                return data.split(b"\x00", 1)[0], "cleartext", plugin
            if plugin in ("", NATIVE):
                if not data:
                    return b"", "empty", NATIVE
                for cand in known:
                    if auth.verify_native(data, cand, self.salt):
                        return cand, "scramble_match", NATIVE
                return None, None, NATIVE
            if plugin == CACHING:
                if data in (b"", b"\x00"):  # libmysqlclient sends one NUL for an empty password
                    return b"", "empty", plugin
                for cand in known:
                    if auth.verify_caching_sha2(data, cand, self.salt):
                        await self._send([wire.auth_more_data(b"\x03")])  # fast auth success
                        return cand, "scramble_match", plugin
                password, source = await self._full_auth()
                return password, source, plugin
            # Not a plugin we serve: ask for the default one with a fresh salt, as a server would.
            plugin = self.cfg.default_plugin
            self.salt = auth.new_salt()
            await self._send([wire.auth_switch_payload(plugin, self.salt + b"\x00")])
            data = (await self._read_auth_packet(512)).payload
        return None, None, plugin

    async def _full_auth(self) -> tuple[bytes | None, str | None]:
        """caching_sha2_password full authentication: the client sends its password."""
        await self._send([wire.auth_more_data(b"\x04")])
        for _ in range(3):
            pkt = await self._read_auth_packet(1024)
            if self.tls_active:
                password = pkt.payload
                return (password[:-1] if password.endswith(b"\x00") else password), "tls_cleartext"
            if pkt.payload == b"\x02":  # request for the public key
                await self._send([wire.auth_more_data(self.sensor.identity.rsa_public_pem)])
                continue
            if not self.sensor.rsa_allowed(self.ip):
                return None, "rsa_rate_limited"
            clear = auth.decrypt_password(self.sensor.identity.rsa_private, pkt.payload, self.salt)
            return (clear, "rsa_cleartext") if clear is not None else (None, "rsa_invalid")
        return None, None

    async def _authenticate(
        self,
        user: str,
        plugin: str,
        data: bytes,
        database: str,
        resp: wire.HandshakeResponse | None = None,
    ) -> bool:
        """One login attempt: exchange, verdict, event, final OK or ERR packet."""
        self.auth_attempts += 1
        self.sensor.logins += 1
        password: bytes | None = None
        source: str | None = None
        method = plugin or NATIVE
        failure: _Closed | None = None
        if self.auth_attempts > self.cfg.max_auth_attempts:
            failure = _Closed("auth_limit")
        else:
            try:
                password, source, method = await self._exchange(user, plugin, data)
            except _Closed as closed:
                failure = closed
        known = self.cfg.accounts.get(user)
        ok = failure is None and known is not None and password is not None and password in known
        event: dict[str, Any] = {
            "username": user[:256],
            "password": password.decode("utf-8", "replace")[:128] if password is not None else None,
            "success": ok,
            "method": method,
            "password_source": source,
            "auth_response_len": len(data),
            "auth_response_preview": data[:LOGIN_PREVIEW_BYTES].hex(),
            "client_plugin": plugin,
            "database": database[:64],
            "tls": self.tls_active,
            "attempt": self.auth_attempts,
        }
        if resp is not None:
            event["client_caps"] = f"{resp.caps:#010x}"
            event["charset"] = resp.charset
            event["client_attrs"] = resp.attrs
        if failure is not None:
            event["incomplete"] = failure.reason
        self.summary.setdefault("username", user[:64])
        self.emit_important(EventType.login_attempt, event)
        if failure is not None:
            raise failure
        if not ok:
            using = "NO" if password == b"" else "YES"
            msg = f"Access denied for user '{user[:64]}'@'{self.ip}' (using password: {using})"
            await self._send([wire.err_payload(1045, "28000", msg)])
            return False
        self.logged_in = True
        self.user = user
        self.responder = Responder(
            version=self.cfg.version,
            hostname=self.sensor.identity.hostname,
            user=user,
            client_ip=self.ip,
            client_port=self.port,
            conn_id=self.conn_id,
            uptime=self.sensor.uptime,
            seed=self.sensor.identity.secret,
            query_steps=self.cfg.query_steps,
            sleep_per_query=self.cfg.sleep_per_query,
            sleep_per_connection=self.cfg.sleep_per_connection,
        )
        if database:
            res = self.responder.use_db(database)
            if isinstance(res, Err):
                await self._send([wire.err_payload(res.code, res.state, res.message)])
                self.summary["reason_detail"] = "unknown_database"
                return False
        await self._send([self._ok()])
        self.stage = "ready"
        return True

    def _ok(
        self,
        affected: int = 0,
        last_insert_id: int = 0,
        status: int = wire.SERVER_STATUS_AUTOCOMMIT,
        info: str = "",
    ) -> bytes:
        tracked = bool(self.caps & wire.CLIENT_SESSION_TRACK)
        return wire.ok_payload(affected, last_insert_id, status, info=info, session_track=tracked)

    # --- command phase -------------------------------------------------------------------

    async def _commands(self) -> str:
        assert self.responder is not None  # noqa: S101
        while True:
            self.seq = 0  # every command starts a new sequence
            try:
                pkt = await self._read_packet(
                    self.cfg.idle_timeout, self.cfg.capture_bytes + 1, "idle_timeout"
                )
            except _TooLarge:
                await self._send([wire.err_payload(1153, "08S01", _TOO_BIG)])
                return "packet_too_large"
            self.seq = (pkt.seq + 1) & 0xFF
            self.commands += 1
            if self.commands > self.cfg.max_commands:
                return "command_limit"
            if not pkt.payload:
                await self._send([wire.err_payload(1047, "08S01", "Unknown command")])
                continue
            cmd, body = pkt.payload[0], pkt.payload[1:]
            if cmd == wire.COM_QUIT:
                return "client_quit"
            if cmd == wire.COM_PING:
                await self._send([self._ok()])
            elif cmd == wire.COM_QUERY:
                await self._com_query(body, pkt.length - 1)
            elif cmd == wire.COM_INIT_DB:
                name = body.decode("utf-8", "replace")[:256]
                res = self.responder.use_db(name)
                self._record_command(cmd, f"USE {name}", pkt.length - 1, [], res, 1)
                await self._send_result(res, more=False)
            elif cmd == wire.COM_CHANGE_USER:
                if not await self._change_user(pkt):
                    return "access_denied"
            elif cmd == wire.COM_STMT_PREPARE:
                text = body.decode("utf-8", "replace")
                res = Err(
                    1295,
                    "HY000",
                    "This command is not supported in the prepared statement protocol yet",
                )
                self._query_side_effects(text, pkt.length - 1, cmd, 1, res)
                await self._send_result(res, more=False)
            elif cmd == wire.COM_STMT_CLOSE:
                continue  # no reply
            elif cmd in (wire.COM_STMT_EXECUTE, wire.COM_STMT_RESET):
                ident = int.from_bytes(body[:4], "little") if len(body) >= 4 else 0
                name = (
                    "mysqld_stmt_execute" if cmd == wire.COM_STMT_EXECUTE else "mysqld_stmt_reset"
                )
                msg = f"Unknown prepared statement handler ({ident}) given to {name}"
                await self._send([wire.err_payload(1243, "HY000", msg)])
            elif cmd == wire.COM_STATISTICS:
                await self._write(wire.pack(self.seq, self.responder.statistics().encode()))
                self.seq = (self.seq + 1) & 0xFF
            elif cmd == wire.COM_SET_OPTION:
                option = int.from_bytes(body[:2], "little") if len(body) >= 2 else 1
                if option == 0:
                    self.caps |= wire.CLIENT_MULTI_STATEMENTS
                elif option == 1:
                    self.caps &= ~wire.CLIENT_MULTI_STATEMENTS
                await self._send([self._eof()])
            elif cmd == wire.COM_FIELD_LIST:
                await self._send([self._eof()])
            elif cmd == wire.COM_RESET_CONNECTION:
                await self._send([self._ok()])
            else:
                name = wire.COMMAND_NAMES.get(cmd, f"0x{cmd:02x}")
                self.emit_routine_command(name, body)
                await self._send([wire.err_payload(1047, "08S01", "Unknown command")])

    def _eof(self) -> bytes:
        if self.caps & wire.CLIENT_DEPRECATE_EOF:
            return wire.ok_payload(
                header=0xFE, session_track=bool(self.caps & wire.CLIENT_SESSION_TRACK)
            )
        return wire.eof_payload()

    def emit_routine_command(self, name: str, body: bytes) -> None:
        self._command_event(
            {"input": name, "protocol_command": name, "raw_preview": body[:32].hex()}, False
        )

    async def _change_user(self, pkt: Packet) -> bool:
        try:
            req = wire.parse_change_user(pkt.payload, self.caps)
        except wire.PacketError:
            await self._send([wire.err_payload(1043, "08S01", "Bad handshake")])
            return False
        self.stage = "auth"
        ok = await self._authenticate(req.username, req.plugin, req.auth_response, req.database)
        return ok

    async def _com_query(self, body: bytes, total: int) -> None:
        """COM_QUERY, with the attribute prefix of clients that negotiated query attributes."""
        assert self.responder is not None  # noqa: S101
        if not self.caps & wire.CLIENT_QUERY_ATTRIBUTES:
            await self._query(body, total)
            return
        try:
            parsed = wire.parse_query_attributes(body)
        except wire.PacketError:
            await self._send([wire.err_payload(1835, "HY000", "Malformed communication packet.")])
            return
        prefix = len(body) - len(parsed.query)
        await self._query(parsed.query, total - prefix, parsed.names)

    async def _query(
        self, raw: bytes, total: int, attributes: dict[str, str | None] | None = None
    ) -> None:
        """Answer the statements of one COM_QUERY within its work budget.

        The budget (``query_steps``, in rows examined) is shared by all statements, so 50
        full scans in one packet cost the same as one. The loop is yielded to after every
        statement, and the time actually spent is charged to the connection, source and
        global CPU token buckets afterwards (the next command waits, nothing else does).
        """
        assert self.responder is not None  # noqa: S101
        responder = self.responder
        responder.begin_query()
        started = time.thread_time()  # CPU time of this thread: immune to preemption
        text = raw.decode("utf-8", "replace")
        stmts = sqlish.split_statements(sqlish.tokenize(text))
        flags = sqlish.compute_flags(stmts)
        work = time.thread_time() - started
        results: list[Result] = []
        multi_ok = bool(self.caps & wire.CLIENT_MULTI_STATEMENTS)
        try:
            await asyncio.sleep(0)
            if not stmts:
                res: Result = Err(1065, "42000", "Query was empty")
                results.append(res)
                await self._send_result(res, more=False)
                return
            if len(stmts) > 1 and not multi_ok:
                res = responder.syntax_error(stmts[1], 0, text)
                results.append(res)
                await self._send_result(res, more=False)
                return
            for i, stmt in enumerate(stmts):
                began = time.thread_time()
                res = responder.respond(stmt, text)
                work += time.thread_time() - began
                results.append(res)
                last = i == len(stmts) - 1 or isinstance(res, Err)
                await self._send_result(res, more=not last)
                await asyncio.sleep(0)  # a turn of the loop between statements, always
                if last:
                    break
        finally:
            self._query_side_effects(
                text,
                total,
                wire.COM_QUERY,
                len(stmts),
                results[-1] if results else None,
                flags,
                attributes,
            )
        await self._spend(max(responder.steps_used, int(work * STEPS_PER_SECOND)))

    def _query_side_effects(
        self,
        text: str,
        total: int,
        cmd: int,
        statements: int,
        result: Result | None,
        flags: list[str] | None = None,
        attributes: dict[str, str | None] | None = None,
    ) -> None:
        if flags is None:
            flags = sqlish.compute_flags(sqlish.split_statements(sqlish.tokenize(text)))
        self._record_command(cmd, text, total, flags, result, statements, attributes)
        urls = sqlish.find_urls(text)
        for url, tool in urls:
            if self._download_events >= self.cfg.session_download_events:
                break
            self._download_events += 1
            self.emit_important(
                EventType.download_attempt,
                {"url": url, "tool": tool, "command": text[:512], "protocol": "mysql"},
            )

    def _record_command(
        self,
        cmd: int,
        text: str,
        total: int,
        flags: list[str],
        result: Result | None,
        statements: int,
        attributes: dict[str, str | None] | None = None,
    ) -> None:
        data: dict[str, Any] = {
            "input": text,
            "protocol_command": wire.COMMAND_NAMES.get(cmd, f"0x{cmd:02x}"),
            "database": self.responder.db if self.responder else None,
            "statements": statements,
            "length": total,
            "truncated": total > self.cfg.capture_bytes,
            "flags": flags,
            "output_preview": _describe(result),
        }
        if attributes:
            data["query_attributes"] = attributes
        self._command_event(data, bool(flags))

    def _command_event(self, data: dict[str, Any], important: bool) -> None:
        if important:
            self.emit_important(EventType.command, data)
        elif self._command_events < self.cfg.session_command_events:
            self._command_events += 1
            if self.recorded:
                self._emit(EventType.command, data)
        else:
            self.suppressed_commands += 1

    async def _send_result(self, res: Result, *, more: bool) -> None:
        status = wire.SERVER_STATUS_AUTOCOMMIT | (wire.SERVER_MORE_RESULTS_EXISTS if more else 0)
        payloads: Iterable[bytes]
        if isinstance(res, Ok):
            payloads = [self._ok(res.affected, res.last_insert_id, status, res.info)]
        elif isinstance(res, Err):
            payloads = [wire.err_payload(res.code, res.state, res.message)]
        else:
            if res.delay > 0:
                await asyncio.sleep(res.delay)
            payloads = wire.result_set_payloads(res.columns, res.rows, self.caps, status)
        await self._send(payloads)


_TOO_BIG = "Got a packet bigger than 'max_allowed_packet' bytes"
_OUT_OF_ORDER = "Got packets out of order"


def _describe(result: Result | None) -> str:
    if result is None:
        return ""
    if isinstance(result, Ok):
        return f"OK, {result.affected} rows affected"
    if isinstance(result, Err):
        return f"ERROR {result.code} ({result.state}): {result.message}"[:OUTPUT_PREVIEW]
    head = ", ".join(c.name for c in result.columns)
    sample = (
        " | ".join(v if v is not None else "NULL" for v in result.rows[0]) if result.rows else ""
    )
    return f"{len(result.rows)} rows [{head}] {sample}"[:OUTPUT_PREVIEW]


class MySQLServer:
    def __init__(self, cfg: Config, sensor: Sensor) -> None:
        self.cfg = cfg
        self.sensor = sensor
        self._server: asyncio.Server | None = None
        self._tasks: list[asyncio.Task[None]] = []

    async def start(self) -> int:
        self._server = await asyncio.start_server(
            self.sensor.handle,
            host=self.cfg.host,
            port=self.cfg.port,
            limit=READ_CHUNK * 2,
            backlog=256,
            reuse_address=True,
        )
        self._tasks = [
            asyncio.create_task(self._summaries()),
            asyncio.create_task(self._guard()),
        ]
        sockets = self._server.sockets
        return int(sockets[0].getsockname()[1]) if sockets else self.cfg.port

    async def _summaries(self) -> None:
        while True:
            await asyncio.sleep(self.cfg.summary_interval)
            self.sensor.sink.flush_suppressed(self.cfg.summary_interval)

    async def _guard(self) -> None:
        while True:
            await asyncio.sleep(1.0)
            self.sensor.shed()

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._server.wait_closed(), 5.0)
        self.sensor.sink.flush_suppressed(self.cfg.summary_interval)


__all__ = ["MySQLServer", "ResultSet", "Sensor", "Session", "make_tls_context"]
