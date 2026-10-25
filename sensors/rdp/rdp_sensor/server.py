"""The RDP listener: X.224 negotiation like Windows Server 2022, TLS, CredSSP (NLA) and an
optional "NLA disabled" MCS path.

Per connection:

1. Wait for the first bytes. Anything that is not a TPKT is recorded as a ``scan`` and closed.
2. Parse the X.224 Connection Request strictly; the ``mstshash`` cookie becomes a cookie
   ``login_attempt``.
3. Answer with a Connection Confirm: HYBRID / HYBRID_EX (CredSSP) when offered; in "NLA
   disabled" mode also SSL; otherwise ``HYBRID_REQUIRED_BY_SERVER``; legacy clients get a bare
   confirm.
4. CredSSP path (HYBRID / HYBRID_EX): complete TLS, read the client's NTLM NEGOTIATE, answer
   with a realistic NTLM CHALLENGE, read the NTLM AUTHENTICATE and record a ``login_attempt``
   (domain, user, workstation, NTLM version, NT-response length + 8-byte preview). For a weak
   pair configured on the sensor the NTLMv2 / NTLMv1 response is verified against the known
   cleartext (the server challenge is known), recording the password and success. The logon is
   always refused with a CredSSP errorCode of STATUS_LOGON_FAILURE; no session is ever granted.
5. NLA-off path (SSL selected): complete TLS, run the MCS / GCC connect sequence to the Client
   Info PDU, record the cleartext domain / user / password, then tear the connection down.

Nothing is executed, fetched or written outside the data directory, and the sensor never opens
an outbound connection. Every read has a deadline, every buffer a size cap, the whole
connection a hard time cap, and expensive work is charged to per-IP CPU and memory budgets.
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
from dataclasses import dataclass
from typing import Any

from suckerpot_common import EventType

from rdp_sensor import credssp, fingerprint, mcs, ntlm, probe, protocol
from rdp_sensor.config import NLA_OPTIONAL, Config
from rdp_sensor.events import Buckets, EventSink
from rdp_sensor.identity import Identity
from rdp_sensor.memguard import MemoryGuard

log = logging.getLogger("rdp_sensor.server")

READ_CHUNK = 16 * 1024
SOCK_BUF = 32 * 1024  # Linux doubles it
MAX_SESSION_INPUT = 96 * 1024  # raw bytes read from one client, all stages together
MAX_CREDSSP_PLAINTEXT = 16 * 1024
MAX_TLS_PLAINTEXT = 32 * 1024  # decrypted bytes held for MCS framing
TLS_COST = 48 * 1024  # budgeted bytes charged per live TLS session (memory backstop)
NON_RDP_EXTRA_WAIT = 0.3
MAX_TLS_ROUNDS = 64  # TLS handshake / read iterations per connection
MAX_OVERFLOW = 64  # over-cap connections being answered slowly at the same time
OVERFLOW_READ_WAIT = 2.0
TLS_SLOT_WAIT = 2.0
# Groups Schannel offers by default (applied only where the ssl module supports it).
TLS_GROUPS = ("x25519", "secp256r1", "secp384r1")

# Per-session event quotas (a single connection cannot flood one event type).
_QUOTA = {
    EventType.login_attempt: 6,
    EventType.scan: 10,
}

# Schannel-like TLS 1.2 cipher preference (TLS 1.3 suites are OpenSSL's defaults).
TLS12_CIPHERS = ":".join(
    [
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "DHE-RSA-AES256-GCM-SHA384",
        "DHE-RSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES256-SHA384",
        "ECDHE-RSA-AES128-SHA256",
        "ECDHE-RSA-AES256-SHA",
        "ECDHE-RSA-AES128-SHA",
        "AES256-GCM-SHA384",
        "AES128-GCM-SHA256",
        "AES256-SHA256",
        "AES128-SHA256",
        "AES256-SHA",
        "AES128-SHA",
    ]
)


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
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(identity.cert_path), str(identity.key_path))
    ctx.set_ciphers(TLS12_CIPHERS)
    # No session tickets: no resumption state to hand out, nothing to encrypt per client.
    ctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE | ssl.OP_NO_COMPRESSION | ssl.OP_NO_TICKET
    set_groups = getattr(ctx, "set_groups", None)
    if set_groups is not None:  # Python 3.15+
        with contextlib.suppress(ssl.SSLError, ValueError):
            set_groups(":".join(TLS_GROUPS))
    return ctx


def der_total_length(data: bytes) -> int | None:
    """Length of the first DER element (header included), if its header is complete."""
    if len(data) < 2:
        return None
    first = data[1]
    if first < 0x80:
        return 2 + first
    n = first & 0x7F
    if n == 0 or n > 3 or len(data) < 2 + n:
        return -1 if n == 0 or n > 3 else None
    return 2 + n + int.from_bytes(data[2 : 2 + n], "big")


class _Closed(Exception):
    """The client went away or a limit was hit; ``reason`` says which."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


async def _close(writer: asyncio.StreamWriter, abort: bool = False) -> None:
    """Close and wait until the transport is really gone; abort it if it does not go quietly."""
    transport = writer.transport
    if abort:
        transport.abort()
        return
    with contextlib.suppress(Exception):
        writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 2.0)
    except Exception:
        transport.abort()


class Sensor:
    """Process-wide state shared by all connections."""

    def __init__(
        self,
        cfg: Config,
        sink: EventSink,
        tls: ssl.SSLContext | None,
        identity: Identity,
        guard: MemoryGuard | None = None,
    ) -> None:
        self.cfg = cfg
        self.sink = sink
        self.tls = tls if cfg.enable_tls else None
        self.identity = identity
        self.hostname = identity.hostname
        self.guard = guard or MemoryGuard(cfg.memory_limit)
        self.total = 0
        self.per_ip: dict[str, int] = {}
        self.sessions: dict[Session, None] = {}  # insertion order = age
        self.buffered = 0  # parser bytes + TLS budget + pending output held by all sessions
        self.rejected = 0
        self.evicted = 0
        self.seen = 0
        self.errors = 0
        self.tls_limited = 0
        self.cpu_limited = 0
        self.overflow = 0
        # Expensive work is rate limited per source before it starts, and globally bounded.
        self.tls_rate = Buckets(cfg.tls_per_sec_per_ip, cfg.tls_burst_per_ip)
        self.tls_slots = asyncio.Semaphore(cfg.max_tls_handshakes)
        # Per-IP cap on concurrent TLS handshakes so a few sources cannot hold every global
        # slot and deny TLS to everyone else (filling 32 slots now needs at least 8 IPs).
        self.tls_per_ip: dict[str, int] = {}
        self.cpu_rate = Buckets(cfg.cpu_per_sec_per_ip, cfg.cpu_burst_per_ip)
        self._sample_at = 0.0

    def tls_ip_try(self, ip: str) -> bool:
        """Reserve a per-IP TLS slot; False if this source already holds its share."""
        if self.tls_per_ip.get(ip, 0) >= self.cfg.max_tls_per_ip:
            return False
        self.tls_per_ip[ip] = self.tls_per_ip.get(ip, 0) + 1
        return True

    def tls_ip_release(self, ip: str) -> None:
        left = self.tls_per_ip.get(ip, 1) - 1
        if left <= 0:
            self.tls_per_ip.pop(ip, None)
        else:
            self.tls_per_ip[ip] = left

    def _maybe_sample(self) -> None:
        now = time.monotonic()
        if now - self._sample_at >= 0.2:
            self._sample_at = now
            self.guard.sample()

    def charge_cpu(self, ip: str) -> bool:
        """Spend one CPU token for an expensive step; False means the source is over budget."""
        if self.cpu_rate.allow(ip):
            return True
        self.cpu_limited += 1
        return False

    def acquire(self, ip: str) -> bool:
        if is_loopback(ip) and self.cfg.quiet_loopback:
            self.total += 1
            self.per_ip[ip] = self.per_ip.get(ip, 0) + 1
            return True  # the container healthcheck is never refused
        self._maybe_sample()
        if self.guard.refusing:
            self.guard.refused += 1
            self.rejected += 1
            return False
        if self.per_ip.get(ip, 0) >= self.cfg.max_per_ip:
            self.rejected += 1
            return False
        if self.total >= self.cfg.max_connections and not self._evict_idle():
            self.rejected += 1
            return False
        self.total += 1
        self.per_ip[ip] = self.per_ip.get(ip, 0) + 1
        return True

    def _evict_idle(self) -> bool:
        """At the global cap, close the oldest connection that has not sent anything yet."""
        for session in self.sessions:
            if session.bytes_in == 0 and not session.evicted:
                session.evicted = True
                session.abort()
                self.evicted += 1
                return True
        return False

    def release(self, ip: str) -> None:
        self.total = max(0, self.total - 1)
        left = self.per_ip.get(ip, 1) - 1
        if left <= 0:
            self.per_ip.pop(ip, None)
        else:
            self.per_ip[ip] = left

    def check_memory(self) -> int:
        """One memory-guard tick: above 85 % abort the sessions holding the most memory."""
        if not self.guard.sample():
            return 0
        self.guard.shed_events += 1
        ranked = sorted(self.sessions, key=lambda s: (-s.held, s.started))
        aborted = 0
        for session in ranked[: max(1, len(ranked) // 2)]:
            if session.abort():
                session.shed = True
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

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)  # noqa: S104
        ip, port = normalize_ip(str(peer[0])), int(peer[1])
        self.seen += 1
        quiet = self.cfg.quiet_loopback and is_loopback(ip)
        if not self.acquire(ip):
            if not quiet:
                self.sink.note_suppressed(ip)
            await self._refuse(reader, writer)
            return
        session: Session | None = None
        try:
            recorded = not quiet and self.sink.admit(ip)
            session = Session(self, reader, writer, ip, port, recorded)
            self.sessions[session] = None
            await session.run()
        finally:
            if session is not None:
                self.sessions.pop(session, None)
                self.buffered -= session.held
            self.release(ip)

    async def _refuse(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Over a cap: read the first bytes, then close after a short random delay."""
        if self.overflow >= MAX_OVERFLOW:
            await _close(writer, abort=True)
            return
        self.overflow += 1
        try:
            with contextlib.suppress(Exception):
                async with asyncio.timeout(OVERFLOW_READ_WAIT):
                    await reader.read(protocol.MAX_CR_TPKT)
            await asyncio.sleep(0.2 + secrets.randbelow(800) / 1000)
        finally:
            self.overflow -= 1
            await _close(writer, abort=True)

    def stats(self) -> dict[str, int]:
        return {
            "connections": self.total,
            "seen": self.seen,
            "rejected": self.rejected,
            "evicted": self.evicted,
            "tls_limited": self.tls_limited,
            "cpu_limited": self.cpu_limited,
            "errors": self.errors,
            "buffered": self.buffered,
            "memory_used": self.guard.usage,
            "memory_peak": self.guard.peak,
            "memory_refused": self.guard.refused,
            "memory_aborted": self.guard.aborted,
            **self.sink.stats(),
        }


@dataclass
class TlsState:
    obj: ssl.SSLObject
    incoming: ssl.MemoryBIO
    outgoing: ssl.MemoryBIO


class Session:
    def __init__(
        self,
        sensor: Sensor,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        ip: str,
        port: int,
        recorded: bool,
    ) -> None:
        self.sensor = sensor
        self.cfg = sensor.cfg
        self.reader = reader
        self.writer = writer
        self.ip = ip
        self.port = port
        self.recorded = recorded
        self.session_id = uuid.uuid4().hex[:24]
        self.started = time.monotonic()
        self.buf = b""
        self.tls_plain = b""  # decrypted plaintext waiting to be framed (MCS path)
        self.tls_cost = 0
        self.held = 0
        self.bytes_in = 0
        self.bytes_out = 0
        self.stage = "connected"
        self.evicted = False
        self.shed = False
        self.reset = False
        self.server_challenge = b""
        self.counts: dict[str, int] = {}
        self.suppressed: dict[str, int] = {}
        self.dropped: dict[str, int] = {}
        self.events = 0
        self.flags_seen: set[str] = set()
        self.signals = fingerprint.Signals()
        self.summary: dict[str, Any] = {}

    def abort(self) -> bool:
        transport = self.writer.transport
        if transport.is_closing():
            return False
        transport.abort()
        return True

    # --- events --------------------------------------------------------------------------

    def _quota(self, type_: EventType) -> bool:
        limit = _QUOTA.get(type_)
        if limit is None:
            return True  # connect / disconnect are always allowed
        key = type_.value
        if self.counts.get(key, 0) >= limit or self.events >= self.cfg.session_event_quota:
            self.suppressed[key] = self.suppressed.get(key, 0) + 1
            return False
        self.counts[key] = self.counts.get(key, 0) + 1
        self.events += 1
        return True

    def emit(self, type_: EventType, data: dict[str, Any]) -> None:
        if not self.recorded or not self._quota(type_):
            return
        if not self.sensor.sink.emit(
            session_id=self.session_id,
            src_ip=self.ip,
            src_port=self.port,
            type_=type_,
            data=data,
        ):
            key = type_.value
            self.dropped[key] = self.dropped.get(key, 0) + 1

    def _scan(self, kind: str, data: bytes, **extra: Any) -> None:
        self.emit(
            EventType.scan,
            {
                "kind": kind,
                "protocol_guess": probe.guess_protocol(data),
                "payload_preview": probe.hex_preview(data),
                "payload_ascii": probe.ascii_preview(data),
                "bytes_received": len(data),
                **extra,
            },
        )

    # --- I/O -----------------------------------------------------------------------------

    def _tune_socket(self) -> None:
        transport = self.writer.transport
        with contextlib.suppress(Exception):
            transport.set_write_buffer_limits(high=64 * 1024)
        sock = transport.get_extra_info("socket")
        if sock is None:
            return
        for level, opt, value in (
            (socket.SOL_SOCKET, socket.SO_SNDBUF, SOCK_BUF),
            (socket.SOL_SOCKET, socket.SO_RCVBUF, SOCK_BUF),
            (socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT, 30_000),
            (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1),
        ):
            with contextlib.suppress(OSError, AttributeError):
                sock.setsockopt(level, opt, value)

    def _set_held(self) -> None:
        size = len(self.buf) + len(self.tls_plain) + self.tls_cost
        self.sensor.buffered += size - self.held
        self.held = size
        if self.sensor.buffered > self.cfg.max_buffered:
            raise _Closed("buffered_limit")

    async def _recv(self, wait: float, limit: int = READ_CHUNK) -> bytes:
        room = MAX_SESSION_INPUT - self.bytes_in
        if room <= 0:
            raise _Closed("input_limit")
        try:
            async with asyncio.timeout(wait):
                data = await self.reader.read(min(limit, room))
        except TimeoutError:
            raise _Closed("timeout") from None
        except (ConnectionError, OSError):
            raise _Closed("client_reset") from None
        if not data:
            raise _Closed("client_closed")
        self.bytes_in += len(data)
        return data

    async def _fill(self, size: int, wait: float) -> None:
        """Read until ``self.buf`` holds ``size`` bytes, within one overall deadline."""
        deadline = time.monotonic() + wait
        while len(self.buf) < size:
            left = deadline - time.monotonic()
            if left <= 0:
                raise _Closed("timeout")
            self.buf += await self._recv(left, min(READ_CHUNK, size - len(self.buf)))
            self._set_held()

    async def _send(self, data: bytes) -> None:
        if not data:
            return
        if len(data) > self.cfg.max_pending_output:
            raise _Closed("output_limit")
        self.writer.write(data)
        self.bytes_out += len(data)
        self.sensor.buffered += len(data)
        try:
            async with asyncio.timeout(self.cfg.handshake_timeout):
                await self.writer.drain()
        except TimeoutError:
            raise _Closed("timeout") from None
        except (ConnectionError, OSError):
            raise _Closed("client_reset") from None
        finally:
            self.sensor.buffered -= len(data)

    # --- main flow -----------------------------------------------------------------------

    async def run(self) -> None:
        self._tune_socket()
        self.emit(EventType.connect, {})
        reason = "server_closed"
        try:
            async with asyncio.timeout(self.cfg.max_session):
                reason = await self._serve()
        except TimeoutError:
            reason = "max_session"
        except _Closed as closed:
            reason = closed.reason
            if self.evicted:
                reason = "evicted"
            elif self.shed:
                reason = "memory_pressure"
            elif reason == "timeout" and self.stage == "connected":
                reason = "no_data"
        except asyncio.CancelledError:
            reason = "shutdown"
            raise
        except Exception as exc:
            self.sensor.errors += 1
            reason = "error"
            log.warning("handler error (%s) at stage %s", type(exc).__name__, self.stage)
        finally:
            await _close(self.writer, abort=self.reset)
            self._finalize_summary()
            self.emit(
                EventType.disconnect,
                {
                    "duration_s": round(time.monotonic() - self.started, 3),
                    "reason": reason,
                    "stage": self.stage,
                    "bytes_in": self.bytes_in,
                    "bytes_out": self.bytes_out,
                    "flags": sorted(self.flags_seen),
                    **self.summary,
                },
            )

    def _finalize_summary(self) -> None:
        if self.suppressed:
            self.summary["events_suppressed"] = dict(self.suppressed)
        if self.dropped:
            self.summary["events_dropped"] = dict(self.dropped)
        self.summary["client_tool"] = fingerprint.identify(self.signals).tool

    async def _serve(self) -> str:
        self.buf = await self._recv(self.cfg.first_data_timeout)
        self._set_held()
        self.stage = "first_data"
        if self.buf[0] == protocol.TPKT_VERSION:
            return await self._rdp()
        if self.buf[0] == 0x16:
            return await self._direct_tls()
        return await self._non_rdp()

    async def _non_rdp(self) -> str:
        if len(self.buf) < probe.PREVIEW_BYTES:
            with contextlib.suppress(_Closed):
                self.buf += await self._recv(NON_RDP_EXTRA_WAIT, probe.PREVIEW_BYTES)
        self._scan("non_rdp", self.buf)
        return "non_rdp"

    async def _direct_tls(self) -> str:
        """A TLS ClientHello without X.224 negotiation: record its fingerprint and close."""
        hello: dict[str, Any] | None = None
        with contextlib.suppress(_Closed):
            await self._fill(probe.TLS_RECORD_HEADER, self.cfg.handshake_timeout)
            total = probe.tls_record_length(self.buf)
            if total is not None:
                await self._fill(total, self.cfg.handshake_timeout)
                hello = probe.parse_client_hello(self.buf[:total])
        self._scan("non_rdp", self.buf, client_hello=hello)
        return "non_rdp"

    async def _rdp(self) -> str:
        try:
            await self._fill(protocol.TPKT_HEADER, self.cfg.handshake_timeout)
            length = protocol.tpkt_length(self.buf)
            if length > protocol.MAX_CR_TPKT:
                raise protocol.ParseError("cr_too_long")
            await self._fill(length, self.cfg.handshake_timeout)
            cr = protocol.parse_connection_request(self.buf[:length])
        except protocol.ParseError as err:
            self._scan("malformed_rdp", self.buf, error=err.reason)
            return "malformed_rdp"
        except _Closed:
            self._scan("malformed_rdp", self.buf, error="truncated")
            raise
        extra = self.buf[length:]
        self.stage = "x224_request"
        neg = protocol.negotiate(cr, allow_ssl=self.cfg.nla_mode == NLA_OPTIONAL)
        self.signals.cookie_username = cr.username is not None
        self.signals.cookie_name = cr.username
        self.signals.requested_protocols = cr.requested_protocols
        details = self._cr_details(cr, self.buf[:length])
        details["negotiation"] = neg.summary
        if cr.username is not None:
            self.emit(
                EventType.login_attempt,
                {
                    "username": cr.username,
                    "password": None,
                    "success": False,
                    "method": "rdp-cookie",
                    "client_tool": fingerprint.identify(self.signals).tool,
                    **details,
                },
            )
        else:
            self.emit(EventType.scan, {"kind": "rdp_negotiation", **details})
        self.summary["negotiation"] = neg.summary
        if cr.username is not None:
            self.summary["username"] = cr.username
        await self._send(neg.response)
        self.stage = "x224_confirm"
        if neg.outcome == "failure":
            return "negotiation_failure"
        if neg.outcome == "legacy":
            await self._legacy_followup(extra)
            return "nla_required"
        if self.sensor.tls is None:
            return "server_closed"
        if not self.sensor.tls_rate.allow(self.ip):
            self.sensor.tls_limited += 1
            return "tls_rate_limited"
        if not self.sensor.tls_ip_try(self.ip):
            self.sensor.tls_limited += 1
            return "tls_busy"
        try:
            try:
                async with asyncio.timeout(TLS_SLOT_WAIT):
                    await self.sensor.tls_slots.acquire()
            except TimeoutError:
                self.sensor.tls_limited += 1
                return "tls_busy"
            try:
                return await self._tls(extra, neg.selected_protocol or 0)
            finally:
                self.sensor.tls_slots.release()
        finally:
            self.sensor.tls_ip_release(self.ip)

    @staticmethod
    def _cr_details(cr: protocol.ConnectionRequest, raw: bytes) -> dict[str, Any]:
        return {
            "requested_protocols": cr.requested_protocol_names,
            "requested_protocols_raw": cr.requested_protocols if cr.neg_present else None,
            "neg_request": cr.neg_present,
            "neg_flags": cr.neg_flags,
            "routing_token": cr.routing_token,
            "other_cookie": cr.other_cookie,
            "correlation_id": cr.correlation_id,
            "notes": list(cr.notes),
            "raw_preview": probe.hex_preview(raw),
        }

    async def _legacy_followup(self, extra: bytes) -> None:
        """Read what a legacy client sends next (usually MCS Connect Initial), then drop it."""
        self.buf = extra
        with contextlib.suppress(_Closed):
            if not self.buf:
                self.buf = await self._recv(self.cfg.handshake_timeout)
            if self.buf[:1] == bytes([protocol.TPKT_VERSION]) and len(self.buf) >= 4:
                want = min((self.buf[2] << 8) | self.buf[3], protocol.MAX_TPKT)
                await self._fill(want, self.cfg.handshake_timeout)
        if self.buf:
            self.summary["followup_preview"] = probe.hex_preview(self.buf)
            if b"ms_t120" in self.buf.lower():
                self.summary["ms_t120"] = True
                self.flags_seen.add("bluekeep_probe")
        self.stage = "legacy_followup"

    # --- TLS -----------------------------------------------------------------------------

    async def _flush_tls(self, tls: TlsState) -> None:
        pending = tls.outgoing.read()
        if pending:
            await self._send(pending)

    async def _tls(self, extra: bytes, selected_protocol: int) -> str:
        assert self.sensor.tls is not None  # noqa: S101 - checked by the caller
        self.stage = "tls_handshake"
        self.buf = extra
        self._set_held()
        try:
            await self._fill(probe.TLS_RECORD_HEADER, self.cfg.handshake_timeout)
        except _Closed as closed:
            if closed.reason == "client_closed":
                return "client_closed_after_confirm"
            raise
        total = probe.tls_record_length(self.buf)
        if total is None:
            self.summary["tls_error"] = "not_tls"
            self.summary["after_confirm_preview"] = probe.hex_preview(self.buf)
            return "tls_error"
        await self._fill(total, self.cfg.handshake_timeout)
        hello = probe.parse_client_hello(self.buf[:total])
        if hello is not None:
            self.summary["client_hello"] = hello
            self.signals.ja3_hash = hello.get("ja3_hash")
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        tls = TlsState(
            self.sensor.tls.wrap_bio(incoming, outgoing, server_side=True), incoming, outgoing
        )
        tls.incoming.write(self.buf)
        self.buf = b""
        self.tls_cost = TLS_COST
        self._set_held()
        deadline = time.monotonic() + self.cfg.handshake_timeout
        for _ in range(MAX_TLS_ROUNDS):
            await asyncio.sleep(0)  # never monopolise the loop, whatever OpenSSL returns
            if time.monotonic() >= deadline:
                raise _Closed("timeout")
            try:
                tls.obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                await self._flush_tls(tls)
                left = deadline - time.monotonic()
                if left <= 0:
                    raise _Closed("timeout") from None
                tls.incoming.write(await self._recv(left, 16 * 1024))
            except ssl.SSLError as err:
                with contextlib.suppress(_Closed):
                    await self._flush_tls(tls)  # the alert, as a real server sends it
                self.summary["tls_error"] = str(err.reason or "handshake_failed")[:64]
                return "tls_error"
        else:
            self.summary["tls_error"] = "too_many_rounds"
            return "tls_error"
        await self._flush_tls(tls)
        self.stage = "tls_established"
        cipher = tls.obj.cipher()
        self.summary["tls"] = {
            "version": tls.obj.version(),
            "cipher": cipher[0] if cipher else None,
        }
        if selected_protocol == protocol.PROTOCOL_SSL:
            reason = await self._mcs(tls)
        else:
            reason = await self._credssp(tls)
        with contextlib.suppress(ssl.SSLError, _Closed):
            tls.obj.unwrap()
        with contextlib.suppress(_Closed, ssl.SSLError):
            await self._flush_tls(tls)
        return reason

    def _pump_decrypt(self, tls: TlsState) -> str | None:
        """Decrypt whatever is in the incoming BIO into ``self.tls_plain``.

        Returns a close reason if the stream ended or errored, else None. Caps the plaintext.
        """
        while len(self.tls_plain) < MAX_TLS_PLAINTEXT:
            try:
                chunk = tls.obj.read(MAX_TLS_PLAINTEXT - len(self.tls_plain))
            except ssl.SSLWantReadError:
                return None
            except ssl.SSLZeroReturnError:
                return "client_closed"
            except ssl.SSLError:
                return "tls_error"
            if not chunk:
                return "client_closed"
            self.tls_plain += chunk
            self._set_held()
        return None

    async def _tls_feed(self, tls: TlsState, deadline: float) -> str | None:
        """Read more ciphertext from the socket into the incoming BIO (one round)."""
        left = deadline - time.monotonic()
        if left <= 0:
            return "timeout"
        try:
            tls.incoming.write(await self._recv(left, 16 * 1024))
        except _Closed as closed:
            return closed.reason
        return None

    async def _tls_send(self, tls: TlsState, data: bytes) -> None:
        tls.obj.write(data)
        await self._flush_tls(tls)

    # --- CredSSP (NLA) -------------------------------------------------------------------

    async def _read_der(self, tls: TlsState, deadline: float) -> bytes | None:
        """Read one complete DER TSRequest from the TLS stream (bounded).

        Returns the element, or None if the stream closed, the deadline passed or the element
        would exceed the plaintext cap. A partially-received element is never returned.
        """
        while True:
            await asyncio.sleep(0)
            want = der_total_length(self.tls_plain)
            if want == -1 or (want is not None and want > MAX_CREDSSP_PLAINTEXT):
                return None
            if want is not None and len(self.tls_plain) >= want:
                out, self.tls_plain = self.tls_plain[:want], self.tls_plain[want:]
                self._set_held()
                return out
            if len(self.tls_plain) >= MAX_CREDSSP_PLAINTEXT:
                return None
            if self._pump_decrypt(tls):
                return None
            want = der_total_length(self.tls_plain)
            if want is not None and len(self.tls_plain) >= want:
                continue  # complete now; the top of the loop extracts it
            if time.monotonic() >= deadline:
                return None
            if await self._tls_feed(tls, deadline):
                return None

    async def _credssp(self, tls: TlsState) -> str:
        """Play the server side of the CredSSP NTLM exchange up to a logon failure."""
        deadline = time.monotonic() + self.cfg.credssp_timeout
        self.stage = "credssp_negotiate"
        first = await self._read_der(tls, deadline)
        if not first:
            return "client_closed"
        try:
            ts = credssp.parse_ts_request(first)
        except credssp.BerError as err:
            self._scan("credssp_malformed", first, error=err.args[0] if err.args else "ber")
            return "credssp_malformed"
        version = ts.version if ts.version else 6
        self.signals.credssp_version = ts.version
        ntlm_msg = ts.nego_token
        if ntlm_msg is None or ntlm.message_type(ntlm_msg) != ntlm.TYPE_NEGOTIATE:
            self.summary["credssp"] = {
                "version": ts.version,
                "preview": probe.hex_preview(first, 64),
            }
            return "credssp_no_negotiate"
        self.flags_seen.add("rdp_ntlm")
        client_flags = ntlm.negotiate_flags(ntlm_msg)
        self.signals.ntlm_flags = client_flags
        self.signals.ntlm_os_version = ntlm.negotiate_os_version(ntlm_msg)
        self.summary["credssp"] = {
            "version": ts.version,
            "ntlm_negotiate": {
                "flags": f"0x{client_flags:08x}" if client_flags is not None else None,
                "os_version": self.signals.ntlm_os_version,
            },
        }
        if not self.sensor.charge_cpu(self.ip):
            return "cpu_rate_limited"
        # Send the NTLM CHALLENGE wrapped in a TSRequest.
        self.server_challenge = ntlm.new_server_challenge()
        ident = self.sensor.identity
        target_info = ntlm.build_target_info(
            ident.netbios_domain,
            ident.netbios_computer,
            ident.dns_domain,
            ident.dns_computer,
            ident.dns_domain,
        )
        challenge = ntlm.build_challenge(
            ident.netbios_domain,
            target_info,
            self.server_challenge,
            flags=ntlm.challenge_flags(client_flags),
        )
        await self._tls_send(tls, credssp.build_nego_token(challenge, version))
        self.stage = "credssp_authenticate"
        second = await self._read_der(tls, time.monotonic() + self.cfg.credssp_timeout)
        if not second:
            return "credssp_no_authenticate"
        try:
            ts2 = credssp.parse_ts_request(second)
        except credssp.BerError as err:
            self._scan("credssp_malformed", second, error=err.args[0] if err.args else "ber")
            return "credssp_malformed"
        auth = ntlm.parse_authenticate(ts2.nego_token or b"")
        if auth is None:
            self._scan("credssp_authenticate_unparsed", ts2.nego_token or second)
        else:
            self._record_ntlm_login(auth)
        # Refuse the logon exactly as a real server does on a failed CredSSP authentication.
        with contextlib.suppress(_Closed, ssl.SSLError):
            await self._tls_send(tls, credssp.build_error(credssp.STATUS_LOGON_FAILURE, version))
        return "credssp_logon_failure"

    def _record_ntlm_login(self, auth: ntlm.Authenticate) -> None:
        if auth.anonymous:
            self.flags_seen.add("null_session")
        password: str | None = None
        success = False
        user = (auth.username or "").lower()
        for acc_user, acc_password, acc_hash in self.cfg.accounts:
            if acc_user == user and ntlm.verify_password(
                auth, self.server_challenge, acc_password, acc_hash
            ):
                password = acc_password
                success = True
                self.flags_seen.add("weak_password_match")
                break
        data: dict[str, Any] = {
            "username": auth.username,
            "password": password,
            "success": success,
            "method": "rdp-ntlm",
            "client_tool": fingerprint.identify(self.signals).tool,
            **auth.to_dict(),
        }
        self.emit(EventType.login_attempt, data)
        self.summary["ntlm"] = auth.to_dict()
        if success:
            self.summary["weak_password_match"] = True

    # --- MCS (NLA disabled) --------------------------------------------------------------

    async def _read_tpkt(self, tls: TlsState, deadline: float) -> bytes | None:
        """Read one complete TPKT PDU from the TLS stream (bounded). None on close/limit.

        The loop only short-circuits when :meth:`_pump_decrypt` actually produced new plaintext;
        a stalled client (e.g. a complete TPKT header promising more bytes that never arrive, or
        a 1-3 byte partial header) always falls through to the deadline check and ``_tls_feed``,
        so it can never spin on ``sleep(0)`` and burn CPU for the whole session.
        """
        while True:
            await asyncio.sleep(0)
            if self.tls_plain:
                if self.tls_plain[0] != protocol.TPKT_VERSION:
                    return None  # not TPKT framing
                if len(self.tls_plain) >= 4:  # a 1-3 byte partial header means "need more"
                    total = (self.tls_plain[2] << 8) | self.tls_plain[3]
                    if total < 7 or total > protocol.MAX_TPKT:
                        return None
                    if len(self.tls_plain) >= total:
                        out, self.tls_plain = self.tls_plain[:total], self.tls_plain[total:]
                        self._set_held()
                        return out
            before = len(self.tls_plain)
            if self._pump_decrypt(tls):
                return None
            if len(self.tls_plain) > before:
                continue  # new plaintext decrypted: re-evaluate the framing at the top
            if time.monotonic() >= deadline:
                return None
            if await self._tls_feed(tls, deadline):
                return None

    async def _mcs(self, tls: TlsState) -> str:
        """Run the MCS / GCC connect sequence to the Client Info PDU (standard RDP over TLS)."""
        self.stage = "mcs"
        self.flags_seen.add("rdp_nla_off")
        deadline = time.monotonic() + self.cfg.mcs_timeout
        channel_count = 0
        for _ in range(self.cfg.max_mcs_pdus):
            if not self.sensor.charge_cpu(self.ip):
                return "cpu_rate_limited"
            pdu = await self._read_tpkt(tls, deadline)
            if pdu is None:
                return "mcs_closed"
            try:
                payload = mcs.unwrap(pdu)
            except mcs.McsError:
                self._scan("mcs_malformed", pdu)
                return "mcs_malformed"
            if not payload:
                continue
            tag = payload[0]
            if tag == 0x7F:  # Connect Initial (application 101)
                client = mcs.parse_client_data(payload)
                channel_count = client.channel_count
                self._record_client_data(client)
                await self._tls_send(
                    tls, mcs.build_connect_response(channel_count, protocol.PROTOCOL_SSL)
                )
            elif tag == mcs.ERECT_DOMAIN:
                continue  # no response
            elif tag == mcs.ATTACH_USER_REQUEST:
                await self._tls_send(tls, mcs.build_attach_user_confirm())
            elif tag == mcs.CHANNEL_JOIN_REQUEST:
                join = mcs.parse_channel_join_request(payload)
                if join is not None:
                    await self._tls_send(tls, mcs.build_channel_join_confirm(join))
            elif tag == mcs.SEND_DATA_REQUEST:
                result = mcs.parse_send_data_request(payload)
                if result is not None and result[0] == mcs.MCS_IO_CHANNEL:
                    info = mcs.parse_client_info(result[1])
                    if info is not None:
                        self._record_client_info(info)
                        with contextlib.suppress(_Closed, ssl.SSLError):
                            await self._tls_send(tls, mcs.build_disconnect_ultimatum())
                        return "client_info_captured"
        return "mcs_max_pdus"

    def _record_client_data(self, client: mcs.ClientMcsData) -> None:
        self.signals.gcc_client_name = client.core.client_name or None
        self.signals.gcc_client_build = client.core.client_build
        self.summary["gcc"] = client.core.to_dict()
        if client.channel_names:
            self.summary["gcc"]["channels"] = client.channel_names[:16]
        if any("ms_t120" in n.lower() for n in client.channel_names):
            self.flags_seen.add("bluekeep_probe")

    def _record_client_info(self, info: mcs.ClientInfo) -> None:
        data: dict[str, Any] = {
            "username": info.username,
            "password": info.password,
            "success": False,
            "method": "rdp-nla-off",
            "client_tool": fingerprint.identify(self.signals).tool,
            **info.to_dict(),
        }
        self.emit(EventType.login_attempt, data)
        self.summary["client_info"] = info.to_dict()


class RDPServer:
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
        self.sensor.guard.sample()
        self._tasks = [
            asyncio.create_task(self._summaries()),
            asyncio.create_task(self._guard_loop()),
        ]
        sockets = self._server.sockets
        return int(sockets[0].getsockname()[1]) if sockets else self.cfg.port

    async def _summaries(self) -> None:
        while True:
            await asyncio.sleep(self.cfg.summary_interval)
            self.sensor.sink.flush_suppressed(self.cfg.summary_interval)

    async def _guard_loop(self) -> None:
        while True:
            await asyncio.sleep(1.0)
            self.sensor.check_memory()

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
