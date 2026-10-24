"""The RDP listener: X.224 negotiation like an NLA-enforcing Windows Server 2022, optional TLS.

Per connection:

1. Wait for the first bytes. Anything that is not a TPKT is recorded as a ``scan`` (with a
   hex preview and a protocol guess) and the connection is closed, as Windows does.
2. Parse the X.224 Connection Request strictly. The ``Cookie: mstshash=`` user name becomes a
   ``login_attempt``; a request without one becomes a ``scan`` (``kind = rdp_negotiation``).
3. Answer with a Connection Confirm: HYBRID / HYBRID_EX (CredSSP) when the client offers it,
   otherwise ``HYBRID_REQUIRED_BY_SERVER``; legacy clients get a bare confirm.
4. For CredSSP: complete the TLS handshake with the per-deployment certificate, read the
   client's first TSRequest (its NTLM NEGOTIATE carries no credentials) and close with a TLS
   close_notify. No CredSSP or NTLM authentication is implemented and no credential material
   is ever requested from the client.

Every read has a deadline, every buffer a size cap, and the whole connection a hard time cap.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import secrets
import ssl
import time
import uuid
from dataclasses import dataclass
from typing import Any

from suckerpot_common import EventType

from rdp_sensor import probe, protocol
from rdp_sensor.config import Config
from rdp_sensor.events import Buckets, EventSink
from rdp_sensor.identity import Identity

log = logging.getLogger("rdp_sensor.server")

READ_CHUNK = 4096
MAX_SESSION_INPUT = 64 * 1024  # bytes read from one client, all stages together
MAX_CREDSSP_PLAINTEXT = 16 * 1024
NON_RDP_EXTRA_WAIT = 0.3
MAX_TLS_ROUNDS = 64  # TLS handshake / CredSSP read iterations per connection
MAX_OVERFLOW = 64  # over-cap connections being answered slowly at the same time
OVERFLOW_READ_WAIT = 2.0
TLS_SLOT_WAIT = 2.0
# Groups Schannel offers by default (applied only where the ssl module supports it).
TLS_GROUPS = ("x25519", "secp256r1", "secp384r1")

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


class Sensor:
    """Process-wide state shared by all connections."""

    def __init__(
        self, cfg: Config, sink: EventSink, tls: ssl.SSLContext | None, hostname: str
    ) -> None:
        self.cfg = cfg
        self.sink = sink
        self.tls = tls if cfg.enable_tls else None
        self.hostname = hostname
        self.total = 0
        self.per_ip: dict[str, int] = {}
        self.sessions: dict[Session, None] = {}  # insertion order = age
        self.rejected = 0
        self.evicted = 0
        self.seen = 0
        self.errors = 0
        self.tls_limited = 0
        self.overflow = 0
        # Expensive work (TLS handshakes) is rate limited per source before it starts, and
        # globally bounded in concurrency.
        self.tls_rate = Buckets(cfg.tls_per_sec_per_ip, cfg.tls_burst_per_ip)
        self.tls_slots = asyncio.Semaphore(cfg.max_tls_handshakes)

    def acquire(self, ip: str) -> bool:
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
            if session.stage == "connected" and not session.evicted:
                session.evict()
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
            self.release(ip)

    async def _refuse(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Over a cap: read the first bytes, then close after a short random delay.

        An instant accept-and-FIN would be an easy fingerprint. The number of connections
        handled this way is itself bounded; beyond it they are closed at once.
        """
        if self.overflow >= MAX_OVERFLOW:
            await _close(writer)
            return
        self.overflow += 1
        try:
            with contextlib.suppress(Exception):
                async with asyncio.timeout(OVERFLOW_READ_WAIT):
                    await reader.read(protocol.MAX_CR_TPKT)
            await asyncio.sleep(0.2 + secrets.randbelow(800) / 1000)
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
            "errors": self.errors,
            **self.sink.stats(),
        }


async def _close(writer: asyncio.StreamWriter) -> None:
    with contextlib.suppress(Exception):
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), 2.0)


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
        self.bytes_in = 0
        self.bytes_out = 0
        self.stage = "connected"
        self.evicted = False
        self.summary: dict[str, Any] = {}

    def evict(self) -> None:
        """Close this (idle) connection to make room; its pending read then ends."""
        self.evicted = True
        with contextlib.suppress(Exception):
            self.writer.transport.close()

    # --- events --------------------------------------------------------------------------

    def emit(self, type_: EventType, data: dict[str, Any]) -> None:
        if self.recorded:
            self.sensor.sink.emit(
                session_id=self.session_id,
                src_ip=self.ip,
                src_port=self.port,
                type_=type_,
                data=data,
            )

    # --- I/O -----------------------------------------------------------------------------

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

    async def _send(self, data: bytes) -> None:
        if not data:
            return
        self.writer.write(data)
        self.bytes_out += len(data)
        try:
            async with asyncio.timeout(self.cfg.handshake_timeout):
                await self.writer.drain()
        except TimeoutError:
            raise _Closed("timeout") from None
        except (ConnectionError, OSError):
            raise _Closed("client_reset") from None

    # --- main flow -----------------------------------------------------------------------

    async def run(self) -> None:
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
            await _close(self.writer)
            self.emit(
                EventType.disconnect,
                {
                    "duration_s": round(time.monotonic() - self.started, 3),
                    "reason": reason,
                    "stage": self.stage,
                    "bytes_in": self.bytes_in,
                    "bytes_out": self.bytes_out,
                    **self.summary,
                },
            )

    async def _serve(self) -> str:
        self.buf = await self._recv(self.cfg.first_data_timeout)
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
        neg = protocol.negotiate(cr)
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
        # Expensive part: check the per-source rate and take a global slot first. A busy
        # Windows host also drops the connection after the confirm.
        if not self.sensor.tls_rate.allow(self.ip):
            self.sensor.tls_limited += 1
            return "tls_rate_limited"
        try:
            async with asyncio.timeout(TLS_SLOT_WAIT):
                await self.sensor.tls_slots.acquire()
        except TimeoutError:
            self.sensor.tls_limited += 1
            return "tls_busy"
        try:
            return await self._tls(extra)
        finally:
            self.sensor.tls_slots.release()

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
            self.summary["ms_t120"] = b"ms_t120" in self.buf.lower()
        self.stage = "legacy_followup"

    # --- TLS -----------------------------------------------------------------------------

    async def _flush_tls(self, tls: TlsState) -> None:
        pending = tls.outgoing.read()
        if pending:
            await self._send(pending)

    async def _tls(self, extra: bytes) -> str:
        assert self.sensor.tls is not None  # noqa: S101 - checked by the caller
        self.stage = "tls_handshake"
        self.buf = extra
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
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        tls = TlsState(
            self.sensor.tls.wrap_bio(incoming, outgoing, server_side=True), incoming, outgoing
        )
        tls.incoming.write(self.buf)
        self.buf = b""
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
        reason = await self._credssp(tls)
        with contextlib.suppress(ssl.SSLError, _Closed):
            tls.obj.unwrap()
        with contextlib.suppress(_Closed, ssl.SSLError):
            await self._flush_tls(tls)
        return reason

    async def _credssp(self, tls: TlsState) -> str:
        """Read the client's first TSRequest (bounded), describe it, then give up."""
        plain = b""
        deadline = time.monotonic() + self.cfg.credssp_timeout
        reason = "credssp_not_supported"
        for _ in range(MAX_TLS_ROUNDS):
            await asyncio.sleep(0)  # never monopolise the loop, whatever OpenSSL returns
            if len(plain) >= MAX_CREDSSP_PLAINTEXT:
                break
            want = der_total_length(plain)
            if want is not None and (want < 0 or len(plain) >= want):
                break
            if time.monotonic() >= deadline:
                reason = "timeout"
                break
            try:
                chunk = tls.obj.read(MAX_CREDSSP_PLAINTEXT - len(plain))
                if not chunk:  # close_notify received: end of stream
                    reason = "client_closed"
                    break
                plain += chunk
                continue
            except ssl.SSLWantReadError:
                pass
            except ssl.SSLZeroReturnError:
                reason = "client_closed"
                break
            except ssl.SSLError:
                reason = "tls_error"
                break
            left = deadline - time.monotonic()
            if left <= 0:
                reason = "timeout"
                break
            try:
                tls.incoming.write(await self._recv(left, 16 * 1024))
            except _Closed as closed:
                reason = closed.reason
                break
        else:
            reason = "too_many_rounds"
        if plain:
            self.stage = "credssp"
            info: dict[str, Any] = {
                "bytes": len(plain),
                "version": probe.credssp_version(plain),
            }
            ntlm = probe.parse_ntlm_negotiate(plain)
            if ntlm is not None:
                info["ntlm_negotiate"] = ntlm
            else:
                info["preview"] = probe.hex_preview(plain, 64)
            self.summary["credssp"] = info
        return reason


class RDPServer:
    def __init__(self, cfg: Config, sensor: Sensor) -> None:
        self.cfg = cfg
        self.sensor = sensor
        self._server: asyncio.Server | None = None
        self._summary_task: asyncio.Task[None] | None = None

    async def start(self) -> int:
        self._server = await asyncio.start_server(
            self.sensor.handle,
            host=self.cfg.host,
            port=self.cfg.port,
            limit=READ_CHUNK * 2,
            backlog=256,
            reuse_address=True,
        )
        self._summary_task = asyncio.create_task(self._summaries())
        sockets = self._server.sockets
        return int(sockets[0].getsockname()[1]) if sockets else self.cfg.port

    async def _summaries(self) -> None:
        while True:
            await asyncio.sleep(self.cfg.summary_interval)
            self.sensor.sink.flush_suppressed(self.cfg.summary_interval)

    async def stop(self) -> None:
        if self._summary_task is not None:
            self._summary_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._summary_task
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._server.wait_closed(), 5.0)
        self.sensor.sink.flush_suppressed(self.cfg.summary_interval)
