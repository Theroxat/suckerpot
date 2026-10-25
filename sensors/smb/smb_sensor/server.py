"""The SMB listener.

It frames NetBIOS session messages, answers SMB2 NEGOTIATE / SESSION_SETUP like a modern
Windows file server, steers SMB1 clients to SMB2, records what every client sends, and closes.
No session is ever granted, nothing is executed, and the sensor never connects anywhere.

Every read has a deadline, every buffer a size cap, and the whole connection a hard time cap.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import secrets
import socket
import time
import uuid
from typing import Any

from suckerpot_common import EventType

from smb_sensor import framing, messages, ntlm, probe, smb, spnego
from smb_sensor.config import SMB1_STEER, Config
from smb_sensor.events import Buckets, EventSink
from smb_sensor.identity import Identity
from smb_sensor.memguard import MemoryGuard

log = logging.getLogger("smb_sensor.server")

READ_CHUNK = 16 * 1024
SOCK_BUF = 32 * 1024  # Linux doubles it
MAX_OVERFLOW = 64  # over-cap connections answered slowly at the same time
OVERFLOW_READ_WAIT = 2.0
NON_SMB_EXTRA_WAIT = 0.3

# Per-session event quotas (a single connection cannot flood one event type).
_QUOTA = {
    EventType.login_attempt: 8,
    EventType.scan: 12,
}


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
        identity: Identity,
        guard: MemoryGuard | None = None,
    ) -> None:
        self.cfg = cfg
        self.sink = sink
        self.identity = identity
        self.guard = guard or MemoryGuard(cfg.memory_limit)
        self.total = 0
        self.per_ip: dict[str, int] = {}
        self.sessions: dict[Session, None] = {}  # insertion order = age
        self.buffered = 0  # parser bytes + pending output held by all sessions
        self.rejected = 0
        self.evicted = 0
        self.seen = 0
        self.errors = 0
        self.overflow = 0
        self.cpu_limited = 0
        # Per-IP token bucket for expensive responses (negotiate / NTLM crypto), so no mix of
        # IPs and connections can monopolise the loop (lesson 16).
        self.cpu_rate = Buckets(cfg.cpu_per_sec_per_ip, cfg.cpu_burst_per_ip)
        self._sample_at = 0.0

    # --- admission -----------------------------------------------------------------------

    def _maybe_sample(self) -> None:
        """Sample the memory guard on admission too (throttled), not only in the guard loop."""
        now = time.monotonic()
        if now - self._sample_at >= 0.2:
            self._sample_at = now
            self.guard.sample()

    def charge_cpu(self, ip: str) -> bool:
        """Spend one CPU token for an expensive response; False means the source is over budget."""
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

    # --- connections ---------------------------------------------------------------------

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
                    await reader.read(self.cfg.max_pdu_bytes)
            await asyncio.sleep(0.2 + secrets.randbelow(600) / 1000)
        finally:
            self.overflow -= 1
            await _close(writer, abort=True)

    def stats(self) -> dict[str, Any]:
        return {
            "connections": self.total,
            "seen": self.seen,
            "rejected": self.rejected,
            "evicted": self.evicted,
            "errors": self.errors,
            "cpu_limited": self.cpu_limited,
            "buffered": self.buffered,
            "memory_used": self.guard.usage,
            "memory_peak": self.guard.peak,
            "memory_refused": self.guard.refused,
            "memory_aborted": self.guard.aborted,
            **self.sink.stats(),
        }


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
        self.held = 0
        self.bytes_in = 0
        self.bytes_out = 0
        self.pdu_count = 0
        self.stage = "connected"
        self.evicted = False
        self.shed = False
        self.smb_session_id = 0  # the SMB2 SessionId we hand out (never authenticated)
        self.negotiated_dialect: int | None = None
        self.smb1_steered = False
        self.reset = False  # close with a TCP reset (abort) instead of a FIN
        self.logins = 0
        self.counts: dict[str, int] = {}
        self.suppressed: dict[str, int] = {}
        self.dropped: dict[str, int] = {}
        self.events = 0
        self.flags_seen: set[str] = set()
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
            # Dropped by a rate budget: reported in the disconnect summary.
            key = type_.value
            self.dropped[key] = self.dropped.get(key, 0) + 1

    def _scan(self, kind: str, data: bytes, **extra: Any) -> None:
        flags = sorted(self.flags_seen | set(extra.pop("flags", [])))
        self.emit(
            EventType.scan,
            {
                "kind": kind,
                "protocol_guess": probe.guess_protocol(data),
                "payload_preview": probe.hex_preview(data),
                "payload_ascii": probe.ascii_preview(data),
                "bytes_received": len(data),
                "flags": flags,
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

    def _set_held(self, size: int) -> None:
        self.sensor.buffered += size - self.held
        self.held = size

    async def _recv(self, wait: float, limit: int = READ_CHUNK) -> bytes:
        room = self.cfg.max_session_input - self.bytes_in
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
            self._set_held(len(self.buf))
            if self.sensor.buffered > self.cfg.max_buffered:
                raise _Closed("buffered_limit")

    async def _send(self, data: bytes) -> None:
        if not data:
            return
        # Size-check before building more, and charge pending output to the global budget until
        # it has drained (lesson 17). Responses are small, but the accounting bounds them.
        if len(data) > self.cfg.max_pending_output:
            raise _Closed("output_limit")
        self.writer.write(data)
        self.bytes_out += len(data)
        self.sensor.buffered += len(data)
        try:
            async with asyncio.timeout(self.cfg.read_timeout):
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
        self.emit(EventType.connect, {"transport": "netbios-session"})
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
            if self.suppressed:
                self.summary["events_suppressed"] = dict(self.suppressed)
            if self.dropped:
                self.summary["events_dropped"] = dict(self.dropped)
            if self.negotiated_dialect is not None:
                self.summary["dialect"] = smb.DIALECT_NAMES.get(
                    self.negotiated_dialect, f"0x{self.negotiated_dialect:04x}"
                )
            self.emit(
                EventType.disconnect,
                {
                    "duration_s": round(time.monotonic() - self.started, 3),
                    "reason": reason,
                    "stage": self.stage,
                    "bytes_in": self.bytes_in,
                    "bytes_out": self.bytes_out,
                    "pdus": self.pdu_count,
                    "flags": sorted(self.flags_seen),
                    **self.summary,
                },
            )

    async def _serve(self) -> str:
        first = True
        while self.pdu_count < self.cfg.max_pdus:
            await asyncio.sleep(0)  # wall-clock yield: never monopolise the loop (lesson 16)
            wait = self.cfg.first_data_timeout if first else self.cfg.idle_timeout
            payload = await self._read_pdu(wait, first)
            first = False
            if payload is None:
                continue  # NetBIOS keepalive / empty message: keep reading (counted as a PDU)
            reason = await self._dispatch(payload)
            if reason is not None:
                return reason
        return "max_pdus"

    async def _read_pdu(self, wait: float, first: bool) -> bytes | None:
        """Read one framed SMB message. Returns the SMB payload, or None for a keepalive."""
        self.buf = b""
        self._set_held(0)
        await self._fill(framing.HEADER_LEN, wait)
        message_type, length = framing.parse_header(self.buf[: framing.HEADER_LEN])
        self.buf = self.buf[framing.HEADER_LEN :]
        self._set_held(len(self.buf))
        if message_type == framing.SESSION_KEEPALIVE and length == 0:
            self.pdu_count += 1  # bounded by max_pdus like any other message
            return None
        if message_type != framing.SESSION_MESSAGE:
            self.stage = "framing"
            self._scan(
                "netbios_control",
                self.buf,
                netbios_type=framing.type_name(message_type),
                declared_length=length,
            )
            raise _Closed("netbios_control")
        if length == 0:
            self.pdu_count += 1
            return None  # empty session message: treat as a keepalive
        if length > self.cfg.max_pdu_bytes:
            self.stage = "framing"
            with contextlib.suppress(_Closed):
                await self._fill(min(len(self.buf) + 64, self.cfg.max_pdu_bytes), 0.2)
            self._scan("oversized_pdu", self.buf, declared_length=length)
            raise _Closed("oversized_pdu")
        await self._fill(length, self.cfg.read_timeout)
        self.pdu_count += 1
        return self.buf[:length]

    async def _dispatch(self, payload: bytes) -> str | None:
        """Handle one SMB payload. Returns a disconnect reason, or None to keep the loop going."""
        variant = smb.smb_variant(payload)
        if variant == "smb2":
            return await self._dispatch_smb2(payload)
        if variant == "smb1":
            return await self._dispatch_smb1(payload)
        self.stage = "non_smb"
        if len(self.buf) < probe.PREVIEW_BYTES:
            with contextlib.suppress(_Closed):
                await self._fill(probe.PREVIEW_BYTES, NON_SMB_EXTRA_WAIT)
        self._scan("non_smb", self.buf)
        return "non_smb"

    # --- SMB2 ----------------------------------------------------------------------------

    async def _dispatch_smb2(self, payload: bytes) -> str | None:
        try:
            header = smb.parse_smb2_header(payload)
        except smb.ParseError as err:
            self._scan("malformed_smb2", payload, error=err.reason)
            return "malformed_smb2"
        if header.next_command:
            self.flags_seen.add("compound_request")
        credit = header.credit_request
        if header.command == smb.SMB2_NEGOTIATE:
            return await self._smb2_negotiate(payload, header, credit)
        if header.command == smb.SMB2_SESSION_SETUP:
            return await self._smb2_session_setup(payload, header, credit)
        if header.command == smb.SMB2_LOGOFF:
            self.stage = "logoff"
            await self._send(
                framing.build_message(
                    messages.build_error_response(
                        header.command,
                        header.message_id,
                        header.session_id,
                        smb.STATUS_USER_SESSION_DELETED,  # no session is ever authenticated
                        credit=credit,
                    )
                )
            )
            return None
        # Any other command: we grant no session, so answer with an error and record the probe.
        self.stage = f"cmd_{header.command_name}"
        self._scan(
            "unexpected_command",
            payload,
            smb2_command=header.command_name,
            session_id=header.session_id,
            tree_id=header.tree_id,
        )
        status = (
            smb.STATUS_ACCESS_DENIED if header.session_id == 0 else smb.STATUS_USER_SESSION_DELETED
        )
        await self._send(
            framing.build_message(
                messages.build_error_response(
                    header.command,
                    header.message_id,
                    header.session_id,
                    status,
                    credit=credit,
                    tree_id=header.tree_id,
                )
            )
        )
        return None

    async def _smb2_negotiate(
        self, payload: bytes, header: smb.Smb2Header, credit: int
    ) -> str | None:
        self.stage = "negotiate"
        request = smb.parse_negotiate_request(payload)
        self.summary["offered_dialects"] = [
            smb.DIALECT_NAMES.get(d, f"0x{d:04x}") for d in request.dialects
        ]
        dialect = smb.choose_dialect(request.dialects)
        if dialect is None:
            await self._send(
                framing.build_message(
                    messages.build_error_response(
                        header.command,
                        header.message_id,
                        0,
                        smb.STATUS_NOT_SUPPORTED,
                        credit=credit,
                    )
                )
            )
            return "negotiate_unsupported"
        self.negotiated_dialect = dialect
        if not self.sensor.charge_cpu(self.ip):
            return await self._busy(header, credit)
        cipher = (
            messages.choose_cipher(request.ciphers)
            if smb.CTX_ENCRYPTION in request.context_types
            else None
        )
        response = messages.build_negotiate_response(
            self.sensor.identity,
            dialect,
            message_id=header.message_id,
            credit=credit,
            cipher=cipher,
            client_caps=request.capabilities,
        )
        await self._send(framing.build_message(response))
        return None

    async def _smb2_session_setup(
        self, payload: bytes, header: smb.Smb2Header, credit: int
    ) -> str | None:
        self.stage = "session_setup"
        security = smb.extract_security_buffer(payload, smb.SESSION_SETUP_SECBUF_FIELD)
        ntlm_msg = spnego.find_ntlm_message(security)
        if self.smb_session_id == 0:
            self.smb_session_id = int.from_bytes(secrets.token_bytes(6), "little") | 1
        if ntlm_msg is None:
            self._scan("session_setup_non_ntlm", security or payload)
            await self._send(
                framing.build_message(
                    messages.build_session_setup_failure(
                        self.smb_session_id, message_id=header.message_id, credit=credit
                    )
                )
            )
            return None
        kind = ntlm.message_type(ntlm_msg)
        if kind == ntlm.TYPE_NEGOTIATE:
            self.flags_seen.add("ntlm")
            if not self.sensor.charge_cpu(self.ip):
                return await self._busy(header, credit)
            await self._send(
                framing.build_message(
                    messages.build_session_setup_challenge(
                        self.sensor.identity,
                        self.smb_session_id,
                        message_id=header.message_id,
                        credit=credit,
                        client_flags=ntlm.negotiate_flags(ntlm_msg),
                    )
                )
            )
            return None
        if kind == ntlm.TYPE_AUTHENTICATE:
            self._record_login(ntlm_msg)
            await self._send(
                framing.build_message(
                    messages.build_session_setup_failure(
                        self.smb_session_id, message_id=header.message_id, credit=credit
                    )
                )
            )
            return None
        # NTLM signature present but an unexpected message type: record and fail.
        self._scan("session_setup_unexpected_ntlm", ntlm_msg, ntlm_type=kind)
        await self._send(
            framing.build_message(
                messages.build_session_setup_failure(
                    self.smb_session_id, message_id=header.message_id, credit=credit
                )
            )
        )
        return None

    async def _busy(self, header: smb.Smb2Header, credit: int) -> str:
        """Over the per-IP CPU budget: answer with a cheap, pre-sized error, then close.

        A loaded Windows server returns STATUS_INSUFFICIENT_RESOURCES rather than silently
        dropping the connection.
        """
        with contextlib.suppress(_Closed):
            await self._send(
                framing.build_message(
                    messages.build_error_response(
                        header.command,
                        header.message_id,
                        header.session_id,
                        smb.STATUS_INSUFFICIENT_RESOURCES,
                        credit=credit,
                    )
                )
            )
        return "cpu_rate_limited"

    def _record_login(self, ntlm_msg: bytes) -> None:
        parsed = ntlm.parse_authenticate(ntlm_msg)
        self.logins += 1
        self.flags_seen.add("ntlm")
        if parsed is None:
            self._scan("ntlm_authenticate_unparsed", ntlm_msg)
            return
        flags = ["ntlm"]
        if parsed.anonymous:
            flags.append("null_session")
            self.flags_seen.add("null_session")
        data: dict[str, Any] = {
            "username": parsed.username,
            "password": None,  # NTLM never sends a clear password; we keep no response material
            "success": False,
            "method": "ntlm",
            "flags": sorted(set(flags)),
            **parsed.to_dict(),
        }
        self.emit(EventType.login_attempt, data)

    # --- SMB1 ----------------------------------------------------------------------------

    async def _dispatch_smb1(self, payload: bytes) -> str | None:
        self.stage = "smb1"
        self.flags_seen.add("smbv1")
        command = smb.smb1_command(payload)
        name = smb.smb1_command_name(command)
        if command == smb.SMB1_NEGOTIATE and not self.smb1_steered:
            dialects = smb.parse_smb1_negotiate_dialects(payload)
            steer = self.cfg.smb1_mode == SMB1_STEER
            if steer and smb.SMB1_DIALECT_WILDCARD in dialects:
                outcome = "steer_smb2_wildcard"
            elif steer and smb.SMB1_DIALECT_2_002 in dialects:
                outcome = "smb2_002"
            else:
                outcome = "reset"
            self._scan(
                "smb1_negotiate",
                payload,
                smb1_dialects=dialects[:32],
                smb1_outcome=outcome,
                flags=["smbv1"],
            )
            if outcome == "reset":
                # Like Windows with SMB1 disabled: an SMB1-only negotiate gets a reset.
                self.reset = True
                return "smb1_reset"
            # Modern Windows answers a multi-protocol negotiate in SMB2: the "SMB 2.???"
            # wildcard steers the client to a fresh SMB2 NEGOTIATE; a client that offers only
            # "SMB 2.002" gets a real 2.0.2 negotiate. Nothing else of SMB1 is ever answered.
            self.smb1_steered = True
            dialect = (
                smb.DIALECT_WILDCARD if outcome == "steer_smb2_wildcard" else smb.DIALECT_2_0_2
            )
            if dialect == smb.DIALECT_2_0_2:
                self.negotiated_dialect = dialect
            response = messages.build_negotiate_response(
                self.sensor.identity, dialect, message_id=0, credit=1, cipher=None
            )
            await self._send(framing.build_message(response))
            return None
        # Any other SMB1 traffic: opaque, recorded with a best-effort label, then closed.
        self._scan(
            "smb1_command",
            payload,
            smb1_command=f"0x{command & 0xFF:02x}" if command >= 0 else None,
            smb1_command_name=name,
            flags=["smbv1"],
        )
        return "smb1_command"


class SMBServer:
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
