"""The TDS listener: connection handling, limits, event emission.

Per connection: read, feed the strict packet parser, assemble messages (PRELOGIN, LOGIN7, SQL
batch, RPC), answer them from the canned responder in :mod:`mssql_sensor.sql`, and record what
the attacker did. Every read has a deadline, every buffer a cap (per connection and across
connections), the whole connection a time cap, and the number of messages is bounded.

Event policy per session (quotas in :class:`Config`): ``connect`` and ``disconnect`` always;
``login_attempt`` and ``download_attempt`` have their own quotas; commands are split into noisy
ones (plain scalar SELECTs), ordinary ones and priority ones (carrying an indicator flag such
as ``xp_cmdshell``). What exceeds a quota is counted and reported in the ``disconnect`` event.
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
from typing import Any

from suckerpot_common import EventType

from mssql_sensor import sql, tds, tls
from mssql_sensor.config import Config
from mssql_sensor.events import Buckets, EventSink
from mssql_sensor.identity import Profile
from mssql_sensor.memguard import MemoryGuard

log = logging.getLogger("mssql_sensor.server")

READ_CHUNK = 16 * 1024
WORK_SLICE = 0.01  # seconds of work per loop turn before yielding
CPU_IP_RATE = 0.05  # CPU seconds per second one source IP may use
CPU_IP_BURST = 0.25
CPU_GLOBAL_RATE = 0.25
CPU_GLOBAL_BURST = 0.5
CPU_MESSAGE = 0.0002  # fixed CPU cost charged for every message, whatever it contains
MAX_TLS_PACKETS = 24  # handshake packets accepted per connection
MAX_REPLY = 256 * 1024  # a reply larger than this is never sent
MAX_MESSAGE = 128 * 1024  # bytes of one request message that are kept
MAX_PACKETS_PER_MESSAGE = 2048
MAX_OVERFLOW = 64
OVERFLOW_WAIT = 2.0
SOCK_BUF = 64 * 1024
PREVIEW = 64


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


def guess_protocol(head: bytes) -> str:
    """A label for traffic that is not TDS, from its first bytes."""
    if head[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ", b"OPTI", b"CONN", b"DELE", b"PROP"):
        return "http"
    if head[:2] == b"\x16\x03":
        return "tls"
    if head[:4] == b"SSH-":
        return "ssh"
    if head[:1] == b"\x03" and len(head) > 3:
        return "rdp"
    if head[4:8] in (b"\xffSMB", b"\xfeSMB"):
        return "smb"
    if head[:1] in (b"*", b"$") or head[:5].upper() == b"PING\r" or head[:5].upper() == b"INFO\r":
        return "redis"
    if head[:4] == b"\x00\x00\x00\x00":
        return "null"
    return "unknown"


class _Closed(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class Sensor:
    """Process-wide state shared by all connections."""

    def __init__(
        self,
        cfg: Config,
        sink: EventSink,
        profile: Profile,
        guard: MemoryGuard | None = None,
        tls_ctx: ssl.SSLContext | None = None,
    ) -> None:
        self.cfg = cfg
        self.sink = sink
        self.profile = profile
        self.guard = guard or MemoryGuard(cfg.memory_limit)
        self.total = 0
        self.per_ip: dict[str, int] = {}
        self.sessions: dict[Session, None] = {}
        self.buffered = 0
        self.rejected = 0
        self.evicted = 0
        self.seen = 0
        self.errors = 0
        self.overflow = 0
        self.spid = profile.spid_base
        self.cpu_ip: dict[str, tuple[float, float]] = {}
        self.cpu_global = (CPU_GLOBAL_BURST, time.monotonic())
        self.last_sample = 0.0
        self.new_conns = Buckets(cfg.new_conn_per_sec_per_ip, cfg.new_conn_burst_per_ip)
        self.new_conns_all = Buckets(
            cfg.global_new_conn_per_sec, cfg.global_new_conn_per_sec * 2, max_keys=1
        )
        self.spids: set[int] = set()
        self.tls_ctx = tls_ctx
        self.tls_live = 0
        self.tls_per_ip: dict[str, int] = {}

    def acquire(self, ip: str) -> bool:
        if is_loopback(ip) and self.cfg.quiet_loopback:
            self.total += 1
            self.per_ip[ip] = self.per_ip.get(ip, 0) + 1
            return True
        if not self.new_conns.allow(ip) or not self.new_conns_all.allow("*"):
            self.rejected += 1
            return False  # before any work is done for this connection
        now = time.monotonic()
        if now - self.last_sample > 0.25:  # admission looks at memory too, not just the timer
            self.last_sample = now
            self.guard.sample()
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

    def cpu_delay(self, ip: str, seconds: float) -> float:
        """Charge measured CPU seconds to the IP and the process; returns how long to stall.

        Tokens never drop below minus one burst, so debt (and so the stall) is bounded. The shared
        bucket only slows sources that are already over half of their own budget: a quiet client
        is never made to wait for the cost of a noisy one."""
        now = time.monotonic()
        tokens, last = self.cpu_ip.get(ip, (CPU_IP_BURST, now))
        tokens = max(
            -CPU_IP_BURST, min(CPU_IP_BURST, tokens + (now - last) * CPU_IP_RATE) - seconds
        )
        if len(self.cpu_ip) > 10_000 and ip not in self.cpu_ip:
            self.cpu_ip.pop(next(iter(self.cpu_ip)))
        self.cpu_ip[ip] = (tokens, now)
        g_tokens, g_last = self.cpu_global
        g_tokens = max(
            -CPU_GLOBAL_BURST,
            min(CPU_GLOBAL_BURST, g_tokens + (now - g_last) * CPU_GLOBAL_RATE) - seconds,
        )
        self.cpu_global = (g_tokens, now)
        wait = -tokens / CPU_IP_RATE if tokens < 0 else 0.0
        if g_tokens < 0 and tokens < CPU_IP_BURST / 2:
            wait = max(wait, -g_tokens / CPU_GLOBAL_RATE)
        return wait

    def tls_acquire(self, ip: str) -> bool:
        """A TLS slot for this IP: bounded per IP, and overall by the connection cap."""
        limit = self.cfg.max_tls or self.cfg.max_connections
        if self.tls_live >= limit or self.tls_per_ip.get(ip, 0) >= self.cfg.max_tls_per_ip:
            return False
        self.tls_live += 1
        self.tls_per_ip[ip] = self.tls_per_ip.get(ip, 0) + 1
        return True

    def tls_release(self, ip: str) -> None:
        self.tls_live = max(0, self.tls_live - 1)
        left = self.tls_per_ip.get(ip, 1) - 1
        if left <= 0:
            self.tls_per_ip.pop(ip, None)
        else:
            self.tls_per_ip[ip] = left

    def alloc_spid(self) -> int:
        """The lowest free session id from the profile's base, like a real server's."""
        spid = self.profile.spid_base
        while spid in self.spids:
            spid += 1
        self.spids.add(spid)
        return spid

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
                session.drop_tls()
                self.buffered -= session.held + session.out_held
                session.held = 0
                session.out_held = 0
                self.spids.discard(session.spid)
            self.release(ip)

    async def _refuse(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Over a cap: wait for the first bytes, then close (a server out of workers does that)."""
        if self.overflow >= MAX_OVERFLOW:
            await _close(writer, abort=True)
            return
        self.overflow += 1
        try:
            with contextlib.suppress(Exception):
                async with asyncio.timeout(OVERFLOW_WAIT):
                    await reader.read(1024)
        finally:
            self.overflow -= 1
            await _close(writer)

    def stats(self) -> dict[str, int]:
        return {
            "connections": self.total,
            "seen": self.seen,
            "rejected": self.rejected,
            "evicted": self.evicted,
            "errors": self.errors,
            "buffered": self.buffered,
            "memory_used": self.guard.usage,
            "memory_peak": self.guard.peak,
            "memory_refused": self.guard.refused,
            "memory_aborted": self.guard.aborted,
            **self.sink.stats(),
        }


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
        # the slot is only reusable once connection_lost has really run
        with contextlib.suppress(Exception):
            await asyncio.wait_for(writer.wait_closed(), 1.0)


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
        self.profile = sensor.profile
        self.reader = reader
        self.writer = writer
        self.ip = ip
        self.port = port
        self.recorded = recorded
        self.session_id = uuid.uuid4().hex[:24]
        self.started = time.monotonic()
        self.parser = tds.PacketParser()
        self.chunks: list[bytes] = []
        self.chunk_bytes = 0
        self.msg_type = 0
        self.msg_packets = 0
        self.msg_dropped = 0
        self.held = 0
        self.out_held = 0
        self.bytes_in = 0
        self.bytes_out = 0
        self.messages = 0
        self.evicted = False
        self.shed = False
        self.counts: dict[str, int] = {}
        self.suppressed: dict[str, int] = {}
        self.events = 0
        self.flags_seen: set[str] = set()
        self.urls: set[str] = set()
        self.logins = 0
        self.phase = "start"  # start -> login -> ready
        self.spid = sensor.alloc_spid()
        self.tls: tls.TlsStream | None = None
        self.tls_mode = "none"  # none | handshake | login | full
        self.tls_packets = 0
        self.encrypt_full = False
        self.login_tls = False
        self.deadline: float | None = None  # absolute; TLS handshake and LOGIN7 must beat it
        self.cpu_mark = time.thread_time()
        self.ntlm_challenge = b""
        self.tds_version = 0x74000004
        self.packet_size = tds.DEFAULT_PACKET
        self.state = sql.SqlState(spid=self.spid)
        self.prelogin: tds.PreLogin | None = None
        self.login: tds.Login7 | None = None
        self.authenticated = False

    def abort(self) -> bool:
        transport = self.writer.transport
        if transport.is_closing():
            return False
        transport.abort()
        return True

    # --- events --------------------------------------------------------------------------

    def _quota(self, bucket: str, limit: int) -> bool:
        if self.counts.get(bucket, 0) >= limit or self.events >= self.cfg.quota_session_total:
            self.suppressed[bucket] = self.suppressed.get(bucket, 0) + 1
            return False
        self.counts[bucket] = self.counts.get(bucket, 0) + 1
        self.events += 1
        return True

    def emit(self, type_: EventType, data: dict[str, Any], priority: bool = False) -> None:
        if self.recorded:
            self.sensor.sink.emit(
                session_id=self.session_id,
                src_ip=self.ip,
                src_port=self.port,
                type_=type_,
                data=data,
                priority=priority,
            )

    # --- I/O -----------------------------------------------------------------------------

    def _tune_socket(self) -> None:
        transport = self.writer.transport
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

    async def _recv(self, wait: float) -> bytes:
        room = self.cfg.max_bytes_in - self.bytes_in
        if room <= 0:
            raise _Closed("input_limit")
        due = False
        if self.deadline is not None:
            left = self.deadline - time.monotonic()
            if left <= 0:
                raise _Closed("tls_timeout")
            if left < wait:
                wait, due = left, True
        try:
            async with asyncio.timeout(wait):
                data = await self.reader.read(min(READ_CHUNK, room))
        except TimeoutError:
            raise _Closed("tls_timeout" if due else "timeout") from None
        except (ConnectionError, OSError):
            raise _Closed("client_reset") from None
        if not data:
            raise _Closed("client_closed")
        self.bytes_in += len(data)
        return data

    async def _send(self, data: bytes, raw: bool = False) -> None:
        if not data:
            return
        if not raw and self.tls is not None and self.tls_mode in ("login", "full"):
            try:
                data = self.tls.encrypt(data)
            except tls.TlsError:
                raise _Closed("tls_error") from None
        self.writer.write(data)
        self.bytes_out += len(data)
        try:
            async with asyncio.timeout(self.cfg.write_timeout):
                await self.writer.drain()
        except TimeoutError:
            self.abort()  # a peer that does not read must not pin memory
            raise _Closed("write_timeout") from None
        except (ConnectionError, OSError):
            raise _Closed("client_reset") from None

    async def _pay(self, base: bool = True) -> None:
        """Charge the CPU used since the last mark to this source; stall if it is over budget."""
        now = time.thread_time()
        cost = max(0.0, now - self.cpu_mark) + (CPU_MESSAGE if base else 0.0)
        delay = self.sensor.cpu_delay(self.ip, cost)
        if delay > 0.01:
            await asyncio.sleep(delay)  # stalls this connection only, nothing else waits
        self.cpu_mark = time.thread_time()

    def drop_tls(self) -> None:
        if self.tls is not None:
            self.tls = None
            self.sensor.tls_release(self.ip)
            self.sensor.buffered -= tls.TLS_COST
        self.tls_mode = "none"
        self.deadline = None

    async def _reply(self, payload: bytes) -> None:
        await self._pay()
        # Pending output counts against the same budget as input buffers until it is drained.
        self.out_held = len(payload)
        self.sensor.buffered += self.out_held
        try:
            for packet in tds.frame(tds.T_REPLY, payload, self.packet_size, self.spid):
                await self._send(packet)
        finally:
            self.sensor.buffered -= self.out_held
            self.out_held = 0

    def _account(self) -> None:
        now = self.parser.held + self.chunk_bytes
        self.sensor.buffered += now - self.held
        self.held = now
        if self.sensor.buffered > self.cfg.max_buffered:
            raise _Closed("budget")

    # --- main flow -----------------------------------------------------------------------

    async def run(self) -> None:
        self._tune_socket()
        self.emit(EventType.connect, {}, priority=True)
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
            elif reason == "timeout" and self.bytes_in == 0:
                reason = "no_data"
            elif reason == "timeout":
                reason = "idle"
        except asyncio.CancelledError:
            reason = "shutdown"
            raise
        except Exception as exc:
            self.sensor.errors += 1
            reason = "error"
            log.warning("handler error (%s)", type(exc).__name__)
        finally:
            await _close(self.writer)
            self.emit(EventType.disconnect, self._summary(reason), priority=True)

    def _summary(self, reason: str) -> dict[str, Any]:
        data: dict[str, Any] = {
            "duration_s": round(time.monotonic() - self.started, 3),
            "reason": reason,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "messages": self.messages,
            "logins": self.logins,
            "authenticated": self.authenticated,
            "flags": sorted(self.flags_seen),
        }
        if self.prelogin is not None and self.prelogin.encryption is not None:
            data["client_encryption"] = self.prelogin.encryption
        if self.suppressed:
            data["suppressed_events"] = dict(self.suppressed)
        changed = {
            k: v
            for k, v in self.state.pending.items()
            if v != sql.OPTIONS[k][2] and k != "show advanced options"
        }
        if changed:
            data["config_changes"] = changed
        return data

    async def _serve(self) -> str:
        while True:
            wait = self.cfg.first_data_timeout if self.bytes_in == 0 else self.cfg.idle_timeout
            data = await self._recv(wait)
            self.cpu_mark = time.thread_time()
            if self.tls is not None and self.tls_mode in ("login", "full"):
                data = self._decrypt(data)
            self.parser.feed(data)
            self._account()
            reason = await self._drain()
            self._account()
            if reason is not None:
                return reason

    def _decrypt(self, data: bytes) -> bytes:
        assert self.tls is not None  # noqa: S101 - callers check
        try:
            return self.tls.decrypt(data)
        except tls.TlsClosed:
            raise _Closed("client_closed") from None
        except tls.TlsError:
            raise _Closed("tls_error") from None

    async def _drain(self) -> str | None:
        """Handle every complete packet in the parser. Returns a close reason or None."""
        slice_start = time.monotonic()
        while True:
            self.cpu_mark = time.thread_time()
            try:
                packet = self.parser.next_packet(first=self.phase == "start")
            except tds.TdsError as err:
                self._not_tds(err.reason)
                return "protocol_error"
            if packet is None:
                await self._pay(base=False)
                return None
            stop = await self._packet(packet)
            await self._pay(base=False)
            self._account()
            if stop is not None:
                return stop
            if time.monotonic() - slice_start > WORK_SLICE:
                await asyncio.sleep(0)
                slice_start = time.monotonic()

    def _not_tds(self, reason: str) -> None:
        head = self.parser.preview(PREVIEW)
        first = self.phase == "start" and self.parser.packets == 0
        self.flags_seen.add("non_tds" if first else "tds_malformed")
        if self._quota("scan", 10):
            self.emit(
                EventType.scan,
                {
                    "kind": "non_tds" if first else "tds_malformed",
                    "reason": reason,
                    "protocol_guess": guess_protocol(head) if first else "tds",
                    "hex_preview": head.hex(),
                    "bytes_received": self.bytes_in,
                },
                priority=True,
            )

    async def _tls_handshake(self, data: bytes) -> str | None:
        assert self.tls is not None  # noqa: S101 - mode "handshake" implies a stream
        self.tls_packets += 1
        if self.tls_packets > MAX_TLS_PACKETS:
            return "protocol_error"
        try:
            out = self.tls.handshake(data)
        except tls.TlsError:
            self.flags_seen.add("tls_failed")
            return "tls_error"
        await self._pay()
        for packet in tds.frame(tds.T_PRELOGIN, out, tds.DEFAULT_PACKET, 0) if out else ():
            await self._send(packet, raw=True)
        if self.tls.done:
            self.deadline = time.monotonic() + self.cfg.tls_deadline  # now LOGIN7 must follow
            self.tls_mode = "full" if self.encrypt_full else "login"
            rest = self.parser.take_rest()
            if rest:
                self.parser.feed(self._decrypt(rest))
        return None

    async def _packet(self, packet: tds.Packet) -> str | None:
        if self.tls_mode == "handshake" and packet.type == tds.T_PRELOGIN:
            return await self._tls_handshake(packet.payload)
        if self.chunks and packet.type != self.msg_type:
            self._not_tds("mixed_message")
            return "protocol_error"
        self.msg_type = packet.type
        self.msg_packets += 1
        if self.msg_packets > MAX_PACKETS_PER_MESSAGE:
            return "message_limit"
        room = MAX_MESSAGE - self.chunk_bytes
        keep = packet.payload[: max(0, room)]
        if len(keep) < len(packet.payload):
            self.msg_dropped += len(packet.payload) - len(keep)
        if keep or not self.chunks:
            self.chunks.append(keep)
            self.chunk_bytes += len(keep)
        if not packet.eom:
            return None
        payload = b"".join(self.chunks)
        dropped = self.msg_dropped
        self.chunks, self.chunk_bytes, self.msg_packets, self.msg_dropped = [], 0, 0, 0
        self.messages += 1
        if self.messages > self.cfg.max_commands:
            return "message_limit"
        return await self._message(packet.type, payload, dropped)

    async def _message(self, mtype: int, payload: bytes, dropped: int) -> str | None:
        try:
            if mtype == tds.T_PRELOGIN:
                return await self._on_prelogin(payload)
            if mtype == tds.T_LOGIN7:
                return await self._on_login7(payload)
            if mtype == tds.T_SSPI and self.phase == "sspi":
                return await self._on_sspi(payload)
            if self.phase != "ready":
                self._not_tds("unexpected_" + hex(mtype))
                return "protocol_error"
            if mtype == tds.T_SQLBATCH:
                return await self._on_query(tds.parse_batch(payload), "sql_batch", "", dropped)
            if mtype == tds.T_RPC:
                proc, first = tds.parse_rpc(payload)
                text = first if proc == "sp_executesql" and first else "exec " + proc
                return await self._on_query(text, "rpc", proc, dropped)
            if mtype == tds.T_ATTENTION:
                await self._reply(tds.done(tds.DONE_ATTN, 0, 0, self.tds_version))
                return None
            # transaction manager, bulk load, SSPI continuation: acknowledge, do nothing.
            await self._reply(tds.done(0, 0, 0, self.tds_version))
            return None
        except tds.TdsError as err:
            self._not_tds(err.reason)
            return "protocol_error"

    async def _on_prelogin(self, payload: bytes) -> str | None:
        if self.phase != "start":
            self.flags_seen.add("tls_attempt")
            return "protocol_error"
        pl = tds.parse_prelogin(payload)
        self.prelogin = pl
        if pl.encryption in (tds.ENC_ON, tds.ENC_REQ):
            self.flags_seen.add("encryption_requested")
        self.phase = "login"
        reply_enc = tds.ENC_NOT_SUP
        ctx = self.sensor.tls_ctx
        if ctx is not None and pl.encryption in (tds.ENC_OFF, tds.ENC_ON, tds.ENC_REQ):
            if not self.sensor.tls_acquire(self.ip):
                # Never answer NOT_SUP (a real server with its fallback certificate never does):
                # make the connection slow and then drop it.
                self.flags_seen.add("tls_busy")
                await asyncio.sleep(0.3 + secrets.randbelow(1200) / 1000)
                return "tls_busy"
            reply_enc = tds.ENC_OFF if pl.encryption == tds.ENC_OFF else tds.ENC_ON
            self.tls = tls.TlsStream(ctx)
            self.sensor.buffered += tls.TLS_COST
            self.tls_mode = "handshake"
            self.encrypt_full = reply_enc == tds.ENC_ON
            self.deadline = time.monotonic() + self.cfg.tls_deadline
            self._account()
        reply = tds.build_prelogin_reply(
            self.profile.version, reply_enc, pl.mars, tds.PL_FEDAUTH in pl.options
        )
        await self._pay()
        for packet in tds.frame(tds.T_REPLY, reply, self.packet_size, 0):
            await self._send(packet, raw=True)
        return None

    def _credentials_ok(self, login: tds.Login7) -> bool:
        if login.sspi:
            return False
        if self.cfg.accept_any:
            return True
        return (
            login.username in self.cfg.accept_users and login.password in self.cfg.accept_passwords
        )

    def _login_event(self, data: dict[str, Any]) -> None:
        if self._quota("login", self.cfg.quota_logins):
            self.emit(EventType.login_attempt, {**data, "flags": ["auth"]}, priority=True)

    async def _login_failed(self, username: str, untrusted: bool = False) -> str:
        await self._reply(
            tds.login_failed_message(
                username, self.tds_version, self.profile.server_name, untrusted
            )
        )
        return "auth_failed"

    async def _on_login7(self, payload: bytes) -> str | None:
        if self.phase in ("ready", "sspi") or (self.phase == "login" and self.authenticated):
            return "protocol_error"
        login = tds.parse_login7(payload)
        self.deadline = None
        tls_used = self.tls_mode in ("login", "full")
        self.login_tls = tls_used
        if self.tls_mode == "login":
            self.drop_tls()  # encryption "off": TLS covers LOGIN7 only, replies are plaintext
        self.login = login
        self.logins += 1
        self.tds_version = tds.map_tds_version(login.tds_version)
        if 512 <= login.packet_size <= tds.MAX_PACKET - 1:
            self.packet_size = login.packet_size
        common = {
            "hostname": login.hostname,
            "app_name": login.app_name,
            "client_library": login.library,
            "database": login.database,
            "tds_version": hex(login.tds_version),
            "client_pid": login.client_pid,
            "tls": tls_used,
        }
        if login.sspi:
            tok = login.sspi_token
            if tok[:8] == tds.NTLM_SIG and len(tok) >= 12 and tok[8] == 1:
                self.phase = "sspi"
                challenge = secrets.token_bytes(8)
                blob = tds.ntlm_challenge(
                    challenge,
                    self.profile.server_name.upper(),
                    self.profile.domain,
                    self.profile.dns_domain,
                    time.time(),
                    self.profile.win_build,
                )
                await self._reply(tds.sspi_token(blob))
                return None
            self._login_event(
                {"username": login.username, "password": None, "success": False,
                 "method": "tds-sspi", **common}
            )  # fmt: skip
            return await self._login_failed(login.username)
        ok = self._credentials_ok(login)
        self._login_event(
            {"username": login.username, "password": login.password, "success": ok,
             "method": "tds-sql", **common}
        )  # fmt: skip
        if not ok:
            return await self._login_failed(login.username)
        self.authenticated = True
        self.phase = "ready"
        self.state = sql.SqlState(
            login=login.username[:128], spid=self.spid, app_name=login.app_name[:128]
        )
        wanted = login.database.strip().lower()[:64]
        if wanted in (*sql.SYSTEM_DBS, *self.profile.databases):
            self.state.db = wanted
        await self._reply(
            tds.login_ok_message(
                self.tds_version,
                self.profile.version,
                self.packet_size,
                self.state.db,
                self.profile.server_name,
                features=login.extension,
            )
        )
        return None

    async def _on_sspi(self, payload: bytes) -> str | None:
        """The AUTHENTICATE message of an NTLM login: record who and what, then refuse."""
        try:
            auth = tds.parse_ntlm_authenticate(payload[:8192])
        except tds.TdsError:
            auth = tds.NtlmAuth()
        name = f"{auth.domain}\\{auth.user}" if auth.domain else auth.user
        login = self.login
        self._login_event(
            {
                "username": name,
                "password": None,
                "success": False,
                "method": "tds-ntlm",
                "hash_algorithm": "ntlm",
                "hash_preview": auth.nt_response_preview,
                "hash_bytes": auth.nt_response_len,
                "hostname": auth.workstation or (login.hostname if login else ""),
                "app_name": login.app_name if login else "",
                "client_library": login.library if login else "",
                "tls": self.login_tls,
            }
        )
        known = {self.profile.domain.lower(), self.profile.server_name.lower()}
        untrusted = bool(auth.domain) and auth.domain.lower() not in known
        return await self._login_failed(name, untrusted)

    async def _on_query(self, text: str, kind: str, proc: str, dropped: int) -> str | None:
        try:
            findings = sql.analyze(text)
        except Exception:
            self.sensor.errors += 1
            findings = sql.Findings()
        flags = findings.flags
        self.flags_seen |= flags
        try:
            stmts = sql.respond(self.state, text, self.profile)
            body = tds.encode_statements(
                stmts, self.tds_version, self.profile.server_name, kind == "rpc"
            )
            if len(body) > MAX_REPLY:  # cannot happen with the constant tables
                raise ValueError("reply too large")
        except Exception:
            # Never lose the capture and never answer with a crash: syntax error, like a server.
            self.sensor.errors += 1
            stmts = [sql._err(102, "Incorrect syntax near ''.", 15, 1)]
            body = tds.encode_statements(
                stmts, self.tds_version, self.profile.server_name, kind == "rpc"
            )
        self._command_event(text, kind, proc, flags, stmts, dropped)
        for download in findings.downloads:
            self._download(download, text)
        await self._reply(body)
        return None

    def _command_event(
        self,
        text: str,
        kind: str,
        proc: str,
        flags: set[str],
        stmts: list[tds.Statement],
        dropped: int,
    ) -> None:
        important = bool(flags & sql.PRIORITY_FLAGS)
        first_word = text.lstrip()[:7].lower()
        if important:
            allowed = self._quota("priority", self.cfg.quota_priority)
        elif first_word.startswith("select") and len(text) < 256:
            allowed = self._quota("noisy", self.cfg.quota_noisy)
        else:
            allowed = self._quota("command", self.cfg.quota_commands)
        if not allowed:
            return
        preview = _preview(stmts)
        data: dict[str, Any] = {
            "input": text[:4096],
            "kind": kind,
            "flags": sorted(flags),
            "output_preview": preview,
            "database": self.state.db,
            "login": self.state.login,
        }
        if proc:
            data["rpc"] = proc
        if len(text) > 4096 or dropped:
            data["input_bytes_truncated"] = True
        self.emit(EventType.command, data, priority=important)

    def _download(self, download: Any, line: str) -> None:
        if download.url in self.urls or not self._quota("download", self.cfg.quota_downloads):
            return
        self.urls.add(download.url)
        self.emit(
            EventType.download_attempt,
            {"url": download.url, "tool": download.tool, "command": line[:512]},
            priority=True,
        )


def _preview(stmts: list[tds.Statement]) -> str:
    for st in stmts:
        for msg in st.messages:
            if isinstance(msg, tds.Msg):
                return f"Msg {msg.number}: {msg.text}"[:160]
        if st.rows:
            cells = [str(c) for c in st.rows[0] if c is not None]
            return " | ".join(cells)[:160]
    return ""


class MssqlServer:
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
