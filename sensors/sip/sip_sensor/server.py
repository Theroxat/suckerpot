"""UDP and TCP listeners, plus the memory guard and housekeeping loops.

Order of work for a datagram (all synchronous, nothing awaits attacker-controlled data):
memory guard -> size cap -> packets-per-second buckets -> parse and record -> reply gate
(source sanity, per-source and global reply buckets, reply never larger than the request).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
import time

from sip_sensor import sip
from sip_sensor.config import Config
from sip_sensor.events import Buckets, CpuBuckets, Tracker
from sip_sensor.guard import ReplyGate
from sip_sensor.handler import Handler, Reply
from sip_sensor.memguard import MemoryGuard

log = logging.getLogger("sip_sensor.server")

SOCK_BUF = 64 * 1024
UDP_RCVBUF = 1024 * 1024
MAX_WRITE_BUFFER = 64 * 1024


def _addr(addr: object) -> tuple[str, int]:
    if isinstance(addr, tuple) and len(addr) >= 2:
        return str(addr[0]).split("%", 1)[0], int(addr[1])
    return "0.0.0.0", 0  # noqa: S104 - placeholder for an unknown peer


class Sensor:
    """Shared state of both listeners."""

    def __init__(
        self,
        cfg: Config,
        handler: Handler,
        tracker: Tracker,
        guard: MemoryGuard | None = None,
        reply_gate: ReplyGate | None = None,
    ) -> None:
        self.cfg = cfg
        self.handler = handler
        self.tracker = tracker
        self.guard = guard or MemoryGuard(cfg.memory_limit)
        self.gate = reply_gate or ReplyGate(cfg)
        self.pps_ip = Buckets(cfg.pps_per_ip, cfg.pps_per_ip_burst)
        self.pps_global = Buckets(cfg.pps_global, cfg.pps_global_burst, max_keys=1)
        self.cpu_ip = CpuBuckets(cfg.cpu_per_ip_rate, cfg.cpu_per_ip_burst)
        self.cpu_global = CpuBuckets(cfg.cpu_global_rate, cfg.cpu_global_burst, max_keys=1)
        self.cpu_dropped = 0
        self.udp_in = 0
        self.udp_bytes_in = 0
        self.udp_dropped = 0
        self.udp_oversize = 0
        self.tcp_total = 0
        self.tcp_per_ip: dict[str, int] = {}
        self.tcp_writers: set[asyncio.StreamWriter] = set()
        self.tcp_refused = 0

    def stats(self) -> dict[str, int]:
        g = self.gate.stats
        return {
            "udp_in": self.udp_in,
            "udp_bytes_in": self.udp_bytes_in,
            "udp_dropped": self.udp_dropped,
            "cpu_dropped": self.cpu_dropped,
            "udp_oversize": self.udp_oversize,
            "replies": g.sent,
            "reply_bytes": g.bytes_sent,
            "denied_source": g.denied_source,
            "denied_rate": g.denied_rate,
            "denied_size": g.denied_size,
            "tcp_open": self.tcp_total,
            "tcp_refused": self.tcp_refused,
            "sessions": len(self.tracker),
            "parse_errors": self.handler.parse_errors,
            "memory": self.guard.usage,
        }

    # --- UDP ----------------------------------------------------------------------------

    def on_datagram(self, data: bytes, addr: object) -> bytes | None:
        """Process one datagram and return the reply to send back, if any. Never raises."""
        ip, port = _addr(addr)
        self.udp_in += 1
        self.udp_bytes_in += len(data)
        now = time.monotonic()
        if self.guard.check():
            self.udp_dropped += 1
            return None
        if len(data) > sip.MAX_MESSAGE:
            self.udp_oversize += 1
            self.tracker.note_unrecorded(ip)
            return None
        local = ip == "::1" or ip.startswith("127.")  # cannot come from the network
        if not (self.pps_ip.allow(ip, now=now) and (local or self.pps_global.allow("*", now=now))):
            self.udp_dropped += 1
            self.tracker.note_unrecorded(ip)
            return None
        if not (self.cpu_ip.ready(ip, now) and (local or self.cpu_global.ready("*", now))):
            self.cpu_dropped += 1
            self.udp_dropped += 1
            self.tracker.note_unrecorded(ip)
            return None
        can_reply = self.gate.source_ok(ip, port)
        try:
            reply = self.handler.handle(
                data, ip, port, "udp", now, can_reply=can_reply, max_reply=len(data)
            )
        except Exception:
            log.exception("handler error (udp)")
            return None
        finally:
            spent = time.monotonic() - now
            self.cpu_ip.charge(ip, spent, now)
            self.cpu_global.charge("*", spent, now)
        if reply.data is None:
            return None
        if not self.gate.permit(ip, port, len(data), len(reply.data), now):
            return None
        return reply.data

    # --- TCP ----------------------------------------------------------------------------

    def _tune(self, writer: asyncio.StreamWriter) -> None:
        sock = writer.get_extra_info("socket")
        if sock is None:
            return
        for level, opt, value in (
            (socket.SOL_SOCKET, socket.SO_SNDBUF, SOCK_BUF),
            (socket.SOL_SOCKET, socket.SO_RCVBUF, SOCK_BUF),
            (socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT, 30_000),
        ):
            with contextlib.suppress(OSError, AttributeError):
                sock.setsockopt(level, opt, value)

    async def handle_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        ip, port = _addr(writer.get_extra_info("peername"))
        if (
            self.guard.check()
            or self.tcp_total >= self.cfg.max_connections
            or self.tcp_per_ip.get(ip, 0) >= self.cfg.max_per_ip
        ):
            self.tcp_refused += 1
            writer.transport.abort()
            return
        self.tcp_total += 1
        self.tcp_per_ip[ip] = self.tcp_per_ip.get(ip, 0) + 1
        self.tcp_writers.add(writer)
        self._tune(writer)
        try:
            await self._tcp_loop(reader, writer, ip, port)
        except Exception:
            log.exception("handler error (tcp)")
        finally:
            self.tcp_writers.discard(writer)
            await _close(writer, abort=True)
            self.tcp_total = max(0, self.tcp_total - 1)
            left = self.tcp_per_ip.get(ip, 1) - 1
            if left <= 0:
                self.tcp_per_ip.pop(ip, None)
            else:
                self.tcp_per_ip[ip] = left

    async def _tcp_loop(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ip: str, port: int
    ) -> None:
        cfg = self.cfg
        started = time.monotonic()
        buf = b""
        total_in = 0
        messages = 0
        while messages < cfg.max_messages and total_in < cfg.max_bytes_in:
            try:
                taken = take_message(buf)
            except sip.ParseError:
                return
            if taken is not None:
                raw, buf = taken
                messages += 1
                if not (self.pps_ip.allow(ip) and self.pps_global.allow("*")):
                    return
                t0 = time.monotonic()
                if not (self.cpu_ip.ready(ip, t0) and self.cpu_global.ready("*", t0)):
                    await asyncio.sleep(0.05)  # over its CPU budget: slow down, do not parse
                    continue
                try:
                    reply = self.handler.handle(
                        raw,
                        ip,
                        port,
                        "tcp",
                        t0,
                        can_reply=self.gate.source_ok(ip, port),
                        max_reply=None,
                    )
                except Exception:
                    log.exception("handler error (tcp)")
                    reply = Reply(None, 0)
                spent = time.monotonic() - t0
                self.cpu_ip.charge(ip, spent, t0)
                self.cpu_global.charge("*", spent, t0)
                if reply.data is not None:
                    writer.write(reply.data)
                    try:
                        async with asyncio.timeout(cfg.write_timeout):
                            await writer.drain()
                    except (TimeoutError, ConnectionError, OSError):
                        return
                await asyncio.sleep(0)  # one message per loop turn
                continue
            left = cfg.max_session - (time.monotonic() - started)
            if left <= 0:
                return
            wait = min(left, cfg.first_data_timeout if messages == 0 else cfg.idle_timeout)
            try:
                chunk = await asyncio.wait_for(reader.read(4096), wait)
            except (TimeoutError, ConnectionError, OSError):
                return
            if not chunk:
                return
            total_in += len(chunk)
            buf += chunk

    def shed_tcp(self) -> int:
        for writer in list(self.tcp_writers):
            writer.transport.abort()
        return len(self.tcp_writers)


def take_message(buf: bytes) -> tuple[bytes, bytes] | None:
    """Cut one complete SIP message off the front of a TCP buffer.

    Returns ``None`` while the message is incomplete and raises :class:`sip.ParseError` when
    it can never become valid (head too large, bad or oversized Content-Length).
    """
    buf = buf.lstrip(b"\r\n")
    end = buf.find(b"\r\n\r\n")
    if end < 0:
        if len(buf) > sip.MAX_MESSAGE:
            raise sip.ParseError("head too large")
        return None
    head_len = end + 4
    if head_len > sip.MAX_MESSAGE:
        raise sip.ParseError("head too large")
    length = 0
    for line in buf[:end].decode("latin-1").split("\r\n")[1:]:
        if line[:1] in (" ", "\t"):
            continue  # folded continuation of the previous header
        name, _, value = line.partition(":")
        if name.strip().lower() in ("content-length", "l"):
            value = value.strip()
            if not value.isdigit() or len(value) > 6:
                raise sip.ParseError("bad content-length")
            length = int(value)
            break
    if head_len + length > sip.MAX_MESSAGE:
        raise sip.ParseError("message too large")
    if len(buf) < head_len + length:
        return None
    return buf[: head_len + length], buf[head_len + length :]


async def _close(writer: asyncio.StreamWriter, *, abort: bool = False) -> None:
    transport = writer.transport
    if abort or transport.get_write_buffer_size() > 0:
        transport.abort()
        return
    with contextlib.suppress(Exception):
        writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 2.0)
    except Exception:
        transport.abort()


class UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, sensor: Sensor) -> None:
        self.sensor = sensor
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: object) -> None:
        reply = self.sensor.on_datagram(data, addr)
        transport = self.transport
        if reply is None or transport is None or transport.is_closing():
            return
        if transport.get_write_buffer_size() > MAX_WRITE_BUFFER:  # type: ignore[attr-defined]
            return  # never queue replies for a socket that cannot send
        transport.sendto(reply, addr)  # type: ignore[arg-type]

    def error_received(self, exc: Exception) -> None:
        return None


class SipServer:
    def __init__(self, cfg: Config, sensor: Sensor) -> None:
        self.cfg = cfg
        self.sensor = sensor
        self._udp: asyncio.DatagramTransport | None = None
        self._tcp: asyncio.Server | None = None
        self._tasks: list[asyncio.Task[None]] = []
        self.udp_port = cfg.port
        self.tcp_port = 0

    async def start(self) -> int:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: UdpProtocol(self.sensor),
            local_addr=(self.cfg.host, self.cfg.port),
            reuse_port=False,
        )
        self._udp = transport
        sock = transport.get_extra_info("socket")
        if sock is not None:
            with contextlib.suppress(OSError, AttributeError):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, UDP_RCVBUF)
        self.udp_port = int(transport.get_extra_info("sockname")[1])
        if self.cfg.tcp:
            self._tcp = await asyncio.start_server(
                self.sensor.handle_tcp,
                host=self.cfg.host,
                port=self.cfg.port if self.cfg.port == 0 else self.udp_port,
                limit=8192,
                backlog=128,
                reuse_address=True,
            )
            socks = self._tcp.sockets
            self.tcp_port = int(socks[0].getsockname()[1]) if socks else 0
        self.sensor.guard.sample()
        self._tasks = [asyncio.create_task(self._housekeeping())]
        return self.udp_port

    async def _housekeeping(self) -> None:
        last_summary = time.monotonic()
        while True:
            await asyncio.sleep(1.0)
            sensor = self.sensor
            if sensor.guard.sample():
                sensor.guard.shed_events += 1
                aborted = sensor.shed_tcp()
                sensor.guard.aborted += aborted
                sensor.tracker.close_all("memory_pressure")
                log.warning("memory %d MiB: shed %d connections", sensor.guard.usage >> 20, aborted)
            now = time.monotonic()
            sensor.tracker.sweep(now)
            if now - last_summary >= self.cfg.summary_interval:
                sensor.tracker.flush_unrecorded(now - last_summary)
                last_summary = now

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        if self._tcp is not None:
            self._tcp.close()
            self.sensor.shed_tcp()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._tcp.wait_closed(), 2.0)
        if self._udp is not None:
            self._udp.close()
        self.sensor.tracker.close_all("shutdown")
