"""The Redis listener: connection handling, limits, event emission.

Per connection: read, feed the strict RESP parser, run every complete command through the
in-memory emulation (:mod:`redis_sensor.commands`), write the replies, and record what the
attacker did as events. Every read has a deadline, every buffer a cap (per connection and
across connections), the whole connection a time cap, and the number of commands is bounded.

Event policy per session (the quotas are in :class:`Config`): ``connect`` and ``disconnect``
always; ``login_attempt`` and ``download_attempt`` have their own quotas; commands are split
into noisy ones (PING, INFO, GET, ...), ordinary ones and priority ones (carrying an indicator
flag such as ``cron_write`` or ``slaveof``). Whatever exceeds a quota is counted and reported
in the ``disconnect`` event, never silently lost.
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
from collections.abc import Iterator
from typing import Any

from suckerpot_common import EventType

from redis_sensor import commands, extract, resp
from redis_sensor.config import Config
from redis_sensor.cpu import CpuAccount, IpSteps, StepBucket
from redis_sensor.events import EventSink
from redis_sensor.info import ServerContext
from redis_sensor.memguard import MemoryGuard

log = logging.getLogger("redis_sensor.server")

READ_CHUNK = 32 * 1024
TIME_SLICE = 0.005  # seconds of command processing before the loop gets control back
MAX_OUT = 64 * 1024  # reply bytes built before they are written (and drained)
MAX_OVERFLOW = 64  # over-cap connections being answered slowly at the same time
OVERFLOW_READ_WAIT = 2.0
SOCK_BUF = 32 * 1024  # Linux doubles it
PRIORITY_FLAGS = frozenset(
    {
        "config_set_dir",
        "config_set_dbfilename",
        "slaveof",
        "module_load",
        "cron_write",
        "ssh_key_write",
        "webshell_write",
        "flushall",
        "flushdb",
        "eval",
        "lua_sandbox_escape",
        "reverse_shell",
        "miner",
        "kinsing",
        "dropper",
        "download",
        "ssh_key_payload",
        "webshell_payload",
        "ransom_note",
        "cron_payload",
        "psync",
        "shutdown",
        "requirepass_set",
        "aof_enabled",
        "save",
    }
)
_NO_TEXT_SCAN = frozenset({"PING", "ECHO", "INFO", "GET", "DBSIZE", "SELECT", "CLIENT", "COMMAND"})


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


def format_input(args: list[bytes], limit: int = 2048) -> str:
    """The command as a redis-cli style line, capped at ``limit`` characters.

    Each argument is cut to what still fits *before* it is decoded or quoted."""
    parts: list[str] = []
    size = 0
    for i, arg in enumerate(args):
        room = limit - size
        if room <= 0:
            parts.append(f"...(+{len(args) - i} args)")
            break
        chunk = arg[: room + 1]
        text = chunk.decode("utf-8", "replace")
        plain = (
            bool(text) and text.isprintable() and not any(c in text for c in (" ", '"', "'", "\\"))
        )
        if not plain:
            esc = (
                text.replace("\\", "\\\\")
                .replace('"', '\\"')
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t")
            )
            text = f'"{esc}"'
        if len(arg) > room:
            text = text[:room] + f"...({len(arg)} bytes)"
        parts.append(text)
        size += len(text) + 1
    return " ".join(parts)[: limit + 64]


class _Closed(Exception):
    """The client went away or a limit was hit; ``reason`` says which."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class Sensor:
    """Process-wide state shared by all connections."""

    def __init__(
        self,
        cfg: Config,
        sink: EventSink,
        ctx: ServerContext,
        guard: MemoryGuard | None = None,
    ) -> None:
        self.cfg = cfg
        self.sink = sink
        self.ctx = ctx
        self.guard = guard or MemoryGuard(cfg.memory_limit)
        self.total = 0
        self.per_ip: dict[str, int] = {}
        self.sessions: dict[Session, None] = {}  # insertion order = age
        self.buffered = 0  # parser bytes held by all sessions
        self.rejected = 0
        self.evicted = 0
        self.seen = 0
        self.errors = 0
        self.overflow = 0
        self.ip_steps = IpSteps(cfg.cpu_steps_per_sec_per_ip, cfg.cpu_steps_per_sec_per_ip * 2)
        self.global_steps = StepBucket(cfg.cpu_steps_per_sec, cfg.cpu_steps_per_sec * 2)
        self._guard_at = 0.0
        self.next_client_id = 3 + secrets.randbelow(5000)

    # --- admission -----------------------------------------------------------------------

    def acquire(self, ip: str) -> bool:
        if is_loopback(ip) and self.cfg.quiet_loopback:
            self.total += 1
            self.per_ip[ip] = self.per_ip.get(ip, 0) + 1
            return True  # the container healthcheck is never refused
        self._sample_guard()
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

    def _sample_guard(self) -> None:
        """Admission checks the memory guard too, not only the once-a-second timer."""
        now = time.monotonic()
        if now - self._guard_at >= 0.2:
            self._guard_at = now
            self.guard.sample()

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
        self.ctx.total_connections += 1
        quiet = self.cfg.quiet_loopback and is_loopback(ip)
        if not self.acquire(ip):
            self.ctx.rejected = self.rejected
            if not quiet:
                self.sink.note_suppressed(ip)
            await self._refuse(reader, writer)
            return
        session: Session | None = None
        try:
            recorded = not quiet and self.sink.admit(ip)
            session = Session(self, reader, writer, ip, port, recorded)
            self.sessions[session] = None
            self.ctx.clients = len(self.sessions)
            await session.run()
        finally:
            if session is not None:
                self.sessions.pop(session, None)
                self.ctx.clients = len(self.sessions)
                self.buffered -= session.held
                session.held = 0
            self.release(ip)

    async def _refuse(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Over a cap: read the first bytes, answer like a server at ``maxclients``, close.

        An instant accept-and-FIN would be an easy fingerprint. The number of connections
        handled this way is itself bounded; beyond it they are aborted at once."""
        if self.overflow >= MAX_OVERFLOW:
            await _close(writer, abort=True)
            return
        self.overflow += 1
        try:
            with contextlib.suppress(Exception):
                async with asyncio.timeout(OVERFLOW_READ_WAIT):
                    await reader.read(1024)
            await asyncio.sleep(0.05 + secrets.randbelow(300) / 1000)
            with contextlib.suppress(Exception):
                writer.write(resp.error("ERR max number of clients reached"))
                async with asyncio.timeout(1.0):
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
        self.parser = resp.RequestParser()
        cpu = CpuAccount(
            StepBucket(
                self.cfg.cpu_steps_per_sec_per_conn, self.cfg.cpu_steps_per_sec_per_conn * 2
            ),
            sensor.ip_steps.get(ip),
            sensor.global_steps,
        )
        self.state = commands.ClientState(sensor.ctx, self._take_id(), f"{ip}:{port}", cpu)
        self._parts: Iterator[bytes] | None = None
        self._last_key: tuple[str, str] | None = None
        self._repeats = 0
        self._scan_cache: tuple[str, extract.TextFindings] | None = None
        self.held = 0
        self.bytes_in = 0
        self.bytes_out = 0
        self.commands = 0
        self.evicted = False
        self.shed = False
        self.counts: dict[str, int] = {}
        self.suppressed: dict[str, int] = {}
        self.events = 0
        self.flags_seen: set[str] = set()
        self.urls: set[str] = set()
        self.logins = 0

    def _take_id(self) -> int:
        self.sensor.next_client_id += 1
        return self.sensor.next_client_id

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
        try:
            async with asyncio.timeout(wait):
                data = await self.reader.read(min(READ_CHUNK, room))
        except TimeoutError:
            raise _Closed("timeout") from None
        except (ConnectionError, OSError):
            raise _Closed("client_reset") from None
        if not data:
            raise _Closed("client_closed")
        self.bytes_in += len(data)
        self.sensor.ctx.net_in += len(data)
        return data

    async def _send(self, data: bytes) -> None:
        if not data:
            return
        self.writer.write(data)
        self.bytes_out += len(data)
        self.sensor.ctx.net_out += len(data)
        self._account()  # what was just queued counts until the peer has taken it
        try:
            async with asyncio.timeout(self.cfg.write_timeout):
                await self.writer.drain()
        except TimeoutError:
            self.abort()  # a peer that does not read must not pin memory
            raise _Closed("write_timeout") from None
        except (ConnectionError, OSError):
            raise _Closed("client_reset") from None
        self._account()

    def _account(self) -> None:
        """Keep the process-wide total in step with what this session holds in memory.

        That is the parser's buffered input plus the reply bytes the transport has not yet
        handed to the kernel."""
        now = self.parser.held + self.writer.transport.get_write_buffer_size()
        self.sensor.buffered += now - self.held
        self.held = now
        if self.sensor.buffered > self.cfg.max_buffered:
            self.abort()
            raise _Closed("budget")

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
            "commands": self.commands,
            "flags": sorted(self.flags_seen),
        }
        if self.suppressed:
            data["suppressed_events"] = dict(self.suppressed)
        changed = {
            k: v
            for k, v in self.state.config.items()
            if k in ("dir", "dbfilename", "appendonly", "requirepass", "save")
            and v != dict(commands._CONFIG_DEFAULTS)[k]
        }
        if changed:
            data["config_changes"] = changed
        if self.state.config_log:
            data["config_history"] = [list(item) for item in self.state.config_log]
        if self.state.master is not None:
            data["replicaof"] = f"{self.state.master[0]}:{self.state.master[1]}"
        return data

    async def _serve(self) -> str:
        while True:
            wait = self.cfg.first_data_timeout if self.bytes_in == 0 else self.cfg.idle_timeout
            self.parser.feed(await self._recv(wait))
            self._account()
            reason = await self._drain()
            self._account()
            if reason is not None:
                return reason

    async def _flush(self, out: bytearray) -> None:
        if out:
            data = bytes(out)
            out.clear()
            await self._send(data)

    async def _drain(self) -> str | None:
        """Run every complete command in the parser. Returns a close reason or None.

        Work is sliced by wall-clock time (``TIME_SLICE``), not by command count, so no mix
        of commands can hold the event loop for long; replies are written (and drained) every
        ``MAX_OUT`` bytes so a peer that does not read never makes the output pile up."""
        while True:
            out = bytearray()
            stop: str | None = None
            drained = False
            started = time.perf_counter()
            while True:
                try:
                    cmd = self.parser.next_command()
                except resp.ProtocolError as err:
                    out += resp.error(f"ERR Protocol error: {err.message}")
                    self._protocol_error(err.message)
                    stop = "protocol_error"
                    break
                if cmd is None:
                    drained = True
                    break
                stop = self._process(cmd, out)
                if self._parts is not None:
                    parts, self._parts = self._parts, None
                    for piece in parts:
                        out += piece
                        if len(out) >= MAX_OUT:
                            await self._flush(out)
                if stop is not None:
                    break
                if self.commands >= self.cfg.max_commands:
                    stop = "command_limit"
                    break
                if len(out) >= MAX_OUT:
                    await self._flush(out)
                if time.perf_counter() - started >= TIME_SLICE:
                    break
            if stop == "cross_protocol":
                out.clear()  # real Redis closes without a word
            await self._flush(out)
            self._account()
            if stop is not None:
                return stop
            if drained:
                return None
            await asyncio.sleep(0)

    def _protocol_error(self, message: str) -> None:
        self.flags_seen.add("protocol_error")
        if self._quota("scan", 10):
            self.emit(
                EventType.scan,
                {
                    "kind": "redis_protocol_error",
                    "error": message,
                    "bytes_received": self.bytes_in,
                },
            )

    def _process(self, args: list[bytes], out: bytearray) -> str | None:
        """Handle one command; append the reply to ``out``. Returns a close reason or None."""
        self.commands += 1
        head = args[0][:8].lower()
        if head in (b"host:", b"post") and len(args[0]) == len(head):
            # What real Redis does for HTTP-looking input: log it and drop the connection.
            self.flags_seen.add("cross_protocol")
            if self._quota("scan", 10):
                self.emit(
                    EventType.scan,
                    {
                        "kind": "cross_protocol",
                        "input": format_input(args, 512),
                        "protocol_guess": "http",
                        "bytes_received": self.bytes_in,
                    },
                    priority=True,
                )
            return "cross_protocol"
        name, outcome = commands.execute(self.state, args)
        flags = set(outcome.flags)
        text_findings = extract.TextFindings()
        if name not in _NO_TEXT_SCAN and not (
            name == "CONFIG" and len(args) > 1 and args[1].upper() == b"GET"
        ):
            text_findings = self._scan_text(_joined(args[1:]))
            flags |= text_findings.flags
        if self.parser.oversized:
            self.parser.oversized = False
            flags.add("oversized_arg")
        self.flags_seen |= flags
        if outcome.parts is not None:
            self._parts = outcome.parts
        else:
            out += outcome.reply
        line = format_input(args)
        if outcome.login is not None:
            self._login(outcome.login, name)
        if outcome.login is None or name == "HELLO":
            self._command_event(name, args, line, flags, outcome)
        for download in text_findings.downloads:
            self._download(download, name, line)
        if outcome.master is not None and self._quota("scan", 10):
            self.emit(
                EventType.scan,
                {
                    "kind": "redis_replication",
                    "master_host": outcome.master[0],
                    "master_port": outcome.master[1],
                    "command": name,
                    "flags": ["slaveof"],
                },
                priority=True,
            )
        return (
            "quit"
            if outcome.close and name == "QUIT"
            else ("shutdown_command" if outcome.close else None)
        )

    def _scan_text(self, text: str) -> extract.TextFindings:
        """Indicator scan, charged to the CPU buckets (about one step per 4 characters).

        An exactly repeated text reuses the previous result for free. When the buckets are
        empty the scan is skipped (the event is still recorded, flagged ``scan_skipped``)."""
        if self._scan_cache is not None and self._scan_cache[0] == text:
            return self._scan_cache[1]
        cost = len(text) // 4
        if cost > self.state.cpu.headroom():
            self.flags_seen.add("scan_skipped")
            return extract.TextFindings(flags={"scan_skipped"})
        self.state.cpu.charge(cost)
        found = extract.analyze(text)
        self._scan_cache = (text, found)
        return found

    def _login(self, login: tuple[str, str | None, bool], name: str) -> None:
        if not self._quota("login", self.cfg.quota_logins):
            return
        username, password, success = login
        self.emit(
            EventType.login_attempt,
            {
                "username": username,
                "password": password,
                "success": success,
                "method": "redis-hello" if name == "HELLO" else "redis-auth",
                "flags": ["auth"],
            },
            priority=True,
        )

    def _command_event(
        self,
        name: str,
        args: list[bytes],
        line: str,
        flags: set[str],
        outcome: commands.Outcome,
    ) -> None:
        key = (name, line)
        if key == self._last_key:
            self._repeats += 1
            self.suppressed["repeat"] = self.suppressed.get("repeat", 0) + 1
            return
        self._last_key = key
        important = bool(flags & PRIORITY_FLAGS)
        if important:
            allowed = self._quota("priority", self.cfg.quota_priority)
        elif commands.is_noisy(name):
            allowed = self._quota("noisy", self.cfg.quota_noisy)
        else:
            allowed = self._quota("command", self.cfg.quota_commands)
        if not allowed:
            return
        data: dict[str, Any] = {
            "input": line,
            "command": name,
            "argc": len(args),
            "flags": sorted(flags),
            "output_preview": outcome.reply[:160].decode("utf-8", "replace"),
            "db": self.state.db,
        }
        if self._repeats:
            data["repeated_before"] = self._repeats
            self._repeats = 0
        if outcome.module_path is not None:
            data["module_path"] = outcome.module_path
        if outcome.master is not None:
            data["master"] = f"{outcome.master[0]}:{outcome.master[1]}"
        if name in ("SAVE", "BGSAVE"):
            data["dir"] = self.state.config["dir"]
            data["dbfilename"] = self.state.config["dbfilename"]
        self.emit(EventType.command, data, priority=important)

    def _download(self, download: extract.Download, name: str, line: str) -> None:
        if download.url in self.urls or not self._quota("download", self.cfg.quota_downloads):
            return
        self.urls.add(download.url)
        self.emit(
            EventType.download_attempt,
            {
                "url": download.url,
                "tool": download.tool,
                "command": line[:512],
                "via": name,
            },
            priority=True,
        )


def _joined(args: list[bytes]) -> str:
    """Arguments as one text for indicator scanning: capped per argument and in total."""
    parts: list[str] = []
    size = 0
    for arg in args:
        if size >= extract.MAX_TEXT:
            break
        chunk = arg[: min(8192, extract.MAX_TEXT - size)]
        parts.append(chunk.decode("utf-8", "replace"))
        size += len(chunk) + 1
    return "\n".join(parts)


class RedisServer:
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
