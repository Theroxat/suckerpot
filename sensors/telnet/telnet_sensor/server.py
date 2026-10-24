"""The Telnet server: connection limits, login, event emission and the shell session."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import random
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from ssh_sensor.config import Config as ShellConfig
from ssh_sensor.shell.baseimage import Profile
from ssh_sensor.shell.fs import BaseImage
from suckerpot_common import EventType, truncate_data

from telnet_sensor.config import Config
from telnet_sensor.device import (
    PERSONALITY_BY_NAME,
    Personality,
    build_base_image,
    derive_device,
)
from telnet_sensor.devshell import DeviceShell
from telnet_sensor.events import EventSink, TokenBuckets
from telnet_sensor.protocol import LineEditor, Negotiator, TelnetParser
from telnet_sensor.replay import ReplayRecorder

log = logging.getLogger("telnet_sensor.server")

_READ_SIZE = 1024
_MAX_USERNAME = 128
_MAX_PASSWORD = 256
_PAYLOAD_PREVIEW = 256
_CONNECTION_OVERHEAD = 16 * 1024  # rough per-connection cost counted against the budget
_ERROR_LOG_INTERVAL = 60.0
_last_error_log = 0.0


def normalize_ip(raw: str) -> str:
    try:
        addr = ipaddress.ip_address(raw.split("%")[0])
    except ValueError:
        return "0.0.0.0"  # noqa: S104 - placeholder for an unparsable peer address
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return str(addr.ipv4_mapped)
    return str(addr)


class _End(Exception):
    """The session is over; ``reason`` goes into the disconnect event."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def to_wire(text: str) -> bytes:
    """Terminal text to NVT bytes: CR LF line ends, IAC doubled."""
    if "\n" in text:
        text = text.replace("\r\n", "\n").replace("\n", "\r\n")
    return text.encode("utf-8", "replace").replace(b"\xff", b"\xff\xff")


class Sensor:
    """Process-wide state shared by all connections."""

    def __init__(self, cfg: Config, sink: EventSink, seed: str) -> None:
        self.cfg = cfg
        self.sink = sink
        self.personality: Personality = PERSONALITY_BY_NAME[cfg.personality]
        self.profile: Profile = derive_device(seed, cfg.hostname, self.personality)
        self.base: BaseImage = build_base_image(self.profile, self.personality)
        self.shell_cfg = ShellConfig(
            command_delay=cfg.command_delay,
            line_budget=cfg.line_budget,
            max_fs_bytes=cfg.max_fs_bytes,
            max_fs_nodes=cfg.max_fs_nodes,
            max_output_per_line=cfg.max_output_per_line,
        )
        self.total = 0
        self.per_ip: dict[str, int] = {}
        self.rejected = 0
        self.rate_rejected = 0
        self.memory_rejected = 0
        self.connections_seen = 0
        self.connections: set[Connection] = set()
        self._rng = random.SystemRandom()
        self._new_conn = TokenBuckets(cfg.conn_rate_per_ip, cfg.conn_burst_per_ip)
        # Shell CPU-seconds, shared by all sessions: refills at ``shell_cpu_share`` per second.
        # Running a line spends what it used; a session that finds the balance negative waits.
        self._cpu = cfg.shell_cpu_burst
        self._cpu_at = time.monotonic()

    def cpu_debt_wait(self) -> float:
        """Seconds a session should wait before running its next line (0 when affordable)."""
        now = time.monotonic()
        self._cpu = min(
            self.cfg.shell_cpu_burst,
            self._cpu + (now - self._cpu_at) * self.cfg.shell_cpu_share,
        )
        self._cpu_at = now
        return 0.0 if self._cpu >= 0 else -self._cpu / self.cfg.shell_cpu_share

    def cpu_spend(self, seconds: float) -> None:
        self._cpu -= seconds

    @property
    def login_prompt(self) -> str:
        return self.cfg.login_prompt.replace("{hostname}", self.profile.hostname)

    @property
    def motd(self) -> str:
        return self.cfg.motd or self.personality.motd

    def admit(self, ip: str) -> bool:
        """Admit a new connection, or refuse it (caps, per-IP rate, memory budget)."""
        if self.total >= self.cfg.max_connections or self.per_ip.get(ip, 0) >= self.cfg.max_per_ip:
            self.rejected += 1
            return False
        if not self._new_conn.allow(ip):
            self.rejected += 1
            self.rate_rejected += 1
            return False
        if self.over_budget():
            self.rejected += 1
            self.memory_rejected += 1
            return False
        self.total += 1
        self.per_ip[ip] = self.per_ip.get(ip, 0) + 1
        return True

    def release(self, ip: str) -> None:
        self.total = max(0, self.total - 1)
        left = self.per_ip.get(ip, 1) - 1
        if left <= 0:
            self.per_ip.pop(ip, None)
        else:
            self.per_ip[ip] = left

    def credentials_ok(self, username: str, password: str) -> bool:
        if (username, password) in self.cfg.accept_credentials:
            return True
        return bool(password) and self._rng.random() < self.cfg.accept_random_prob

    def fail_delay(self) -> float:
        lo, hi = self.cfg.auth_fail_delay
        return self._rng.uniform(lo, hi) if hi > 0 else 0.0

    def memory_in_use(self) -> int:
        return sum(conn.memory_bytes() for conn in self.connections)

    def over_budget(self) -> bool:
        return self.memory_in_use() > self.cfg.memory_budget

    def stats(self) -> dict[str, int]:
        return {
            "memory_bytes": self.memory_in_use(),
            "connections": self.total,
            "seen": self.connections_seen,
            "rejected": self.rejected,
            "rate_rejected": self.rate_rejected,
            "memory_rejected": self.memory_rejected,
            **self.sink.stats(),
        }


class Connection:
    """One client connection."""

    def __init__(
        self,
        sensor: Sensor,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self.sensor = sensor
        self.cfg = sensor.cfg
        self.reader = reader
        self.writer = writer
        self.session_id = uuid.uuid4().hex[:24]
        peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)  # noqa: S104
        self.src_ip = normalize_ip(str(peer[0]))
        self.src_port = int(peer[1]) if len(peer) > 1 else 0
        self.started_ts = datetime.now(UTC)
        self.started = time.monotonic()
        self.admitted = False
        self.parser = TelnetParser()
        self.negotiator = Negotiator()
        self.editor = LineEditor(self.cfg.max_line)
        self.replay = ReplayRecorder()
        self.shell: DeviceShell | None = None
        self.reason = "closed by client"
        self.connect_emitted = False
        self.logged_in = False
        self.attempts = 0
        self.commands = 0
        self.downloads = 0
        self.bytes_in = 0
        self.bytes_out = 0
        self.data_in = 0
        self.first_data = bytearray()
        self.deadline = self.started + self.cfg.max_session

    # ---- bookkeeping -----------------------------------------------------------------------
    def memory_bytes(self) -> int:
        total = _CONNECTION_OVERHEAD + self.replay.size
        if self.shell is not None:
            total += self.shell.fs.used_bytes + self.shell.private_bytes() + 64 * 1024
        return total

    def _quiet(self) -> bool:
        return self.cfg.quiet_loopback and ipaddress.ip_address(self.src_ip).is_loopback

    def emit(
        self,
        type_: EventType,
        data: dict[str, Any],
        *,
        ts: datetime | None = None,
        cap: bool = True,
        force: bool = False,
        priority: bool = False,
        max_string: int = 4096,
    ) -> None:
        if self._quiet():
            return
        if not cap:
            # Only the replay frames bypass truncate_data (it limits lists to 64 items).
            replay = data.pop("replay", None)
            data = truncate_data(data)
            if replay is not None:
                data["replay"] = replay
        self.sensor.sink.emit(
            session_id=self.session_id,
            src_ip=self.src_ip,
            src_port=self.src_port,
            type_=type_,
            data=data,
            ts=ts,
            cap_data=cap,
            max_string=max_string,
            force=force,
            priority=priority,
        )

    def _ensure_connect(self) -> None:
        if self.connect_emitted:
            return
        self.connect_emitted = True
        banner = (self.cfg.prelogin_banner + self.sensor.login_prompt).strip()[:256]
        self.emit(
            EventType.connect,
            {
                "banner": banner,
                "client_options": list(self.negotiator.seen),
                "window": list(self.negotiator.window),
                "terminal": self.negotiator.terminal,
            },
            ts=self.started_ts,
        )

    # ---- I/O ----------------------------------------------------------------------------------
    async def _send(self, data: bytes, *, record: bool = True) -> None:
        if not data:
            return
        self.bytes_out += len(data)
        if self.logged_in and self.bytes_out > self.cfg.max_session_output:
            raise _End("output limit")
        if record:
            self.replay.add("o", data.decode("utf-8", "replace").replace("\xff\xff", "\xff"))
        try:
            self.writer.write(data)
            await asyncio.wait_for(self.writer.drain(), self.cfg.write_timeout)
        except TimeoutError:
            raise _End("write timeout") from None
        except (ConnectionError, OSError):
            raise _End("connection lost") from None

    async def _fill(self, until: float | None = None) -> None:
        """Read one chunk from the client and feed the parser and the editor.

        The wait is the shortest of the idle timeout, the login deadline (``until``) and the
        total session limit; whichever it is names the reason when it expires."""
        now = time.monotonic()
        wait, reason = self.cfg.idle_timeout, "idle timeout"
        if until is not None and until - now < wait:
            wait, reason = until - now, "login timeout"
        if self.deadline - now < wait:
            wait, reason = self.deadline - now, "session time limit"
        if wait <= 0:
            raise _End(reason)
        try:
            chunk = await asyncio.wait_for(self.reader.read(_READ_SIZE), wait)
        except TimeoutError:
            raise _End(reason) from None
        except (ConnectionError, OSError):
            raise _End("connection lost") from None
        if not chunk:
            raise _End("closed by client")
        self.bytes_in += len(chunk)
        if self.bytes_in > self.cfg.max_input_bytes:
            raise _End("input limit")
        data, items = self.parser.feed(chunk)
        if items:
            reply = self.negotiator.handle(items)
            if reply:
                await self._send(reply, record=False)
        if data:
            self.data_in += len(data)
            if len(self.first_data) < _PAYLOAD_PREVIEW:
                self.first_data += data[: _PAYLOAD_PREVIEW - len(self.first_data)]
            if self.logged_in:
                self.replay.add("i", data.decode("utf-8", "replace"))
            self.editor.push(data)
            await asyncio.sleep(0)

    async def _readline(self, echo: bool, until: float | None = None) -> str | object:
        while True:
            line, echoed = self.editor.next_line(echo)
            if echoed:
                await self._send(echoed)
            if line is not None:
                return line
            await self._fill(until)

    # ---- lifecycle ----------------------------------------------------------------------------
    async def run(self) -> None:
        self.sensor.connections_seen += 1
        if not self.sensor.admit(self.src_ip):
            self.reason = "connection limit"
            if not self._quiet():
                self.sensor.sink.note_connection(self.src_ip, rejected=True)
            await self._close()
            return
        self.admitted = True
        self.sensor.connections.add(self)
        try:
            await self._session()
        except _End as end:
            self.reason = end.reason
        except asyncio.CancelledError:
            self.reason = "sensor shutdown"
            raise
        except Exception:
            self.reason = "internal error"
            self._log_error()
        finally:
            await self._finish()

    @staticmethod
    def _log_error() -> None:
        global _last_error_log
        now = time.monotonic()
        if now - _last_error_log >= _ERROR_LOG_INTERVAL:
            _last_error_log = now
            log.exception("session handler failed")
        else:
            log.warning("session handler failed (traceback rate-limited)")

    async def _close(self) -> None:
        with contextlib.suppress(Exception):
            self.writer.close()
            await asyncio.wait_for(self.writer.wait_closed(), 2.0)

    async def _finish(self) -> None:
        try:
            if self.admitted:
                self.sensor.release(self.src_ip)
            self.sensor.connections.discard(self)
            if self.admitted:
                self._emit_disconnect()
        finally:
            await self._close()

    def _emit_disconnect(self) -> None:
        engaged = self.attempts > 0 or self.commands > 0
        if not engaged:
            if self.data_in and not self._quiet():
                self.emit(
                    EventType.scan,
                    {
                        "kind": "raw_payload",
                        "payload_preview": bytes(self.first_data).hex(),
                        "bytes": self.data_in,
                        "client_options": list(self.negotiator.seen),
                    },
                )
            elif not self._quiet():
                self.sensor.sink.note_connection(self.src_ip)
            self.sensor.sink.end_session(self.session_id)
            return
        suppressed = self.sensor.sink.end_session(self.session_id)
        self._ensure_connect()
        if suppressed:
            self.emit(
                EventType.scan, {"kind": "events_suppressed", "count": suppressed}, force=True
            )
        data: dict[str, Any] = {
            "duration_s": round(time.monotonic() - self.started, 2),
            "reason": self.reason,
            "login_attempts": self.attempts,
            "commands": self.commands,
            "downloads": self.downloads,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
        }
        if suppressed:
            data["events_suppressed"] = suppressed
        if self.replay:
            frames, truncated = self.replay.export()
            data["replay"] = frames
            if truncated:
                data["replay_truncated"] = True
        self.emit(EventType.disconnect, data, cap=False, priority=True)

    # ---- the session ----------------------------------------------------------------------------
    async def _session(self) -> None:
        await self._send(self.negotiator.initial(), record=False)
        username = await self._login()
        self.logged_in = True
        shell = DeviceShell(
            cfg=self.sensor.shell_cfg,
            base=self.sensor.base,
            profile=self.sensor.profile,
            username=username,
            client_ip=self.src_ip,
            client_port=self.src_port,
            term=self.negotiator.terminal or "vt102",
            tty=True,
            interactive=True,
            personality_name=self.sensor.personality.name,
        )
        self.shell = shell
        await self._send(to_wire(self.sensor.motd))
        await self._shell_loop(shell)

    async def _login(self) -> str:
        login_until = self.started + self.cfg.login_timeout
        empties = 0
        if self.cfg.prelogin_banner:
            await self._send(to_wire(self.cfg.prelogin_banner))
        while True:
            await self._send(to_wire(self.sensor.login_prompt))
            user_line = await self._login_line(True, login_until)
            username = user_line[:_MAX_USERNAME]
            if not username.strip():
                empties += 1
                if empties > self.cfg.max_empty_logins:
                    raise _End("too many empty logins")
                continue
            await self._send(b"Password: ")
            password = (await self._login_line(False, login_until))[:_MAX_PASSWORD]
            await self._send(b"\r\n")
            self.attempts += 1
            ok = self.sensor.credentials_ok(username, password)
            self._ensure_connect()
            self.emit(
                EventType.login_attempt,
                {"username": username, "password": password, "success": ok, "method": "telnet"},
            )
            if ok:
                return username
            delay = self.sensor.fail_delay()
            if delay:
                await asyncio.sleep(delay)
            await self._send(b"Login incorrect\r\n")
            if self.attempts >= self.cfg.max_auth_attempts:
                raise _End("too many authentication failures")

    async def _login_line(self, echo: bool, until: float) -> str:
        try:
            line = await self._readline(echo, until)
        except _End as end:
            if end.reason == "login timeout":
                with contextlib.suppress(_End):
                    # BusyBox login prints its compile-time TIMEOUT whatever the real limit is
                    await self._send(b"\r\nLogin timed out after 60 seconds.\r\n")
            raise
        if not isinstance(line, str):
            raise _End("closed by client")
        return line

    async def _shell_loop(self, shell: DeviceShell) -> None:
        while True:
            await self._send(to_wire(shell.prompt()))
            line = await self._readline(True)
            if not isinstance(line, str):
                raise _End("closed by client")
            if not line.strip():
                continue
            # Lines already buffered in the editor must not monopolise the event loop.
            await asyncio.sleep(0)
            self.commands += 1
            if self.commands > self.cfg.max_commands:
                raise _End("command limit")
            if time.monotonic() > self.deadline:
                raise _End("session time limit")
            prompt_before = shell.prompt()
            cwd, user = shell.cwd, shell.user.name
            wait = self.sensor.cpu_debt_wait()
            if wait > 0:
                await asyncio.sleep(min(wait, 10.0))
                wait = self.sensor.cpu_debt_wait()
            if wait > 0:
                text, status, delay, leave = (
                    "sh: can't fork: Resource temporarily unavailable\n",
                    1,
                    0.0,
                    False,
                )
            elif self.sensor.over_budget():
                text, status, delay, leave = (
                    "sh: can't fork: Cannot allocate memory\n",
                    12,
                    0.0,
                    False,
                )
            else:
                started = time.perf_counter()
                try:
                    result = shell.run_line(line)
                    text, status = result.output, result.status
                    delay, leave = result.delay, result.exit
                except Exception:
                    self._log_error()
                    text, status, delay, leave = "", 1, 0.0, False
                self.sensor.cpu_spend(time.perf_counter() - started)
            self.emit(
                EventType.command,
                {
                    "input": line,
                    "output": text[:8192],
                    "output_preview": text[:256],
                    "cwd": cwd,
                    "user": user,
                    "prompt": prompt_before,
                    "status": status,
                },
                max_string=8192,
            )
            for pending in shell.pending[:16]:
                self.downloads += 1
                self.emit(pending.type, {**pending.data, "cwd": cwd, "user": user})
            shell.pending.clear()
            if delay > 0:
                await asyncio.sleep(min(delay, 3.0))
            await self._send(to_wire(text))
            if leave:
                raise _End("exit")


class TelnetServer:
    def __init__(self, cfg: Config, sensor: Sensor) -> None:
        self.cfg = cfg
        self.sensor = sensor
        self._server: asyncio.Server | None = None
        self._tasks: set[asyncio.Task[None]] = set()

    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        try:
            await Connection(self.sensor, reader, writer).run()
        finally:
            if task is not None:
                self._tasks.discard(task)

    async def start(self) -> int:
        self._server = await asyncio.start_server(
            self._on_client, self.cfg.host, self.cfg.port, limit=4096, backlog=128
        )
        return int(self._server.sockets[0].getsockname()[1])

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
