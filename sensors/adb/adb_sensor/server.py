"""The ADB server: connection limits, the CNXN handshake, streams and event emission.

The wire format lives in ``wire.py``, the push/pull protocol in ``sync.py`` and the shell in
``androidshell.py``. This module ties them to sockets and to the event sink.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ipaddress
import logging
import socket
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ssh_sensor.config import Config as ShellConfig
from ssh_sensor.cpu import FairBudget
from ssh_sensor.shell.fs import BaseImage, FakeFS
from suckerpot_common import EventType, truncate_data

from adb_sensor.androidshell import AndroidShell
from adb_sensor.config import Config
from adb_sensor.device import Device, build_base_image, derive_device
from adb_sensor.events import EventSink, TokenBuckets
from adb_sensor.replay import ReplayRecorder
from adb_sensor.sync import MAX_BUFFER, MAX_REPLY, HashBudget, SyncSession, flush_partial
from adb_sensor.wire import (
    A_AUTH,
    A_CLSE,
    A_CNXN,
    A_OKAY,
    A_OPEN,
    A_WRTE,
    COMMAND_NAMES,
    HEADER_SIZE,
    PRE_CNXN_MAX_PAYLOAD,
    V2_CLOSE_STDIN,
    V2_EXIT,
    V2_STDERR,
    V2_STDIN,
    V2_STDOUT,
    VERSION_SKIP_CHECKSUM,
    V2Parser,
    WireError,
    checksum,
    clean_text,
    pack,
    parse_cnxn_banner,
    parse_header,
    v2_pack,
)

log = logging.getLogger("adb_sensor.server")

_MAX_SERVICE = 1024
_PAYLOAD_PREVIEW = 256
_CONNECTION_OVERHEAD = 24 * 1024  # rough per-connection cost counted against the budget
_STREAM_OVERHEAD = 8 * 1024
_MAX_UNACKED = 512
_ERROR_LOG_INTERVAL = 60.0
_URL_SCHEMES = ("http://", "https://", "ftp://", "tftp://")
_MEM_REFUSE = 0.70
_MEM_ABORT = 0.85
CGROUP_DIR = "/sys/fs/cgroup"
_last_error_log = 0.0


def normalize_ip(raw: str) -> str:
    try:
        addr = ipaddress.ip_address(raw.split("%")[0])
    except ValueError:
        return "0.0.0.0"  # noqa: S104 - placeholder for an unparsable peer address
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return str(addr.ipv4_mapped)
    return str(addr)


def cgroup_fraction(base: str = CGROUP_DIR) -> float | None:
    """Memory in use as a fraction of the cgroup limit, or None when there is no limit."""
    try:
        current = int(Path(base, "memory.current").read_text().strip())
        limit_text = Path(base, "memory.max").read_text().strip()
        if limit_text == "max":
            return None
        return current / max(1, int(limit_text))
    except (OSError, ValueError):
        return None


class _End(Exception):
    """The session is over; ``reason`` goes into the disconnect event."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def extract_urls(line: str, limit: int = 8) -> list[str]:
    """URLs in a command line, found with plain string methods (no regular expressions)."""
    table = {ord(c): " " for c in "'\"`;|&()<>{}\\"}
    urls: list[str] = []
    for token in line[:4096].translate(table).split():
        if token.lower().startswith(_URL_SCHEMES) and token not in urls:
            urls.append(token[:2048])
            if len(urls) >= limit:
                break
    return urls


def install_size(command: str) -> int | None:
    """The ``-S <size>`` of ``cmd package install -S 12345`` (an APK streamed on stdin)."""
    words = [w.strip("'\"") for w in command.split()[:16]]
    if len(words) < 4 or words[0] not in ("cmd", "pm") or "install" not in words[:3]:
        return None
    if "-S" in words:
        index = words.index("-S")
        if index + 1 < len(words) and words[index + 1].isascii() and words[index + 1].isdigit():
            return min(int(words[index + 1][:12]), 1 << 40)
    return None


class LineEditor:
    """Turns the bytes typed by the client into lines, with a minimal tty-like editing."""

    EOF = object()

    def __init__(self, max_line: int = 4096) -> None:
        self._max = max_line
        self._buf = bytearray()
        self._pending = bytearray()
        self._pos = 0
        self._after_cr = False
        self._esc = 0

    def push(self, data: bytes) -> None:
        self._pending += data

    @property
    def size(self) -> int:
        return len(self._buf) + len(self._pending) - self._pos

    def next_line(self, echo: bool) -> tuple[str | object | None, bytes]:
        out = bytearray()
        pending = self._pending
        i = self._pos
        n = len(pending)
        result: str | object | None = None
        while i < n:
            byte = pending[i]
            i += 1
            if self._esc:
                if self._esc == 1:
                    self._esc = 2 if byte in (0x5B, 0x4F) else 0
                else:
                    self._esc = 0 if 0x40 <= byte <= 0x7E or self._esc > 16 else self._esc + 1
                continue
            if self._after_cr:
                self._after_cr = False
                if byte == 0x0A:
                    continue
            if byte in (0x0D, 0x0A):
                self._after_cr = byte == 0x0D
                result = self._buf.decode("utf-8", "replace")
                self._buf = bytearray()
                if echo:
                    out += b"\r\n"
                break
            if byte == 0x03:
                self._buf = bytearray()
                if echo:
                    out += b"^C\r\n"
                result = ""
                break
            if byte == 0x04:
                if not self._buf:
                    result = self.EOF
                    break
                continue
            if byte in (0x7F, 0x08):
                if self._buf:
                    self._buf.pop()
                    if echo:
                        out += b"\x08 \x08"
                continue
            if byte == 0x1B:
                self._esc = 1
                continue
            if byte < 0x20 and byte != 0x09:
                continue
            if len(self._buf) < self._max:
                self._buf.append(byte)
                if echo:
                    out.append(byte)
        # an index instead of deleting from the front per line: O(n) overall, not O(n^2)
        if i >= n:
            pending.clear()
            i = 0
        elif i > 65536:
            del pending[:i]
            i = 0
        self._pos = i
        return result, bytes(out)


class Stream:
    """One logical stream (a shell, a sync session, an APK being streamed)."""

    def __init__(self, local_id: int, remote_id: int, service: str) -> None:
        self.local_id = local_id
        self.remote_id = remote_id
        self.service = service
        self.kind = "shell"  # shell | sync | sink
        self.v2 = False
        self.pty = False
        self.echo = False
        self.crlf = False
        self.prompt = False
        self.unacked = 0
        self.shell: AndroidShell | None = None
        self.editor = LineEditor()
        self.v2_parser = V2Parser()
        self.sync: SyncSession | None = None
        self.pushes_seen = 0
        self.pulls_seen = 0
        self.sink_digest: Any = None
        self.sink_size = 0
        self.sink_expected: int | None = None
        self.sink_truncated = False

    def memory(self) -> int:
        total = _STREAM_OVERHEAD + self.editor.size + self.v2_parser.buffered
        if self.sync is not None:
            total += self.sync.buffered
        return total


class Sensor:
    """Process-wide state shared by all connections."""

    def __init__(self, cfg: Config, sink: EventSink, seed: str) -> None:
        self.cfg = cfg
        self.sink = sink
        self.device: Device = derive_device(seed, cfg.hostname, cfg.busybox, cfg.root_shell)
        self.base: BaseImage = build_base_image(self.device)
        self.version = self.device.model.version
        nul = b"\0" if self.device.model.banner_nul else b""
        self.banner = f"device::{self.device.banner_props}".encode() + nul
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
        self._new_conn = TokenBuckets(cfg.conn_rate_per_ip, cfg.conn_burst_per_ip)
        self.cpu = FairBudget(cfg.shell_cpu_share, cfg.shell_cpu_burst)
        self._cg_at = 0.0
        self._cg: float | None = None
        self.cgroup_dir = CGROUP_DIR
        self.aborted_for_memory = 0

    def cgroup_pressure(self) -> float | None:
        now = time.monotonic()
        if now - self._cg_at >= 1.0:
            self._cg_at = now
            self._cg = cgroup_fraction(self.cgroup_dir)
        return self._cg

    def admit(self, ip: str) -> bool:
        if self.total >= self.cfg.max_connections or self.per_ip.get(ip, 0) >= self.cfg.max_per_ip:
            self.rejected += 1
            return False
        if not self._new_conn.allow(ip):
            self.rejected += 1
            self.rate_rejected += 1
            return False
        self._cg_at = 0.0  # sample the guard on every admission
        pressure = self.cgroup_pressure()
        if self.over_budget() or (pressure is not None and pressure > _MEM_REFUSE):
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

    def memory_in_use(self) -> int:
        return sum(conn.memory_bytes() for conn in self.connections)

    def over_budget(self) -> bool:
        return self.memory_in_use() > self.cfg.memory_budget

    def enforce_memory(self) -> bool:
        """Abort the heaviest connection when the cgroup is nearly full. Returns True if done."""
        self._cg_at = 0.0
        pressure = self.cgroup_pressure()
        if (pressure is None or pressure <= _MEM_ABORT) and not self.over_budget():
            return False
        if not self.connections:
            return False
        heaviest = max(self.connections, key=lambda c: c.memory_bytes())
        heaviest.abort("memory pressure")
        self.aborted_for_memory += 1
        return True

    async def guard_loop(self) -> None:
        while True:
            await asyncio.sleep(2.0)
            self.enforce_memory()

    def stats(self) -> dict[str, int]:
        return {
            "memory_bytes": self.memory_in_use(),
            "connections": self.total,
            "seen": self.connections_seen,
            "rejected": self.rejected,
            "rate_rejected": self.rate_rejected,
            "memory_rejected": self.memory_rejected,
            "aborted_for_memory": self.aborted_for_memory,
            **self.cpu.stats(),
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
        self.deadline = self.started + self.cfg.max_session
        self.admitted = False
        self.connected = False  # CNXN received
        self.client_version = 0
        self.client_maxdata = 4096
        self.client_banner: dict[str, str] = {}
        self.streams: dict[int, Stream] = {}
        self.next_local = 1
        self.opened = 0
        self.fs: FakeFS | None = None
        self.budget = HashBudget(self.cfg.max_hash_bytes)
        self.replay = ReplayRecorder()
        self.reason = "closed by client"
        self.connect_emitted = False
        self.commands = 0
        self.downloads = 0
        self.pushes = 0
        self.installs = 0
        self.bytes_in = 0
        self.bytes_out = 0
        self.pending_payload = 0
        self.first_data = bytearray()
        self.aborted = False

    # ---- bookkeeping -------------------------------------------------------------------------
    def memory_bytes(self) -> int:
        total = _CONNECTION_OVERHEAD + self.replay.size + self.pending_payload
        transport = self.writer.transport
        if transport is not None:
            total += transport.get_write_buffer_size()  # output the peer has not read yet
        if self.fs is not None:
            total += self.fs.used_bytes
        for stream in self.streams.values():
            total += stream.memory()
            if stream.shell is not None:
                total += stream.shell.private_bytes() + 32 * 1024
        return total

    def abort(self, reason: str) -> None:
        self.reason = reason
        self.aborted = True
        transport = self.writer.transport
        if transport is not None:
            transport.abort()

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
        self.emit(
            EventType.connect,
            {
                "banner": self.sensor.banner.rstrip(b"\0").decode(),
                "client_version": f"0x{self.client_version:08x}",
                "client_maxdata": self.client_maxdata,
                "client_banner": self.client_banner,
            },
            ts=self.started_ts,
        )

    # ---- I/O ---------------------------------------------------------------------------------
    async def _send(self, data: bytes) -> None:
        if not data:
            return
        self.bytes_out += len(data)
        if self.bytes_out > self.cfg.max_session_output:
            raise _End("output limit")
        try:
            self.writer.write(data)
            await asyncio.wait_for(self.writer.drain(), self.cfg.write_timeout)
        except TimeoutError:
            raise _End("write timeout") from None
        except (ConnectionError, OSError):
            raise _End("connection lost") from None

    async def _read_message(self) -> tuple[int, int, int, bytes]:
        now = time.monotonic()
        wait, reason = self.cfg.idle_timeout, "idle timeout"
        if not self.connected and self.cfg.handshake_timeout < wait:
            wait, reason = self.cfg.handshake_timeout, "handshake timeout"
        if self.deadline - now < wait:
            wait, reason = self.deadline - now, "session time limit"
        if wait <= 0:
            raise _End(reason)
        try:
            first = await asyncio.wait_for(self.reader.readexactly(1), wait)
        except TimeoutError:
            raise _End(reason) from None
        except asyncio.IncompleteReadError:
            raise _End("closed by client") from None
        except (ConnectionError, OSError):
            raise _End("connection lost") from None
        try:
            rest = await asyncio.wait_for(
                self.reader.readexactly(HEADER_SIZE - 1), self.cfg.message_timeout
            )
        except TimeoutError:
            self._note_raw(first)
            raise _End("message timeout") from None
        except asyncio.IncompleteReadError as exc:
            self._note_raw(first + exc.partial)
            raise _End("closed by client") from None
        except (ConnectionError, OSError):
            raise _End("connection lost") from None
        raw = first + rest
        self._note_raw(raw)
        self.bytes_in += HEADER_SIZE
        try:
            command, arg0, arg1, length, data_check = parse_header(raw)
        except WireError as exc:
            raise _End(exc.reason) from None
        cap = self.cfg.maxdata if self.connected else PRE_CNXN_MAX_PAYLOAD
        if length > cap:
            raise _End("oversized message")
        payload = b""
        if length:
            self.pending_payload = length
            try:
                payload = await asyncio.wait_for(
                    self.reader.readexactly(length), self.cfg.message_timeout
                )
            except TimeoutError:
                raise _End("message timeout") from None
            except asyncio.IncompleteReadError:
                raise _End("closed by client") from None
            except (ConnectionError, OSError):
                raise _End("connection lost") from None
            finally:
                self.pending_payload = 0
            self.bytes_in += length
            self._note_raw(payload[:_PAYLOAD_PREVIEW])
        if self.bytes_in > self.cfg.max_input_bytes:
            raise _End("input limit")
        legacy_crc = self.connected and self._negotiated() < VERSION_SKIP_CHECKSUM
        if legacy_crc and command != A_CNXN and checksum(payload) != data_check:
            raise _End("bad checksum")
        await asyncio.sleep(0)
        return command, arg0, arg1, payload

    def _negotiated(self) -> int:
        return min(self.client_version, self.sensor.version)

    def _pack(self, command: int, arg0: int, arg1: int, data: bytes = b"") -> bytes:
        """Frame a message; adbd writes a zero data_check once both sides speak >= 0x01000001."""
        return pack(command, arg0, arg1, data, crc=self._negotiated() < VERSION_SKIP_CHECKSUM)

    def _note_raw(self, data: bytes) -> None:
        room = _PAYLOAD_PREVIEW - len(self.first_data)
        if room > 0:
            self.first_data += data[:room]

    # ---- lifecycle ---------------------------------------------------------------------------
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
            if not self.aborted:
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
        transport = self.writer.transport
        try:
            self.writer.close()
            await asyncio.wait_for(self.writer.wait_closed(), 2.0)
        except Exception:
            if transport is not None:
                transport.abort()

    async def _finish(self) -> None:
        try:
            self._flush_streams()
            await self._close()
        finally:
            if self.admitted:
                self.sensor.release(self.src_ip)
            self.sensor.connections.discard(self)
            if self.admitted:
                self._emit_disconnect()

    def _flush_streams(self) -> None:
        for stream in list(self.streams.values()):
            self._drop_stream(stream, partial=True)

    def _emit_disconnect(self) -> None:
        engaged = self.connected
        if not engaged:
            if self.first_data and not self._quiet():
                self.emit(
                    EventType.scan,
                    {
                        "kind": "raw_payload",
                        "payload_preview": bytes(self.first_data).hex(),
                        "bytes": self.bytes_in,
                        "reason": self.reason,
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
            "commands": self.commands,
            "downloads": self.downloads,
            "pushes": self.pushes,
            "installs": self.installs,
            "streams_opened": self.opened,
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

    # ---- messages ----------------------------------------------------------------------------
    async def _session(self) -> None:
        while True:
            command, arg0, arg1, payload = await self._read_message()
            if not self.connected and command != A_CNXN:
                raise _End("no CNXN")
            if command == A_CNXN:
                await self._on_cnxn(arg0, arg1, payload)
            elif command == A_OPEN:
                await self._on_open(arg0, payload)
            elif command == A_WRTE:
                await self._on_wrte(arg0, arg1, payload)
            elif command == A_OKAY:
                stream = self.streams.get(arg1)
                if stream is not None and stream.remote_id == arg0:
                    stream.unacked = max(0, stream.unacked - 1)
            elif command == A_CLSE:
                await self._on_clse(arg0, arg1)
            elif command == A_AUTH:
                # We never ask for authentication; a client that sends AUTH anyway gets the
                # connection banner, which is what a device with auth disabled does.
                self._ensure_connect()
                self.emit(
                    EventType.scan,
                    {
                        "kind": "adb_auth",
                        "auth_type": arg0,
                        "payload_preview": payload[:200].decode("latin-1"),
                    },
                )
                await self._send(
                    pack(A_CNXN, self.sensor.version, self.cfg.maxdata, self.sensor.banner)
                )
            else:
                self._ensure_connect()
                self.emit(
                    EventType.scan,
                    {"kind": "adb_unsupported", "command": COMMAND_NAMES.get(command, "?")},
                )

    async def _on_cnxn(self, version: int, maxdata: int, payload: bytes) -> None:
        self.client_version = version
        self.client_maxdata = max(256, min(maxdata, 1024 * 1024))
        self.client_banner = parse_cnxn_banner(payload)
        if self.connected:  # a second CNXN resets the connection state
            self._flush_streams()
        self.connected = True
        self._ensure_connect()
        await self._send(pack(A_CNXN, self.sensor.version, self.cfg.maxdata, self.sensor.banner))

    async def _on_clse(self, remote: int, local: int) -> None:
        stream = self.streams.get(local)
        if stream is None or stream.remote_id != remote:
            return
        await self._finish_input(stream)
        if local in self.streams:
            self._drop_stream(stream)
            await self._send(self._pack(A_CLSE, local, remote))

    async def _close_stream(self, stream: Stream) -> None:
        if stream.local_id in self.streams:
            self._drop_stream(stream)
            await self._send(self._pack(A_CLSE, stream.local_id, stream.remote_id))

    def _drop_stream(self, stream: Stream, *, partial: bool = False) -> None:
        if stream.sync is not None:
            flush_partial(stream.sync)
            self._emit_sync_records(stream)
        if stream.kind == "sink" and partial:
            self._emit_install(stream)
        self.streams.pop(stream.local_id, None)

    # ---- opening services ----------------------------------------------------------------------
    async def _on_open(self, remote: int, payload: bytes) -> None:
        service = clean_text(payload, _MAX_SERVICE)
        if (
            remote == 0
            or len(self.streams) >= self.cfg.max_streams
            or self.opened >= self.cfg.max_streams_total
        ):
            await self._send(self._pack(A_CLSE, 0, remote))
            return
        head, _, rest = service.partition(":")
        name, _, option_text = head.partition(",")
        stream = Stream(self.next_local, remote, service)
        self.next_local += 1
        self.opened += 1
        if name in ("shell", "exec"):
            options = option_text.split(",") if option_text else []
            stream.v2 = name == "shell" and "v2" in options
            stream.pty = name == "shell" and ("pty" in options or not stream.v2)
            stream.crlf = stream.pty
            await self._open_shell(stream, rest, name)
        elif name == "sync" and not option_text:
            fs = self._ensure_fs()
            owner = "root" if self.sensor.device.root else "shell"
            stream.kind = "sync"
            stream.sync = SyncSession(
                fs, owner, self.budget, self.cfg.max_stub_bytes, int(time.time())
            )
            self.streams[stream.local_id] = stream
            await self._send(self._pack(A_OKAY, stream.local_id, remote))
        elif name == "reboot":
            await self._send(self._pack(A_OKAY, stream.local_id, remote))
            self._record_service(service, ["adb_reboot"])
            await self._send(self._pack(A_CLSE, stream.local_id, remote))
            raise _End("reboot")
        elif name in ("root", "unroot", "remount", "tcpip", "usb"):
            await self._static_service(stream, name, rest)
        else:
            self._ensure_connect()
            self.emit(EventType.scan, {"kind": "adb_service", "service": service[:512]})
            await self._send(self._pack(A_CLSE, 0, remote))

    def _record_service(self, service: str, flags: list[str]) -> None:
        self._ensure_connect()
        self.commands += 1
        self.emit(
            EventType.command,
            {"input": service[:1024], "output": "", "flags": flags, "service": service[:64]},
        )

    async def _static_service(self, stream: Stream, name: str, rest: str) -> None:
        root = self.sensor.device.root
        text = {
            "root": "adbd is already running as root\n" if root else "restarting adbd as root\n",
            "unroot": "adbd not running as root\n" if not root else "restarting adbd as non root\n",
            "remount": "remount succeeded\n" if root else "remount failed: Permission denied\n",
            "tcpip": f"restarting in TCP mode port: {rest[:5]}\n",
            "usb": "restarting in USB mode\n",
        }[name]
        self.streams[stream.local_id] = stream
        await self._send(self._pack(A_OKAY, stream.local_id, stream.remote_id))
        await self._write_stream(stream, text.encode())
        self._record_service(stream.service, ["adb_service"])
        await self._close_stream(stream)

    def _ensure_fs(self) -> FakeFS:
        if self.fs is None:
            self.fs = FakeFS(
                self.sensor.base,
                max_bytes=self.cfg.max_fs_bytes,
                max_nodes=self.cfg.max_fs_nodes,
                now=int(time.time()),
            )
        return self.fs

    def _new_shell(self, stream: Stream, *, interactive: bool) -> AndroidShell:
        dev = self.sensor.device
        shell = AndroidShell(
            cfg=self.sensor.shell_cfg,
            base=self.sensor.base,
            profile=dev.profile,
            username="root" if dev.root else "shell",
            client_ip=self.src_ip,
            client_port=self.src_port,
            term="xterm-256color",
            shared_fs=self._ensure_fs(),
            tty=stream.pty,
            interactive=interactive,
            device=dev,
        )
        self.fs = shell.fs
        return shell

    async def _open_shell(self, stream: Stream, command: str, service_name: str) -> None:
        self._ensure_connect()
        self.streams[stream.local_id] = stream
        await self._send(self._pack(A_OKAY, stream.local_id, stream.remote_id))
        command = command[: self.cfg.max_line]
        size = install_size(command)
        if command.strip() and size is not None:
            stream.kind = "sink"
            stream.service = command
            stream.sink_expected = size
            stream.sink_digest = hashlib.sha256()
            return
        stream.shell = self._new_shell(stream, interactive=not command.strip())
        if command.strip():
            await self._run_one_shot(stream, command)
            return
        stream.echo = stream.pty
        stream.prompt = stream.pty
        if stream.prompt:
            await self._write_text(stream, stream.shell.prompt())

    async def _run_one_shot(self, stream: Stream, command: str) -> None:
        shell = stream.shell
        if shell is None:
            return
        prompt = shell.prompt()
        self.replay.add("o", prompt)
        self.replay.add("i", command + "\r\n")
        chunks, status, delay, _leave = await self._execute(stream, command, prompt)
        await self._deliver(stream, chunks, delay)
        if stream.v2:
            await self._write_stream(stream, v2_pack(V2_EXIT, bytes((status & 0xFF,))), raw=True)
        await self._close_stream(stream)
        if shell.rebooted:
            raise _End("reboot")

    # ---- running commands ----------------------------------------------------------------------
    async def _execute(
        self, stream: Stream, line: str, prompt: str
    ) -> tuple[list[tuple[bool, str]], int, float, bool]:
        shell = stream.shell
        if shell is None:
            return [], 1, 0.0, True
        self.commands += 1
        if self.commands > self.cfg.max_commands:
            raise _End("command limit")
        if time.monotonic() > self.deadline:
            raise _End("session time limit")
        cwd, user = shell.cwd, shell.user.name
        chunks: list[tuple[bool, str]]
        may_run = await self.sensor.cpu.acquire(self.src_ip, 10.0)
        if not may_run:
            chunks, status, delay, leave = (
                [(True, "/system/bin/sh: can't fork: Out of memory\n")],
                1,
                0.0,
                False,
            )
        elif self.sensor.over_budget():
            chunks, status, delay, leave = (
                [(True, "/system/bin/sh: can't fork: Out of memory\n")],
                12,
                0.0,
                False,
            )
        else:
            started = time.perf_counter()
            try:
                result = shell.run_line(line)
                chunks, status = result.chunks, result.status
                delay, leave = result.delay, result.exit
            except Exception:
                self._log_error()
                chunks, status, delay, leave = [], 1, 0.0, False
            self.sensor.cpu.spend(self.src_ip, time.perf_counter() - started)
        await asyncio.sleep(0)  # never run two lines back to back without yielding
        text = "".join(t for _, t in chunks)
        flags = ["adb_shell", *sorted(shell.flags)]
        shell.flags.clear()
        service = stream.service.partition(":")[0][:32]
        self.emit(
            EventType.command,
            {
                "input": line,
                "output": text[:8192],
                "output_preview": text[:256],
                "cwd": cwd,
                "user": user,
                "prompt": prompt,
                "status": status,
                "flags": flags,
                "service": service,
                "interactive": stream.prompt,
            },
            max_string=8192,
        )
        seen: set[str] = set()
        for pending in shell.pending[:16]:
            self.downloads += 1
            url = str(pending.data.get("url", ""))
            seen.add(url)
            self.emit(
                pending.type,
                {**pending.data, "cwd": cwd, "user": user, "flags": ["adb_shell"]},
            )
        shell.pending.clear()
        for url in extract_urls(line):
            if url not in seen:
                self.downloads += 1
                self.emit(
                    EventType.download_attempt,
                    {"url": url, "tool": "command-line", "command": line[:2048], "cwd": cwd,
                     "user": user, "flags": ["adb_shell"]},
                )  # fmt: skip
        if shell.rebooted:
            self.reason = "reboot"
        return chunks, status, delay, leave

    async def _deliver(self, stream: Stream, chunks: list[tuple[bool, str]], delay: float) -> None:
        if delay > 0:
            await asyncio.sleep(min(delay, 3.0))
        text = "".join(t for _, t in chunks)
        self.replay.add("o", text.replace("\n", "\r\n"))
        if stream.v2:
            for is_err, part in chunks:
                await self._write_stream(
                    stream, b"", text=part, frame_id=V2_STDERR if is_err else V2_STDOUT
                )
        else:
            await self._write_text(stream, text, record=False)

    # ---- stream I/O -----------------------------------------------------------------------------
    def _chunk_size(self) -> int:
        return max(256, min(self.client_maxdata, self.cfg.maxdata, 16 * 1024))

    async def _write_text(self, stream: Stream, text: str, *, record: bool = True) -> None:
        """Terminal text to the client, framed for the stream's protocol."""
        if not text:
            return
        if record:
            self.replay.add("o", text.replace("\n", "\r\n") if "\n" in text else text)
        if stream.v2:
            await self._write_stream(stream, b"", text=text)
        else:
            await self._write_stream(stream, text.encode("utf-8", "replace"))

    async def _write_stream(
        self,
        stream: Stream,
        data: bytes,
        *,
        raw: bool = False,
        text: str | None = None,
        frame_id: int = V2_STDOUT,
    ) -> None:
        """Send bytes on a stream as WRTE messages of bounded size.

        ``raw`` data is already framed. For shell v2, ``text`` (stdout; the frame id is taken
        from the header ``data`` carries) is framed here. ``\\n`` becomes ``\\r\\n`` when the
        stream has a pty."""
        limit = self._chunk_size()
        if text is not None:
            body = text.replace("\n", "\r\n") if stream.crlf and "\r\n" not in text else text
            payload = body.encode("utf-8", "replace")
            step = limit - 5
            parts = [v2_pack(frame_id, payload[i : i + step]) for i in range(0, len(payload), step)]
        elif raw:
            parts = [data[i : i + limit] for i in range(0, len(data), limit)]
        else:
            if stream.crlf and b"\n" in data and b"\r\n" not in data:
                data = data.replace(b"\n", b"\r\n")
            parts = [data[i : i + limit] for i in range(0, len(data), limit)]
        for part in parts:
            if stream.unacked >= _MAX_UNACKED:
                return  # the peer never acknowledges: stop feeding it
            stream.unacked += 1
            await self._send(self._pack(A_WRTE, stream.local_id, stream.remote_id, part))

    async def _on_wrte(self, remote: int, local: int, payload: bytes) -> None:
        stream = self.streams.get(local)
        if stream is None or stream.remote_id != remote:
            return
        await self._send(self._pack(A_OKAY, local, remote))
        if stream.kind == "sync":
            await self._on_sync(stream, payload)
        elif stream.kind == "sink":
            await self._on_sink(stream, payload)
        else:
            await self._on_shell_input(stream, payload)

    # ---- sync ----------------------------------------------------------------------------------
    async def _on_sync(self, stream: Stream, payload: bytes) -> None:
        """Sync requests are handled ONE at a time: each step is charged to the shared CPU
        scheduler, its reply is size-bounded and drained before the next request is parsed, and
        the loop yields in between, so a WRTE full of LIST requests cannot block the event loop."""
        session = stream.sync
        if session is None:
            return
        session.append(payload, self.cfg.maxdata + MAX_BUFFER)
        while stream.local_id in self.streams:
            if self.bytes_out + MAX_REPLY + 4096 > self.cfg.max_session_output:
                raise _End("output limit")
            if stream.unacked >= _MAX_UNACKED:
                break  # the peer never acknowledges: stop answering
            if not await self.sensor.cpu.acquire(self.src_ip, 10.0):
                raise _End("cpu budget")
            started = time.perf_counter()
            replies = session.step()
            self.sensor.cpu.spend(self.src_ip, time.perf_counter() - started)
            self._emit_sync_records(stream)
            if replies is None:
                break
            for reply in replies:
                limit = self._chunk_size()
                for i in range(0, min(len(reply), MAX_REPLY), limit):
                    stream.unacked += 1
                    await self._send(
                        self._pack(A_WRTE, stream.local_id, stream.remote_id, reply[i : i + limit])
                    )
            await asyncio.sleep(0)
        if session.closed or stream.unacked >= _MAX_UNACKED:
            await self._close_stream(stream)

    def _emit_sync_records(self, stream: Stream) -> None:
        session = stream.sync
        if session is None:
            return
        for push in session.pushes[stream.pushes_seen :]:
            stream.pushes_seen += 1
            self.pushes += 1
            self.commands += 1
            self.emit(
                EventType.command,
                {
                    "input": f"adb push {push.path[:512]}",
                    "output": "",
                    "flags": ["adb_push"],
                    "path": push.path[:512],
                    "sha256": push.sha256,
                    "size": push.size,
                    "mode": f"{push.mode:o}",
                    "truncated": push.truncated,
                    "stored": push.stored,
                    "service": "sync",
                },
            )
        for pull in session.pulls[stream.pulls_seen :]:
            stream.pulls_seen += 1
            self.commands += 1
            self.emit(
                EventType.command,
                {
                    "input": f"adb pull {pull.path[:512]}",
                    "output": "",
                    "flags": ["adb_pull"],
                    "path": pull.path[:512],
                    "found": pull.found,
                    "service": "sync",
                },
            )

    # ---- streamed APK (adb install without the abb feature) -----------------------------
    async def _on_sink(self, stream: Stream, payload: bytes) -> None:
        if stream.v2:
            try:
                packets = stream.v2_parser.feed(payload)
            except WireError as exc:
                raise _End(exc.reason) from None
            data = b"".join(body for pid, body in packets if pid == V2_STDIN)
        else:
            data = payload
        stream.sink_size += len(data)
        take = self.budget.take(len(data))
        if take:
            stream.sink_digest.update(data[:take])
        if take < len(data):
            stream.sink_truncated = True
        if stream.sink_expected is not None and stream.sink_size >= stream.sink_expected:
            await self._finish_input(stream)
            await self._write_text(stream, "Success\n", record=False)
            if stream.v2:
                await self._write_stream(stream, v2_pack(V2_EXIT, b"\0"), raw=True)
            await self._close_stream(stream)

    def _emit_install(self, stream: Stream) -> None:
        if stream.sink_digest is None:
            return
        digest, stream.sink_digest = stream.sink_digest, None
        self.installs += 1
        self.commands += 1
        self.emit(
            EventType.command,
            {
                "input": stream.service[:1024],
                "output": "Success\n",
                "flags": ["adb_install"],
                "sha256": digest.hexdigest(),
                "size": stream.sink_size,
                "expected_size": stream.sink_expected,
                "truncated": stream.sink_truncated,
                "service": "install",
            },
        )

    async def _finish_input(self, stream: Stream) -> None:
        if stream.kind == "sink":
            self._emit_install(stream)

    # ---- interactive shell ---------------------------------------------------------------
    async def _on_shell_input(self, stream: Stream, payload: bytes) -> None:
        shell = stream.shell
        if shell is None:
            return
        if stream.v2:
            data = bytearray()
            try:
                packets = stream.v2_parser.feed(payload)
            except WireError as exc:
                raise _End(exc.reason) from None
            for packet_id, body in packets:
                if packet_id == V2_STDIN:
                    data += body
                elif packet_id == V2_CLOSE_STDIN:
                    data += b"\x04"
        else:
            data = bytearray(payload)
        if stream.echo:
            self.replay.add("i", bytes(data).decode("utf-8", "replace"))
        stream.editor.push(bytes(data))
        slice_start = time.perf_counter()
        while stream.local_id in self.streams:
            # Every line, even an empty one, costs scheduler time, and the loop yields after
            # ~10 ms of work, so a WRTE full of newlines cannot hold the event loop.
            now = time.perf_counter()
            if now - slice_start > 0.01:
                self.sensor.cpu.spend(self.src_ip, now - slice_start)
                await asyncio.sleep(0)
                if not await self.sensor.cpu.acquire(self.src_ip, 10.0):
                    raise _End("cpu budget")
                slice_start = time.perf_counter()
            line, echoed = stream.editor.next_line(stream.echo)
            if echoed:
                await self._write_text(stream, echoed.decode("latin-1"))
            if line is None:
                return
            if line is LineEditor.EOF or not isinstance(line, str):
                if stream.v2:
                    await self._write_stream(stream, v2_pack(V2_EXIT, b"\0"), raw=True)
                await self._close_stream(stream)
                return
            if not line.strip():
                if stream.prompt:
                    await self._write_text(stream, shell.prompt())
                continue
            prompt_before = shell.prompt()
            if not stream.echo:
                self.replay.add("o", prompt_before)
                self.replay.add("i", line + "\r\n")
            chunks, status, delay, leave = await self._execute(stream, line, prompt_before)
            await self._deliver(stream, chunks, delay)
            if leave or shell.rebooted:
                if stream.v2:
                    await self._write_stream(
                        stream, v2_pack(V2_EXIT, bytes((status & 0xFF,))), raw=True
                    )
                await self._close_stream(stream)
                if shell.rebooted:
                    raise _End("reboot")
                return
            if stream.prompt:
                await self._write_text(stream, shell.prompt())


class AdbServer:
    def __init__(self, cfg: Config, sensor: Sensor) -> None:
        self.cfg = cfg
        self.sensor = sensor
        self._server: asyncio.Server | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._guard: asyncio.Task[None] | None = None

    @staticmethod
    def _tune(writer: asyncio.StreamWriter) -> None:
        sock = writer.get_extra_info("socket")
        if sock is not None:
            with contextlib.suppress(OSError):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 64 * 1024)
                opt = getattr(socket, "TCP_USER_TIMEOUT", 18)
                sock.setsockopt(socket.IPPROTO_TCP, opt, 30_000)
        transport = writer.transport
        if transport is not None:
            transport.set_write_buffer_limits(high=64 * 1024, low=16 * 1024)

    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        self._tune(writer)
        try:
            await Connection(self.sensor, reader, writer).run()
        finally:
            if task is not None:
                self._tasks.discard(task)

    async def start(self) -> int:
        self._server = await asyncio.start_server(
            self._on_client, self.cfg.host, self.cfg.port, limit=64 * 1024, backlog=128
        )
        self._guard = asyncio.create_task(self.sensor.guard_loop())
        return int(self._server.sockets[0].getsockname()[1])

    async def stop(self) -> None:
        if self._guard is not None:
            self._guard.cancel()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
