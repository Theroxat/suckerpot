"""The ADB ``sync:`` sub-protocol (file push, pull, list, stat), against the in-memory fake fs.

A push never touches the disk: the pushed bytes are hashed (sha256) while they stream through,
counted, and only the first few KB are kept in the per-connection fake filesystem so that a
following ``ls`` or ``sh file`` behaves plausibly. Everything is bounded: the request buffer, the
path length, the size of one data frame, the bytes hashed per connection.
"""

from __future__ import annotations

import hashlib
import posixpath
import struct
from dataclasses import dataclass, field

from ssh_sensor.shell.fs import FakeFS, FSError, Node

from adb_sensor.commands import node_size
from adb_sensor.wire import SYNC_MAX_DATA, SYNC_MAX_PATH

S_IFDIR = 0o040000
S_IFREG = 0o100000
S_IFLNK = 0o120000
STA2 = struct.Struct("<4sIQQIIIIQqqq")
DNT2 = struct.Struct("<4sIQQIIIIQqqqI")
STAT1 = struct.Struct("<4sIII")
DENT1 = struct.Struct("<4sIIII")
FRAME = struct.Struct("<4sI")
ENOENT = 2
MAX_LIST = 256
MAX_PULL = 64 * 1024
MAX_REPLY = 64 * 1024
MAX_PULLS = 64
MAX_BUFFER = 8 + SYNC_MAX_PATH + 16 + SYNC_MAX_DATA + 8


@dataclass(slots=True)
class PushRecord:
    path: str
    mode: int
    size: int
    sha256: str
    truncated: bool
    stored: bool


@dataclass(slots=True)
class PullRecord:
    path: str
    found: bool


class HashBudget:
    """Bytes that may still be hashed on one connection (shared by all its streams)."""

    def __init__(self, limit: int) -> None:
        self.left = limit

    def take(self, wanted: int) -> int:
        got = min(wanted, self.left)
        self.left -= got
        return got


def mode_bits(node: Node) -> int:
    kind = {"d": S_IFDIR, "l": S_IFLNK}.get(node.kind, S_IFREG)
    return kind | (node.mode & 0o7777)


@dataclass
class SyncSession:
    fs: FakeFS
    owner: str
    budget: HashBudget
    stub_cap: int
    now: int
    pushes: list[PushRecord] = field(default_factory=list)
    pulls: list[PullRecord] = field(default_factory=list)
    _buf: bytearray = field(default_factory=bytearray)
    _off: int = 0  # consumed prefix of _buf (compacted lazily, never per request)
    _recv: _Receive | None = None
    closed: bool = False

    @property
    def buffered(self) -> int:
        return len(self._buf) - self._off + (self._recv.stub_len if self._recv else 0)

    def append(self, data: bytes, limit: int) -> None:
        """Buffer stream bytes (bounded by ``limit``); nothing is parsed here."""
        if self._off:
            del self._buf[: self._off]
            self._off = 0
        self._buf += data
        if len(self._buf) > limit:
            self.closed = True

    def step(self) -> list[bytes] | None:
        """Process exactly ONE request or data frame. Returns its reply payloads (each bounded
        by ``MAX_REPLY``), or None when more data is needed or the session is over."""
        if self.closed:
            return None
        out: list[bytes] = []
        progressed = self._step_receive(out) if self._recv is not None else self._step_request(out)
        if not progressed:
            return out or None  # a refusal (FAIL) that also ends the session still gets sent
        return out

    # ---- requests ---------------------------------------------------------------------------
    def _step_request(self, out: list[bytes]) -> bool:
        if len(self._buf) - self._off < 8:
            return False
        ident, length = FRAME.unpack_from(self._buf, self._off)
        if ident == b"QUIT":
            self.closed = True
            return False
        if length > SYNC_MAX_PATH:
            out.append(self._fail("path too long"))
            self.closed = True
            return False
        if len(self._buf) - self._off < 8 + length:
            return False
        arg = bytes(self._buf[self._off + 8 : self._off + 8 + length]).decode("utf-8", "replace")
        self._off += 8 + length
        if ident == b"STAT":
            out.append(self._stat1(arg))
        elif ident == b"STA2":
            out.append(self._stat2(arg))
        elif ident == b"LIST":
            out.append(self._list1(arg))
        elif ident == b"LST2":
            out.append(self._list2(arg))
        elif ident == b"RECV":
            out.extend(self._recv_file(arg))
        elif ident == b"SEND":
            path, _, mode_text = arg.rpartition(",")
            if not path:
                path, mode_text = arg, "33188"
            mode = int(mode_text) if mode_text.isascii() and mode_text.isdigit() else 0o100644
            self._recv = _Receive(path[:SYNC_MAX_PATH], mode & 0o7777)
        else:
            out.append(self._fail("unknown sync command"))
            self.closed = True
        return True

    @staticmethod
    def _fail(message: str) -> bytes:
        text = message.encode()
        return FRAME.pack(b"FAIL", len(text)) + text

    def _abs(self, path: str) -> str | None:
        try:
            return self.fs.resolve("/", path)
        except FSError:
            return None

    def _node(self, path: str) -> Node | None:
        resolved = self._abs(path)
        return None if resolved is None else self.fs.stat(resolved)

    def _stat1(self, path: str) -> bytes:
        node = self._node(path)
        if node is None:
            return STAT1.pack(b"STAT", 0, 0, 0)
        return STAT1.pack(b"STAT", mode_bits(node), node_size(node) & 0xFFFFFFFF, node.mtime)

    def _stat2(self, path: str) -> bytes:
        node = self._node(path)
        if node is None:
            return STA2.pack(b"STA2", ENOENT, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        uid = 2000 if node.owner == "shell" else 0
        return STA2.pack(
            b"STA2", 0, 1, hash(path) & 0xFFFFFF, mode_bits(node), 1, uid, uid,
            node_size(node), node.mtime, node.mtime, node.mtime,
        )  # fmt: skip

    def _entries(self, path: str) -> list[tuple[str, Node]]:
        resolved = self._abs(path)
        if resolved is None or not self.fs.is_dir(resolved):
            return []
        rows: list[tuple[str, Node]] = []
        for name in self.fs.listdir(resolved)[:MAX_LIST]:
            child = self.fs.stat(posixpath.join(resolved, name))
            if child is not None:
                rows.append((name, child))
        return rows

    def _list1(self, path: str) -> bytes:
        out = bytearray()
        for name, node in self._entries(path):
            if len(out) > MAX_REPLY - 400:  # size-checked BEFORE building the next entry
                break
            raw = name.encode()[:255]
            out += DENT1.pack(
                b"DENT", mode_bits(node), node_size(node) & 0xFFFFFFFF, node.mtime, len(raw)
            )
            out += raw
        out += DENT1.pack(b"DONE", 0, 0, 0, 0)
        return bytes(out)

    def _list2(self, path: str) -> bytes:
        out = bytearray()
        for name, node in self._entries(path):
            if len(out) > MAX_REPLY - 400:
                break
            raw = name.encode()[:255]
            out += DNT2.pack(
                b"DNT2", 0, 1, 1, mode_bits(node), 1, 0, 0, node_size(node),
                node.mtime, node.mtime, node.mtime, len(raw),
            )  # fmt: skip
            out += raw
        out += DNT2.pack(b"DONE", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        return bytes(out)

    def _recv_file(self, path: str) -> list[bytes]:
        resolved = self._abs(path)
        node = None if resolved is None else self.fs.stat(resolved)
        if len(self.pulls) < MAX_PULLS:
            self.pulls.append(
                PullRecord(path[:SYNC_MAX_PATH], node is not None and node.kind == "f")
            )
        if resolved is None or node is None or node.kind != "f":
            return [self._fail("No such file or directory")]
        try:
            content = self.fs.read(resolved)[:MAX_PULL]
        except FSError:
            return [self._fail("Permission denied")]
        out = [
            FRAME.pack(b"DATA", len(content[i : i + SYNC_MAX_DATA]))
            + content[i : i + SYNC_MAX_DATA]
            for i in range(0, len(content), SYNC_MAX_DATA)
        ]
        out.append(FRAME.pack(b"DONE", 0))
        return [b"".join(out)]

    # ---- push -------------------------------------------------------------------------------
    def _step_receive(self, out: list[bytes]) -> bool:
        recv = self._recv
        if recv is None or len(self._buf) - self._off < 8:
            return False
        ident, length = FRAME.unpack_from(self._buf, self._off)
        if ident == b"DONE":
            self._off += 8
            out.append(self._finish_push(recv, length))
            self._recv = None
            return True
        if ident != b"DATA" or length > SYNC_MAX_DATA:
            self._recv = None
            self.closed = True
            self._record(recv, stored=False)
            out.append(self._fail("invalid data frame"))
            return False
        if len(self._buf) - self._off < 8 + length:
            return False
        chunk = bytes(self._buf[self._off + 8 : self._off + 8 + length])
        self._off += 8 + length
        recv.size += length
        take = self.budget.take(length)
        if take:
            recv.digest.update(chunk[:take])
        if take < length:
            recv.truncated = True
        room = self.stub_cap - recv.stub_len
        if room > 0:
            recv.stub += chunk[:room]
        return True

    def _record(self, recv: _Receive, *, stored: bool) -> None:
        if len(self.pushes) < 64:
            self.pushes.append(
                PushRecord(
                    recv.path, recv.mode, recv.size, recv.digest.hexdigest(), recv.truncated, stored
                )
            )

    def _finish_push(self, recv: _Receive, mtime: int) -> bytes:
        stored = False
        reply = FRAME.pack(b"OKAY", 0)
        try:
            path = self.fs.resolve("/", recv.path)
            self.fs.write(
                path,
                bytes(recv.stub),
                append=False,
                owner=self.owner,
                mode=recv.mode or 0o644,
                tag=f"size:{recv.size}",
            )
            stored = True
        except FSError as exc:
            reply = self._fail(str(exc))
        self._record(recv, stored=stored)
        return reply


@dataclass
class _Receive:
    path: str
    mode: int
    size: int = 0
    truncated: bool = False
    stub: bytearray = field(default_factory=bytearray)
    digest: hashlib._Hash = field(default_factory=hashlib.sha256)

    @property
    def stub_len(self) -> int:
        return len(self.stub)


def flush_partial(session: SyncSession) -> None:
    """Record a push that was cut short by the connection ending."""
    recv = session._recv
    if recv is not None:
        session._record(recv, stored=False)
        session._recv = None
