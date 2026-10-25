"""The ADB wire format: 24-byte message headers, sync sub-protocol frames, shell v2 packets.

Everything is parsed by hand with ``struct`` and explicit length checks. Nothing here touches
the network or the filesystem.
"""

from __future__ import annotations

import struct

A_SYNC = 0x434E5953
A_CNXN = 0x4E584E43
A_AUTH = 0x48545541
A_OPEN = 0x4E45504F
A_OKAY = 0x59414B4F
A_CLSE = 0x45534C43
A_WRTE = 0x45545257
A_STLS = 0x534C5453

COMMAND_NAMES = {
    A_SYNC: "SYNC",
    A_CNXN: "CNXN",
    A_AUTH: "AUTH",
    A_OPEN: "OPEN",
    A_OKAY: "OKAY",
    A_CLSE: "CLSE",
    A_WRTE: "WRTE",
    A_STLS: "STLS",
}
VALID_COMMANDS = frozenset(COMMAND_NAMES)

HEADER = struct.Struct("<6I")
HEADER_SIZE = HEADER.size  # 24
VERSION_SKIP_CHECKSUM = 0x01000001
VERSION = VERSION_SKIP_CHECKSUM
PRE_CNXN_MAX_PAYLOAD = 4096  # before CNXN only a small banner is acceptable (MAX_PAYLOAD_V1)

MASK32 = 0xFFFFFFFF


class WireError(Exception):
    """A malformed or oversized message; ``reason`` goes into the disconnect event."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def checksum(data: bytes) -> int:
    """The legacy ADB data checksum: the sum of all payload bytes modulo 2**32."""
    return sum(data) & MASK32


def pack(command: int, arg0: int, arg1: int, data: bytes = b"", *, crc: bool = True) -> bytes:
    """One message. ``crc=False`` writes a zero data_check (protocol >= 0x01000001)."""
    check = checksum(data) if crc else 0
    head = HEADER.pack(command, arg0 & MASK32, arg1 & MASK32, len(data), check, command ^ MASK32)
    return head + data


def parse_header(raw: bytes) -> tuple[int, int, int, int, int]:
    """Return ``(command, arg0, arg1, length, data_check)``; raises WireError if the magic fails."""
    command, arg0, arg1, length, data_check, magic = HEADER.unpack(raw)
    if magic != command ^ MASK32 or command not in VALID_COMMANDS:
        raise WireError("bad message magic")
    return command, arg0, arg1, length, data_check


def clean_text(data: bytes, limit: int = 4096) -> str:
    """Decode a service string or banner: stop at NUL, replace bad bytes, bounded."""
    return data[:limit].split(b"\0", 1)[0].decode("utf-8", "replace")


def parse_cnxn_banner(payload: bytes) -> dict[str, str]:
    """``host::features=a,b;ro.x=y`` to a small dict of the client's identity (bounded)."""
    text = clean_text(payload, 1024)
    parts = text.split(":", 2)
    info: dict[str, str] = {}
    if parts:
        info["kind"] = parts[0][:32]
    if len(parts) > 2:
        for item in parts[2].split(";")[:16]:
            key, _, value = item.partition("=")
            if key:
                info[key[:64]] = value[:256]
    return info


# ---- shell v2 -----------------------------------------------------------------------------
V2_STDIN = 0
V2_STDOUT = 1
V2_STDERR = 2
V2_EXIT = 3
V2_CLOSE_STDIN = 4
V2_WINDOW_SIZE = 5
V2_HEADER = struct.Struct("<BI")


def v2_pack(packet_id: int, data: bytes) -> bytes:
    return V2_HEADER.pack(packet_id, len(data)) + data


class V2Parser:
    """Reassembles shell v2 packets from the byte stream of WRTE payloads (bounded)."""

    MAX_PACKET = 64 * 1024

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, data: bytes) -> list[tuple[int, bytes]]:
        self._buf += data
        out: list[tuple[int, bytes]] = []
        while len(self._buf) >= V2_HEADER.size:
            packet_id, length = V2_HEADER.unpack_from(self._buf)
            if length > self.MAX_PACKET:
                raise WireError("oversized shell packet")
            end = V2_HEADER.size + length
            if len(self._buf) < end:
                break
            out.append((packet_id, bytes(self._buf[V2_HEADER.size : end])))
            del self._buf[:end]
        return out

    @property
    def buffered(self) -> int:
        return len(self._buf)


# ---- sync sub-protocol ----------------------------------------------------------------------
SYNC_REQ = struct.Struct("<4sI")
SYNC_MAX_PATH = 1024
SYNC_MAX_DATA = 64 * 1024
