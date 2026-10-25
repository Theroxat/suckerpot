"""SMB1 / SMB2 header parsing and the protocol constants we need.

The sensor reads just enough structure to tell a NEGOTIATE from a SESSION_SETUP, to recover
the offered dialects and the client's NTLM blob, and to echo the right ids and an error status
back. It never processes a command: anything past NEGOTIATE / SESSION_SETUP is answered with an
error and recorded. Parsing is strict and bounds-checked; it never raises on hostile input
other than :class:`ParseError`.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Final

SMB1_MAGIC: Final = b"\xffSMB"
SMB2_MAGIC: Final = b"\xfeSMB"

SMB2_HEADER_LEN: Final = 64
SMB1_HEADER_LEN: Final = 32

# SMB2 commands we name (we only act on NEGOTIATE and SESSION_SETUP).
SMB2_NEGOTIATE: Final = 0x0000
SMB2_SESSION_SETUP: Final = 0x0001
SMB2_LOGOFF: Final = 0x0002
SMB2_TREE_CONNECT: Final = 0x0003
SMB2_TREE_DISCONNECT: Final = 0x0004
SMB2_CREATE: Final = 0x0005
SMB2_CLOSE: Final = 0x0006
SMB2_READ: Final = 0x0008
SMB2_WRITE: Final = 0x0009
SMB2_IOCTL: Final = 0x000B
SMB2_ECHO: Final = 0x000D
SMB2_QUERY_DIRECTORY: Final = 0x000E
SMB2_QUERY_INFO: Final = 0x0010

SMB2_COMMAND_NAMES: Final = {
    0x0000: "negotiate",
    0x0001: "session_setup",
    0x0002: "logoff",
    0x0003: "tree_connect",
    0x0004: "tree_disconnect",
    0x0005: "create",
    0x0006: "close",
    0x0007: "flush",
    0x0008: "read",
    0x0009: "write",
    0x000A: "lock",
    0x000B: "ioctl",
    0x000C: "cancel",
    0x000D: "echo",
    0x000E: "query_directory",
    0x000F: "change_notify",
    0x0010: "query_info",
    0x0011: "set_info",
    0x0012: "oplock_break",
}

# A small, well-known subset of SMB1 command names, for the best-effort label on SMB1 probes.
SMB1_COMMAND_NAMES: Final = {
    0x04: "close",
    0x06: "delete",
    0x24: "locking_andx",
    0x25: "trans",
    0x2B: "echo",
    0x2D: "open_andx",
    0x2E: "read_andx",
    0x2F: "write_andx",
    0x32: "trans2",
    0x34: "find_close2",
    0xA0: "nt_transact",
    0xA2: "nt_create_andx",
    0x70: "tree_connect",
    0x71: "tree_disconnect",
    0x72: "negotiate",
    0x73: "session_setup_andx",
    0x74: "logoff_andx",
    0x75: "tree_connect_andx",
}

SMB1_NEGOTIATE: Final = 0x72
SMB1_DIALECT_WILDCARD: Final = "SMB 2.???"
SMB1_DIALECT_2_002: Final = "SMB 2.002"

# SMB2 dialect revisions.
DIALECT_2_0_2: Final = 0x0202
DIALECT_2_1_0: Final = 0x0210
DIALECT_3_0_0: Final = 0x0300
DIALECT_3_0_2: Final = 0x0302
DIALECT_3_1_1: Final = 0x0311
DIALECT_WILDCARD: Final = 0x02FF  # "SMB 2.???": the steer-to-SMB2 answer to an SMB1 negotiate

SUPPORTED_DIALECTS: Final = (
    DIALECT_2_0_2,
    DIALECT_2_1_0,
    DIALECT_3_0_0,
    DIALECT_3_0_2,
    DIALECT_3_1_1,
)
DIALECT_NAMES: Final = {
    DIALECT_2_0_2: "2.0.2",
    DIALECT_2_1_0: "2.1",
    DIALECT_3_0_0: "3.0",
    DIALECT_3_0_2: "3.0.2",
    DIALECT_3_1_1: "3.1.1",
    DIALECT_WILDCARD: "2.???",
}

# NT status codes we return.
STATUS_SUCCESS: Final = 0x00000000
STATUS_MORE_PROCESSING_REQUIRED: Final = 0xC0000016
STATUS_INVALID_PARAMETER: Final = 0xC000000D
STATUS_ACCESS_DENIED: Final = 0xC0000022
STATUS_LOGON_FAILURE: Final = 0xC000006D
STATUS_INSUFFICIENT_RESOURCES: Final = 0xC000009A
STATUS_NOT_SUPPORTED: Final = 0xC00000BB
STATUS_USER_SESSION_DELETED: Final = 0xC0000203

# SMB2 header flags.
SMB2_FLAGS_SERVER_TO_REDIR: Final = 0x00000001

# SMB2 negotiate-context types (SMB 3.1.1).
CTX_PREAUTH_INTEGRITY: Final = 0x0001
CTX_ENCRYPTION: Final = 0x0002
CTX_COMPRESSION: Final = 0x0003
CTX_NETNAME: Final = 0x0005
CTX_SIGNING: Final = 0x0008

_MAX_DIALECTS = 64
_MAX_CONTEXTS = 16


class ParseError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def smb_variant(payload: bytes) -> str | None:
    """``"smb2"``, ``"smb1"`` or None for the SMB payload after the NetBIOS header."""
    if payload[:4] == SMB2_MAGIC:
        return "smb2"
    if payload[:4] == SMB1_MAGIC:
        return "smb1"
    return None


@dataclass(frozen=True)
class Smb2Header:
    credit_charge: int
    status: int
    command: int
    credit_request: int
    flags: int
    next_command: int
    message_id: int
    tree_id: int
    session_id: int

    @property
    def command_name(self) -> str:
        return SMB2_COMMAND_NAMES.get(self.command, f"0x{self.command:04x}")


def parse_smb2_header(payload: bytes) -> Smb2Header:
    """Parse the 64-byte synchronous SMB2 header. Raises :class:`ParseError`."""
    if len(payload) < SMB2_HEADER_LEN:
        raise ParseError("smb2_header_short")
    if payload[:4] != SMB2_MAGIC:
        raise ParseError("not_smb2")
    structure_size = struct.unpack_from("<H", payload, 4)[0]
    if structure_size != SMB2_HEADER_LEN:
        raise ParseError("smb2_structure_size")
    credit_charge = struct.unpack_from("<H", payload, 6)[0]
    status = struct.unpack_from("<I", payload, 8)[0]
    command = struct.unpack_from("<H", payload, 12)[0]
    credit_request = struct.unpack_from("<H", payload, 14)[0]
    flags = struct.unpack_from("<I", payload, 16)[0]
    next_command = struct.unpack_from("<I", payload, 20)[0]
    message_id = struct.unpack_from("<Q", payload, 24)[0]
    tree_id = struct.unpack_from("<I", payload, 36)[0]
    session_id = struct.unpack_from("<Q", payload, 40)[0]
    return Smb2Header(
        credit_charge=credit_charge,
        status=status,
        command=command,
        credit_request=credit_request,
        flags=flags,
        next_command=next_command,
        message_id=message_id,
        tree_id=tree_id,
        session_id=session_id,
    )


@dataclass
class NegotiateRequest:
    dialects: list[int] = field(default_factory=list)
    security_mode: int = 0
    client_guid: bytes = b""
    capabilities: int = 0
    context_types: list[int] = field(default_factory=list)
    ciphers: list[int] = field(default_factory=list)


def parse_negotiate_request(payload: bytes) -> NegotiateRequest:
    """Parse an SMB2 NEGOTIATE request body (dialects + 3.1.1 contexts). Never raises."""
    out = NegotiateRequest()
    body = payload[SMB2_HEADER_LEN:]
    if len(body) < 36:
        return out
    dialect_count = struct.unpack_from("<H", body, 2)[0]
    out.security_mode = struct.unpack_from("<H", body, 4)[0]
    out.capabilities = struct.unpack_from("<I", body, 8)[0]
    out.client_guid = body[12:28]
    ctx_offset = struct.unpack_from("<I", body, 28)[0]
    ctx_count = struct.unpack_from("<H", body, 32)[0]
    dialect_count = min(dialect_count, _MAX_DIALECTS)
    for i in range(dialect_count):
        pos = 36 + i * 2
        if pos + 2 > len(body):
            break
        out.dialects.append(struct.unpack_from("<H", body, pos)[0])
    if DIALECT_3_1_1 in out.dialects and ctx_count:
        _parse_negotiate_contexts(payload, ctx_offset, min(ctx_count, _MAX_CONTEXTS), out)
    return out


def _parse_negotiate_contexts(
    payload: bytes, offset: int, count: int, out: NegotiateRequest
) -> None:
    pos = offset  # negotiate-context offset is from the start of the SMB2 header
    for _ in range(count):
        if pos + 8 > len(payload):
            break
        ctx_type = struct.unpack_from("<H", payload, pos)[0]
        data_len = struct.unpack_from("<H", payload, pos + 2)[0]
        data_start = pos + 8
        data_end = data_start + data_len
        if data_end > len(payload):
            break
        out.context_types.append(ctx_type)
        if ctx_type == CTX_ENCRYPTION and data_len >= 2:
            cipher_count = struct.unpack_from("<H", payload, data_start)[0]
            for j in range(min(cipher_count, 8)):
                cp = data_start + 2 + j * 2
                if cp + 2 > data_end:
                    break
                out.ciphers.append(struct.unpack_from("<H", payload, cp)[0])
        pos = data_end + ((8 - (data_end % 8)) % 8)  # 8-byte aligned


def choose_dialect(offered: list[int]) -> int | None:
    """The highest dialect we support that the client offered, or None."""
    usable = [d for d in offered if d in SUPPORTED_DIALECTS]
    return max(usable) if usable else None


# Body offset of the SecurityBufferOffset u16 in a SESSION_SETUP request:
# StructureSize(2) Flags(1) SecurityMode(1) Capabilities(4) Channel(4) -> 12.
SESSION_SETUP_SECBUF_FIELD: Final = 12


def extract_security_buffer(payload: bytes, offset_field_pos: int) -> bytes:
    """Return a request's SecurityBuffer, given the body offset of its ``SecurityBufferOffset``
    u16 (followed by ``SecurityBufferLength``). Offsets are from the SMB2 header start. The
    length is clamped so a hostile value cannot read past the payload. Never raises.
    """
    body = payload[SMB2_HEADER_LEN:]
    if offset_field_pos < 0 or offset_field_pos + 4 > len(body):
        return b""
    sec_offset = struct.unpack_from("<H", body, offset_field_pos)[0]
    sec_len = struct.unpack_from("<H", body, offset_field_pos + 2)[0]
    end = sec_offset + sec_len
    if sec_len == 0 or sec_offset < SMB2_HEADER_LEN or end > len(payload):
        return b""
    return payload[sec_offset:end]


def parse_smb1_negotiate_dialects(payload: bytes) -> list[str]:
    """The NUL-terminated dialect strings of an SMB1 NEGOTIATE request. Never raises."""
    body = payload[SMB1_HEADER_LEN:]
    if not body:
        return []
    # WordCount (1 byte, 0 for negotiate) then ByteCount (2) then the dialect buffer.
    pos = 1
    if pos + 2 > len(body):
        return []
    byte_count = struct.unpack_from("<H", body, pos)[0]
    pos += 2
    buffer = body[pos : pos + min(byte_count, 4096)]
    dialects: list[str] = []
    i = 0
    while i < len(buffer) and len(dialects) < _MAX_DIALECTS:
        if buffer[i] != 0x02:  # each entry is a dialect record: 0x02 then an ASCII string
            i += 1
            continue
        end = buffer.find(b"\x00", i + 1)
        if end < 0:
            break
        dialects.append(buffer[i + 1 : end].decode("ascii", "replace")[:64])
        i = end + 1
    return dialects


def smb1_command(payload: bytes) -> int:
    return payload[4] if len(payload) > 4 else -1


def smb1_command_name(command: int) -> str:
    return SMB1_COMMAND_NAMES.get(command, f"0x{command & 0xFF:02x}")
