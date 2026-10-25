"""MySQL client/server protocol primitives, hand written with strict bounds.

Only what a MySQL 8.0 server needs for the handshake, authentication and the text protocol is
implemented. Parsers never read past the buffer they are given and raise :class:`PacketError`
on anything inconsistent. Builders take sizes that the caller has already capped.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field

# --- capability flags ---------------------------------------------------------------------
CLIENT_LONG_PASSWORD = 0x1
CLIENT_FOUND_ROWS = 0x2
CLIENT_LONG_FLAG = 0x4
CLIENT_CONNECT_WITH_DB = 0x8
CLIENT_NO_SCHEMA = 0x10
CLIENT_ODBC = 0x40
CLIENT_LOCAL_FILES = 0x80
CLIENT_IGNORE_SPACE = 0x100
CLIENT_PROTOCOL_41 = 0x200
CLIENT_INTERACTIVE = 0x400
CLIENT_SSL = 0x800
CLIENT_IGNORE_SIGPIPE = 0x1000
CLIENT_TRANSACTIONS = 0x2000
CLIENT_RESERVED = 0x4000
CLIENT_SECURE_CONNECTION = 0x8000
CLIENT_MULTI_STATEMENTS = 1 << 16
CLIENT_MULTI_RESULTS = 1 << 17
CLIENT_PS_MULTI_RESULTS = 1 << 18
CLIENT_PLUGIN_AUTH = 1 << 19
CLIENT_CONNECT_ATTRS = 1 << 20
CLIENT_PLUGIN_AUTH_LENENC = 1 << 21
CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS = 1 << 22
CLIENT_SESSION_TRACK = 1 << 23
CLIENT_DEPRECATE_EOF = 1 << 24
CLIENT_OPTIONAL_RESULTSET_METADATA = 1 << 25
CLIENT_QUERY_ATTRIBUTES = 1 << 27

# What a stock 8.0 server offers, minus what is not emulated: CLIENT_COMPRESS (0x20) and
# CLIENT_ZSTD_COMPRESSION_ALGORITHM, because the sensor has no bounded decompressor. A stock
# server advertises 0xFFFF in the lower word; this one 0xFFDF (nmap mysql-info: 65503). That is
# the one known difference in the capability words.
SERVER_CAPS = (
    CLIENT_LONG_PASSWORD
    | CLIENT_FOUND_ROWS
    | CLIENT_LONG_FLAG
    | CLIENT_CONNECT_WITH_DB
    | CLIENT_NO_SCHEMA
    | CLIENT_ODBC
    | CLIENT_LOCAL_FILES
    | CLIENT_IGNORE_SPACE
    | CLIENT_PROTOCOL_41
    | CLIENT_INTERACTIVE
    | CLIENT_IGNORE_SIGPIPE
    | CLIENT_TRANSACTIONS
    | CLIENT_RESERVED
    | CLIENT_SECURE_CONNECTION
    | CLIENT_MULTI_STATEMENTS
    | CLIENT_MULTI_RESULTS
    | CLIENT_PS_MULTI_RESULTS
    | CLIENT_PLUGIN_AUTH
    | CLIENT_CONNECT_ATTRS
    | CLIENT_PLUGIN_AUTH_LENENC
    | CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS
    | CLIENT_SESSION_TRACK
    | CLIENT_DEPRECATE_EOF
    | CLIENT_OPTIONAL_RESULTSET_METADATA
    | CLIENT_QUERY_ATTRIBUTES
)

SERVER_STATUS_AUTOCOMMIT = 0x0002
SERVER_MORE_RESULTS_EXISTS = 0x0008
CHARSET_UTF8MB4_0900 = 255
CHARSET_BINARY = 63

# --- commands -----------------------------------------------------------------------------
COM_QUIT = 0x01
COM_INIT_DB = 0x02
COM_QUERY = 0x03
COM_FIELD_LIST = 0x04
COM_STATISTICS = 0x09
COM_PROCESS_INFO = 0x0A
COM_DEBUG = 0x0D
COM_PING = 0x0E
COM_CHANGE_USER = 0x11
COM_STMT_PREPARE = 0x16
COM_STMT_EXECUTE = 0x17
COM_STMT_CLOSE = 0x19
COM_STMT_RESET = 0x1A
COM_SET_OPTION = 0x1B
COM_RESET_CONNECTION = 0x1F

COMMAND_NAMES = {
    COM_QUIT: "COM_QUIT",
    COM_INIT_DB: "COM_INIT_DB",
    COM_QUERY: "COM_QUERY",
    COM_FIELD_LIST: "COM_FIELD_LIST",
    COM_STATISTICS: "COM_STATISTICS",
    COM_PROCESS_INFO: "COM_PROCESS_INFO",
    COM_DEBUG: "COM_DEBUG",
    COM_PING: "COM_PING",
    COM_CHANGE_USER: "COM_CHANGE_USER",
    COM_STMT_PREPARE: "COM_STMT_PREPARE",
    COM_STMT_EXECUTE: "COM_STMT_EXECUTE",
    COM_STMT_CLOSE: "COM_STMT_CLOSE",
    COM_STMT_RESET: "COM_STMT_RESET",
    COM_SET_OPTION: "COM_SET_OPTION",
    COM_RESET_CONNECTION: "COM_RESET_CONNECTION",
}

# --- column types -------------------------------------------------------------------------
TYPE_LONG = 0x03
TYPE_LONGLONG = 0x08
TYPE_DATETIME = 0x0C
TYPE_NEWDECIMAL = 0xF6
TYPE_VAR_STRING = 0xFD

MAX_ATTRS = 32
MAX_ATTR_LEN = 256
MAX_USERNAME = 256


class PacketError(Exception):
    """A malformed packet; ``reason`` is a short machine-readable code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# --- encoding -----------------------------------------------------------------------------


def lenenc_int(value: int) -> bytes:
    if value < 0:
        raise ValueError("negative length")
    if value < 251:
        return bytes([value])
    if value < 1 << 16:
        return b"\xfc" + value.to_bytes(2, "little")
    if value < 1 << 24:
        return b"\xfd" + value.to_bytes(3, "little")
    return b"\xfe" + value.to_bytes(8, "little")


def lenenc_str(data: bytes) -> bytes:
    return lenenc_int(len(data)) + data


def pack(seq: int, payload: bytes) -> bytes:
    if len(payload) >= 0xFFFFFF:
        raise ValueError("payload too large for one packet")
    return len(payload).to_bytes(3, "little") + bytes([seq & 0xFF]) + payload


def ok_payload(
    affected: int = 0,
    last_insert_id: int = 0,
    status: int = SERVER_STATUS_AUTOCOMMIT,
    warnings: int = 0,
    info: str = "",
    header: int = 0x00,
    session_track: bool = False,
) -> bytes:
    """OK packet. With CLIENT_SESSION_TRACK the info is length-encoded, and an (empty) session
    state follows only when the status says it changed, which this sensor never does."""
    body = (
        bytes([header])
        + lenenc_int(affected)
        + lenenc_int(last_insert_id)
        + status.to_bytes(2, "little")
        + warnings.to_bytes(2, "little")
    )
    text = info.encode("utf-8", "replace")[:256]
    return body + (lenenc_str(text) if session_track else text)


def err_payload(code: int, state: str, message: str) -> bytes:
    return (
        b"\xff"
        + code.to_bytes(2, "little")
        + b"#"
        + state.encode("ascii")[:5].ljust(5, b"0")
        + message.encode("utf-8", "replace")[:512]
    )


def eof_payload(status: int = SERVER_STATUS_AUTOCOMMIT, warnings: int = 0) -> bytes:
    return b"\xfe" + warnings.to_bytes(2, "little") + status.to_bytes(2, "little")


def auth_switch_payload(plugin: str, data: bytes) -> bytes:
    return b"\xfe" + plugin.encode("ascii") + b"\x00" + data


def auth_more_data(data: bytes) -> bytes:
    return b"\x01" + data


@dataclass(frozen=True)
class Column:
    name: str
    type: int = TYPE_VAR_STRING
    length: int = 1020
    flags: int = 0
    decimals: int = 0
    table: str = ""
    schema: str = ""

    @property
    def charset(self) -> int:
        numeric = self.type in (TYPE_LONG, TYPE_LONGLONG, TYPE_NEWDECIMAL, TYPE_DATETIME)
        return CHARSET_BINARY if numeric else CHARSET_UTF8MB4_0900


def column_payload(col: Column) -> bytes:
    name = col.name.encode("utf-8", "replace")[:256]
    return (
        lenenc_str(b"def")
        + lenenc_str(col.schema.encode("utf-8", "replace")[:64])
        + lenenc_str(col.table.encode("utf-8", "replace")[:64])
        + lenenc_str(col.table.encode("utf-8", "replace")[:64])
        + lenenc_str(name)
        + lenenc_str(name)
        + b"\x0c"
        + col.charset.to_bytes(2, "little")
        + col.length.to_bytes(4, "little")
        + bytes([col.type])
        + col.flags.to_bytes(2, "little")
        + bytes([col.decimals])
        + b"\x00\x00"
    )


def row_payload(values: tuple[str | None, ...]) -> bytes:
    out = bytearray()
    for value in values:
        if value is None:
            out += b"\xfb"
        else:
            out += lenenc_str(value.encode("utf-8", "replace"))
    return bytes(out)


def result_set_payloads(
    columns: list[Column],
    rows: list[tuple[str | None, ...]],
    caps: int,
    status: int = SERVER_STATUS_AUTOCOMMIT,
) -> Iterator[bytes]:
    """The packets of a text-protocol result set, built lazily (the caller capped ``rows``).

    Lazy so that the sender can hold back (drain) before the next rows are built.
    """
    count = lenenc_int(len(columns))
    if caps & CLIENT_OPTIONAL_RESULTSET_METADATA:
        count += b"\x01"  # metadata_follows = RESULTSET_METADATA_FULL
    yield count
    for c in columns:
        yield column_payload(c)
    deprecate_eof = bool(caps & CLIENT_DEPRECATE_EOF)
    if not deprecate_eof:
        yield eof_payload(status)
    for r in rows:
        yield row_payload(r)
    if deprecate_eof:
        yield ok_payload(
            status=status, header=0xFE, session_track=bool(caps & CLIENT_SESSION_TRACK)
        )
    else:
        yield eof_payload(status)


@dataclass
class QueryAttributes:
    """The attribute prefix of a COM_QUERY from a client that negotiated CLIENT_QUERY_ATTRIBUTES."""

    query: bytes
    names: dict[str, str | None]


_ATTR_FIXED = {0x01: 1, 0x02: 2, 0x03: 4, 0x04: 4, 0x05: 8, 0x08: 8, 0x09: 4, 0x0D: 2}
_ATTR_VARLEN = frozenset({0x0F, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE})
_ATTR_TEMPORAL = frozenset({0x07, 0x0A, 0x0B, 0x0C})
MAX_QUERY_ATTRS = 32


def parse_query_attributes(body: bytes) -> QueryAttributes:
    """Split ``parameter_count, parameter_set_count, [bitmap, types, values], query``.

    Bounded: at most ``MAX_QUERY_ATTRS`` attributes, names and values are cut short. Raises
    :class:`PacketError` on anything inconsistent or of an unknown type.
    """
    r = Reader(body)
    count = r.lenenc_int()
    r.lenenc_int()  # parameter_set_count, always 1
    names: dict[str, str | None] = {}
    if count:
        if count > MAX_QUERY_ATTRS:
            raise PacketError("too_many_attributes")
        bitmap = r.take((count + 7) // 8)
        if r.u8() != 1:
            raise PacketError("no_bound_types")
        types: list[tuple[int, str]] = []
        for _ in range(count):
            kind = r.u8()
            r.u8()  # unsigned flag
            types.append((kind, _text(r.lenenc_bytes(MAX_ATTR_LEN), 64)))
        for n, (kind, name) in enumerate(types):
            if bitmap[n // 8] & (1 << (n % 8)) or kind == 0x06:
                names[name] = None
            elif kind in _ATTR_FIXED:
                names[name] = r.take(_ATTR_FIXED[kind]).hex()
            elif kind in _ATTR_TEMPORAL:
                names[name] = r.take(r.u8()).hex()
            elif kind in _ATTR_VARLEN:
                names[name] = _text(r.lenenc_bytes(1 << 20), MAX_ATTR_LEN)
            else:
                raise PacketError("unknown_attribute_type")
    return QueryAttributes(body[r.pos :], names)


def handshake_payload(
    version: str, conn_id: int, salt: bytes, caps: int, plugin: str, status: int
) -> bytes:
    """Initial Handshake Packet v10. ``salt`` is the 20 byte scramble."""
    if len(salt) != 20:
        raise ValueError("salt must be 20 bytes")
    return (
        b"\x0a"
        + version.encode("ascii")
        + b"\x00"
        + (conn_id & 0xFFFFFFFF).to_bytes(4, "little")
        + salt[:8]
        + b"\x00"
        + (caps & 0xFFFF).to_bytes(2, "little")
        + bytes([CHARSET_UTF8MB4_0900])
        + status.to_bytes(2, "little")
        + (caps >> 16).to_bytes(2, "little")
        + bytes([21])
        + b"\x00" * 10
        + salt[8:]
        + b"\x00"
        + plugin.encode("ascii")
        + b"\x00"
    )


# --- parsing ------------------------------------------------------------------------------


class Reader:
    """A bounds-checked cursor over ``data``."""

    def __init__(self, data: bytes, pos: int = 0) -> None:
        self.data = data
        self.pos = pos

    def left(self) -> int:
        return len(self.data) - self.pos

    def take(self, n: int) -> bytes:
        if n < 0 or n > self.left():
            raise PacketError("truncated")
        chunk = self.data[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "little")

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "little")

    def cstring(self, limit: int = 1024) -> bytes:
        end = self.data.find(b"\x00", self.pos, self.pos + limit + 1)
        if end < 0:
            raise PacketError("unterminated_string")
        chunk = self.data[self.pos : end]
        self.pos = end + 1
        return chunk

    def lenenc_int(self) -> int:
        first = self.u8()
        if first < 251:
            return first
        if first == 0xFC:
            return self.u16()
        if first == 0xFD:
            return int.from_bytes(self.take(3), "little")
        if first == 0xFE:
            return int.from_bytes(self.take(8), "little")
        raise PacketError("bad_lenenc")

    def lenenc_bytes(self, limit: int = 4096) -> bytes:
        n = self.lenenc_int()
        if n > limit:
            raise PacketError("lenenc_too_long")
        return self.take(n)


@dataclass
class HandshakeResponse:
    caps: int
    max_packet: int
    charset: int
    ssl_request: bool = False
    username: str = ""
    auth_response: bytes = b""
    database: str = ""
    plugin: str = ""
    attrs: dict[str, str] = field(default_factory=dict)


def _text(raw: bytes, limit: int = MAX_ATTR_LEN) -> str:
    return raw[:limit].decode("utf-8", "replace")


def parse_attrs(reader: Reader) -> dict[str, str]:
    total = reader.lenenc_int()
    if total > reader.left():
        raise PacketError("attrs_truncated")
    sub = Reader(reader.take(total))
    attrs: dict[str, str] = {}
    while sub.left() > 0 and len(attrs) < MAX_ATTRS:
        key = sub.lenenc_bytes(MAX_ATTR_LEN)
        value = sub.lenenc_bytes(MAX_ATTR_LEN)
        attrs[_text(key, 64)] = _text(value)
    return attrs


def parse_handshake_response(payload: bytes) -> HandshakeResponse:
    """Parse HandshakeResponse41 (or the 32 byte SSLRequest prefix of it)."""
    r = Reader(payload)
    caps = r.u32()
    if not caps & CLIENT_PROTOCOL_41:
        raise PacketError("pre41_client")
    max_packet = r.u32()
    charset = r.u8()
    r.take(23)  # filler
    if len(payload) == 32:
        if not caps & CLIENT_SSL:
            raise PacketError("short_response")
        return HandshakeResponse(caps, max_packet, charset, ssl_request=True)
    username = r.cstring(MAX_USERNAME)
    if caps & CLIENT_PLUGIN_AUTH_LENENC:
        auth = r.lenenc_bytes(2048)
    elif caps & CLIENT_SECURE_CONNECTION:
        auth = r.take(r.u8())
    else:
        auth = r.cstring(2048)
    database = r.cstring(256) if caps & CLIENT_CONNECT_WITH_DB and r.left() else b""
    plugin = r.cstring(64) if caps & CLIENT_PLUGIN_AUTH and r.left() else b""
    attrs: dict[str, str] = {}
    if caps & CLIENT_CONNECT_ATTRS and r.left():
        try:
            attrs = parse_attrs(r)
        except PacketError:
            attrs = {}  # attributes are optional decoration, never a reason to reject
    return HandshakeResponse(
        caps,
        max_packet,
        charset,
        False,
        _text(username, MAX_USERNAME),
        auth,
        _text(database),
        _text(plugin, 64),
        attrs,
    )


@dataclass
class ChangeUser:
    username: str
    auth_response: bytes
    database: str
    plugin: str


def parse_change_user(payload: bytes, caps: int) -> ChangeUser:
    r = Reader(payload, 1)
    username = r.cstring(MAX_USERNAME)
    if caps & CLIENT_SECURE_CONNECTION:
        auth = r.take(r.u8())
    else:
        auth = r.cstring(2048)
    database = r.cstring(256) if r.left() else b""
    if r.left() >= 2:
        r.take(2)  # character set
    plugin = r.cstring(64) if caps & CLIENT_PLUGIN_AUTH and r.left() else b""
    return ChangeUser(_text(username, MAX_USERNAME), auth, _text(database), _text(plugin, 64))
