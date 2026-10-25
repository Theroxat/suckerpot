"""Hand-written TDS (Tabular Data Stream) framing, decoding and token encoding.

Only what a SQL Server look-alike needs: the 8 byte packet header with strict validation, the
PRELOGIN option list, the LOGIN7 record (with the trivial password obfuscation reversed, as every
TDS client sends it that way when encryption is off), and the handful of response tokens
(LOGINACK, ENVCHANGE, INFO, ERROR, COLMETADATA, ROW, DONE...).

Every length read from the wire is checked against the bytes actually received before anything is
sliced or allocated, and the parser never holds more than one maximal packet plus one read chunk.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

# --- packet header ----------------------------------------------------------------------

HEADER = 8
MAX_PACKET = 32768  # TDS allows at most 32767 bytes per packet
DEFAULT_PACKET = 4096

T_SQLBATCH = 0x01
T_RPC = 0x03
T_REPLY = 0x04
T_BULK = 0x07
T_ATTENTION = 0x06
T_TXN = 0x0E
T_LOGIN7 = 0x10
T_SSPI = 0x11
T_PRELOGIN = 0x12
VALID_TYPES = frozenset(
    {T_SQLBATCH, T_RPC, T_REPLY, T_ATTENTION, T_BULK, T_TXN, T_LOGIN7, T_SSPI, T_PRELOGIN}
)
FIRST_TYPES = frozenset({T_PRELOGIN, T_LOGIN7})

S_EOM = 0x01
S_IGNORE = 0x02
_VALID_STATUS = 0x01 | 0x02 | 0x08 | 0x10


class TdsError(Exception):
    """Malformed input; ``reason`` is a short machine-friendly label."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Packet:
    type: int
    status: int
    payload: bytes

    @property
    def eom(self) -> bool:
        return bool(self.status & S_EOM)


class PacketParser:
    """Incremental packet reader. ``feed`` appends, ``next_packet`` pops one complete packet."""

    def __init__(self, max_packet: int = MAX_PACKET) -> None:
        self.max_packet = max_packet
        self._buf = bytearray()
        self.packets = 0

    @property
    def held(self) -> int:
        return len(self._buf)

    def preview(self, n: int = 64) -> bytes:
        return bytes(self._buf[:n])

    def take_rest(self) -> bytes:
        """Hand over (and forget) the buffered bytes: the stream turned into raw TLS records."""
        rest = bytes(self._buf)
        self._buf.clear()
        return rest

    def feed(self, data: bytes) -> None:
        self._buf += data

    def next_packet(self, first: bool = False) -> Packet | None:
        buf = self._buf
        if not buf:
            return None
        # Reject at the first byte: a non-TDS client is not made to wait for 8 bytes.
        allowed = FIRST_TYPES if first and self.packets == 0 else VALID_TYPES
        if buf[0] not in allowed:
            raise TdsError("bad_type")
        if len(buf) < HEADER:
            return None
        ptype, status, length = buf[0], buf[1], struct.unpack_from(">H", buf, 2)[0]
        if status & ~_VALID_STATUS & 0xFF:
            raise TdsError("bad_status")
        if length < HEADER or length > self.max_packet:
            raise TdsError("bad_length")
        if len(buf) < length:
            return None
        payload = bytes(buf[HEADER:length])
        del buf[:length]
        self.packets += 1
        return Packet(ptype, status, payload)


def frame(ptype: int, payload: bytes, packet_size: int, spid: int) -> list[bytes]:
    """Split ``payload`` into packets of at most ``packet_size`` bytes (last one has EOM)."""
    room = max(512, min(packet_size, MAX_PACKET)) - HEADER
    out: list[bytes] = []
    pid = 1
    for start in range(0, max(1, len(payload)), room):
        chunk = payload[start : start + room]
        last = start + room >= len(payload)
        head = struct.pack(
            ">BBHHBB", ptype, S_EOM if last else 0, HEADER + len(chunk), spid, pid, 0
        )
        out.append(head + chunk)
        pid = (pid + 1) & 0xFF
    return out


# --- PRELOGIN ---------------------------------------------------------------------------

PL_VERSION, PL_ENCRYPTION, PL_INSTOPT, PL_THREADID, PL_MARS = 0, 1, 2, 3, 4
PL_FEDAUTH = 6
ENC_OFF, ENC_ON, ENC_NOT_SUP, ENC_REQ = 0, 1, 2, 3


@dataclass
class PreLogin:
    encryption: int | None = None
    instance: str = ""
    version: tuple[int, int, int, int] | None = None
    options: list[int] = field(default_factory=list)
    mars: int = 0


def parse_prelogin(payload: bytes) -> PreLogin:
    """Decode the option table. Offsets are relative to the start of the payload."""
    out = PreLogin()
    pos = 0
    n = len(payload)
    entries: list[tuple[int, int, int]] = []
    while True:
        if pos >= n:
            raise TdsError("prelogin_truncated")
        token = payload[pos]
        if token == 0xFF:
            break
        if pos + 5 > n or len(entries) >= 32:
            raise TdsError("prelogin_table")
        offset, length = struct.unpack_from(">HH", payload, pos + 1)
        entries.append((token, offset, length))
        pos += 5
    for token, offset, length in entries:
        if offset + length > n:
            raise TdsError("prelogin_range")
        out.options.append(token)
        data = payload[offset : offset + length]
        if token == PL_ENCRYPTION and length >= 1:
            out.encryption = data[0]
        elif token == PL_INSTOPT:
            out.instance = data.split(b"\x00", 1)[0][:64].decode("latin-1")
        elif token == PL_MARS and length >= 1:
            out.mars = 1 if data[0] else 0
        elif token == PL_VERSION and length >= 6:
            major, minor, build, sub = struct.unpack(">BBHH", data[:6])
            out.version = (major, minor, build, sub)
    return out


def build_prelogin_reply(
    version: tuple[int, int, int, int],
    encryption: int,
    mars: int = 0,
    fedauth: bool = False,
) -> bytes:
    """A SQL Server 2019/2022 PRELOGIN reply: VERSION, ENCRYPTION, INSTOPT, THREADID, MARS and,
    when the client asked for it, FEDAUTHREQUIRED (43 bytes with the header, 48 with FEDAUTH)."""
    major, minor, build, sub = version
    plan: list[tuple[int, bytes]] = [
        (PL_VERSION, struct.pack(">BBHH", major, minor, build, sub)),
        (PL_ENCRYPTION, bytes([encryption])),
        (PL_INSTOPT, b"\x00"),
        (PL_THREADID, b""),
        (PL_MARS, bytes([mars])),
    ]
    if fedauth:
        plan.append((PL_FEDAUTH, b"\x00"))
    table = len(plan) * 5 + 1
    head = bytearray()
    body = bytearray()
    for token, data in plan:
        head += struct.pack(">BHH", token, table + len(body), len(data))
        body += data
    return bytes(head) + b"\xff" + bytes(body)


# --- LOGIN7 -----------------------------------------------------------------------------

MAX_FIELD_CHARS = 256
MAX_PASSWORD_CHARS = 256
LOGIN7_FIXED = 86  # TDS 7.0/7.1; 7.2+ adds ChangePassword and cbSSPILong (94)


@dataclass
class Login7:
    tds_version: int = 0
    packet_size: int = DEFAULT_PACKET
    client_pid: int = 0
    hostname: str = ""
    username: str = ""
    password: str = ""
    app_name: str = ""
    server_name: str = ""
    library: str = ""
    language: str = ""
    database: str = ""
    sspi: bool = False
    read_only_intent: bool = False
    extension: bool = False
    sspi_token: bytes = b""
    truncated: list[str] = field(default_factory=list)


def decode_password(raw: bytes) -> str:
    """Reverse the TDS password obfuscation: XOR 0xA5, then swap the nibbles of every byte."""
    plain = bytearray(len(raw))
    for i, b in enumerate(raw):
        x = b ^ 0xA5
        plain[i] = ((x & 0x0F) << 4) | (x >> 4)
    return plain.decode("utf-16-le", "replace")


def encode_password(text: str) -> bytes:
    """Inverse of :func:`decode_password` (used by tests)."""
    out = bytearray()
    for b in text.encode("utf-16-le"):
        out.append((((b & 0x0F) << 4) | (b >> 4)) ^ 0xA5)
    return bytes(out)


def parse_login7(payload: bytes) -> Login7:
    n = len(payload)
    if n < LOGIN7_FIXED:
        raise TdsError("login7_short")
    total = struct.unpack_from("<I", payload, 0)[0]
    if total > n or total < LOGIN7_FIXED:
        raise TdsError("login7_length")
    payload = payload[:total]
    n = total
    out = Login7()
    out.tds_version = struct.unpack_from("<I", payload, 4)[0]
    out.packet_size = struct.unpack_from("<I", payload, 8)[0]
    out.client_pid = struct.unpack_from("<I", payload, 16)[0]
    out.sspi = bool(payload[25] & 0x80)  # OptionFlags2: fIntSecurity
    out.read_only_intent = bool(payload[26] & 0x20)  # TypeFlags: fReadOnlyIntent

    def field_at(slot: int, cap: int, name: str) -> bytes:
        ib, cch = struct.unpack_from("<HH", payload, 36 + 4 * slot)
        if cch == 0:
            return b""
        if ib < LOGIN7_FIXED or ib + 2 * cch > n:
            raise TdsError("login7_field_" + name)
        if cch > cap:
            out.truncated.append(name)
            cch = cap
        return payload[ib : ib + 2 * cch]

    def text(slot: int, name: str, cap: int = MAX_FIELD_CHARS) -> str:
        return field_at(slot, cap, name).decode("utf-16-le", "replace")

    out.hostname = text(0, "hostname")
    out.username = text(1, "username")
    out.password = decode_password(field_at(2, MAX_PASSWORD_CHARS, "password"))
    out.app_name = text(3, "app_name")
    out.server_name = text(4, "server_name")
    out.library = text(6, "library")
    out.language = text(7, "language")
    out.database = text(8, "database")
    out.extension = bool(payload[27] & 0x10)  # OptionFlags3: fExtension
    ib, cb = struct.unpack_from("<HH", payload, 78)
    if cb:
        out.sspi = True
        if LOGIN7_FIXED <= ib and ib + cb <= n:
            out.sspi_token = payload[ib : ib + min(cb, 4096)]
    return out


# --- ALL_HEADERS / batch / RPC ------------------------------------------------------------

MAX_SQL_BYTES = 64 * 1024  # raw bytes of statement text decoded per batch (32 K characters)


def _skip_all_headers(payload: bytes) -> int:
    if len(payload) >= 4:
        total = int(struct.unpack_from("<I", payload, 0)[0])
        if 4 <= total <= len(payload) and total <= 4096:
            return total
    return 0


def parse_batch(payload: bytes) -> str:
    start = _skip_all_headers(payload)
    raw = payload[start : start + MAX_SQL_BYTES]
    return raw[: len(raw) & ~1].decode("utf-16-le", "replace")


KNOWN_PROC_IDS = {
    1: "sp_cursor",
    2: "sp_cursoropen",
    3: "sp_cursorprepare",
    4: "sp_cursorexecute",
    5: "sp_cursorprepexec",
    6: "sp_cursorunprepare",
    7: "sp_cursorfetch",
    8: "sp_cursoroption",
    9: "sp_cursorclose",
    10: "sp_executesql",
    11: "sp_prepare",
    12: "sp_execute",
    13: "sp_prepexec",
    14: "sp_prepexecrpc",
    15: "sp_unprepare",
}


def _read_plp(payload: bytes, pos: int) -> bytes:
    """Chunks of a PLP value: 8 byte total length, then (u32 length, data) until a zero chunk."""
    n = len(payload)
    if pos + 8 > n:
        return b""
    pos += 8
    out = bytearray()
    while pos + 4 <= n and len(out) < MAX_SQL_BYTES:
        size = int(struct.unpack_from("<I", payload, pos)[0])
        pos += 4
        if size == 0 or pos + size > n:
            break
        out += payload[pos : pos + min(size, MAX_SQL_BYTES - len(out))]
        pos += size
    return bytes(out)


def parse_rpc(payload: bytes) -> tuple[str, str]:
    """Return ``(procedure name, first string parameter)``, best effort and fully bounded."""
    pos = _skip_all_headers(payload)
    n = len(payload)
    if pos + 2 > n:
        raise TdsError("rpc_short")
    nlen = struct.unpack_from("<H", payload, pos)[0]
    pos += 2
    if nlen == 0xFFFF:
        if pos + 2 > n:
            raise TdsError("rpc_short")
        proc = KNOWN_PROC_IDS.get(struct.unpack_from("<H", payload, pos)[0], "sp_unknown")
        pos += 2
    else:
        if nlen > 128 or pos + 2 * nlen > n:
            raise TdsError("rpc_name")
        proc = payload[pos : pos + 2 * nlen].decode("utf-16-le", "replace")
        pos += 2 * nlen
    pos += 2  # option flags
    # First parameter: B_VARCHAR name, status byte, TYPE_INFO, value.
    first = ""
    try:
        if pos < n:
            pos += 1 + 2 * payload[pos]
            pos += 1
            if pos < n and payload[pos] in (0xE7, 0xEF, 0xA7, 0xAF):
                ctype = payload[pos]
                maxlen = struct.unpack_from("<H", payload, pos + 1)[0]
                pos += 1 + 2 + 5
                if maxlen == 0xFFFF:  # (N)VARCHAR(MAX): partially length-prefixed stream
                    raw = _read_plp(payload, pos)
                    if ctype in (0xE7, 0xEF):
                        first = raw[: len(raw) & ~1].decode("utf-16-le", "replace")
                    else:
                        first = raw.decode("latin-1")
                elif pos + 2 <= n:
                    vlen = struct.unpack_from("<H", payload, pos)[0]
                    pos += 2
                    if vlen != 0xFFFF and pos + vlen <= n:
                        raw = payload[pos : pos + min(vlen, MAX_SQL_BYTES)]
                        if ctype in (0xE7, 0xEF):
                            first = raw[: len(raw) & ~1].decode("utf-16-le", "replace")
                        else:
                            first = raw.decode("latin-1")
    except (IndexError, struct.error):
        first = ""
    return proc, first


# --- response model and tokens ----------------------------------------------------------

K_STR, K_INT, K_DATETIME = "s", "i", "d"

TOKEN_COLMETADATA = 0x81
TOKEN_ERROR = 0xAA
TOKEN_INFO = 0xAB
TOKEN_LOGINACK = 0xAD
TOKEN_ROW = 0xD1
TOKEN_RETURNSTATUS = 0x79
TOKEN_ENVCHANGE = 0xE3
TOKEN_FEATUREEXTACK = 0xAE
TOKEN_SSPI = 0xED
TOKEN_DONE = 0xFD
TOKEN_DONEPROC = 0xFE
TOKEN_DONEINPROC = 0xFF

DONE_MORE = 0x0001
DONE_ERROR = 0x0002
DONE_COUNT = 0x0010
DONE_ATTN = 0x0020

COLLATION = bytes([0x09, 0x04, 0xD0, 0x00, 0x34])  # SQL_Latin1_General_CP1_CI_AS

Cell = str | int | float | None


@dataclass(frozen=True)
class Column:
    name: str
    kind: str = K_STR


@dataclass(frozen=True)
class Msg:
    """An INFO or ERROR token."""

    number: int
    text: str
    cls: int = 0
    state: int = 1
    error: bool = False


@dataclass(frozen=True)
class Env:
    kind: int  # 1 database, 2 language, 4 packet size
    new: str
    old: str = ""


@dataclass
class Statement:
    messages: list[Msg | Env] = field(default_factory=list)
    columns: list[Column] = field(default_factory=list)
    rows: list[list[Cell]] = field(default_factory=list)
    curcmd: int = 0
    count: int | None = None  # rows affected (DONE_COUNT) when not a result set
    failed: bool = False


def b_varchar(text: str) -> bytes:
    text = text[:255]
    return bytes([len(text)]) + text.encode("utf-16-le")


def us_varchar(text: str) -> bytes:
    text = text[:4000]
    return struct.pack("<H", len(text)) + text.encode("utf-16-le")


def done(status: int, curcmd: int, count: int, ver: int, token: int = TOKEN_DONE) -> bytes:
    fmt = "<BHHQ" if ver >= 0x72000000 else "<BHHI"
    return struct.pack(fmt, token, status, curcmd, count)


def _msg_token(msg: Msg, server: str, ver: int) -> bytes:
    body = (
        struct.pack("<IBB", msg.number, msg.state, msg.cls)
        + us_varchar(msg.text)
        + b_varchar(server)
        + b_varchar("")
        + struct.pack("<I" if ver >= 0x72000000 else "<H", 1)
    )
    return bytes([TOKEN_ERROR if msg.error else TOKEN_INFO]) + struct.pack("<H", len(body)) + body


def env_token(kind: int, new: str, old: str = "") -> bytes:
    body = bytes([kind]) + b_varchar(new) + b_varchar(old)
    return bytes([TOKEN_ENVCHANGE]) + struct.pack("<H", len(body)) + body


def collation_env() -> bytes:
    body = bytes([7, len(COLLATION)]) + COLLATION + b"\x00"
    return bytes([TOKEN_ENVCHANGE]) + struct.pack("<H", len(body)) + body


def loginack(tds_version: int, version: tuple[int, int, int, int]) -> bytes:
    major, minor, build, _sub = version
    name = "Microsoft SQL Server"
    body = (
        bytes([1])
        + struct.pack(">I", tds_version)
        + bytes([len(name)])
        + name.encode("utf-16-le")
        + bytes([major, minor, (build >> 8) & 0xFF, build & 0xFF])
    )
    return bytes([TOKEN_LOGINACK]) + struct.pack("<H", len(body)) + body


def _typeinfo(col: Column, width: int) -> bytes:
    if col.kind == K_INT:
        return b"\x38"
    if col.kind == K_DATETIME:
        return b"\x3d"
    return b"\xe7" + struct.pack("<H", min(8000, 2 * width)) + COLLATION


def _width(index: int, rows: list[list[Cell]]) -> int:
    """Declared character width of a string column: 128 or what its longest value needs."""
    longest = max(
        (len(str(r[index]).encode("utf-16-le")) // 2 for r in rows if r[index] is not None),
        default=0,
    )
    return max(128, longest)


def colmetadata(cols: list[Column], ver: int, rows: list[list[Cell]] | None = None) -> bytes:
    out = bytearray([TOKEN_COLMETADATA]) + struct.pack("<H", len(cols))
    for i, col in enumerate(cols):
        out += struct.pack("<I" if ver >= 0x72000000 else "<H", 0)
        out += struct.pack("<H", 0x0009 if col.kind == K_STR else 0x0008)
        out += _typeinfo(col, _width(i, rows or [])) + b_varchar(col.name)
    return bytes(out)


_EPOCH_DAYS = 25567  # 1900-01-01 .. 1970-01-01


def row_token(cols: list[Column], row: list[Cell]) -> bytes:
    out = bytearray([TOKEN_ROW])
    for col, cell in zip(cols, row, strict=False):
        if col.kind == K_INT:
            out += struct.pack("<i", int(cell or 0))
        elif col.kind == K_DATETIME:
            ts = float(cell or 0)
            days, rem = divmod(ts, 86400)
            out += struct.pack("<iI", int(days) + _EPOCH_DAYS, int(rem * 300))
        elif cell is None:
            out += b"\xff\xff"
        else:
            raw = str(cell)[:4000].encode("utf-16-le")
            out += struct.pack("<H", len(raw)) + raw
    return bytes(out)


def encode_statements(
    stmts: list[Statement],
    ver: int,
    server: str,
    rpc: bool = False,
) -> bytes:
    """Serialize statements into one reply message (without packet framing)."""
    out = bytearray()
    for i, st in enumerate(stmts):
        last = i == len(stmts) - 1
        for msg in st.messages:
            if isinstance(msg, Env):
                out += env_token(msg.kind, msg.new, msg.old)
            else:
                out += _msg_token(msg, server, ver)
        status = (0 if last else DONE_MORE) | (DONE_ERROR if st.failed else 0)
        if st.columns:
            out += colmetadata(st.columns, ver, st.rows)
            for row in st.rows:
                out += row_token(st.columns, row)
            status |= DONE_COUNT
            count = len(st.rows)
        elif st.count is not None:
            status |= DONE_COUNT
            count = st.count
        else:
            count = 0
        token = TOKEN_DONE
        if rpc:
            token = TOKEN_DONEPROC if last else TOKEN_DONEINPROC
            if last:
                out += bytes([TOKEN_RETURNSTATUS]) + struct.pack("<i", 1 if st.failed else 0)
        out += done(status, st.curcmd, count, ver, token)
    if not stmts:
        out += done(0, 0, 0, ver)
    return bytes(out)


def login_ok_message(
    tds_version: int,
    version: tuple[int, int, int, int],
    packet_size: int,
    database: str,
    server: str,
    features: bool = False,
) -> bytes:
    ver = tds_version
    out = bytearray()
    out += env_token(1, database, "")
    out += _msg_token(Msg(5701, f"Changed database context to '{database}'.", 0, 2), server, ver)
    out += env_token(2, "us_english", "")
    out += _msg_token(Msg(5703, "Changed language setting to us_english.", 0, 1), server, ver)
    out += collation_env()
    out += env_token(4, str(packet_size), "4096")
    out += loginack(tds_version, version)
    if features:  # the client sent a LOGIN7 extension block: acknowledge none of its features
        out += bytes([TOKEN_FEATUREEXTACK, 0xFF])
    out += done(0, 0, 0, ver)
    return bytes(out)


UNTRUSTED_DOMAIN = (
    "Login failed. The login is from an untrusted domain and cannot be used with "
    "Windows authentication."
)


def login_failed_message(
    username: str, tds_version: int, server: str, untrusted: bool = False
) -> bytes:
    if untrusted:
        msg = Msg(18452, UNTRUSTED_DOMAIN, 14, 1, error=True)
    else:
        msg = Msg(18456, f"Login failed for user '{username[:128]}'.", 14, 1, error=True)
    out = _msg_token(msg, server, tds_version)
    return out + done(DONE_ERROR, 0, 0, tds_version)


def map_tds_version(requested: int) -> int:
    """The nearest real TDS version not above what the client asked for."""
    for floor, real in (
        (0x74000000, 0x74000004),
        (0x730B0000, 0x730B0003),
        (0x730A0000, 0x730A0003),
        (0x72000000, 0x72090002),
        (0x71000000, 0x71000001),
    ):
        if requested >= floor:
            return real
    return 0x70000000


# --- NTLM (Windows authentication over SSPI) -----------------------------------------------

NTLM_SIG = b"NTLMSSP\x00"
_FILETIME_EPOCH = 11644473600


def sspi_token(data: bytes) -> bytes:
    return bytes([TOKEN_SSPI]) + struct.pack("<H", len(data)) + data


def ntlm_challenge(
    challenge: bytes,
    netbios_computer: str,
    netbios_domain: str,
    dns_domain: str,
    now: float,
    win_build: int = 20348,
) -> bytes:
    """An NTLM CHALLENGE_MESSAGE like a domain-less Windows Server 2019/2022 sends."""

    def av(kind: int, value: bytes) -> bytes:
        return struct.pack("<HH", kind, len(value)) + value

    comp = netbios_computer.encode("utf-16-le")
    dom = netbios_domain.encode("utf-16-le")
    info = (
        av(2, dom)
        + av(1, comp)
        + av(4, dns_domain.encode("utf-16-le"))
        + av(5, dns_domain.encode("utf-16-le"))
        + av(3, (netbios_computer + "." + dns_domain).encode("utf-16-le"))
        + av(7, struct.pack("<Q", int((now + _FILETIME_EPOCH) * 10_000_000)))
        + av(0, b"")
    )
    fixed = 56
    flags = 0xE2898215
    return (
        NTLM_SIG
        + struct.pack("<I", 2)
        + struct.pack("<HHI", len(dom), len(dom), fixed)
        + struct.pack("<I", flags)
        + challenge
        + bytes(8)
        + struct.pack("<HHI", len(info), len(info), fixed + len(dom))
        + bytes([10, 0])
        + struct.pack("<H", win_build)
        + bytes([0, 0, 0, 15])
        + dom
        + info
    )


@dataclass
class NtlmAuth:
    domain: str = ""
    user: str = ""
    workstation: str = ""
    nt_response_len: int = 0
    nt_response_preview: str = ""


def parse_ntlm_authenticate(data: bytes) -> NtlmAuth:
    """Bounded decode of an NTLM AUTHENTICATE_MESSAGE; only a short hash preview is kept."""
    if len(data) < 52 or data[:8] != NTLM_SIG or struct.unpack_from("<I", data, 8)[0] != 3:
        raise TdsError("ntlm_message")

    def field_at(at: int, cap: int) -> bytes:
        length, _max, off = struct.unpack_from("<HHI", data, at)
        if length == 0:
            return b""
        if off + length > len(data):
            raise TdsError("ntlm_field")
        return data[off : off + min(length, cap)]

    nt = field_at(20, 4096)
    return NtlmAuth(
        domain=field_at(28, 128).decode("utf-16-le", "replace"),
        user=field_at(36, 128).decode("utf-16-le", "replace"),
        workstation=field_at(44, 128).decode("utf-16-le", "replace"),
        nt_response_len=len(nt),
        nt_response_preview=nt[:8].hex(),
    )
