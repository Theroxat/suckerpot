"""TPKT / X.224 / RDP negotiation: strict, bounded, hand-written parsing (no regex).

References: RFC 1006 (TPKT), ITU-T X.224 class 0, MS-RDPBCGR 2.2.1.1 (Client X.224 Connection
Request PDU) and 2.2.1.2 (Server X.224 Connection Confirm PDU).

Everything here is a pure function over ``bytes``: no I/O, no state, linear time in the input
length, and inputs are never longer than a few KiB because the server caps its reads.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

TPKT_VERSION = 3
TPKT_HEADER = 4
X224_CR = 0xE0
X224_CC = 0xD0
X224_DT = 0xF0
# The X.224 length indicator is one byte, so a Connection Request TPKT is at most 4 + 1 + 255.
MAX_CR_TPKT = TPKT_HEADER + 1 + 255
MIN_CR_TPKT = TPKT_HEADER + 7
# Any later TPKT we are willing to buffer (e.g. an MCS Connect Initial from a legacy client).
MAX_TPKT = 8192

TYPE_RDP_NEG_REQ = 0x01
TYPE_RDP_NEG_RSP = 0x02
TYPE_RDP_NEG_FAILURE = 0x03
TYPE_RDP_CORRELATION_INFO = 0x06
CORRELATION_INFO_PRESENT = 0x08

PROTOCOL_RDP = 0x00
PROTOCOL_SSL = 0x01
PROTOCOL_HYBRID = 0x02
PROTOCOL_RDSTLS = 0x04
PROTOCOL_HYBRID_EX = 0x08
PROTOCOL_RDSAAD = 0x10

PROTOCOL_NAMES: tuple[tuple[int, str], ...] = (
    (PROTOCOL_SSL, "SSL"),
    (PROTOCOL_HYBRID, "HYBRID"),
    (PROTOCOL_RDSTLS, "RDSTLS"),
    (PROTOCOL_HYBRID_EX, "HYBRID_EX"),
    (PROTOCOL_RDSAAD, "RDSAAD"),
)

# RDP_NEG_FAILURE codes (MS-RDPBCGR 2.2.1.2.2).
HYBRID_REQUIRED_BY_SERVER = 0x05
FAILURE_NAMES = {
    0x01: "SSL_REQUIRED_BY_SERVER",
    0x02: "SSL_NOT_ALLOWED_BY_SERVER",
    0x03: "SSL_CERT_NOT_ON_SERVER",
    0x04: "INCONSISTENT_FLAGS",
    0x05: "HYBRID_REQUIRED_BY_SERVER",
    0x06: "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER",
}

# Flags a Windows Server 2016+ host sets in its RDP_NEG_RSP: EXTENDED_CLIENT_DATA_SUPPORTED,
# DYNVC_GFX_PROTOCOL_SUPPORTED, NEGRSP_FLAG_RESERVED, RESTRICTED_ADMIN_MODE_SUPPORTED,
# REDIRECTED_AUTHENTICATION_MODE_SUPPORTED.
WINDOWS_NEG_RSP_FLAGS = 0x1F
# Windows always answers with this X.224 source reference.
WINDOWS_SRC_REF = 0x1234

COOKIE_MSTSHASH = b"Cookie: mstshash="
COOKIE_MSTS = b"Cookie: msts="
COOKIE_PREFIX = b"Cookie: "
CRLF = b"\r\n"


class ParseError(ValueError):
    """The bytes are not a well-formed X.224 Connection Request. ``reason`` is a short tag."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class ConnectionRequest:
    tpkt_length: int
    dst_ref: int
    src_ref: int
    class_option: int
    username: str | None = None  # from "Cookie: mstshash=<name>"
    routing_token: str | None = None  # from "Cookie: msts=<token>"
    other_cookie: str | None = None  # any other "Cookie: ..." line
    cookie_unterminated: bool = False
    neg_present: bool = False
    neg_flags: int = 0
    requested_protocols: int = 0
    correlation_id: str | None = None  # hex
    trailing_bytes: int = 0
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def requested_protocol_names(self) -> list[str]:
        return protocol_names(self.requested_protocols) if self.neg_present else []


def protocol_names(mask: int) -> list[str]:
    names = [name for bit, name in PROTOCOL_NAMES if mask & bit]
    return names or ["RDP"]


def tpkt_length(buf: bytes) -> int:
    """Return the TPKT length from a header, or raise ParseError. Needs at least 4 bytes."""
    if len(buf) < TPKT_HEADER:
        raise ParseError("short_tpkt_header")
    if buf[0] != TPKT_VERSION or buf[1] != 0:
        raise ParseError("bad_tpkt_version")
    length = (buf[2] << 8) | buf[3]
    if length < MIN_CR_TPKT:
        raise ParseError("tpkt_too_short")
    if length > MAX_TPKT:
        raise ParseError("tpkt_too_long")
    return length


def _decode(raw: bytes) -> str:
    return raw.decode("utf-8", "replace")


def parse_connection_request(packet: bytes) -> ConnectionRequest:
    """Parse one complete TPKT carrying an X.224 Connection Request.

    ``packet`` must be exactly ``tpkt_length`` bytes long (extra bytes are the caller's job).
    Framing errors raise :class:`ParseError`; tolerable oddities are listed in ``notes``.
    """
    length = tpkt_length(packet)
    if length > MAX_CR_TPKT:
        raise ParseError("cr_too_long")
    if len(packet) != length:
        raise ParseError("length_mismatch")
    li = packet[4]
    if li + 5 != length:
        raise ParseError("bad_length_indicator")
    if li < 6:
        raise ParseError("li_too_short")
    code = packet[5]
    if code & 0xF0 != X224_CR:
        raise ParseError("not_connection_request")
    notes: list[str] = []
    if code & 0x0F:
        notes.append("nonzero_cdt")
    dst_ref, src_ref = struct.unpack_from(">HH", packet, 6)
    class_option = packet[10]
    if dst_ref:
        notes.append("nonzero_dst_ref")
    if class_option & 0xF0:
        notes.append("non_class0")

    var = packet[11:length]
    pos = 0
    username: str | None = None
    routing: str | None = None
    other: str | None = None
    unterminated = False
    if var.startswith(COOKIE_PREFIX):
        end = var.find(CRLF)
        if end < 0:
            unterminated = True
            end = len(var)
            notes.append("cookie_unterminated")
        line = var[:end]
        pos = min(len(var), end + len(CRLF))
        if line.startswith(COOKIE_MSTSHASH):
            username = _decode(line[len(COOKIE_MSTSHASH) :])
        elif line.startswith(COOKIE_MSTS):
            routing = _decode(line[len(COOKIE_MSTS) :])
        else:
            other = _decode(line[len(COOKIE_PREFIX) :])

    neg_present = False
    neg_flags = 0
    protocols = 0
    correlation: str | None = None
    rest = var[pos:]
    if len(rest) >= 8 and rest[0] == TYPE_RDP_NEG_REQ:
        _neg_type, neg_flags, neg_len, protocols = struct.unpack_from("<BBHI", rest, 0)
        if neg_len != 8:
            raise ParseError("bad_neg_req_length")
        neg_present = True
        rest = rest[8:]
        if neg_flags & CORRELATION_INFO_PRESENT:
            if len(rest) >= 36 and rest[0] == TYPE_RDP_CORRELATION_INFO:
                corr_len = struct.unpack_from("<H", rest, 2)[0]
                if corr_len != 36:
                    raise ParseError("bad_correlation_length")
                correlation = rest[4:20].hex()
                rest = rest[36:]
            else:
                notes.append("correlation_flag_without_info")
        if protocols & ~0x1F:
            notes.append("unknown_protocol_bits")
    elif rest:
        notes.append("unparsed_variable_data")
    return ConnectionRequest(
        tpkt_length=length,
        dst_ref=dst_ref,
        src_ref=src_ref,
        class_option=class_option,
        username=username,
        routing_token=routing,
        other_cookie=other,
        cookie_unterminated=unterminated,
        neg_present=neg_present,
        neg_flags=neg_flags,
        requested_protocols=protocols,
        correlation_id=correlation,
        trailing_bytes=len(rest),
        notes=tuple(notes),
    )


@dataclass(frozen=True)
class Negotiation:
    """What the server answers to a Connection Request."""

    response: bytes
    outcome: str  # "legacy" | "selected" | "failure"
    selected_protocol: int | None = None
    failure_code: int | None = None

    @property
    def summary(self) -> str:
        if self.outcome == "selected" and self.selected_protocol is not None:
            return protocol_names(self.selected_protocol)[0]
        if self.outcome == "failure" and self.failure_code is not None:
            return FAILURE_NAMES.get(self.failure_code, f"0x{self.failure_code:02x}")
        return "legacy"


def _connection_confirm(neg: bytes = b"") -> bytes:
    li = 6 + len(neg)
    header = struct.pack(">BBHH", li, X224_CC, 0, WINDOWS_SRC_REF) + b"\x00"
    body = header + neg
    return struct.pack(">BBH", TPKT_VERSION, 0, TPKT_HEADER + len(body)) + body


def negotiation_response(selected: int) -> bytes:
    return _connection_confirm(
        struct.pack("<BBHI", TYPE_RDP_NEG_RSP, WINDOWS_NEG_RSP_FLAGS, 8, selected)
    )


def negotiation_failure(code: int) -> bytes:
    return _connection_confirm(struct.pack("<BBHI", TYPE_RDP_NEG_FAILURE, 0, 8, code))


def legacy_confirm() -> bytes:
    return _connection_confirm()


def negotiate(cr: ConnectionRequest, *, allow_ssl: bool = False) -> Negotiation:
    """Behave like Windows Server 2022 with Network Level Authentication required.

    With ``allow_ssl`` (the "NLA disabled" mode) a client that offers only ``PROTOCOL_SSL`` is
    accepted with SSL selected, so the MCS connect sequence can run to the Client Info PDU.
    CredSSP is still preferred when the client offers it, exactly as a real host that also
    advertises NLA does. A client offering only standard RDP security is always refused.
    """
    if not cr.neg_present:
        # No RDP_NEG_REQ: a pre-RDP-5.2 client. Windows confirms without negotiation data and
        # drops the connection once the client sends its MCS Connect Initial.
        return Negotiation(legacy_confirm(), "legacy")
    if cr.requested_protocols & PROTOCOL_HYBRID_EX:
        return Negotiation(negotiation_response(PROTOCOL_HYBRID_EX), "selected", PROTOCOL_HYBRID_EX)
    if cr.requested_protocols & PROTOCOL_HYBRID:
        return Negotiation(negotiation_response(PROTOCOL_HYBRID), "selected", PROTOCOL_HYBRID)
    if allow_ssl and cr.requested_protocols & PROTOCOL_SSL:
        return Negotiation(negotiation_response(PROTOCOL_SSL), "selected", PROTOCOL_SSL)
    return Negotiation(
        negotiation_failure(HYBRID_REQUIRED_BY_SERVER),
        "failure",
        failure_code=HYBRID_REQUIRED_BY_SERVER,
    )


def build_connection_request(
    *,
    cookie: bytes | None = None,
    protocols: int | None = None,
    flags: int = 0,
    correlation: bytes | None = None,
) -> bytes:
    """Client-side builder, used by the healthcheck and the tests."""
    var = b""
    if cookie is not None:
        var += cookie + CRLF
    if protocols is not None:
        if correlation is not None:
            flags |= CORRELATION_INFO_PRESENT
        var += struct.pack("<BBHI", TYPE_RDP_NEG_REQ, flags, 8, protocols)
        if correlation is not None:
            var += struct.pack("<BBH", TYPE_RDP_CORRELATION_INFO, 0, 36) + correlation[:16].ljust(
                16, b"\x00"
            )
            var += b"\x00" * 16
    li = 6 + len(var)
    body = struct.pack(">BBHHB", li, X224_CR, 0, 0, 0) + var
    return struct.pack(">BBH", TPKT_VERSION, 0, TPKT_HEADER + len(body)) + body
