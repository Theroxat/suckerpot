"""MCS / GCC for the optional "NLA disabled" path (standard RDP security over TLS).

When ``SENSOR_RDP_NLA_MODE=optional`` the sensor selects ``PROTOCOL_SSL`` for a client that
offers it, completes the TLS handshake, then plays the MCS connect sequence just far enough to
receive the Client Info PDU, which carries the cleartext domain / user name / password:

    Connect Initial  -> Connect Response
    Erect Domain     (no reply)
    Attach User      -> Attach User Confirm
    Channel Joins    -> Channel Join Confirms
    Client Info PDU  -> recorded, then a plausible teardown

No bitmap, licensing or real session is ever produced. Everything here is byte assembly and a
bounded, hand-written reader: no regex, no recursion on attacker-controlled depth, every length
read with a cap and never indexed past the buffer. Reference layouts: MS-RDPBCGR 2.2.1.3/1.5
and the 4.1 worked examples; T.125 PER for the domain MCSPDUs.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Final

# X.224 Data (DT) over TPKT framing used by every post-confirm PDU.
TPKT_VERSION: Final = 3
X224_DT_HEADER: Final = b"\x02\xf0\x80"  # LI=2, DT, EOT

# Domain MCSPDU choice indices (<< 2 in the first byte; low bits carry PER preamble flags).
ERECT_DOMAIN: Final = 0x04  # 1 << 2
ATTACH_USER_REQUEST: Final = 0x28  # 10 << 2
ATTACH_USER_CONFIRM: Final = 0x2E  # (11 << 2) | result/initiator preamble
CHANNEL_JOIN_REQUEST: Final = 0x38  # 14 << 2
CHANNEL_JOIN_CONFIRM: Final = 0x3E  # (15 << 2) | preamble
SEND_DATA_REQUEST: Final = 0x64  # 25 << 2
DISCONNECT_ULTIMATUM: Final = 0x20  # 8 << 2

MCS_IO_CHANNEL: Final = 1003  # the global / IO channel the Client Info PDU travels on
MCS_USER_CHANNEL: Final = 1007  # the user channel we hand out (base 1001 + 6)
MCS_BASE_CHANNEL: Final = 1001

# GCC client data block types (little-endian on the wire).
CS_CORE: Final = 0xC001
CS_SECURITY: Final = 0xC002
CS_NET: Final = 0xC003
CS_CLUSTER: Final = 0xC004
# GCC server data block types.
SC_CORE: Final = 0x0C01
SC_SECURITY: Final = 0x0C02
SC_NET: Final = 0x0C03

# Client Info PDU security flags.
SEC_INFO_PKT: Final = 0x0040
INFO_UNICODE: Final = 0x00000010

MAX_FIELD: Final = 256  # cap on any captured string, before truncate_data caps it again
MAX_BLOCKS: Final = 16
MAX_CHANNELS: Final = 31


class McsError(ValueError):
    """The bytes are not a well-formed MCS / GCC structure we accept."""


# --- framing ---------------------------------------------------------------------------------


def wrap(payload: bytes) -> bytes:
    """Wrap an MCS payload in X.224 Data over TPKT."""
    total = 4 + len(X224_DT_HEADER) + len(payload)
    return struct.pack(">BBH", TPKT_VERSION, 0, total) + X224_DT_HEADER + payload


def unwrap(packet: bytes) -> bytes:
    """Return the MCS payload of one TPKT/X.224-Data packet (``packet`` is exactly that TPKT)."""
    if len(packet) < 7 or packet[0] != TPKT_VERSION:
        raise McsError("not_tpkt")
    li = packet[4]  # X.224 length indicator
    start = 5 + li
    if li < 2 or start > len(packet):
        raise McsError("bad_x224")
    return packet[start:]


# --- GCC client data -------------------------------------------------------------------------


@dataclass
class ClientCore:
    version: int = 0
    keyboard_layout: int = 0
    client_build: int = 0
    client_name: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "client_build": self.client_build,
            "client_name": self.client_name,
            "keyboard_layout": f"0x{self.keyboard_layout:08x}",
            "rdp_version": f"0x{self.version:08x}",
        }


@dataclass
class ClientMcsData:
    core: ClientCore = field(default_factory=ClientCore)
    channel_count: int = 0
    channel_names: list[str] = field(default_factory=list)


def _u16(buf: bytes, off: int) -> int:
    return int(struct.unpack_from("<H", buf, off)[0])


def _u32(buf: bytes, off: int) -> int:
    return int(struct.unpack_from("<I", buf, off)[0])


def _parse_core(body: bytes) -> ClientCore:
    core = ClientCore()
    if len(body) >= 4:
        core.version = _u32(body, 0)
    if len(body) >= 16:
        core.keyboard_layout = _u32(body, 12)
    if len(body) >= 20:
        core.client_build = _u32(body, 16)
    if len(body) >= 52:
        raw = body[20:52]
        core.client_name = raw.decode("utf-16-le", "replace").split("\x00", 1)[0][:MAX_FIELD]
    return core


def _parse_net(body: bytes) -> tuple[int, list[str]]:
    if len(body) < 4:
        return 0, []
    count = min(_u32(body, 0), MAX_CHANNELS)
    names: list[str] = []
    pos = 4
    for _ in range(count):
        if pos + 12 > len(body):
            break
        name = body[pos : pos + 8].split(b"\x00", 1)[0].decode("latin-1", "replace")
        names.append(name[:MAX_FIELD])
        pos += 12
    return count, names


def parse_client_data(user_data: bytes) -> ClientMcsData:
    """Parse the GCC client data blocks from a Connect Initial's userData.

    We anchor on the first ``CS_CORE`` block header (``01 c0``) and then read fixed TLV blocks
    (little-endian ``type``, ``length``), which avoids a full PER descent of the GCC wrapper.
    """
    data = ClientMcsData()
    # The client data blocks follow the "Duca" H.221 key; search for CS_CORE after it so the
    # ``00 01 c0 00`` that also appears in the GCC wrapper prefix cannot be mistaken for it.
    duca = user_data.find(b"Duca")
    anchor = user_data.find(b"\x01\xc0", duca + 4 if duca >= 0 else 0)
    if anchor < 0:
        return data
    pos = anchor
    end = len(user_data)
    for _ in range(MAX_BLOCKS):
        if pos + 4 > end:
            break
        block_type = _u16(user_data, pos)
        block_len = _u16(user_data, pos + 2)
        if block_len < 4 or pos + block_len > end:
            break
        body = user_data[pos + 4 : pos + block_len]
        if block_type == CS_CORE:
            data.core = _parse_core(body)
        elif block_type == CS_NET:
            data.channel_count, data.channel_names = _parse_net(body)
        pos += block_len
    return data


# --- Connect Response ------------------------------------------------------------------------


def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes((n,))
    out = []
    while n:
        out.append(n & 0xFF)
        n >>= 8
    out.reverse()
    return bytes((0x80 | len(out), *out))


def _ber(tag: int, content: bytes) -> bytes:
    return bytes((tag,)) + _ber_len(len(content)) + content


def _per_len(n: int) -> bytes:
    """PER length determinant (semi-constrained, < 16 KiB)."""
    if n < 0x80:
        return bytes((n,))
    return bytes((0x80 | (n >> 8), n & 0xFF))


def _server_data(channel_count: int, requested_protocol: int) -> bytes:
    """SC_CORE + SC_NET + SC_SECURITY (TLS: encryption method and level both none)."""
    # SC_CORE version 0x00080005 (RDP 8+), as a current Windows Server returns.
    sc_core = struct.pack("<HHII", SC_CORE, 12, 0x00080005, requested_protocol)
    # SC_NET: IO channel + one allocated id per requested virtual channel, 4-byte aligned.
    ids = b"".join(struct.pack("<H", 1004 + i) for i in range(channel_count))
    pad = b"\x00\x00" if channel_count % 2 else b""
    net_body = struct.pack("<HH", MCS_IO_CHANNEL, channel_count) + ids + pad
    sc_net = struct.pack("<HH", SC_NET, 4 + len(net_body)) + net_body
    sc_sec = struct.pack("<HHII", SC_SECURITY, 12, 0, 0)
    return sc_core + sc_net + sc_sec


# GCC ConferenceCreateResponse prefix up to and including the "McDn" H.221 key (MS-RDPBCGR 4.1.4).
_GCC_CCR_PREFIX: Final = bytes.fromhex("000500147c00012a14760a01010001c0004d63446e")


def build_connect_response(channel_count: int, requested_protocol: int) -> bytes:
    """Build the MCS Connect Response carrying the GCC ConferenceCreateResponse."""
    blocks = _server_data(channel_count, requested_protocol)
    gcc = _GCC_CCR_PREFIX + _per_len(len(blocks)) + blocks
    domain_params = (
        _ber(0x02, b"\x22")  # maxChannelIds
        + _ber(0x02, b"\x02")  # maxUserIds
        + _ber(0x02, b"\x00")  # maxTokenIds
        + _ber(0x02, b"\x01")  # numPriorities
        + _ber(0x02, b"\x00")  # minThroughput
        + _ber(0x02, b"\x01")  # maxHeight
        + _ber(0x02, b"\xff\xff")  # maxMCSPDUsize
        + _ber(0x02, b"\x02")  # protocolVersion
    )
    body = (
        _ber(0x0A, b"\x00")  # result = rt-successful
        + _ber(0x02, b"\x00")  # calledConnectId
        + _ber(0x30, domain_params)  # domainParameters
        + _ber(0x04, gcc)  # userData OCTET STRING
    )
    # Connect-Response is BER [APPLICATION 102] -> the two-byte tag ``7f 66``.
    return wrap(b"\x7f\x66" + _ber_len(len(body)) + body)


# --- domain PDUs -----------------------------------------------------------------------------


def build_attach_user_confirm() -> bytes:
    """Attach User Confirm granting :data:`MCS_USER_CHANNEL` (result rt-successful)."""
    initiator = MCS_USER_CHANNEL - MCS_BASE_CHANNEL
    return wrap(bytes((ATTACH_USER_CONFIRM, 0x00)) + struct.pack(">H", initiator))


@dataclass(frozen=True)
class ChannelJoin:
    initiator: int
    channel_id: int


def parse_channel_join_request(payload: bytes) -> ChannelJoin | None:
    """Parse a Channel Join Request (``38 <initiator u16> <channelId u16>``)."""
    if len(payload) < 5 or payload[0] != CHANNEL_JOIN_REQUEST:
        return None
    initiator = struct.unpack_from(">H", payload, 1)[0] + MCS_BASE_CHANNEL
    channel_id = struct.unpack_from(">H", payload, 3)[0]
    return ChannelJoin(initiator, channel_id)


def build_channel_join_confirm(join: ChannelJoin) -> bytes:
    """Confirm a channel join, echoing the requested and granted channel id."""
    initiator = join.initiator - MCS_BASE_CHANNEL
    return wrap(
        bytes((CHANNEL_JOIN_CONFIRM, 0x00))
        + struct.pack(">H", initiator)
        + struct.pack(">H", join.channel_id)
        + struct.pack(">H", join.channel_id)
    )


def build_disconnect_ultimatum() -> bytes:
    """MCS Disconnect Provider Ultimatum (reason: rn-provider-initiated), a plausible teardown."""
    # per_write_choice(8<<2) | reason enumerated encoding, as a real server tears a session down.
    return wrap(bytes((DISCONNECT_ULTIMATUM | 0x01, 0x80)))


# --- Send Data Request / Client Info PDU -----------------------------------------------------


def parse_send_data_request(payload: bytes) -> tuple[int, bytes] | None:
    """Return ``(channel_id, user_data)`` of a Send Data Request, or None if it is not one."""
    if len(payload) < 7 or payload[0] != SEND_DATA_REQUEST:
        return None
    channel_id = struct.unpack_from(">H", payload, 3)[0]
    pos = 6  # skip choice, initiator(2), channelId(2), dataPriority/segmentation(1)
    first = payload[pos]
    if first & 0x80:
        if pos + 2 > len(payload):
            return None
        length = ((first & 0x7F) << 8) | payload[pos + 1]
        pos += 2
    else:
        length = first
        pos += 1
    user_data = payload[pos : pos + length]
    return channel_id, user_data


@dataclass
class ClientInfo:
    domain: str | None = None
    username: str | None = None
    password: str | None = None
    alternate_shell: str | None = None
    working_dir: str | None = None
    unicode: bool = True

    def to_dict(self) -> dict[str, object]:
        return {
            "domain": self.domain,
            "username": self.username,
            "alternate_shell": self.alternate_shell,
            "working_dir": self.working_dir,
        }


def _info_string(buf: bytes, pos: int, cb: int, unicode: bool) -> tuple[str, int]:
    """Read one TS_INFO_PACKET string (``cb`` bytes, then a null terminator)."""
    raw = buf[pos : pos + cb]
    text = raw.decode("utf-16-le" if unicode else "latin-1", "replace")[:MAX_FIELD]
    terminator = 2 if unicode else 1
    return text, pos + cb + terminator


def parse_client_info(user_data: bytes) -> ClientInfo | None:
    """Parse the Client Info PDU user data (basic security header + TS_INFO_PACKET).

    Returns None if the security header does not mark an info packet. Never raises; a truncated
    packet yields whatever fields were complete.
    """
    if len(user_data) < 4:
        return None
    sec_flags = _u16(user_data, 0)
    if not sec_flags & SEC_INFO_PKT:
        return None
    body = user_data[4:]  # skip basic security header (flags + flagsHi)
    if len(body) < 18:
        return ClientInfo()
    flags = _u32(body, 4)
    unicode = bool(flags & INFO_UNICODE)
    cb_domain = _u16(body, 8)
    cb_user = _u16(body, 10)
    cb_password = _u16(body, 12)
    cb_shell = _u16(body, 14)
    cb_dir = _u16(body, 16)
    # Guard every length against the buffer so a lying cb cannot walk off the end.
    total = cb_domain + cb_user + cb_password + cb_shell + cb_dir
    if total > len(body):
        return ClientInfo(unicode=unicode)
    pos = 18
    info = ClientInfo(unicode=unicode)
    info.domain, pos = _info_string(body, pos, cb_domain, unicode)
    info.username, pos = _info_string(body, pos, cb_user, unicode)
    info.password, pos = _info_string(body, pos, cb_password, unicode)
    info.alternate_shell, pos = _info_string(body, pos, cb_shell, unicode)
    info.working_dir, pos = _info_string(body, pos, cb_dir, unicode)
    return info
