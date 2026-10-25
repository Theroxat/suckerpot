"""A minimal NTLM client, used by the tests to drive the sensor's CredSSP path.

It builds valid NTLM AUTHENTICATE (type 3) messages for both NTLMv2 and NTLMv1 so the sensor's
weak-password verification can be exercised against the real listener. Nothing here is used by
the sensor itself.
"""

from __future__ import annotations

import hashlib
import hmac
import struct

from rdp_sensor.ntlm import _desl, nt_hash

NTLMSSP = b"NTLMSSP\x00"
NEG_UNICODE = 0x00000001
NEG_EXTENDED_SESSION_SECURITY = 0x00080000


def ntowf_v2(password: str, user: str, domain: str) -> bytes:
    ident = (user.upper() + domain).encode("utf-16-le")
    return hmac.new(nt_hash(password), ident, hashlib.md5).digest()


def _field(length: int, offset: int) -> bytes:
    return struct.pack("<HHI", length, length, offset)


def build_authenticate_v2(
    user: str,
    domain: str,
    workstation: str,
    server_challenge: bytes,
    password: str,
    *,
    target_info: bytes = b"",
) -> bytes:
    """An NTLMv2 AUTHENTICATE message for ``password`` against ``server_challenge``."""
    temp = (
        b"\x01\x01\x00\x00\x00\x00\x00\x00"
        + struct.pack("<Q", 0)  # timestamp
        + b"\xaa" * 8  # client challenge
        + b"\x00\x00\x00\x00"
        + target_info
        + b"\x00\x00\x00\x00"
    )
    ntowf = ntowf_v2(password, user, domain)
    proof = hmac.new(ntowf, server_challenge + temp, hashlib.md5).digest()
    nt_response = proof + temp
    return _assemble(user, domain, workstation, lm=b"\x00" * 24, nt=nt_response)


def build_authenticate_v1(
    user: str,
    domain: str,
    workstation: str,
    server_challenge: bytes,
    password: str,
    *,
    ess: bool = False,
) -> bytes:
    """An NTLMv1 AUTHENTICATE message (optionally with extended session security)."""
    nh = nt_hash(password)
    if ess:
        client_challenge = b"\xbb" * 8
        nonce = hashlib.md5(server_challenge + client_challenge).digest()[:8]  # noqa: S324
        nt = _desl(nh, nonce)
        lm = client_challenge + b"\x00" * 16
        flags = NEG_UNICODE | NEG_EXTENDED_SESSION_SECURITY
    else:
        nt = _desl(nh, server_challenge)
        lm = b"\x00" * 24
        flags = NEG_UNICODE
    return _assemble(user, domain, workstation, lm=lm, nt=nt, flags=flags)


def _assemble(
    user: str,
    domain: str,
    workstation: str,
    *,
    lm: bytes,
    nt: bytes,
    flags: int = NEG_UNICODE,
) -> bytes:
    dom = domain.encode("utf-16-le")
    usr = user.encode("utf-16-le")
    wks = workstation.encode("utf-16-le")
    payload = dom + usr + wks + lm + nt
    base = 64  # fixed header through NegotiateFlags
    off_dom = base
    off_usr = off_dom + len(dom)
    off_wks = off_usr + len(usr)
    off_lm = off_wks + len(wks)
    off_nt = off_lm + len(lm)
    header = (
        NTLMSSP
        + struct.pack("<I", 3)
        + _field(len(lm), off_lm)
        + _field(len(nt), off_nt)
        + _field(len(dom), off_dom)
        + _field(len(usr), off_usr)
        + _field(len(wks), off_wks)
        + _field(0, off_nt + len(nt))  # session key (empty)
        + struct.pack("<I", flags)
    )
    assert len(header) == base, len(header)
    return header + payload


# --- MCS / GCC client (NLA-off path) ---------------------------------------------------------

from rdp_sensor import mcs  # noqa: E402


def build_connect_initial(client_name: str, client_build: int, channels: list[str]) -> bytes:
    """A GCC Connect Initial carrying CS_CORE (and CS_NET if ``channels``)."""
    name = client_name.encode("utf-16-le")[:30].ljust(32, b"\x00")
    core_body = (
        struct.pack("<I", 0x00080004)  # version
        + struct.pack("<HHHH", 1024, 768, 0xCA01, 0xAA03)  # width/height/colour/SAS
        + struct.pack("<I", 0x00000409)  # keyboard layout (en-US)
        + struct.pack("<I", client_build)
        + name
    )
    core = struct.pack("<HH", mcs.CS_CORE, 4 + len(core_body)) + core_body
    net = b""
    if channels:
        net_body = struct.pack("<I", len(channels))
        for ch in channels:
            net_body += ch.encode("latin-1")[:8].ljust(8, b"\x00") + struct.pack("<I", 0)
        net = struct.pack("<HH", mcs.CS_NET, 4 + len(net_body)) + net_body
    client_data = core + net
    # "Duca" GCC ConferenceCreateRequest wrapper (prefix is ignored by the sensor, which anchors
    # on the CS_CORE block header), then the client data blocks.
    gcc = bytes.fromhex("000500147c0001812a000800100001c0004475636121")
    gcc += struct.pack(">H", 0x8000 | len(client_data)) + client_data
    payload = b"\x7f\x65" + mcs._ber_len(len(gcc)) + gcc
    return mcs.wrap(payload)


def build_erect_domain() -> bytes:
    return mcs.wrap(bytes((mcs.ERECT_DOMAIN,)) + b"\x01\x00\x01\x00")


def build_attach_user_request() -> bytes:
    return mcs.wrap(bytes((mcs.ATTACH_USER_REQUEST,)))


def build_channel_join_request(initiator: int, channel_id: int) -> bytes:
    body = bytes((mcs.CHANNEL_JOIN_REQUEST,))
    body += struct.pack(">H", initiator - mcs.MCS_BASE_CHANNEL) + struct.pack(">H", channel_id)
    return mcs.wrap(body)


def build_client_info(domain: str, user: str, password: str) -> bytes:
    def enc(text: str) -> bytes:
        return text.encode("utf-16-le")

    dom, usr, pw = enc(domain), enc(user), enc(password)
    shell = b""
    wdir = b""
    info = struct.pack("<II", 0, mcs.INFO_UNICODE)  # codePage, flags
    info += struct.pack("<HHHHH", len(dom), len(usr), len(pw), len(shell), len(wdir))
    for field in (dom, usr, pw, shell, wdir):
        info += field + b"\x00\x00"
    sec_header = struct.pack("<HH", mcs.SEC_INFO_PKT, 0)
    user_data = sec_header + info
    body = bytes((mcs.SEND_DATA_REQUEST,))
    body += struct.pack(">H", mcs.MCS_USER_CHANNEL - mcs.MCS_BASE_CHANNEL)
    body += struct.pack(">H", mcs.MCS_IO_CHANNEL)
    body += bytes((0x70,))  # dataPriority + segmentation
    body += mcs._per_len(len(user_data)) + user_data
    return mcs.wrap(body)
