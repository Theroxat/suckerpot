"""NTLMSSP for the RDP CredSSP (NLA) path.

The sensor plays the server side of one NTLM exchange carried inside CredSSP ``TSRequest``
tokens (see :mod:`rdp_sensor.credssp`):

* it sends a realistic CHALLENGE (type 2) whose NegotiateFlags are derived from the client's
  NEGOTIATE and whose target-info AV pairs carry the per-deployment NetBIOS / DNS names, the
  DNS tree name and a current timestamp, so the exchange looks like a domain-joined Windows
  Server 2022 host;
* from the AUTHENTICATE (type 3) it records only the domain, user name, workstation, the
  negotiated flags, the NTLM version and a short length + 8-byte preview of the NT response.

It never stores a full response blob. It can *verify* an NTLMv2 / NTLMv1 response against a
known cleartext password **only for the handful of weak pairs configured on the sensor** (it
knows the server challenge it sent): this confirms a decoy credential, it is not cracking.
The server always ends the exchange with a logon failure; no session is ever granted.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
from dataclasses import dataclass, field
from typing import Final

from cryptography.hazmat.decrepit.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import Cipher, modes

SIGNATURE: Final = b"NTLMSSP\x00"
TYPE_NEGOTIATE: Final = 1
TYPE_CHALLENGE: Final = 2
TYPE_AUTHENTICATE: Final = 3

# NTLMSSP negotiate flags.
NEG_UNICODE: Final = 0x00000001
NEG_OEM: Final = 0x00000002
NEG_REQUEST_TARGET: Final = 0x00000004
NEG_SIGN: Final = 0x00000010
NEG_SEAL: Final = 0x00000020
NEG_NTLM: Final = 0x00000200
NEG_DOMAIN_SUPPLIED: Final = 0x00001000
NEG_WORKSTATION_SUPPLIED: Final = 0x00002000
NEG_ALWAYS_SIGN: Final = 0x00008000
NEG_TARGET_TYPE_DOMAIN: Final = 0x00010000
NEG_TARGET_TYPE_SERVER: Final = 0x00020000
NEG_EXTENDED_SESSION_SECURITY: Final = 0x00080000
NEG_TARGET_INFO: Final = 0x00800000
NEG_VERSION: Final = 0x02000000
NEG_128: Final = 0x20000000
NEG_KEY_EXCH: Final = 0x40000000
NEG_56: Final = 0x80000000

# AV-pair ids for the target info.
AV_EOL: Final = 0x0000
AV_NB_COMPUTER: Final = 0x0001
AV_NB_DOMAIN: Final = 0x0002
AV_DNS_COMPUTER: Final = 0x0003
AV_DNS_DOMAIN: Final = 0x0004
AV_DNS_TREE: Final = 0x0005
AV_TIMESTAMP: Final = 0x0007

# What the server supports; the CHALLENGE echoes the subset the client asked for.
_SERVER_OPTIONAL: Final = (
    NEG_SIGN
    | NEG_SEAL
    | NEG_ALWAYS_SIGN
    | NEG_EXTENDED_SESSION_SECURITY
    | NEG_VERSION
    | NEG_128
    | NEG_KEY_EXCH
    | NEG_56
)
# Always set by a domain-joined Windows server.
_SERVER_ALWAYS: Final = NEG_NTLM | NEG_TARGET_TYPE_DOMAIN | NEG_TARGET_INFO | NEG_REQUEST_TARGET
# Used when the client's NEGOTIATE flags are unknown (typical Windows 10/11 client request).
_DEFAULT_CLIENT_FLAGS: Final = (
    NEG_UNICODE
    | NEG_REQUEST_TARGET
    | NEG_SIGN
    | NEG_ALWAYS_SIGN
    | NEG_EXTENDED_SESSION_SECURITY
    | NEG_VERSION
    | NEG_128
    | NEG_KEY_EXCH
    | NEG_56
)

_DEFAULT_BUILD: Final = 20348  # Windows Server 2022
MAX_PREVIEW: Final = 8  # bytes of each response blob kept (hex), never the full blob
MAX_FIELD: Final = 64
_MAX_MSG: Final = 4096  # an NTLM message we are willing to parse


def challenge_flags(client_flags: int | None) -> int:
    """CHALLENGE NegotiateFlags computed from the client's NEGOTIATE flags, like Windows."""
    requested = _DEFAULT_CLIENT_FLAGS if client_flags is None else client_flags
    flags = _SERVER_ALWAYS | (requested & _SERVER_OPTIONAL)
    flags |= NEG_UNICODE if requested & NEG_UNICODE or not requested & NEG_OEM else NEG_OEM
    return flags


def message_type(message: bytes) -> int | None:
    """The NTLMSSP message type, or None if ``message`` is not an NTLM message."""
    if len(message) < 12 or message[:8] != SIGNATURE:
        return None
    return int(struct.unpack_from("<I", message, 8)[0])


def negotiate_flags(message: bytes) -> int | None:
    """NegotiateFlags of an NTLM NEGOTIATE (type 1), or None if absent / malformed."""
    if message_type(message) != TYPE_NEGOTIATE or len(message) < 16:
        return None
    return int(struct.unpack_from("<I", message, 12)[0])


def negotiate_os_version(message: bytes) -> str | None:
    """The client OS version ``major.minor.build`` from a NEGOTIATE's version block, if present."""
    flags = negotiate_flags(message)
    if flags is None or not flags & NEG_VERSION or len(message) < 40:
        return None
    major, minor, build = struct.unpack_from("<BBH", message, 32)
    return f"{major}.{minor}.{build}"


def _version_block(build: int = _DEFAULT_BUILD) -> bytes:
    # ProductMajor(10), ProductMinor(0), ProductBuild, Reserved(3), NTLMRevision(0x0f).
    return struct.pack("<BBH3sB", 10, 0, build & 0xFFFF, b"\x00\x00\x00", 0x0F)


def filetime(now: float | None = None) -> int:
    """Windows FILETIME (100 ns ticks since 1601-01-01) for ``now`` (default: current time)."""
    import time

    seconds = time.time() if now is None else now
    return int((seconds + 11644473600) * 10_000_000)


def _av_pair(av_id: int, value: bytes) -> bytes:
    return struct.pack("<HH", av_id, len(value)) + value


def build_target_info(
    nb_domain: str,
    nb_computer: str,
    dns_domain: str,
    dns_computer: str,
    dns_tree: str | None = None,
    now: float | None = None,
) -> bytes:
    """Build the AV-pair target info advertised in the CHALLENGE (Windows order)."""

    def u(text: str) -> bytes:
        return text.encode("utf-16-le")

    return b"".join(
        [
            _av_pair(AV_NB_DOMAIN, u(nb_domain)),
            _av_pair(AV_NB_COMPUTER, u(nb_computer)),
            _av_pair(AV_DNS_DOMAIN, u(dns_domain)),
            _av_pair(AV_DNS_COMPUTER, u(dns_computer)),
            _av_pair(AV_DNS_TREE, u(dns_tree if dns_tree is not None else dns_domain)),
            _av_pair(AV_TIMESTAMP, struct.pack("<Q", filetime(now))),
            _av_pair(AV_EOL, b""),
        ]
    )


def build_challenge(
    target_name: str,
    target_info: bytes,
    server_challenge: bytes,
    build: int = _DEFAULT_BUILD,
    flags: int | None = None,
) -> bytes:
    """Build an NTLMSSP CHALLENGE (type 2) message carrying ``server_challenge`` (8 bytes)."""
    neg = challenge_flags(None) if flags is None else flags
    target = target_name.encode("utf-16-le" if neg & NEG_UNICODE else "latin-1", "replace")
    version = _version_block(build)
    payload_offset = 56  # fixed part through the version field
    target_offset = payload_offset
    info_offset = target_offset + len(target)
    header = struct.pack(
        "<8sIHHII8s8sHHI8s",
        SIGNATURE,
        TYPE_CHALLENGE,
        len(target),
        len(target),
        target_offset,
        neg,
        server_challenge[:8].ljust(8, b"\x00"),
        b"\x00" * 8,  # Reserved
        len(target_info),
        len(target_info),
        info_offset,
        version,
    )
    return header + target + target_info


@dataclass
class Authenticate:
    """The fields of an NTLM AUTHENTICATE worth recording (no secret material emitted)."""

    domain: str | None = None
    username: str | None = None
    workstation: str | None = None
    flags: int = 0
    lm_response_len: int = 0
    nt_response_len: int = 0
    nt_response_preview: str = ""
    session_key_len: int = 0
    anonymous: bool = False
    ntlm_version: str | None = None  # "v1" (24-byte NT response), "v2" (longer) or None
    # In-memory only, for the weak-list verification; never emitted.
    _nt_response: bytes = field(default=b"", repr=False)
    _lm_response: bytes = field(default=b"", repr=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "domain": self.domain,
            "username": self.username,
            "workstation": self.workstation,
            "ntlm_flags": f"0x{self.flags:08x}",
            "nt_response_len": self.nt_response_len,
            "nt_response_preview": self.nt_response_preview,
            "ntlm_version": self.ntlm_version,
            "anonymous": self.anonymous,
        }


def _field(msg: bytes, offset: int) -> tuple[int, int]:
    """Return ``(length, data_offset)`` of a security-buffer field, bounds-checked."""
    if offset + 8 > len(msg):
        return 0, 0
    length, _max, start = struct.unpack_from("<HHI", msg, offset)
    if length == 0 or start + length > len(msg):
        return 0, 0
    return int(length), int(start)


def _decode(msg: bytes, offset: int, unicode: bool) -> str | None:
    length, start = _field(msg, offset)
    if length == 0:
        return None
    raw = msg[start : start + length]
    encoding = "utf-16-le" if unicode else "latin-1"
    return raw.decode(encoding, "replace")[:MAX_FIELD]


def _bytes(msg: bytes, offset: int) -> bytes:
    length, start = _field(msg, offset)
    return msg[start : start + length]


def parse_authenticate(message: bytes) -> Authenticate | None:
    """Parse an NTLM AUTHENTICATE (type 3). Returns None if it is not one. Never raises."""
    if message_type(message) != TYPE_AUTHENTICATE or len(message) < 64 or len(message) > _MAX_MSG:
        return None
    flags = int(struct.unpack_from("<I", message, 60)[0])
    unicode = bool(flags & NEG_UNICODE)
    out = Authenticate(flags=flags)
    lm = _bytes(message, 12)
    nt = _bytes(message, 20)
    out._lm_response = lm
    out._nt_response = nt
    out.lm_response_len = len(lm)
    out.nt_response_len = len(nt)
    out.nt_response_preview = nt[:MAX_PREVIEW].hex()
    if len(nt) == 24:
        out.ntlm_version = "v1"
    elif len(nt) > 24:
        out.ntlm_version = "v2"
    out.domain = _decode(message, 28, unicode)
    out.username = _decode(message, 36, unicode)
    out.workstation = _decode(message, 44, unicode)
    out.session_key_len = _field(message, 52)[0]
    out.anonymous = (out.username or "") == "" and len(nt) == 0 and len(lm) <= 1
    return out


# --- verification against a known cleartext (weak list only) ---------------------------------


def _md4(data: bytes) -> bytes:
    """MD4 (RFC 1320), pure Python: OpenSSL 3 disables MD4, so hashlib cannot provide it."""
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    msg = bytearray(data)
    bit_len = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", bit_len)

    def rol(x: int, n: int) -> int:
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    for off in range(0, len(msg), 64):
        x = list(struct.unpack_from("<16I", msg, off))
        a, b, c, d = h
        for i in (0, 4, 8, 12):
            a = rol(a + ((b & c) | (~b & d)) + x[i], 3)
            d = rol(d + ((a & b) | (~a & c)) + x[i + 1], 7)
            c = rol(c + ((d & a) | (~d & b)) + x[i + 2], 11)
            b = rol(b + ((c & d) | (~c & a)) + x[i + 3], 19)
        for i in (0, 1, 2, 3):
            a = rol(a + ((b & c) | (b & d) | (c & d)) + x[i] + 0x5A827999, 3)
            d = rol(d + ((a & b) | (a & c) | (b & c)) + x[i + 4] + 0x5A827999, 5)
            c = rol(c + ((d & a) | (d & b) | (a & b)) + x[i + 8] + 0x5A827999, 9)
            b = rol(b + ((c & d) | (c & a) | (d & a)) + x[i + 12] + 0x5A827999, 13)
        for i in (0, 2, 1, 3):
            a = rol(a + (b ^ c ^ d) + x[i] + 0x6ED9EBA1, 3)
            d = rol(d + (a ^ b ^ c) + x[i + 8] + 0x6ED9EBA1, 9)
            c = rol(c + (d ^ a ^ b) + x[i + 4] + 0x6ED9EBA1, 11)
            b = rol(b + (c ^ d ^ a) + x[i + 12] + 0x6ED9EBA1, 15)
        h = [(h[0] + a) & 0xFFFFFFFF, (h[1] + b) & 0xFFFFFFFF, (h[2] + c) & 0xFFFFFFFF,
             (h[3] + d) & 0xFFFFFFFF]  # fmt: skip
    return struct.pack("<4I", *h)


def nt_hash(password: str) -> bytes:
    """NT hash = MD4(UTF-16-LE(password))."""
    return _md4(password.encode("utf-16-le"))


def _ntowf_v2(nt_h: bytes, user: str, domain: str) -> bytes:
    ident = (user.upper() + domain).encode("utf-16-le")
    return hmac.new(nt_h, ident, hashlib.md5).digest()


def _des_key(seven: bytes) -> bytes:
    """Expand 7 key bytes to an 8-byte DES key (parity bits are ignored by the cipher)."""
    b = int.from_bytes(seven.ljust(7, b"\x00"), "big")
    out = bytearray(8)
    for i in range(8):
        out[7 - i] = ((b >> (7 * i)) & 0x7F) << 1
    return bytes(out)


def _desl(key16: bytes, block8: bytes) -> bytes:
    """DESL: three DES-ECB encryptions of ``block8`` with the 16-byte key padded to 21."""
    key21 = key16.ljust(21, b"\x00")
    out = b""
    for chunk in (key21[0:7], key21[7:14], key21[14:21]):
        k = _des_key(chunk)
        # TripleDES with K1=K2=K3 is single DES, so a 24-byte key of three copies of ``k``.
        enc = Cipher(algorithms.TripleDES(k * 3), modes.ECB()).encryptor()  # noqa: S305
        out += enc.update(block8) + enc.finalize()
    return out


def verify_password(
    auth: Authenticate, server_challenge: bytes, password: str, nt_h: bytes | None = None
) -> bool:
    """True if ``password`` reproduces the captured NT response for the server challenge.

    Supports NTLMv2 and NTLMv1 (with and without extended session security). The user and
    domain come from the AUTHENTICATE itself; ``server_challenge`` is the 8 bytes we sent.
    ``nt_h`` is the precomputed ``MD4(password)`` (so startup does the MD4 once per decoy, not
    per attempt); when omitted it is derived from ``password``.
    """
    user = auth.username or ""
    domain = auth.domain or ""
    nh = nt_h if nt_h is not None else nt_hash(password)
    nt = auth._nt_response
    if len(nt) > 24:  # NTLMv2
        proof, temp = nt[:16], nt[16:]
        ntowf = _ntowf_v2(nh, user, domain)
        expected = hmac.new(ntowf, server_challenge[:8] + temp, hashlib.md5).digest()
        return hmac.compare_digest(proof, expected)
    if len(nt) == 24:  # NTLMv1
        if auth.flags & NEG_EXTENDED_SESSION_SECURITY and len(auth._lm_response) >= 8:
            nonce = hashlib.md5(server_challenge[:8] + auth._lm_response[:8]).digest()[:8]  # noqa: S324
            expected = _desl(nh, nonce)
        else:
            expected = _desl(nh, server_challenge[:8])
        return hmac.compare_digest(nt, expected)
    return False


def new_server_challenge() -> bytes:
    """8 fresh random bytes; never reused, only kept for the lifetime of one connection."""
    return secrets.token_bytes(8)
