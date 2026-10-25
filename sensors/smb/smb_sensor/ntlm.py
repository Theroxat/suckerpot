"""NTLMSSP: build a realistic CHALLENGE (type 2) and read an AUTHENTICATE (type 3).

What we do:

* send a CHALLENGE whose target-info AV pairs carry the NetBIOS / DNS names from the profile
  identity and a current timestamp, so the exchange looks like a domain-joined Windows server;
* from the AUTHENTICATE, record only the domain, user name, workstation, the negotiated flags
  and a short length + preview of the LM/NT response blobs.

What we never do: crack or verify anything, store the full response blobs, or succeed. The
server challenge is random per connection and thrown away; the sensor always answers with a
logon failure.
"""

from __future__ import annotations

import secrets
import struct
import time
from dataclasses import dataclass, field
from typing import Final

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
NEG_ALWAYS_SIGN: Final = 0x00008000
NEG_TARGET_TYPE_DOMAIN: Final = 0x00010000
NEG_TARGET_TYPE_SERVER: Final = 0x00020000
NEG_EXTENDED_SESSION_SECURITY: Final = 0x00080000
NEG_TARGET_INFO: Final = 0x00800000
NEG_VERSION: Final = 0x02000000
NEG_128: Final = 0x20000000
NEG_KEY_EXCH: Final = 0x40000000
NEG_56: Final = 0x80000000

# AV pair ids for the target info.
AV_EOL: Final = 0x0000
AV_NB_COMPUTER: Final = 0x0001
AV_NB_DOMAIN: Final = 0x0002
AV_DNS_COMPUTER: Final = 0x0003
AV_DNS_DOMAIN: Final = 0x0004
AV_TIMESTAMP: Final = 0x0007

AV_DNS_TREE: Final = 0x0005

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


def challenge_flags(client_flags: int | None) -> int:
    """CHALLENGE NegotiateFlags computed from the client's NEGOTIATE flags, like Windows."""
    requested = _DEFAULT_CLIENT_FLAGS if client_flags is None else client_flags
    flags = _SERVER_ALWAYS | (requested & _SERVER_OPTIONAL)
    flags |= NEG_UNICODE if requested & NEG_UNICODE or not requested & NEG_OEM else NEG_OEM
    return flags


def negotiate_flags(message: bytes) -> int | None:
    """NegotiateFlags of an NTLM NEGOTIATE (type 1), or None if absent / malformed."""
    if message_type(message) != TYPE_NEGOTIATE or len(message) < 16:
        return None
    return int(struct.unpack_from("<I", message, 12)[0])


# A Windows Server 10.0 version block: major 10, minor 0, build, reserved, NTLM revision 0x0f.
_DEFAULT_BUILD: Final = 20348  # Windows Server 2022
MAX_PREVIEW: Final = 8  # bytes of each response blob kept (hex), never the full blob
MAX_FIELD: Final = 64


def message_type(message: bytes) -> int | None:
    """The NTLMSSP message type, or None if ``message`` is not an NTLM message."""
    if len(message) < 12 or message[:8] != SIGNATURE:
        return None
    return int(struct.unpack_from("<I", message, 8)[0])


def _version_block(build: int = _DEFAULT_BUILD) -> bytes:
    # ProductMajor(10), ProductMinor(0), ProductBuild, Reserved(3), NTLMRevision(0x0f).
    return struct.pack("<BBH3sB", 10, 0, build & 0xFFFF, b"\x00\x00\x00", 0x0F)


def filetime(now: float | None = None) -> int:
    """Windows FILETIME (100 ns ticks since 1601-01-01) for ``now`` (default: current time)."""
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
    server_challenge: bytes | None = None,
    build: int = _DEFAULT_BUILD,
    flags: int | None = None,
) -> bytes:
    """Build an NTLMSSP CHALLENGE (type 2) message.

    ``server_challenge`` defaults to 8 fresh random bytes; it is never reused or stored.
    """
    challenge = server_challenge if server_challenge is not None else secrets.token_bytes(8)
    neg = challenge_flags(None) if flags is None else flags
    target = target_name.encode("utf-16-le" if neg & NEG_UNICODE else "latin-1", "replace")
    version = _version_block(build)
    # Fixed part is 56 bytes (through the version field); payload follows.
    payload_offset = 56
    target_offset = payload_offset
    info_offset = target_offset + len(target)
    header = struct.pack(
        "<8sIHHII8s8sHHI8s",
        SIGNATURE,
        TYPE_CHALLENGE,
        len(target),
        len(target),
        target_offset,
        challenge_flags(None) if flags is None else flags,
        challenge,
        b"\x00" * 8,  # Reserved
        len(target_info),
        len(target_info),
        info_offset,
        version,
    )
    return header + target + target_info


@dataclass
class Authenticate:
    """The fields of an NTLM AUTHENTICATE worth recording (no secret material kept)."""

    domain: str | None = None
    username: str | None = None
    workstation: str | None = None
    flags: int = 0
    lm_response_len: int = 0
    nt_response_len: int = 0
    lm_response_preview: str = ""
    nt_response_preview: str = ""
    session_key_len: int = 0
    anonymous: bool = False
    ntlm_version: str | None = None  # "v1" (24-byte NT response), "v2" (longer) or None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "domain": self.domain,
            "username": self.username,
            "workstation": self.workstation,
            "ntlm_flags": f"0x{self.flags:08x}",
            "lm_response_len": self.lm_response_len,
            "nt_response_len": self.nt_response_len,
            "lm_response_preview": self.lm_response_preview,
            "nt_response_preview": self.nt_response_preview,
            "session_key_len": self.session_key_len,
            "anonymous": self.anonymous,
            "ntlm_version": self.ntlm_version,
        }


def _field(msg: bytes, offset: int) -> tuple[int, int]:
    """Return ``(length, data_offset)`` of a security-buffer field, bounds-checked."""
    if offset + 8 > len(msg):
        return 0, 0
    length, _max, start = struct.unpack_from("<HHI", msg, offset)
    if length == 0 or start + length > len(msg):
        return 0, 0
    return length, start


def _decode(msg: bytes, offset: int, unicode: bool) -> tuple[str | None, int]:
    length, start = _field(msg, offset)
    if length == 0:
        return (None, 0) if start == 0 else ("", 0)
    raw = msg[start : start + length]
    encoding = "utf-16-le" if unicode else "latin-1"
    text = raw.decode(encoding, "replace")[:MAX_FIELD]
    return text, length


def _preview(message: bytes, length: int, start: int) -> str:
    """Hex of at most MAX_PREVIEW bytes of a field, never past its own length; empty if none."""
    if length == 0:
        return ""
    return message[start : start + min(length, MAX_PREVIEW)].hex()


def parse_authenticate(message: bytes) -> Authenticate | None:
    """Parse an NTLM AUTHENTICATE (type 3). Returns None if it is not one. Never raises."""
    if message_type(message) != TYPE_AUTHENTICATE or len(message) < 64:
        return None
    flags = int(struct.unpack_from("<I", message, 60)[0])
    unicode = bool(flags & NEG_UNICODE)
    out = Authenticate(flags=flags)
    lm_len, lm_start = _field(message, 12)
    nt_len, nt_start = _field(message, 20)
    out.lm_response_len = lm_len
    out.nt_response_len = nt_len
    out.lm_response_preview = _preview(message, lm_len, lm_start)
    out.nt_response_preview = _preview(message, nt_len, nt_start)
    if nt_len == 24:
        out.ntlm_version = "v1"
    elif nt_len > 24:
        out.ntlm_version = "v2"
    out.domain = _decode(message, 28, unicode)[0]
    out.username = _decode(message, 36, unicode)[0]
    out.workstation = _decode(message, 44, unicode)[0]
    out.session_key_len = _field(message, 52)[0]
    out.anonymous = (out.username or "") == "" and nt_len == 0 and lm_len <= 1
    return out
