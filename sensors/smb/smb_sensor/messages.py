"""Builders for the SMB2 responses the sensor sends.

Everything here is pure byte assembly for a response that grants nothing: NEGOTIATE (including
the 3.1.1 negotiate contexts), the SESSION_SETUP challenge and final logon failure, a generic
error for any other command, and the "switch to SMB2" answer to an SMB1 negotiate. Sizes are
computed before the bytes are built (never build-then-truncate).
"""

from __future__ import annotations

import secrets
import struct
from typing import Final

from smb_sensor import ntlm, smb
from smb_sensor.identity import Identity

SECURITY_MODE_SIGNING_ENABLED: Final = 0x0001
MAX_SIZE: Final = 0x00800000  # 8 MiB, like a modern Windows server

# Global capabilities (MS-SMB2 2.2.4).
_CAP_DFS: Final = 0x01
_CAP_LEASING: Final = 0x02
_CAP_LARGE_MTU: Final = 0x04
_CAP_ENCRYPTION: Final = 0x40

# Encryption ciphers (negotiate context).
CIPHER_AES_128_CCM: Final = 0x0001
CIPHER_AES_128_GCM: Final = 0x0002
CIPHER_AES_256_CCM: Final = 0x0003
CIPHER_AES_256_GCM: Final = 0x0004
_SUPPORTED_CIPHERS: Final = (
    CIPHER_AES_256_GCM,
    CIPHER_AES_128_GCM,
    CIPHER_AES_256_CCM,
    CIPHER_AES_128_CCM,
)
HASH_SHA_512: Final = 0x0001


def _capabilities(dialect: int, client_caps: int) -> int:
    """Capabilities a stand-alone Windows file server returns for ``dialect``.

    2.0.2 only knows DFS; 2.1+ adds leasing and large MTU (server properties, independent of
    the client). 3.0 / 3.0.2 add encryption only when the client offered it; 3.1.1 negotiates
    encryption with a context instead (MS-SMB2 3.3.5.4).
    """
    if dialect == smb.DIALECT_2_0_2:
        return _CAP_DFS
    caps = _CAP_DFS | _CAP_LEASING | _CAP_LARGE_MTU
    if dialect in (smb.DIALECT_3_0_0, smb.DIALECT_3_0_2):
        caps |= _CAP_ENCRYPTION & client_caps
    return caps


def build_header(
    command: int,
    message_id: int,
    session_id: int,
    status: int,
    *,
    credit: int = 1,
    tree_id: int = 0,
    next_command: int = 0,
) -> bytes:
    """Build a 64-byte synchronous SMB2 response header."""
    return struct.pack(
        "<4sHHIHHIIQIIQ16s",
        smb.SMB2_MAGIC,
        smb.SMB2_HEADER_LEN,
        0,  # CreditCharge
        status,
        command,
        max(1, min(credit, 8192)),  # CreditResponse
        smb.SMB2_FLAGS_SERVER_TO_REDIR,
        next_command,
        message_id,
        0,  # Reserved
        tree_id,
        session_id,
        b"\x00" * 16,  # Signature: we never sign (no session is ever granted)
    )


def choose_cipher(offered: list[int]) -> int:
    for cipher in offered:
        if cipher in _SUPPORTED_CIPHERS:
            return cipher
    return CIPHER_AES_128_GCM


def _negotiate_contexts(cipher: int | None) -> tuple[bytes, int]:
    """Pre-auth integrity (SHA-512) context, plus an encryption context only when the client
    sent one (``cipher`` is None otherwise)."""
    preauth_data = (
        struct.pack("<HH", 1, 32) + struct.pack("<H", HASH_SHA_512) + secrets.token_bytes(32)
    )
    preauth = struct.pack("<HHI", smb.CTX_PREAUTH_INTEGRITY, len(preauth_data), 0) + preauth_data
    if cipher is None:
        return preauth, 1
    pad = b"\x00" * ((8 - (len(preauth) % 8)) % 8)
    enc_data = struct.pack("<HH", 1, cipher)
    enc = struct.pack("<HHI", smb.CTX_ENCRYPTION, len(enc_data), 0) + enc_data
    return preauth + pad + enc, 2


def build_negotiate_response(
    identity: Identity,
    dialect: int,
    *,
    message_id: int = 0,
    credit: int = 1,
    cipher: int | None = CIPHER_AES_128_GCM,
    client_caps: int = 0xFFFFFFFF,
) -> bytes:
    """A NEGOTIATE response selecting ``dialect`` (``DIALECT_WILDCARD`` for the SMB1 steer).

    ``cipher`` is the encryption context to return for 3.1.1, or None when the client did not
    send one; ``client_caps`` masks the optional SMB 3.x capabilities.
    """
    from smb_sensor.spnego import build_neg_token_init

    sec_buffer = build_neg_token_init()
    is_311 = dialect == smb.DIALECT_3_1_1
    sec_offset = smb.SMB2_HEADER_LEN + 64  # header + fixed negotiate body
    header = build_header(smb.SMB2_NEGOTIATE, message_id, 0, smb.STATUS_SUCCESS, credit=credit)
    contexts = b""
    context_count = 0
    context_offset = 0
    if is_311:
        contexts, context_count = _negotiate_contexts(cipher)
        after_sec = sec_offset + len(sec_buffer)
        context_offset = after_sec + ((8 - (after_sec % 8)) % 8)
    body = struct.pack(
        "<HHHH16sIIIIQQHHI",
        65,  # StructureSize
        SECURITY_MODE_SIGNING_ENABLED,
        dialect,
        context_count,  # NegotiateContextCount (Reserved, 0, for < 3.1.1)
        identity.server_guid,
        _capabilities(dialect, client_caps),
        MAX_SIZE,
        MAX_SIZE,
        MAX_SIZE,
        ntlm.filetime(),
        0,  # ServerStartTime: Windows returns 0
        sec_offset,
        len(sec_buffer),
        context_offset,  # NegotiateContextOffset (Reserved2, 0, for < 3.1.1)
    )
    message = header + body + sec_buffer
    if is_311:
        pad = b"\x00" * (context_offset - (sec_offset + len(sec_buffer)))
        message += pad + contexts
    return message


def build_session_setup_challenge(
    identity: Identity,
    session_id: int,
    *,
    message_id: int,
    credit: int = 1,
    client_flags: int | None = None,
) -> bytes:
    """SESSION_SETUP response with STATUS_MORE_PROCESSING_REQUIRED and an NTLM CHALLENGE."""
    from smb_sensor.spnego import build_neg_token_resp

    target_info = ntlm.build_target_info(
        identity.domain_name,
        identity.netbios_computer,
        identity.dns_domain,
        identity.dns_computer,
        identity.dns_domain,  # DNS tree (forest) name
    )
    challenge = ntlm.build_challenge(
        identity.domain_name, target_info, flags=ntlm.challenge_flags(client_flags)
    )
    sec_buffer = build_neg_token_resp(challenge)
    sec_offset = smb.SMB2_HEADER_LEN + 8
    header = build_header(
        smb.SMB2_SESSION_SETUP,
        message_id,
        session_id,
        smb.STATUS_MORE_PROCESSING_REQUIRED,
        credit=credit,
    )
    body = struct.pack("<HHHH", 9, 0, sec_offset, len(sec_buffer))
    return header + body + sec_buffer


def build_session_setup_failure(session_id: int, *, message_id: int, credit: int = 1) -> bytes:
    """SESSION_SETUP response with STATUS_LOGON_FAILURE and an empty security buffer."""
    header = build_header(
        smb.SMB2_SESSION_SETUP,
        message_id,
        session_id,
        smb.STATUS_LOGON_FAILURE,
        credit=credit,
    )
    body = struct.pack("<HHHH", 9, 0, 0, 0)
    return header + body


def build_error_response(
    command: int,
    message_id: int,
    session_id: int,
    status: int,
    *,
    credit: int = 1,
    tree_id: int = 0,
) -> bytes:
    """A minimal SMB2 ERROR response for a command the sensor does not service."""
    header = build_header(command, message_id, session_id, status, credit=credit, tree_id=tree_id)
    body = struct.pack("<HBBI", 9, 0, 0, 0) + b"\x00"  # ErrorData: one reserved byte
    return header + body
