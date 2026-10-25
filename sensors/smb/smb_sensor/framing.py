"""NetBIOS session service framing (the transport SMB uses on TCP 445 and 139).

Every SMB message is prefixed with a 4-byte header: a 1-byte message type and a 3-byte
big-endian length of the payload that follows. On direct TCP (445) the type is always
``0x00`` (session message). We parse the header strictly, cap the length, and never trust it:
the caller reads exactly ``length`` further bytes, with its own deadline and size budget.

This module only *frames* bytes. It does not interpret the SMB payload.
"""

from __future__ import annotations

from typing import Final

HEADER_LEN: Final = 4

# RFC 1002 NetBIOS session service message types.
SESSION_MESSAGE: Final = 0x00
SESSION_REQUEST: Final = 0x81
POSITIVE_SESSION_RESPONSE: Final = 0x82
NEGATIVE_SESSION_RESPONSE: Final = 0x83
RETARGET_SESSION_RESPONSE: Final = 0x84
SESSION_KEEPALIVE: Final = 0x85

_TYPE_NAMES = {
    SESSION_MESSAGE: "session_message",
    SESSION_REQUEST: "session_request",
    POSITIVE_SESSION_RESPONSE: "positive_session_response",
    NEGATIVE_SESSION_RESPONSE: "negative_session_response",
    RETARGET_SESSION_RESPONSE: "retarget_session_response",
    SESSION_KEEPALIVE: "session_keepalive",
}


def type_name(message_type: int) -> str:
    return _TYPE_NAMES.get(message_type, f"0x{message_type & 0xFF:02x}")


def parse_header(header: bytes) -> tuple[int, int]:
    """Return ``(message_type, payload_length)`` from a 4-byte NetBIOS header.

    On direct TCP the length is the low 3 bytes, big-endian (max ~16 MiB); the caller still
    clamps it to its own per-PDU cap.
    """
    if len(header) < HEADER_LEN:
        raise ValueError("short netbios header")
    message_type = header[0]
    length = (header[1] << 16) | (header[2] << 8) | header[3]
    return message_type, length


def build_message(payload: bytes) -> bytes:
    """Frame an outgoing SMB payload as a NetBIOS session message."""
    n = len(payload)
    return bytes((SESSION_MESSAGE, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF)) + payload
