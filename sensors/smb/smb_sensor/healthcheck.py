"""Container healthcheck: send an SMB2 NEGOTIATE, expect an SMB2 NEGOTIATE response."""

from __future__ import annotations

import os
import socket
import struct
import sys

from smb_sensor import framing, smb


def build_negotiate_request() -> bytes:
    header = struct.pack(
        "<4sHHIHHIIQIIQ16s",
        smb.SMB2_MAGIC,
        smb.SMB2_HEADER_LEN,
        0,  # CreditCharge
        0,  # Status (ChannelSequence/Reserved on a request)
        smb.SMB2_NEGOTIATE,
        1,  # CreditRequest
        0,  # Flags (client request)
        0,  # NextCommand
        0,  # MessageId
        0,  # Reserved
        0,  # TreeId
        0,  # SessionId
        b"\x00" * 16,  # Signature
    )
    body = struct.pack(
        "<HHHHI16sQ",
        36,  # StructureSize
        1,  # DialectCount
        1,  # SecurityMode (signing enabled)
        0,  # Reserved
        0,  # Capabilities
        b"\x00" * 16,  # ClientGuid
        0,  # ClientStartTime
    ) + struct.pack("<H", smb.DIALECT_2_0_2)
    return framing.build_message(header + body)


def main() -> int:
    port = int(os.environ.get("SMB_PORT", "4450"))
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
            sock.settimeout(3)
            sock.sendall(build_negotiate_request())
            reply = sock.recv(512)
    except OSError:
        return 1
    if len(reply) < framing.HEADER_LEN + smb.SMB2_HEADER_LEN:
        return 1
    payload = reply[framing.HEADER_LEN :]
    if payload[:4] != smb.SMB2_MAGIC:
        return 1
    command = struct.unpack_from("<H", payload, 12)[0]
    return 0 if command == smb.SMB2_NEGOTIATE else 1


if __name__ == "__main__":
    sys.exit(main())
