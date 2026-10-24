"""Sends one RDP X.224 Connection Request with a user name cookie and checks the reply.

Usage: python rdp-test.py HOST PORT USER
"""

import socket
import struct
import sys


def connection_request(user: str) -> bytes:
    cookie = f"Cookie: mstshash={user}\r\n".encode("ascii")
    # RDP_NEG_REQ: type 1, flags 0, length 8, requested protocols SSL | HYBRID | HYBRID_EX.
    neg = struct.pack("<BBHI", 0x01, 0x00, 8, 0x0B)
    x224 = bytes([0xE0, 0, 0, 0, 0, 0]) + cookie + neg  # CR, dst ref, src ref, class
    x224 = bytes([len(x224)]) + x224  # length indicator
    return b"\x03\x00" + struct.pack(">H", 4 + len(x224)) + x224


def main() -> int:
    host, port, user = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    with socket.create_connection((host, port), timeout=10) as s:
        s.sendall(connection_request(user))
        reply = s.recv(64)
    # A Connection Confirm starts with a TPKT header (03 00) and the CC code (0xD0).
    if len(reply) < 11 or reply[:2] != b"\x03\x00" or reply[5] != 0xD0:
        print(f"unexpected reply: {reply.hex()}", file=sys.stderr)
        return 1
    print(f"Connection Confirm received ({len(reply)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
