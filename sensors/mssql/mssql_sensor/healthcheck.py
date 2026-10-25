"""Container healthcheck: send a PRELOGIN, expect a TDS reply packet."""

from __future__ import annotations

import os
import socket
import sys

# A minimal client PRELOGIN: VERSION and ENCRYPTION options, encryption not supported.
_BODY = bytes([0, 0, 11, 0, 6, 1, 0, 17, 0, 1, 0xFF]) + bytes([9, 0, 0, 0, 0, 0]) + bytes([2])
PROBE = bytes([0x12, 0x01, 0x00, 8 + len(_BODY), 0, 0, 1, 0]) + _BODY


def main() -> int:
    port = int(os.environ.get("SENSOR_PORT", "1433"))
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
            sock.settimeout(3)
            sock.sendall(PROBE)
            reply = sock.recv(64)
    except OSError:
        return 1
    return 0 if reply[:1] == b"\x04" else 1


if __name__ == "__main__":
    sys.exit(main())
