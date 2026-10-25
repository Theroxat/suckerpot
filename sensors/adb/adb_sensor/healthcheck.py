"""Container healthcheck: send a CNXN and expect a CNXN back."""

from __future__ import annotations

import os
import socket
import sys

from adb_sensor.wire import A_CNXN, HEADER_SIZE, pack, parse_header


def main() -> int:
    port = int(os.environ.get("SENSOR_PORT", os.environ.get("ADB_PORT", "5555")))
    hello = pack(A_CNXN, 0x01000001, 4096, b"host::\0")
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
            sock.settimeout(3)
            sock.sendall(hello)
            head = b""
            while len(head) < HEADER_SIZE:
                chunk = sock.recv(HEADER_SIZE - len(head))
                if not chunk:
                    return 1
                head += chunk
            return 0 if parse_header(head)[0] == A_CNXN else 1
    except Exception:
        return 1


if __name__ == "__main__":
    sys.exit(main())
