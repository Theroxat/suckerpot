"""Container healthcheck: send an inline PING, expect ``+PONG``."""

from __future__ import annotations

import os
import socket
import sys


def main() -> int:
    port = int(os.environ.get("SENSOR_PORT", "6379"))
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
            sock.settimeout(3)
            sock.sendall(b"PING\r\n")
            reply = sock.recv(64)
    except OSError:
        return 1
    return 0 if reply.startswith(b"+PONG") else 1


if __name__ == "__main__":
    sys.exit(main())
