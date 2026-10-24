"""Container healthcheck: connect to the local port and expect the Telnet option negotiation."""

from __future__ import annotations

import os
import socket
import sys

IAC = 0xFF


def main() -> int:
    port = int(os.environ.get("TELNET_PORT", "2323"))
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
            sock.settimeout(3)
            head = sock.recv(16)
    except OSError:
        return 1
    return 0 if head[:1] == bytes([IAC]) else 1


if __name__ == "__main__":
    sys.exit(main())
