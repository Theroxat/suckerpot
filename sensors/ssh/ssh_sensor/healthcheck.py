"""Container healthcheck: connect to the local port and read the SSH banner line."""

from __future__ import annotations

import os
import socket
import sys


def main() -> int:
    port = int(os.environ.get("SSH_PORT", "2222"))
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
            sock.settimeout(3)
            line = sock.recv(255)
    except OSError:
        return 1
    return 0 if line.startswith(b"SSH-2.0-") else 1


if __name__ == "__main__":
    sys.exit(main())
