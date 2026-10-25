"""Container healthcheck: ``GET /_ping`` on the local port."""

from __future__ import annotations

import os
import socket
import sys


def main() -> int:
    port = int(os.environ.get("DOCKER_PORT", "2375"))
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
            sock.settimeout(3)
            sock.sendall(b"GET /_ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            data = b""
            while len(data) < 4096:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                data += chunk
        if not data.startswith(b"HTTP/1.1 200") or not data.endswith(b"OK"):
            return 1
    except OSError:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
