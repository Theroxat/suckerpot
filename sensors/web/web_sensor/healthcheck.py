"""Container healthcheck: a plain HTTP request on the local port, TCP connect on the TLS port."""

from __future__ import annotations

import os
import socket
import sys


def main() -> int:
    http = int(os.environ.get("WEB_HTTP_PORT", "8080"))
    https = int(os.environ.get("WEB_HTTPS_PORT", "8443"))
    try:
        with socket.create_connection(("127.0.0.1", http), timeout=3) as sock:
            sock.settimeout(3)
            sock.sendall(b"HEAD /robots.txt HTTP/1.0\r\n\r\n")
            line = sock.recv(64)
        if not line.startswith(b"HTTP/1.1 200"):
            return 1
        with socket.create_connection(("127.0.0.1", https), timeout=3):
            pass
    except OSError:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
