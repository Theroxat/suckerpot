"""Container healthcheck: fetch the favicon from the local HTTP port."""

from __future__ import annotations

import os
import socket
import sys


def main() -> int:
    port = int(os.environ.get("SYNOLOGY_HTTP_PORT", "5000"))
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
            sock.settimeout(3)
            sock.sendall(
                b"GET /webman/favicon.ico HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            )
            data = b""
            while len(data) < 4096:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                data += chunk
        if not data.startswith(b"HTTP/1.1 200"):
            return 1
    except OSError:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
