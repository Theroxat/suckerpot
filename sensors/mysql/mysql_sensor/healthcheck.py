"""Container healthcheck: connect and expect a MySQL v10 Initial Handshake packet."""

from __future__ import annotations

import os
import socket
import sys


def main() -> int:
    port = int(os.environ.get("SENSOR_PORT") or os.environ.get("MYSQL_PORT") or "3306")
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
            sock.settimeout(3)
            data = sock.recv(256)
    except OSError:
        return 1
    ok = len(data) > 10 and data[3] == 0 and data[4] == 10
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
