"""Container healthcheck: send a bare X.224 Connection Request, expect a Connection Confirm."""

from __future__ import annotations

import os
import socket
import sys

from rdp_sensor.protocol import X224_CC, build_connection_request


def main() -> int:
    port = int(os.environ.get("RDP_PORT", "3389"))
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
            sock.settimeout(3)
            sock.sendall(build_connection_request())
            reply = sock.recv(64)
    except OSError:
        return 1
    return 0 if len(reply) >= 6 and reply[0] == 3 and reply[5] == X224_CC else 1


if __name__ == "__main__":
    sys.exit(main())
