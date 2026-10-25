"""Container healthcheck: send an OPTIONS over UDP to 127.0.0.1, expect a SIP 200."""

from __future__ import annotations

import os
import socket
import sys

PROBE = (
    b"OPTIONS sip:ping@127.0.0.1 SIP/2.0\r\n"
    b"Via: SIP/2.0/UDP 127.0.0.1:9;branch=z9hG4bK0001\r\n"
    b"From: <sip:ping@127.0.0.1>;tag=0001\r\n"
    b"To: <sip:ping@127.0.0.1>\r\n"
    b"Call-ID: healthcheck@127.0.0.1\r\n"
    b"CSeq: 1 OPTIONS\r\n"
    b"Content-Length: 0\r\n\r\n"
)


def main() -> int:
    port = int(os.environ.get("SENSOR_PORT", "5060"))
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.sendto(PROBE, ("127.0.0.1", port))
            reply, _ = sock.recvfrom(2048)
    except OSError:
        return 1
    return 0 if reply.startswith(b"SIP/2.0 200") else 1


if __name__ == "__main__":
    sys.exit(main())
