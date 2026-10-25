"""Manual load tool: reconnect churn by clients that never read and never close.

Each process opens a new connection every ``--interval`` seconds, sends ``--pipeline`` copies
of a ~118 KB request (98 headers of 1200 quotes, reflected by ``phpinfo()``), and then holds
the socket forever with a 4 KB receive buffer, so the server's responses never drain. Run one
process per source IP (one throwaway container each) against the hardened 256 MB sensor
container and watch its memory (``run_load.sh`` does all of this).

Usage: python churn.py --host sp-web [--tls] [--pipeline 3] [--duration 600] [--path /info.php]
"""

from __future__ import annotations

import argparse
import socket
import ssl
import time


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="sp-web")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--tls", action="store_true")
    ap.add_argument("--pipeline", type=int, default=1)
    ap.add_argument("--duration", type=float, default=600.0)
    ap.add_argument("--interval", type=float, default=0.25)
    ap.add_argument("--path", default="/info.php")
    ap.add_argument("--max-held", type=int, default=200, help="close the oldest beyond this")
    ap.add_argument("--count", type=int, default=0, help="stop after this many connections")
    ap.add_argument("--hold", type=float, default=0.0, help="keep the sockets this long at the end")
    args = ap.parse_args()
    port = args.port or (8443 if args.tls else 8080)
    headers = b"".join(b"X-%03d: %s\r\n" % (i, b'"' * 1200) for i in range(98))
    request = b"GET " + args.path.encode() + b" HTTP/1.1\r\nHost: srv-web01\r\n" + headers + b"\r\n"
    payload = request * max(1, args.pipeline)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    held: list[socket.socket] = []
    opened = fails = 0
    end = time.monotonic() + args.duration
    while time.monotonic() < end and not (args.count and opened >= args.count):
        try:
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            s.settimeout(3)
            s.connect((args.host, port))
            if args.tls:
                s = ctx.wrap_socket(s)
            s.sendall(payload)
            held.append(s)  # never read; closed only once it is old (the client's own limits)
            opened += 1
            while len(held) > args.max_held:
                held.pop(0).close()
        except (OSError, ssl.SSLError):
            fails += 1
        time.sleep(args.interval)
    print(f"opened={opened} fails={fails}", flush=True)
    time.sleep(args.hold)


if __name__ == "__main__":
    main()
