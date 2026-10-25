"""Manual load tool: latency of a normal page (GET /) every 0.5 s while a flood runs.

Usage: python probe.py --host sp-web [--duration 60]
"""

from __future__ import annotations

import argparse
import socket
import time


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="sp-web")
    ap.add_argument("--duration", type=float, default=60.0)
    args = ap.parse_args()
    lat: list[float] = []
    fails = 0
    end = time.monotonic() + args.duration
    while time.monotonic() < end:
        t = time.monotonic()
        try:
            with socket.create_connection((args.host, 8080), timeout=10) as c:
                c.sendall(b"GET / HTTP/1.1\r\nHost: srv-web01\r\nConnection: close\r\n\r\n")
                while c.recv(65536):
                    pass
            lat.append(time.monotonic() - t)
        except OSError:
            fails += 1
        time.sleep(0.5)
    lat.sort()
    if lat:
        p50, p95 = lat[len(lat) // 2], lat[int(len(lat) * 0.95)]
        print(f"probe n={len(lat)} fails={fails} p50={p50:.3f}s p95={p95:.3f}s max={lat[-1]:.3f}s")


if __name__ == "__main__":
    main()
