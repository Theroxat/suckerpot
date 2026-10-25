"""Manual load tool: flood of gzip-accepting ``system.multicall`` requests made only of
``system.listMethods`` entries (the CPU amplification case). Each thread connects, sends one
~250 KB request, reads the whole response and repeats.

Usage: python mcflood.py --host sp-web [--threads 4] [--duration 60] [--no-gzip]
"""

from __future__ import annotations

import argparse
import socket
import threading
import time


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="sp-web")
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--duration", type=float, default=60.0)
    ap.add_argument("--no-gzip", action="store_true")
    args = ap.parse_args()
    one = (
        b"<value><struct><member><name>methodName</name><value><string>system.listMethods"
        b"</string></value></member><member><name>params</name><value><array><data></data>"
        b"</array></value></member></struct></value>"
    )
    n = (250 * 1024 - 300) // len(one)
    body = (
        b"<?xml version='1.0'?><methodCall><methodName>system.multicall</methodName><params>"
        b"<param><value><array><data>" + one * n + b"</data></array></value></param></params>"
        b"</methodCall>"
    )
    gz = b"" if args.no_gzip else b"Accept-Encoding: gzip\r\n"
    req = (
        b"POST /xmlrpc.php HTTP/1.1\r\nHost: srv-web01\r\n" + gz
        + b"Content-Length: %d\r\n\r\n" % len(body) + body
    )  # fmt: skip
    stats = {"200": 0, "503": 0, "other": 0, "err": 0}
    lat: list[float] = []
    lock = threading.Lock()
    end = time.monotonic() + args.duration

    def worker() -> None:
        while time.monotonic() < end:
            try:
                c = socket.create_connection((args.host, 8080), timeout=20)
                t = time.monotonic()
                c.sendall(req)
                out = b""
                while chunk := c.recv(1 << 20):
                    out += chunk
                c.close()
                key = out[9:12].decode("latin-1")
                with lock:
                    lat.append(time.monotonic() - t)
                    stats[key if key in stats else "other"] += 1
            except OSError:
                with lock:
                    stats["err"] += 1
                time.sleep(0.2)

    threads = [threading.Thread(target=worker) for _ in range(args.threads)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    lat.sort()
    p50 = lat[len(lat) // 2] if lat else 0.0
    print(f"entries={n} {stats} p50={p50:.2f}s", flush=True)


if __name__ == "__main__":
    main()
