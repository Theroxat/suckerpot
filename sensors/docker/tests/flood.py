"""Manual load tool, run from a throwaway container on the sensor's network (not part of pytest).

    python flood.py HOST PORT MODE CONNS SECONDS

MODE is one of ``body`` (large create bodies trickled in slowly), ``pipeline`` (a pile of
requests sent and never read) ``churn`` (reconnect forever without reading) or ``mixed`` (half of each, plus a few slowloris heads).
"""

from __future__ import annotations

import asyncio
import json
import sys

BODY = json.dumps({"Image": "alpine", "Cmd": ["sh", "-c", "x" * 250_000]}).encode()
URLS = " ".join(f"http://198.51.100.{i % 250}/a/b{i}.sh" for i in range(6000))[:240000]
CPU_BODY = json.dumps({"Image": "a", "Cmd": ["sh", "-c", URLS]}).encode()
CPU_REQ = (
    b"POST /containers/create HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % len(CPU_BODY)
    + CPU_BODY
)
PIPE = b"GET /info HTTP/1.1\r\nHost: x\r\n\r\n" * 300


async def body_conn(host: str, port: int, seconds: float) -> None:
    r, w = await asyncio.open_connection(host, port)
    w.write(
        b"POST /containers/create HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % len(BODY)
    )
    end = asyncio.get_running_loop().time() + seconds
    sent = 0
    while asyncio.get_running_loop().time() < end and sent < len(BODY) - 1000:
        w.write(BODY[sent : sent + 20_000])
        sent += 20_000
        await w.drain()
        await asyncio.sleep(1.0)
    w.close()


async def pipe_conn(host: str, port: int, seconds: float) -> None:
    import socket

    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
    s.setblocking(False)
    loop = asyncio.get_running_loop()
    await loop.sock_connect(s, (host, port))
    try:
        await asyncio.wait_for(loop.sock_sendall(s, PIPE), seconds)
    except (TimeoutError, OSError):
        pass
    await asyncio.sleep(seconds)
    s.close()


async def cpu_conn(host: str, port: int, seconds: float) -> None:
    """Keep-alive connection that sends expensive create bodies and pipelined listings, reading."""
    loop = asyncio.get_running_loop()
    end = loop.time() + seconds
    r, w = await asyncio.open_connection(host, port)
    while loop.time() < end:
        w.write(CPU_REQ * 2 + b"GET /containers/json?all=1 HTTP/1.1\r\nHost: x\r\n\r\n" * 50)
        await w.drain()
        try:
            await asyncio.wait_for(r.read(65536), 2.0)
        except TimeoutError:
            pass
    w.close()


async def victim(host: str, port: int, seconds: float) -> None:
    """GET /_ping on fresh connections; prints the worst and median latency."""
    loop = asyncio.get_running_loop()
    end = loop.time() + seconds
    lat = []
    while loop.time() < end:
        t0 = loop.time()
        try:
            r, w = await asyncio.open_connection(host, port)
            w.write(b"GET /_ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            ok = (await asyncio.wait_for(r.read(300), 5)).startswith(b"HTTP/1.1 200")
            w.close()
        except (OSError, TimeoutError):
            ok = False
        lat.append((loop.time() - t0, ok))
        await asyncio.sleep(0.5)
    lat.sort()
    bad = sum(1 for _, ok in lat if not ok)
    print(
        f"victim n={len(lat)} failed={bad} p50={lat[len(lat) // 2][0]:.3f}s max={lat[-1][0]:.3f}s"
    )


async def churn_conn(host: str, port: int, seconds: float) -> None:
    """Reconnect in a loop with a client that never reads (lesson 14: memory must plateau)."""
    loop = asyncio.get_running_loop()
    end = loop.time() + seconds
    while loop.time() < end:
        await pipe_conn(host, port, 1.0)


async def head_conn(host: str, port: int, seconds: float) -> None:
    r, w = await asyncio.open_connection(host, port)
    w.write(b"GET /_ping HTTP/1.1\r\nHost: x\r\n")
    for _ in range(int(seconds)):
        w.write(b"X-A: b\r\n")
        await asyncio.sleep(1.0)
    w.close()


async def main() -> None:
    host, port, mode, conns, seconds = (
        sys.argv[1],
        int(sys.argv[2]),
        sys.argv[3],
        int(sys.argv[4]),
        float(sys.argv[5]),
    )
    jobs = []
    for i in range(conns):
        kind = mode if mode != "mixed" else ("body", "pipeline", "head")[i % 3]
        fn = {
            "body": body_conn,
            "pipeline": pipe_conn,
            "head": head_conn,
            "churn": churn_conn,
            "cpu": cpu_conn,
            "victim": victim,
        }[kind]
        jobs.append(fn(host, port, seconds))
    await asyncio.gather(*jobs, return_exceptions=True)


asyncio.run(main())
