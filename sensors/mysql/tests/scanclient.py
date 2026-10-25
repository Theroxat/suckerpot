"""Hostile-client helper: logs in as root (empty password) and sends full-scan statements.

Run as a separate process so that its own CPU use does not disturb the event loop under test:
``python scanclient.py <host> <port> <source_ip> <connections> <seconds> [statements_per_query]``.
Prints ``answered=<COM_QUERY count>``. Standard library only.
"""

from __future__ import annotations

import asyncio
import socket
import struct
import sys
import time

CAPS = 0x200 | 0x8000 | 0x80000 | 0x20000 | (1 << 16) | (1 << 24)


def pack(seq: int, payload: bytes) -> bytes:
    return struct.pack("<I", len(payload))[:3] + bytes([seq]) + payload


def login() -> bytes:
    body = struct.pack("<IIB", CAPS, 1 << 24, 255) + b"\0" * 23 + b"root\0\0"
    return pack(1, body + b"mysql_native_password\0")


async def packet(reader: asyncio.StreamReader) -> bytes:
    head = await reader.readexactly(4)
    return await reader.readexactly(int.from_bytes(head[:3], "little"))


async def one(host: str, port: int, src: str, deadline: float, stmts: int, done: list[int]) -> None:
    while time.monotonic() < deadline:
        await session(host, port, src, deadline, stmts, done)
        await asyncio.sleep(0.2)  # closed by the sensor (CPU limit, ...): come back


async def session(
    host: str, port: int, src: str, deadline: float, stmts: int, done: list[int]
) -> None:
    sock = socket.socket()
    sock.setblocking(False)
    sock.bind((src, 0))
    try:
        await asyncio.get_running_loop().sock_connect(sock, (host, port))
    except OSError:
        sock.close()
        return
    reader, writer = await asyncio.open_connection(sock=sock)
    try:
        await packet(reader)
        writer.write(login())
        await packet(reader)
        n = 0
        while time.monotonic() < deadline:
            sql = "".join(
                f"SELECT COUNT(*) FROM shop.orders WHERE status='zz{n}_{i}';" for i in range(stmts)
            )
            n += 1
            writer.write(pack(0, b"\x03" + sql.encode()))
            await writer.drain()
            ended = 0
            while ended < stmts:
                body = await asyncio.wait_for(packet(reader), 30)
                if body[:1] == b"\xff":
                    break
                if body[:1] == b"\xfe":
                    ended += 1
            done[0] += 1
    except (asyncio.IncompleteReadError, ConnectionError, TimeoutError, OSError):
        pass
    finally:
        writer.transport.abort()


async def main() -> None:
    host, port, src = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    conns, secs = int(sys.argv[4]), float(sys.argv[5])
    stmts = int(sys.argv[6]) if len(sys.argv) > 6 else 50
    done = [0]
    deadline = time.monotonic() + secs
    await asyncio.gather(*(one(host, port, src, deadline, stmts, done) for _ in range(conns)))
    print(f"answered={done[0]}")


asyncio.run(main())
