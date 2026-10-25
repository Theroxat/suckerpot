"""Non-reading clients must not be able to inflate the sensor's memory (response amplification)."""

from __future__ import annotations

import asyncio
import os
import socket
from typing import Any

from conftest import Harness


def _rss() -> int:
    with open("/proc/self/statm") as fh:
        return int(fh.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")


def _phpinfo_request() -> bytes:
    hdrs = b"".join(b"X-%03d: %s\r\n" % (i, b'"' * 1200) for i in range(99))
    return b"GET /info.php HTTP/1.1\r\nHost: srv-web01\r\n" + hdrs + b"\r\n"


def _multicall_request() -> bytes:
    call = (
        b"<value><struct><member><name>methodName</name><value><string>system.listMethods"
        b"</string></value></member><member><name>params</name><value><array><data></data>"
        b"</array></value></member></struct></value>"
    )
    cred = call.replace(b"system.listMethods", b"wp.getUsersBlogs")
    body = (
        b"<?xml version='1.0'?><methodCall><methodName>system.multicall</methodName><params>"
        b"<param><value><array><data>" + (call + cred) * 100 + b"</data></array></value></param>"
        b"</params></methodCall>"
    )
    return b"POST /xmlrpc.php HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % len(body) + body


def _open_stuck(port: int, payload: bytes, n: int) -> list[socket.socket]:
    socks = []
    for _ in range(n):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
        s.connect(("127.0.0.1", port))
        s.sendall(payload)
        socks.append(s)
    return socks


async def test_non_reading_clients_do_not_inflate_memory(start_with: Any) -> None:
    async with start_with(max_connections=200, max_per_ip=200, memory_budget=24 * 1024 * 1024) as h:
        base = _rss()
        socks = await asyncio.to_thread(_open_stuck, h.http, _phpinfo_request(), 60)
        socks += await asyncio.to_thread(_open_stuck, h.http, _multicall_request(), 60)
        peak = 0
        for _ in range(20):
            await asyncio.sleep(0.1)
            peak = max(peak, _rss() - base)
            assert h.sensor.budget.used <= h.sensor.budget.limit
        assert peak < 80 * 1024 * 1024, peak
        # the sensor still answers a normal client
        r, w = await asyncio.open_connection("127.0.0.1", h.http)
        w.write(b"GET /robots.txt HTTP/1.0\r\n\r\n")
        assert (await asyncio.wait_for(r.read(64), 5)).startswith(b"HTTP/1.1 200")
        w.close()
        for s in socks:
            s.close()
        for _ in range(100):
            if h.sensor.total == 0:
                break
            await asyncio.sleep(0.1)
        assert h.sensor.total == 0 and h.sensor.budget.used == 0


async def test_reflected_output_is_bounded(harness: Harness) -> None:
    raw = await harness.raw(_phpinfo_request().replace(b"GET", b"GET", 1), wait=1.0)
    assert len(raw) < 400 * 1024  # was ~730 KB with 3x reflection of 100 x 1200-byte headers


async def test_multicall_answers_every_entry_but_records_200(harness: Harness) -> None:
    cred = (
        b"<value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs"
        b"</string></value></member><member><name>params</name><value><array><data>"
        b"<value><string>u%d</string></value><value><string>p</string></value></data></array>"
        b"</value></member></struct></value>"
    )
    body = (
        b"<methodCall><methodName>system.multicall</methodName><params><param><value><array><data>"
        + b"".join(cred % i for i in range(300))
        + b"</data></array></value></param></params></methodCall>"
    )
    raw = await harness.raw(
        b"POST /xmlrpc.php HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: %d\r\n\r\n"
        % len(body)
        + body,
        wait=1.0,
    )
    assert raw.count(b"<int>403</int>") == 300
    logins = [e for e in await harness.events(wait=0.5) if e.type == "login_attempt"]
    assert len(logins) <= 200 and len(logins) >= 150  # event buckets may trim a little


async def test_more_than_100_form_fields_keep_credentials(harness: Harness) -> None:
    filler = "&".join(f"f{i}=x" for i in range(150))
    body = f"log=admin&pwd=secret&{filler}"
    r = await harness.raw(
        b"POST /wp-login.php HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n"
        % len(body)
        + body.encode(),
        wait=0.5,
    )
    assert b"is incorrect" in r
