"""Memory hardening: TLS buffer sizes, the TLS cap, budget refusals and the memory guard."""

from __future__ import annotations

import asyncio
import socket
import ssl
import time
from pathlib import Path
from typing import Any

import pytest
from conftest import FakePublisher, Harness
from suckerpot_common import EventType

from web_sensor import xmlrpc
from web_sensor.events import EventSink
from web_sensor.memguard import MemoryGuard
from web_sensor.server import Conn, conn_cost


def _phpinfo_request() -> bytes:
    hdrs = b"".join(b"X-%03d: %s\r\n" % (i, b'"' * 1200) for i in range(98))
    return b"GET /info.php HTTP/1.1\r\nHost: srv-web01\r\n" + hdrs + b"\r\n"


def _stuck(port: int, payload: bytes) -> socket.socket:
    """A client that sends a request and never reads the response."""
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
    s.connect(("127.0.0.1", port))
    s.sendall(payload)
    return s


async def _wait_live(h: Harness, n: int, *, tls: bool | None = None) -> list[Conn]:
    for _ in range(100):
        conns = [
            c
            for c in h.sensor.live.values()
            if c.transport is not None and (tls is None or c.listener.tls == tls)
        ]
        if len(conns) >= n:
            return conns
        await asyncio.sleep(0.05)
    raise AssertionError(f"expected {n} live connections, have {len(h.sensor.live)}")


async def _fetch(port: int, data: bytes, wait: float = 3.0) -> tuple[bytes, float]:
    start = time.monotonic()
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(data)
    out = b""
    try:
        while True:
            chunk = await asyncio.wait_for(reader.read(65536), wait)
            if not chunk:
                break
            out += chunk
    except (TimeoutError, ConnectionError):
        pass
    writer.close()
    return out, time.monotonic() - start


# -- TLS buffers -------------------------------------------------------------------------------


async def test_tls_connection_buffers_are_small(harness: Harness) -> None:
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", harness.https, ssl=harness.tls_context()
    )
    writer.write(b"GET / HTTP/1.1\r\nHost: x\r\nX-Partial: ")  # keeps the connection open
    await writer.drain()
    (conn,) = await _wait_live(harness, 1, tls=True)
    proto: Any = getattr(conn.transport, "_ssl_protocol")  # noqa: B009 - asyncio internals
    assert type(proto).max_size == 16 * 1024
    assert len(proto._ssl_buffer) == 16 * 1024  # was 256 KiB per connection
    assert proto._incoming_high_water == 32 * 1024  # was 256 KiB
    assert proto._outgoing_high_water == 32 * 1024
    assert proto._transport.get_write_buffer_limits()[1] == 32 * 1024
    raw = conn.transport.get_extra_info("socket") if conn.transport else None
    assert raw is not None
    # Linux doubles the requested size: 32 KiB asked, 64 KiB effective (the default autotunes
    # up to several MB).
    assert raw.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF) <= 64 * 1024
    assert raw.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF) <= 64 * 1024
    writer.close()


async def test_large_response_over_tls_is_complete(harness: Harness) -> None:
    """16 KiB write chunks over TLS still deliver big responses byte for byte."""
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", harness.https, ssl=harness.tls_context()
    )
    writer.write(
        _phpinfo_request().replace(b"Host: srv-web01\r\n", b"Host: x\r\nConnection: close\r\n")
    )
    data = await asyncio.wait_for(reader.read(), 10)
    head, _, body = data.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 200 OK")
    assert b"Transfer-Encoding: chunked" in head
    assert body.endswith(b"0\r\n\r\n") and b"</html>" in body
    writer.close()


async def test_tls_connections_have_their_own_cap(start_with: Any) -> None:
    async with start_with(max_tls_connections=2) as h:
        held = []
        for _ in range(2):
            r, w = await asyncio.open_connection("127.0.0.1", h.https, ssl=h.tls_context())
            w.write(b"GET / HTTP/1.1\r\nHost: x\r\nX-Partial: ")
            await w.drain()
            held.append(w)
        await _wait_live(h, 2, tls=True)
        assert h.sensor.tls_total == 2
        with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
            r, w = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", h.https, ssl=h.tls_context()), 5
            )
            w.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            if not await asyncio.wait_for(r.read(10), 5):
                raise ConnectionError("closed")
        # Plain HTTP is not affected.
        out, _ = await _fetch(h.http, b"GET /robots.txt HTTP/1.0\r\n\r\n")
        assert out.startswith(b"HTTP/1.1 200")
        assert h.sensor._limited.get(("127.0.0.1", h.cfg.https_public_port), 0) >= 1
        for w in held:
            w.close()
        for _ in range(100):
            if h.sensor.tls_total == 0:
                break
            await asyncio.sleep(0.05)
        assert h.sensor.tls_total == 0 and h.sensor.budget.used == 0


# -- admission budget --------------------------------------------------------------------------


async def test_exhausted_budget_is_a_slow_503_not_a_reset(start_with: Any) -> None:
    async with start_with(memory_budget=conn_cost(False) + 4096) as h:
        r, w = await asyncio.open_connection("127.0.0.1", h.http)
        w.write(b"GET / HTTP/1.1\r\nHost: x\r\nX-Partial: ")  # holds the only budget slot
        await w.drain()
        await _wait_live(h, 1)
        out, elapsed = await _fetch(h.http, b"GET / HTTP/1.1\r\nHost: srv-web01\r\n\r\n")
        assert out.startswith(b"HTTP/1.1 503 Service Unavailable\r\n"), out[:80]
        assert b"Connection: close" in out and b"<title>503 Service Unavailable</title>" in out
        assert elapsed >= 0.1  # jittered, like the other refusals
        assert h.sensor._limited.get(("127.0.0.1", h.cfg.http_public_port), 0) == 1
        w.close()


# -- memory guard ------------------------------------------------------------------------------


def _cgroup(path: Path, current: int, limit: int | str = 1_000_000, inactive: int = 0) -> None:
    (path / "memory.current").write_text(f"{current}\n")
    (path / "memory.max").write_text(f"{limit}\n")
    (path / "memory.stat").write_text(f"anon 1\nfile 2\ninactive_file {inactive}\nactive_file 3\n")


def test_guard_reads_cgroup_minus_inactive_file(tmp_path: Path) -> None:
    _cgroup(tmp_path, 800_000, inactive=200_000)
    g = MemoryGuard(123, cgroup=tmp_path)
    assert g.source == "cgroup" and g.limit == 1_000_000
    assert not g.sample() and not g.refusing and g.usage == 600_000
    _cgroup(tmp_path, 750_000)
    assert not g.sample() and g.refusing and g.excess() == 50_000
    _cgroup(tmp_path, 900_000)
    assert g.sample() and g.refusing


def test_guard_falls_back_to_configured_limit_and_rss(tmp_path: Path) -> None:
    _cgroup(tmp_path, 10, limit="max")
    assert MemoryGuard(5000, cgroup=tmp_path).limit == 5000
    g = MemoryGuard(1 << 40, cgroup=tmp_path / "absent")
    assert g.source == "rss" and g.read() > 1 << 20 and not g.sample()


async def test_guard_refuses_then_aborts_the_fattest_connection(
    start_with: Any, tmp_path: Path
) -> None:
    _cgroup(tmp_path, 100_000)
    guard = MemoryGuard(1, cgroup=tmp_path)
    async with start_with(guard=guard, max_per_ip=50) as h:
        r, w = await asyncio.open_connection("127.0.0.1", h.http)
        w.write(b"GET / HTTP/1.1\r\nHost: x\r\nX-Partial: ")  # small, idle
        await w.drain()
        fat = await asyncio.to_thread(_stuck, h.http, _phpinfo_request())
        await _wait_live(h, 2)
        for _ in range(50):  # wait until the response is pending on the stuck connection
            if max(c.inflight for c in h.sensor.live.values()) > 0:
                break
            await asyncio.sleep(0.05)
        # 75 %: refuse new connections (Apache's 503), keep the live ones.
        _cgroup(tmp_path, 750_000)
        assert h.sensor.check_memory() == 0 and guard.refusing
        out, _ = await _fetch(h.http, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        assert out.startswith(b"HTTP/1.1 503 Service Unavailable")
        assert len(h.sensor.live) == 2
        # 90 %: abort the connection holding the most bytes, not the idle one.
        _cgroup(tmp_path, 900_000)
        assert h.sensor.check_memory() >= 1
        _cgroup(tmp_path, 750_000)  # before the guard's own 1 s tick sees 90 % again
        await asyncio.sleep(0.3)
        disconnects = [e for e in await h.events(EventType.disconnect.value)]
        assert any(e.data["reason"] == "memory-pressure" for e in disconnects)
        assert len(h.sensor.live) == 1  # the idle connection survived
        # Back to normal: new connections are served again.
        _cgroup(tmp_path, 100_000)
        h.sensor.check_memory()
        out, _ = await _fetch(h.http, b"GET /robots.txt HTTP/1.0\r\n\r\n")
        assert out.startswith(b"HTTP/1.1 200")
        assert h.sensor.stats()["memory_aborted"] >= 1
        fat.close()
        w.close()


# -- xmlrpc multicall --------------------------------------------------------------------------

_LIST = (
    b"<value><struct><member><name>methodName</name><value><string>system.listMethods"
    b"</string></value></member><member><name>params</name><value><array><data></data>"
    b"</array></value></member></struct></value>"
)


def _multicall(entries: bytes) -> bytes:
    body = (
        b"<?xml version='1.0'?><methodCall><methodName>system.multicall</methodName><params>"
        b"<param><value><array><data>" + entries + b"</data></array></value></param>"
        b"</params></methodCall>"
    )
    return b"POST /xmlrpc.php HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % len(body) + body


async def test_multicall_answers_every_list_methods_entry(harness: Harness) -> None:
    unknown = _LIST.replace(b"system.listMethods", b"x.nope")
    out = await harness.raw(_multicall(_LIST * 900 + unknown), wait=3.0)
    assert out.startswith(b"HTTP/1.1 200 OK")
    assert out.count(b"<string>system.multicall</string>") == 900
    assert out.count(b"<name>faultCode</name>") == 1
    assert b"server error. requested method x.nope does not exist." in out


def test_multicall_size_is_exact() -> None:
    entries: list[tuple[bool, Any]] = [
        (False, xmlrpc.LIST_METHODS),
        (True, (403, "Incorrect username or password.")),
        (False, {"a": [1, "b"]}),
        (False, xmlrpc.LIST_METHODS),
    ]
    assert xmlrpc.multicall_size(entries) == len(xmlrpc.multicall(entries))


async def test_multicall_bigger_than_the_budget_is_a_503(start_with: Any) -> None:
    async with start_with(memory_budget=2 * 1024 * 1024) as h:
        out = await h.raw(_multicall(_LIST * 900), wait=2.0)
        assert out.startswith(b"HTTP/1.1 503 Service Unavailable"), out[:60]
        assert h.sensor.budget.used <= h.sensor.budget.limit
        out = await h.raw(_multicall(_LIST * 3), wait=1.0)  # small ones still work
        assert out.count(b"<string>system.multicall</string>") == 3


# -- event queue -------------------------------------------------------------------------------


def test_event_queue_is_bounded_in_bytes() -> None:
    sink = EventSink(FakePublisher(), rate=1e6, burst=1e6, global_rate=1e6, global_burst=1e6,
                     queue_bytes=100_000)  # fmt: skip
    ok = 0
    for i in range(200):  # workers not started: nothing drains
        ok += sink.emit(
            session_id=f"s{i}",
            src_ip="192.0.2.1",
            src_port=1,
            dst_port=80,
            type_=EventType.http_request,
            data={"blob": "x" * 4000},
        )
    assert 0 < ok < 30
    assert sink.queued_bytes <= 100_000 and sink.queue_full == 200 - ok


async def test_multicall_is_rate_limited_per_ip(harness: Harness) -> None:
    statuses = []
    for _ in range(5):
        out = await harness.raw(_multicall(_LIST * 5), wait=1.0)
        statuses.append(out[9:12])
    assert statuses[:3] == [b"200"] * 3  # burst of 3
    assert b"503" in statuses[3:]
    assert harness.sensor.site.multicall.limited >= 1
    # Ordinary xmlrpc calls are not limited.
    single = _multicall(b"").replace(b"system.multicall", b"system.listMethods")
    assert (await harness.raw(single, wait=1.0)).startswith(b"HTTP/1.1 200")


async def test_gzipped_multicall_is_cached_and_correct(harness: Harness) -> None:
    import gzip

    req = _multicall(_LIST * 300).replace(b"Host: x\r\n", b"Host: x\r\nAccept-Encoding: gzip\r\n")
    first = await harness.raw(req, wait=2.0)
    second = await harness.raw(req, wait=2.0)
    assert first.split(b"\r\n\r\n", 1)[1] == second.split(b"\r\n\r\n", 1)[1]
    assert b"Content-Encoding: gzip" in first.split(b"\r\n\r\n", 1)[0]
    body = gzip.decompress(first.split(b"\r\n\r\n", 1)[1])
    assert body.count(b"<string>system.multicall</string>") == 300
    assert harness.sensor.site.multicall.cache_hits == 1


def test_multicall_gzip_budget() -> None:
    lim = xmlrpc.MulticallLimiter(gzip_rate=1.0, gzip_burst=1000.0)
    assert lim.gzip(b"a" * 900) is not None
    assert lim.gzip(b"b" * 900) is None  # budget spent
    assert lim.gzip(b"a" * 900) is not None  # cached: free


async def test_loopback_healthcheck_is_never_refused(start_with: Any, tmp_path: Path) -> None:
    _cgroup(tmp_path, 990_000)  # 99 %: everything else is refused
    guard = MemoryGuard(1, cgroup=tmp_path)
    async with start_with(guard=guard, quiet_loopback=True) as h:
        guard.sample()
        assert guard.refusing
        out, _ = await _fetch(h.http, b"GET /robots.txt HTTP/1.0\r\n\r\n")
        assert out.startswith(b"HTTP/1.1 200")
