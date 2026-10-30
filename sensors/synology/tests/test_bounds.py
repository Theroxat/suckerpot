"""Bounds: body, headers, slow clients, caps, rates, event size, response size."""

from __future__ import annotations

import asyncio
import json
import socket
import ssl
import time
from pathlib import Path

from conftest import Harness, start

from synology_sensor import detect
from synology_sensor.httpio import Request

MAX_EVENT = 16 * 1024


async def test_huge_body_is_drained_and_bounded(harness: Harness) -> None:
    size = 3 * 1024 * 1024
    body = b"api=SYNO.API.Auth&method=login&version=7&account=admin&passwd=x&junk=" + b"A" * size
    r = await harness.form("/webapi/entry.cgi", body.decode())
    assert r.status == 200
    evs = await harness.events("http_request")
    d = evs[0].data
    assert d["body_len"] == len(body) and d["body_truncated"] is True
    assert len(d["body_preview"]) <= 2500 and "oversized_body" in d["flags"]
    assert len(json.dumps(d)) < MAX_EVENT
    await asyncio.sleep(0.1)
    assert harness.sensor.budget.used == 0


async def test_body_above_total_max_is_cut_off(tmp_path: Path) -> None:
    async with start(tmp_path, {"body_total_max": 64 * 1024}) as h:
        body = b"a=" + b"B" * (256 * 1024)
        out = await h.raw(
            b"POST /webapi/entry.cgi HTTP/1.1\r\nHost: x\r\nUser-Agent: t\r\nContent-Length: "
            + str(len(body)).encode()
            + b"\r\n\r\n"
            + body,
            wait=1.5,
        )
        assert out.startswith(b"HTTP/1.1 200")
        d = (await h.events("http_request"))[0].data
        assert d["body_truncated"] is True and d["body_len"] <= 64 * 1024


async def test_many_headers_get_431(harness: Harness) -> None:
    hdrs = b"".join(f"X-H{i}: v\r\n".encode() for i in range(200))
    out = await harness.raw(b"GET / HTTP/1.1\r\nHost: x\r\n" + hdrs + b"\r\n")
    assert out.startswith(b"HTTP/1.1 431")


async def test_huge_head_gets_431_and_events_stay_small(harness: Harness) -> None:
    out = await harness.raw(b"GET /" + b"a" * 20000 + b" HTTP/1.1\r\nHost: x\r\n\r\n")
    assert out.startswith(b"HTTP/1.1 431") or out.startswith(b"HTTP/1.1 414")
    # 60 maximal headers and a maximal request line that still parses
    hdrs = "".join(f"X-{i}: {'v' * 200}\r\n" for i in range(60))
    line = "GET /webapi/entry.cgi?api=SYNO.Core.System&version=1&method=info&" + "q=" + "z" * 7000
    await harness.raw(f"{line} HTTP/1.1\r\nHost: {'h' * 200}\r\n{hdrs}\r\n".encode())
    for e in await harness.events("http_request"):
        assert len(json.dumps(e.data)) < MAX_EVENT


async def test_slowloris_head_times_out(tmp_path: Path) -> None:
    async with start(tmp_path, {"head_timeout": 0.5}) as h:
        r, w = await asyncio.open_connection("127.0.0.1", h.port)
        w.write(b"GET / HTTP/1.1\r\nHost: x\r\n")
        await w.drain()
        t0 = time.monotonic()
        assert await asyncio.wait_for(r.read(100), 5) == b""
        assert time.monotonic() - t0 < 3
        ev = await h.events("disconnect")
        assert ev[-1].data["reason"] == "timeout"
        scans = await h.events("scan")
        assert scans[0].data["kind"] == "incomplete_request"


async def test_slow_body_times_out(tmp_path: Path) -> None:
    async with start(tmp_path, {"body_timeout": 0.5}) as h:
        r, w = await asyncio.open_connection("127.0.0.1", h.port)
        w.write(b"POST /webapi/entry.cgi HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\napi=")
        await w.drain()
        assert await asyncio.wait_for(r.read(100), 5) == b""
        d = (await h.events("http_request"))[0].data
        assert "incomplete_body" in d["flags"]


async def test_idle_connection_without_data_is_closed(tmp_path: Path) -> None:
    async with start(tmp_path, {"first_byte_timeout": 0.4}) as h:
        r, w = await asyncio.open_connection("127.0.0.1", h.port)
        assert await asyncio.wait_for(r.read(10), 5) == b""
        assert (await h.events("disconnect"))[-1].data["reason"] == "no-data"


async def test_per_ip_cap(tmp_path: Path) -> None:
    async with start(tmp_path, {"max_per_ip": 2}) as h:
        socks = [socket.create_connection(("127.0.0.1", h.port)) for _ in range(5)]
        await asyncio.sleep(0.5)
        assert h.sensor.per_ip == {"127.0.0.1": 2}
        assert h.sensor.rejected == 3
        # the admitted ones still work
        socks[0].sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: t\r\nConnection: close\r\n\r\n")
        socks[0].settimeout(3)
        assert (await asyncio.to_thread(socks[0].recv, 20)).startswith(b"HTTP/1.1 200")
        for s in socks:
            s.close()
        await asyncio.sleep(0.3)
        assert h.sensor.per_ip == {} and h.sensor.total == 0


async def test_global_cap_counts_both_ports(tmp_path: Path) -> None:
    async with start(tmp_path, {"max_connections": 3, "max_per_ip": 50}) as h:
        socks = [socket.create_connection(("127.0.0.1", h.port)) for _ in range(2)]
        socks += [socket.create_connection(("127.0.0.1", h.tls_port)) for _ in range(3)]
        await asyncio.sleep(0.5)
        assert h.sensor.total == 3 and h.sensor.rejected == 2
        for s in socks:
            s.close()


async def test_connection_rate_per_ip(tmp_path: Path) -> None:
    async with start(tmp_path, {"conn_rate": 0.1, "conn_burst": 3.0, "max_per_ip": 50}) as h:
        socks = [socket.create_connection(("127.0.0.1", h.port)) for _ in range(8)]
        await asyncio.sleep(0.4)
        assert h.sensor.rejected == 5
        for s in socks:
            s.close()


async def test_request_rate_per_ip(tmp_path: Path) -> None:
    async with start(tmp_path, {"req_rate": 0.1, "req_burst": 5.0}) as h:
        req = b"GET /webman/favicon.ico HTTP/1.1\r\nHost: x\r\nUser-Agent: t\r\n\r\n"
        r, w = await asyncio.open_connection("127.0.0.1", h.port)
        w.write(req * 20)
        await w.drain()
        out = b""
        try:
            while chunk := await asyncio.wait_for(r.read(65536), 2):
                out += chunk
        except TimeoutError:
            pass
        assert out.count(b"HTTP/1.1 200") == 5 and b"HTTP/1.1 503" in out
        assert h.sensor.requests_limited == 1


async def test_max_requests_per_connection(tmp_path: Path) -> None:
    async with start(tmp_path, {"max_requests_per_conn": 4}) as h:
        req = b"GET /webman/favicon.ico HTTP/1.1\r\nHost: x\r\nUser-Agent: t\r\n\r\n"
        out = await h.raw(req * 10, wait=1.0)
        assert out.count(b"HTTP/1.1 200") == 4


def _client_hello() -> bytes:
    """A real ClientHello record, produced by Python's TLS client."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(incoming, outgoing, server_hostname="nas.example.invalid")
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


def _connect_from(ip: str, port: int) -> socket.socket:
    s = socket.socket()
    s.bind((ip, 0))
    s.connect(("127.0.0.1", port))
    return s


async def test_stalled_handshakes_are_capped_per_ip(tmp_path: Path) -> None:
    cfg: dict[str, object] = {"tls_max_per_ip": 2, "tls_handshake_timeout": 1.0, "max_per_ip": 50}
    async with start(tmp_path, cfg) as h:
        hello = _client_hello()
        socks = []
        for _ in range(6):
            s = socket.create_connection(("127.0.0.1", h.tls_port))
            s.sendall(hello)  # a full hello, then silence: the handshake holds a slot
            socks.append(s)
        await asyncio.sleep(0.5)
        assert h.sensor.hs_per_ip == {"127.0.0.1": 2}
        await asyncio.sleep(1.5)
        assert h.sensor.handshakes == 0 and h.sensor.hs_per_ip == {}
        reasons = [e.data["reason"] for e in await h.events("disconnect")]
        assert "tls-busy" in reasons and "tls-handshake-failed" in reasons
        for s in socks:
            s.close()


async def test_partial_client_hellos_cannot_blind_the_tls_port(tmp_path: Path) -> None:
    """Several IPs hold partial ClientHellos; a legitimate client still gets through."""
    cfg: dict[str, object] = {"tls_hello_timeout": 1.0, "max_per_ip": 50, "tls_max_inflight": 8}
    async with start(tmp_path, cfg) as h:
        hello = _client_hello()
        socks = []
        for ip in ("127.0.0.2", "127.0.0.3", "127.0.0.4"):
            for n in range(8):
                s = _connect_from(ip, h.tls_port)
                s.sendall(hello[: 3 + n] if n % 2 else b"\x16\x03\x01")  # header never completes
                socks.append(s)
        await asyncio.sleep(0.3)
        assert h.sensor.handshakes == 0  # nobody holds a handshake slot
        for _ in range(5):
            r = await h.http("GET", "/", tls=True)
            assert r.status == 200
        await asyncio.sleep(1.2)
        reasons = [e.data["reason"] for e in await h.events("disconnect")]
        assert reasons.count("tls-incomplete-hello") == 24
        for s in socks:
            s.close()


async def test_responses_do_not_amplify(harness: Harness) -> None:
    paths = [
        "/",
        "/nope",
        "/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query&query=all",
        "/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query&query="
        + ",".join(["SYNO.API.Auth"] * 500),
        "/webapi/entry.cgi?api=SYNO.Core.System&version=1&method=info",
    ]
    for p in paths:
        r = await harness.http("GET", p)
        assert len(r.body) < 8192, p
    r = await harness.http(
        "GET", "/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query&query=" + "x" * 6000
    )
    assert len(r.body) < 200


async def test_pipelined_non_reader_does_not_grow_memory(tmp_path: Path) -> None:
    async with start(tmp_path, {"write_timeout": 0.5}) as h:
        s = socket.create_connection(("127.0.0.1", h.port))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        req = b"GET /webapi/query.cgi?api=SYNO.API.Info&version=1&method=query&query=all HTTP/1.1\r\nHost: x\r\nUser-Agent: t\r\n\r\n"
        s.sendall(req * 80)
        await asyncio.sleep(1.5)
        assert h.sensor.budget.used <= 300 * 1024
        s.close()
        await asyncio.sleep(0.3)
        assert h.sensor.budget.used == 0


def test_detectors_are_linear_on_adversarial_input() -> None:
    for text in ("http:// " * 40000, "1:" * 40000, "\x00" * 100000, "%0d" * 50000):
        t0 = time.perf_counter()
        detect.find_urls(text)
        detect.scgi_shape(text)
        assert time.perf_counter() - t0 < 0.1


def test_collect_bounds_parameters() -> None:
    q = "&".join(f"p{i}=v" for i in range(5000))
    req = Request(method="GET", target="/x", path="/x", query_raw=q)
    a = detect.collect(req)
    assert len(a.params) <= detect.MAX_PARAMS
    req = Request(method="POST", target="/x", path="/x", query_raw="")
    req.body = json.dumps({f"k{i}": "v" * 10000 for i in range(500)}).encode()
    req.headers = [("Content-Type", "application/json")]
    a = detect.collect(req)
    assert len(a.params) <= detect.MAX_PARAMS and all(
        len(v) <= detect.MAX_VALUE for _, v in a.params
    )
    req.body = b"[" * 100000
    assert detect.collect(req).params == []  # deep nesting is rejected, not recursed into


async def test_churning_ips_cannot_exhaust_the_handshake_budget(tmp_path: Path) -> None:
    """Clients that send a full hello and hang up, from many IPs, leave room for a legit one."""
    cfg: dict[str, object] = {
        "tls_per_sec": 40.0,
        "tls_burst": 80.0,
        "tls_ip_rate": 1.0,
        "tls_ip_burst": 5.0,
        "tls_reserve_rate": 5.0,
        "tls_reserve_burst": 10.0,
        "max_per_ip": 50,
        "conn_rate": 1000.0,
        "conn_burst": 1000.0,
    }
    async with start(tmp_path, cfg) as h:
        hello = _client_hello()
        stop = asyncio.Event()

        async def churn(ip: str) -> None:
            while not stop.is_set():
                try:
                    s = _connect_from(ip, h.tls_port)
                    s.sendall(hello)
                    s.close()
                except OSError:
                    pass
                await asyncio.sleep(0.02)

        tasks = [asyncio.create_task(churn(f"127.0.0.{n}")) for n in range(10, 18)]
        await asyncio.sleep(1.0)  # let the churners drain the burst
        ok = 0
        for _ in range(5):  # a legitimate IP's own burst allowance
            try:
                ok += (await h.http("GET", "/", tls=True)).status == 200
            except OSError:
                pass
            await asyncio.sleep(0.1)
        stop.set()
        await asyncio.gather(*tasks)
        assert ok >= 4, ok


async def test_oversized_hello_record_is_refused(harness: Harness) -> None:
    s = socket.create_connection(("127.0.0.1", harness.tls_port))
    s.sendall(b"\x16\x03\x01\xff\xff" + b"A" * 100)
    await asyncio.sleep(0.4)
    assert harness.sensor.handshakes == 0
    reasons = [e.data["reason"] for e in await harness.events("disconnect")]
    assert reasons == ["tls-incomplete-hello"]
    s.close()
