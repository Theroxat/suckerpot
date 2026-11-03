"""SNI enforcement: the TLS server name must equal the CONNECT host."""

from __future__ import annotations

import asyncio
import random

import pytest

from hubproxy import sni
from tests.helpers import (
    ALLOW,
    _ext,
    client_hello,
    client_hello_body,
    connect_request,
    records,
    running,
    sni_ext,
)


async def tunnel(port: int, flight: bytes, *, then_wait: float = 2.0) -> bytes:
    """CONNECT, send ``flight``, return what comes back after the 200 answer until EOF."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(connect_request())
    await writer.drain()
    assert await reader.readuntil(b"\r\n\r\n") == b"HTTP/1.1 200 Connection established\r\n\r\n"
    writer.write(flight)
    await writer.drain()
    try:
        async with asyncio.timeout(then_wait):
            return await reader.read(65536)
    except TimeoutError:
        return b"<open>"
    finally:
        writer.close()


async def test_matching_sni_is_forwarded_whole() -> None:
    hello = client_hello(ALLOW.upper())
    async with running() as (proxy, _, port, _):
        assert await tunnel(port, hello) == b"echo:" + hello
        assert proxy.counters["allowed"] == 1
        assert proxy.counters["refused_sni"] == 0


async def test_hello_split_across_records_is_accepted() -> None:
    hello = client_hello(split=30)
    async with running() as (_, _, port, _):
        assert await tunnel(port, hello) == b"echo:" + hello


@pytest.mark.parametrize(
    "flight",
    [
        client_hello("other.example.org"),
        client_hello("x." + ALLOW),
        client_hello(ALLOW + "."),
        client_hello(None),
        records(client_hello_body(_ext(0, b"\x00\x00"))),
        records(client_hello_body(sni_ext(ALLOW) + sni_ext("other.example.org"))),
        records(client_hello_body(_ext(0xFE0D, b"\x00") + sni_ext(ALLOW))),
        records(client_hello_body(_ext(0xFE0D, b"\x00"))),
        records(client_hello_body(None)),
        records(client_hello_body(sni_ext(ALLOW)), msg_type=2),
        b"GET / HTTP/1.1\r\n\r\n",
        b"\x16\x03\x01\x00\x00",
        b"\x17\x03\x03\x00\x01x",
        b"\x16\x03\x01\x40\x01" + bytes(16385),
    ],
)
async def test_bad_flights_are_refused(flight: bytes) -> None:
    async with running() as (proxy, _fakes, port, _):
        got = await tunnel(port, flight)
        assert got == b""  # closed, nothing relayed
        assert proxy.counters["refused_sni"] == 1
        assert proxy.counters["allowed"] == 0


async def test_two_names_in_one_extension_are_refused() -> None:
    entries = b"".join(b"\x00" + len(n).to_bytes(2, "big") + n.encode() for n in (ALLOW, ALLOW))
    ext = _ext(0, len(entries).to_bytes(2, "big") + entries)
    async with running() as (proxy, _, port, _):
        assert await tunnel(port, records(client_hello_body(ext))) == b""
        assert proxy.counters["refused_sni"] == 1


async def test_slow_client_is_cut_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sni, "HELLO_TIMEOUT", 0.3)
    async with running() as (proxy, _, port, _):
        assert await tunnel(port, client_hello()[:20], then_wait=3) == b""
        assert proxy.counters["refused_sni"] == 1


async def test_sni_refusal_is_counted_without_logging(caplog: pytest.LogCaptureFixture) -> None:
    async with running() as (_, _, port, _):
        await tunnel(port, client_hello("secret-front.example.org"))
    assert "secret-front" not in "\n".join(r.getMessage() for r in caplog.records)


def _feed(data: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return reader


async def test_fuzz_parser_never_raises_anything_but_helloerror() -> None:
    rng = random.Random(1234)
    seeds = [client_hello(), client_hello(split=17), client_hello("a.example.org")]
    for i in range(1500):
        base = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(0, 6)):
            if base:
                base[rng.randrange(len(base))] = rng.randrange(256)
        if rng.random() < 0.3:
            base = base[: rng.randrange(len(base) + 1)]
        if i % 5 == 0:
            base = bytearray(rng.randbytes(rng.randint(0, 300)))
        try:
            raw, name = await sni.read_client_hello(_feed(bytes(base)))
        except sni.HelloError:
            continue
        assert raw == bytes(base)[: len(raw)]
        assert name == name.lower()
        assert name and "." not in name[-1:]


def test_parse_body_rejects_every_truncation() -> None:
    body = client_hello_body(sni_ext(ALLOW))
    assert sni.parse_hello_body(body) == ALLOW
    for n in range(len(body)):
        with pytest.raises(sni.HelloError):
            sni.parse_hello_body(body[:n])
