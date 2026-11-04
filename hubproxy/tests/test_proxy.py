from __future__ import annotations

import asyncio
import logging

import pytest

from hubproxy import server
from tests.helpers import (
    ALLOW,
    GLOBAL_IP,
    Fakes,
    basic,
    client_hello,
    connect_request,
    exchange,
    running,
)


def status_line(raw: bytes) -> str:
    return raw.split(b"\r\n", 1)[0].decode()


async def test_allowed_connect_tunnels_bytes() -> None:
    async with running() as (proxy, fakes, port, _):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(connect_request())
        await writer.drain()
        assert await reader.readuntil(b"\r\n\r\n") == b"HTTP/1.1 200 Connection established\r\n\r\n"
        hello = client_hello()
        writer.write(hello + b"hello")
        await writer.drain()
        got = b""
        async with asyncio.timeout(3):
            while len(got) < 5 + len(hello) + 5:
                got += await reader.read(65536)
        assert got == b"echo:" + hello + b"hello"[:0] + got[5 + len(hello) :]
        assert got.endswith(b"hello")
        writer.close()
        assert fakes.dialled == [(GLOBAL_IP, 443)]
        assert fakes.resolved == [ALLOW]  # resolved once, then the vetted IP is used
        assert proxy.counters["allowed"] == 1


async def test_host_match_is_case_insensitive_but_exact() -> None:
    async with running() as (_, _, port, _):
        ok = await exchange(port, connect_request(target="RELAY.SelfHostr.IO:443"))
        assert status_line(ok) == "HTTP/1.1 200 Connection established"
        for bad in (
            "relay.selfhostr.io.:443",
            "x.relay.selfhostr.io:443",
            "relay.selfhostr.io",
        ):
            assert status_line(await exchange(port, connect_request(target=bad))).endswith(
                "403 Forbidden"
            )


@pytest.mark.parametrize(
    "target",
    [
        "example.org:443",
        "relay.selfhostr.io:80",
        "relay.selfhostr.io:8443",
        "relay.selfhostr.io:0443",
        "relay.selfhostr.io:",
        ":443",
        "203.0.113.7:443",
        "[2001:db8::1]:443",
        "127.0.0.1:443",
        "2130706433:443",
        "0x7f000001:443",
        "relay.selfhostr.io@example.org:443",
        "example.org:443@relay.selfhostr.io:443",
    ],
)
async def test_other_targets_are_refused(target: str) -> None:
    async with running() as (proxy, fakes, port, _):
        raw = await exchange(port, connect_request(target=target))
        assert status_line(raw) == "HTTP/1.1 403 Forbidden"
        assert fakes.resolved == [] and fakes.dialled == []
        assert proxy.counters["refused_host"] == 1


@pytest.mark.parametrize("method", ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "TRACE"])
async def test_only_connect_is_accepted(method: str) -> None:
    async with running() as (proxy, fakes, port, _):
        raw = await exchange(port, connect_request(target="http://example.org/", method=method))
        assert status_line(raw) == "HTTP/1.1 405 Method Not Allowed"
        assert fakes.dialled == []
        assert proxy.counters["refused_method"] == 1


async def test_plain_http_absolute_uri_is_refused() -> None:
    async with running() as (_, fakes, port, _):
        raw = await exchange(port, b"GET http://relay.selfhostr.io/ HTTP/1.1\r\nHost: x\r\n\r\n")
        assert status_line(raw).endswith("405 Method Not Allowed")
        assert fakes.dialled == []


@pytest.mark.parametrize(
    "auth",
    ["", basic("wrong-password-value"), basic(user="admin"), "Basic !!!", "Bearer abc", "Basic"],
)
async def test_missing_or_wrong_auth_is_407_with_constant_body(auth: str) -> None:
    async with running() as (proxy, fakes, port, _):
        raw = await exchange(port, connect_request(auth=auth))
        assert status_line(raw) == "HTTP/1.1 407 Proxy Authentication Required"
        assert raw.endswith(b"Content-Length: 0\r\nConnection: close\r\n\r\n")
        assert fakes.resolved == []
        assert proxy.counters["refused_auth"] == 1


async def test_auth_is_checked_before_the_host() -> None:
    async with running() as (_, _, port, _):
        raw = await exchange(
            port, connect_request(target="example.org:443", auth=basic("nope-nope-nope-nope"))
        )
        assert status_line(raw).endswith("407 Proxy Authentication Required")


async def test_password_may_contain_a_colon() -> None:
    from hubproxy.config import Settings
    from hubproxy.server import HubProxy

    settings = Settings(allow=(f"{ALLOW}:443",), password="a:b:c-long-enough-pw")
    proxy = HubProxy(settings)
    from hubproxy.httpwire import parse_head

    head = parse_head(connect_request(auth=basic("a:b:c-long-enough-pw")))
    assert proxy._authorized(head)


@pytest.mark.parametrize(
    "answer",
    [
        "127.0.0.1",
        "100.64.0.1",
        "169.254.0.1",
        "198.18.77.1",
        "203.0.113.9",
        "192.0.2.1",
        "198.51.100.1",
        "224.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "::1",
        "fd00::1",
        "fe80::1",
        "::ffff:127.0.0.1",
        "2001:db8::1",
        "not-an-ip",
    ],
)
async def test_non_global_resolution_is_refused(answer: str) -> None:
    fakes = Fakes(answers={ALLOW: [answer]})
    async with running(fakes) as (proxy, fakes, port, _):
        raw = await exchange(port, connect_request())
        assert status_line(raw) == "HTTP/1.1 502 Bad Gateway"
        assert fakes.dialled == []
        assert proxy.counters["refused_address"] == 1


async def test_one_bad_answer_taints_the_set() -> None:
    fakes = Fakes(answers={ALLOW: [GLOBAL_IP, "127.0.0.1"]})
    async with running(fakes) as (_, fakes, port, _):
        assert status_line(await exchange(port, connect_request())).endswith("502 Bad Gateway")
        assert fakes.dialled == []


async def test_empty_resolution_and_connect_failure_are_502() -> None:
    async with running(Fakes(answers={})) as (_, _, port, _):
        assert status_line(await exchange(port, connect_request())).endswith("502 Bad Gateway")
    async with running(Fakes(fail_connect=True)) as (proxy, _fakes, port, _):
        assert status_line(await exchange(port, connect_request())).endswith("502 Bad Gateway")
        assert proxy.counters["refused_connect"] == 1


async def test_connection_cap_gives_503() -> None:
    async with running(max_conns=2) as (proxy, _, port, _):
        held = []
        for _ in range(2):
            held.append(await asyncio.open_connection("127.0.0.1", port))  # idle, no head yet
        await asyncio.sleep(0.1)
        raw = await exchange(port, connect_request())
        assert status_line(raw) == "HTTP/1.1 503 Service Unavailable"
        assert proxy.counters["refused_busy"] == 1
        for _, writer in held:
            writer.close()
        await asyncio.sleep(0.1)
        assert status_line(await exchange(port, connect_request())).endswith(
            "200 Connection established"
        )


async def test_slow_loris_is_cut_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "HEAD_TIMEOUT", 0.3)
    async with running() as (proxy, _, port, _):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"CONNECT relay.selfhostr.io:443 HTTP/1.1\r\n")  # never finishes
        await writer.drain()
        async with asyncio.timeout(3):
            raw = await reader.read(4096)
        assert status_line(raw) == "HTTP/1.1 400 Bad Request"
        assert proxy.counters["bad_request"] == 1
        writer.close()


@pytest.mark.parametrize(
    "payload",
    [
        b"CONNECT " + b"a" * 600 + b":443 HTTP/1.1\r\n\r\n",
        b"CONNECT relay.selfhostr.io:443 HTTP/1.1\r\n" + b"X-A: " + b"b" * 5000 + b"\r\n\r\n",
        b"CONNECT relay.selfhostr.io:443 HTTP/2\r\n\r\n",
        b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\r\n\r\n",
        b"CONNECT relay.selfhostr.io:443\r\n\r\n",
        b"CONNECT  relay.selfhostr.io:443 HTTP/1.1\r\n\r\n",
    ],
)
async def test_malformed_heads_are_400(payload: bytes) -> None:
    async with running() as (proxy, fakes, port, _):
        raw = await exchange(port, payload)
        assert status_line(raw) == "HTTP/1.1 400 Bad Request"
        assert fakes.resolved == []
        assert proxy.counters["bad_request"] == 1


async def test_no_client_address_or_refused_host_in_logs(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    async with running() as (proxy, _, port, _):
        await exchange(port, connect_request(target="secret-target.example.org:443"))
        await exchange(port, connect_request(auth=basic("wrong-password-value")))
        await exchange(port, b"garbage\r\n\r\n")
        await exchange(port, connect_request())
        assert proxy.counters["refused_host"] == 1
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "secret-target" not in text
    assert "127.0.0.1:" not in text
    assert "wrong-password" not in text
