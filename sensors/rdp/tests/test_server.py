"""Protocol tests against the real listener with real sockets and a real TLS client."""

from __future__ import annotations

import asyncio
import contextlib
import os
import ssl
import struct

import pytest
from conftest import Harness, HarnessFactory
from cryptography import x509
from cryptography.x509.oid import NameOID

from rdp_sensor import protocol
from rdp_sensor.protocol import build_connection_request


async def _open(h: Harness) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.open_connection("127.0.0.1", h.port)


async def _read_all(reader: asyncio.StreamReader, timeout: float = 5.0) -> bytes:
    out = b""
    async with asyncio.timeout(timeout):
        while chunk := await reader.read(4096):
            out += chunk
    return out


def _ntlm_tsrequest() -> bytes:
    flags = 0xE2088297
    msg = b"NTLMSSP\x00" + struct.pack("<II", 1, flags) + b"\0" * 16
    msg += struct.pack("<BBH", 10, 0, 22621) + b"\x00\x00\x00\x0f"
    nego = (
        b"\x30"
        + bytes([len(msg) + 4])
        + b"\xa0"
        + bytes([len(msg) + 2])
        + b"\x04"
        + bytes([len(msg)])
        + msg
    )
    tokens = b"\xa1" + bytes([len(nego) + 2]) + b"\x30" + bytes([len(nego)]) + nego
    body = b"\xa0\x03\x02\x01\x06" + tokens
    return b"\x30" + bytes([len(body)]) + body


async def test_cookie_login_attempt_and_hybrid_tls(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        reader, writer = await _open(h)
        writer.write(
            build_connection_request(cookie=b"Cookie: mstshash=administrator", protocols=0x0B)
        )
        await writer.drain()
        cc = await reader.readexactly(19)
        assert cc == bytes.fromhex("030000130ed00000123400021f080008000000")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        await writer.start_tls(ctx)
        der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(der)
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == h.identity.hostname
        assert cert.issuer == cert.subject
        writer.write(_ntlm_tsrequest())  # NTLM NEGOTIATE wrapped in a TSRequest
        await writer.drain()
        challenge = await reader.read(4096)  # the server's TSRequest carrying an NTLM CHALLENGE
        idx = challenge.index(b"NTLMSSP\x00")
        assert challenge[idx + 8] == 2  # NTLM message type 2 (CHALLENGE)
        writer.close()
        disc = (await h.wait_disconnects(1))[0]
        logins = await h.events("login_attempt")
        assert len(logins) == 1  # the cookie login attempt (no AUTHENTICATE was sent)
        data = logins[0].data
        assert data["username"] == "administrator"
        assert data["password"] is None and data["method"] == "rdp-cookie"
        assert data["requested_protocols"] == ["SSL", "HYBRID", "HYBRID_EX"]
        assert data["negotiation"] == "HYBRID_EX"
        assert data["raw_preview"].startswith("0300")
        assert disc.data["reason"] == "credssp_no_authenticate"
        assert disc.data["tls"]["version"] in ("TLSv1.2", "TLSv1.3")
        assert disc.data["credssp"]["version"] == 6
        assert disc.data["credssp"]["ntlm_negotiate"]["os_version"] == "10.0.22621"
        assert "rdp_ntlm" in disc.data["flags"]
        assert disc.data["client_hello"]["ja3_hash"]
        types = [e.type for e in h.publisher.events]
        assert types == ["connect", "login_attempt", "disconnect"]
        assert all(e.dst_port == 3389 and e.sensor == "rdp" for e in h.publisher.events)
        assert len({e.session_id for e in h.publisher.events}) == 1


@pytest.mark.parametrize("protocols", [0, 1])
async def test_nla_required_failure(make_harness: HarnessFactory, protocols: int) -> None:
    async with make_harness() as h:
        reader, writer = await _open(h)
        writer.write(build_connection_request(cookie=b"Cookie: mstshash=bob", protocols=protocols))
        reply = await _read_all(reader)
        assert reply == bytes.fromhex("030000130ed000001234000300080005000000")
        writer.close()
        disc = (await h.wait_disconnects(1))[0]
        assert disc.data["reason"] == "negotiation_failure"
        assert disc.data["negotiation"] == "HYBRID_REQUIRED_BY_SERVER"
        assert (await h.events("login_attempt"))[0].data["username"] == "bob"


async def test_legacy_client_ms_t120(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        reader, writer = await _open(h)
        writer.write(build_connection_request())
        assert await reader.readexactly(11) == bytes.fromhex("0300000b06d00000123400")
        body = b"\x02\xf0\x80\x7f\x65" + b"\x00" * 40 + b"MS_T120\x00" + b"\x00" * 20
        writer.write(struct.pack(">BBH", 3, 0, 4 + len(body)) + body)
        assert await _read_all(reader) == b""
        writer.close()
        disc = (await h.wait_disconnects(1))[0]
        assert disc.data["reason"] == "nla_required"
        assert disc.data["ms_t120"] is True
        scan = (await h.events("scan"))[0]
        assert scan.data["kind"] == "rdp_negotiation" and scan.data["neg_request"] is False
        assert await h.events("login_attempt") == []


async def test_routing_token_scan(make_harness: HarnessFactory) -> None:
    async with make_harness(enable_tls=False) as h:
        reader, writer = await _open(h)
        writer.write(build_connection_request(cookie=b"Cookie: msts=123.456.0000", protocols=3))
        assert len(await _read_all(reader)) == 19
        writer.close()
        await h.wait_disconnects(1)
        scan = (await h.events("scan"))[0]
        assert scan.data["routing_token"] == "123.456.0000"


@pytest.mark.parametrize(
    ("payload", "guess"),
    [
        (b"GET / HTTP/1.1\r\nHost: 192.0.2.10\r\nUser-Agent: Mozilla/5.0\r\n\r\n", "http"),
        (b"SSH-2.0-libssh2_1.11.0\r\n", "ssh"),
        (b"\x00\x00\x00\x85\xffSMBr\x00\x00\x00\x00", "smb"),
        (bytes(range(1, 200)), "unknown"),
    ],
)
async def test_non_rdp_is_scan(make_harness: HarnessFactory, payload: bytes, guess: str) -> None:
    async with make_harness() as h:
        reader, writer = await _open(h)
        writer.write(payload)
        assert await _read_all(reader) == b""  # nothing sent back, like Windows
        writer.close()
        disc = (await h.wait_disconnects(1))[0]
        assert disc.data["reason"] == "non_rdp"
        scan = (await h.events("scan"))[0]
        assert scan.data["kind"] == "non_rdp"
        assert scan.data["protocol_guess"] == guess
        assert scan.data["payload_preview"] == payload[:256].hex()


async def test_direct_tls_hello_is_scan(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        reader, writer = await _open(h)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
            async with asyncio.timeout(5):
                await writer.start_tls(ctx, server_hostname="rdp.example")
        writer.close()
        await h.wait_disconnects(1)
        scan = (await h.events("scan"))[0]
        assert scan.data["protocol_guess"] == "tls"
        assert scan.data["client_hello"]["sni"] == "rdp.example"


@pytest.mark.parametrize(
    "payload",
    [
        b"\x03\x00\x00\x05\x00",
        b"\x03\x00\xff\xff" + b"A" * 300,
        b"\x03\x00\x00\x0b\x06\xf0\x00\x00\x00\x00\x00",
        b"\x03\x00\x00\x0b\x07\xe0\x00\x00\x00\x00\x00",
    ],
)
async def test_malformed_tpkt(make_harness: HarnessFactory, payload: bytes) -> None:
    async with make_harness() as h:
        reader, writer = await _open(h)
        writer.write(payload)
        assert await _read_all(reader) == b""
        writer.close()
        disc = (await h.wait_disconnects(1))[0]
        assert disc.data["reason"] == "malformed_rdp"
        assert (await h.events("scan"))[0].data["kind"] == "malformed_rdp"


async def test_64k_garbage_closed_quickly(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        reader, writer = await _open(h)
        writer.write(os.urandom(64 * 1024))
        with pytest.raises((ConnectionError, OSError)):
            await writer.drain()
            await _read_all(reader, timeout=3)
            raise ConnectionResetError  # closed cleanly is fine too
        writer.close()
        disc = (await h.wait_disconnects(1))[0]
        assert disc.data["bytes_in"] <= 64 * 1024
        scan = (await h.events("scan"))[0]
        assert len(scan.data["payload_preview"]) <= 512


async def test_slowloris_tpkt_times_out(make_harness: HarnessFactory) -> None:
    async with make_harness(handshake_timeout=0.3) as h:
        reader, writer = await _open(h)
        writer.write(b"\x03\x00\x00\x2a\x25")  # promise 42 bytes, send 5
        await writer.drain()
        assert await _read_all(reader, timeout=3) == b""
        writer.close()
        disc = (await h.wait_disconnects(1))[0]
        assert disc.data["reason"] == "timeout"
        assert (await h.events("scan"))[0].data["error"] == "truncated"


async def test_no_data(make_harness: HarnessFactory) -> None:
    async with make_harness(first_data_timeout=0.2) as h:
        reader, writer = await _open(h)
        assert await _read_all(reader, timeout=3) == b""
        writer.close()
        disc = (await h.wait_disconnects(1))[0]
        assert disc.data["reason"] == "no_data"
        assert [e.type for e in h.publisher.events] == ["connect", "disconnect"]


async def test_tls_garbage_after_confirm(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        reader, writer = await _open(h)
        writer.write(build_connection_request(protocols=3))
        await reader.readexactly(19)
        writer.write(b"\x16\x03\x01\x00\x05hello")
        reply = await _read_all(reader)
        assert reply[:1] in (b"", b"\x15")  # nothing or a TLS alert
        writer.close()
        disc = (await h.wait_disconnects(1))[0]
        assert disc.data["reason"] == "tls_error"


async def test_handler_exception_is_contained(
    make_harness: HarnessFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(_cr: object) -> object:
        raise RuntimeError("kaboom")

    monkeypatch.setattr(protocol, "negotiate", boom)
    async with make_harness() as h:
        reader, writer = await _open(h)
        writer.write(build_connection_request(cookie=b"Cookie: mstshash=x", protocols=3))
        assert await _read_all(reader) == b""
        writer.close()
        disc = (await h.wait_disconnects(1))[0]
        assert disc.data["reason"] == "error"
        assert h.sensor.errors == 1


async def test_loopback_is_quiet(make_harness: HarnessFactory) -> None:
    async with make_harness(quiet_loopback=True) as h:
        reader, writer = await _open(h)
        writer.write(build_connection_request())
        assert len(await reader.readexactly(11)) == 11
        writer.close()
        await asyncio.sleep(0.2)
        assert await h.events() == []


def _client_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _tls_connect(h: Harness) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await _open(h)
    writer.write(build_connection_request(cookie=b"Cookie: mstshash=a", protocols=3))
    await writer.drain()
    await reader.readexactly(19)
    await writer.start_tls(_client_ctx())
    return reader, writer


async def _still_responsive(h: Harness) -> None:
    async with asyncio.timeout(1.0):
        reader, writer = await _open(h)
        writer.write(build_connection_request())
        assert len(await reader.readexactly(11)) == 11
        writer.close()


@pytest.mark.parametrize("partial", [b"", b"\x30\x82\x01\x00\xa0"])
async def test_close_notify_does_not_spin(make_harness: HarnessFactory, partial: bytes) -> None:
    """Regression (H1): a clean TLS close during CredSSP must end the read loop."""
    async with make_harness() as h:
        reader, writer = await _tls_connect(h)
        if partial:
            writer.write(partial)
            await writer.drain()
        ssl_obj = writer.get_extra_info("ssl_object")
        assert ssl_obj is not None
        writer.close()  # sends close_notify
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        await _still_responsive(h)
        disc = await h.wait_disconnects(2, timeout=2.0)
        first = next(d for d in disc if d.data.get("username") == "a")
        assert first.data["reason"] == "client_closed"
        assert first.data["duration_s"] < 1.0


async def test_tls_rate_limited_per_ip(make_harness: HarnessFactory) -> None:
    async with make_harness(tls_per_sec_per_ip=0.001, tls_burst_per_ip=1.0) as h:
        reader, writer = await _tls_connect(h)
        writer.close()
        reader, writer = await _open(h)
        writer.write(build_connection_request(protocols=3))
        assert len(await _read_all(reader)) == 19  # confirm, then closed before TLS
        writer.close()
        disc = await h.wait_disconnects(2)
        assert sorted(d.data["reason"] for d in disc)[-1] == "tls_rate_limited"
        assert h.sensor.tls_limited == 1


async def test_tls_slots_bounded(make_harness: HarnessFactory) -> None:
    async with make_harness(max_tls_handshakes=1, credssp_timeout=5.0) as h:
        _r1, w1 = await _tls_connect(h)  # holds the only slot (waiting for a TSRequest)
        reader, writer = await _open(h)
        writer.write(build_connection_request(protocols=3))
        assert len(await _read_all(reader, timeout=4)) == 19
        writer.close()
        w1.close()
        disc = await h.wait_disconnects(2, timeout=8)
        assert "tls_busy" in [d.data["reason"] for d in disc]


async def test_watchdog_detects_stall() -> None:
    import time

    from rdp_sensor.watchdog import LoopWatchdog

    stalls: list[float] = []
    dog = LoopWatchdog(limit=0.3, interval=0.05, on_stall=stalls.append)
    dog.start()
    await asyncio.sleep(0.2)
    assert not stalls
    time.sleep(0.8)  # noqa: ASYNC251 - blocking the loop is the point of the test
    await asyncio.sleep(0.1)
    dog.stop()
    assert stalls and stalls[0] > 0.3
