"""TLS in the login phase (wrapped in PRELOGIN packets) and NTLM (SSPI) logins."""

from __future__ import annotations

import asyncio
import ssl
import struct
import time
from pathlib import Path

from conftest import HarnessFactory
from tdsclient import Client, batch, login7, packet, prelogin

from mssql_sensor import tds, tls

NTLM_NEGOTIATE = b"NTLMSSP\x00" + struct.pack("<I", 1) + struct.pack("<I", 0xE2088297) + bytes(16)


def ntlm_authenticate(domain: str, user: str, host: str) -> bytes:
    parts = [domain, user, host]
    raw = [p.encode("utf-16-le") for p in parts]
    base = 64
    nt = bytes(range(24))
    out = bytearray(b"NTLMSSP\x00" + struct.pack("<I", 3))
    blobs = bytearray()

    def field(data: bytes) -> bytes:
        nonlocal blobs
        f = struct.pack("<HHI", len(data), len(data), base + len(blobs))
        blobs += data
        return f

    out += field(b"")  # LM
    out += field(nt)
    out += field(raw[0]) + field(raw[1]) + field(raw[2])
    out += field(b"")  # session key
    out += struct.pack("<I", 0xE2888215)
    out += bytes(base - len(out))
    return bytes(out + blobs)


def _ctx(tmp_path: Path) -> ssl.SSLContext:
    return tls.make_context(tmp_path)


async def test_certificate_is_fresh_at_every_start_and_private(tmp_path: Path) -> None:
    from cryptography import x509

    tls.make_context(tmp_path)
    cert, key = tmp_path / tls.CERT_FILE, tmp_path / tls.KEY_FILE
    assert (key.stat().st_mode & 0o777) == 0o600 and (cert.stat().st_mode & 0o777) == 0o600
    first = x509.load_pem_x509_certificate(cert.read_bytes())
    assert first.subject.rfc4514_string() == "CN=SSL_Self_Signed_Fallback"
    years = (first.not_valid_after_utc - first.not_valid_before_utc).days / 365
    assert 29 < years < 31
    tls.make_context(tmp_path)
    assert x509.load_pem_x509_certificate(cert.read_bytes()).serial_number != first.serial_number


def test_cipher_list_is_schannel_like(tmp_path: Path) -> None:
    ctx = tls.make_context(tmp_path)
    names = [c["name"] for c in ctx.get_ciphers() if not c["name"].startswith("TLS_")]
    assert names[0] == "ECDHE-RSA-AES256-GCM-SHA384"
    assert not any("CHACHA" in n for n in names) and "AES128-SHA" in names
    assert ctx.options & ssl.OP_NO_TICKET


async def test_encrypt_off_client_logs_in_over_tls_then_plaintext(
    make_harness: HarnessFactory, tmp_path: Path
) -> None:
    async with make_harness(tls_ctx=_ctx(tmp_path)) as h:
        c = await Client.connect(h.port)
        reply = await c.login("sa", "P@ssw0rd", encryption=tds.ENC_OFF)
        assert c.server_encryption == tds.ENC_OFF and reply.login_ack
        assert c.tls is None  # dropped after the login exchange, like a real server
        r = await c.request(batch("select @@servername"))
        assert r.rows == [[h.profile.server_name]]
        await c.close()
        login = (await h.events("login_attempt"))[0]
        assert login.data["password"] == "P@ssw0rd" and login.data["tls"] is True
        assert h.sensor.tls_live == 0 and h.sensor.buffered == 0


async def test_encrypt_on_client_stays_encrypted(
    make_harness: HarnessFactory, tmp_path: Path
) -> None:
    async with make_harness(tls_ctx=_ctx(tmp_path)) as h:
        c = await Client.connect(h.port)
        reply = await c.login("sa", "bad-password", encryption=tds.ENC_ON)
        assert c.server_encryption == tds.ENC_ON and c.tls is not None
        assert reply.errors == [(18456, "Login failed for user 'sa'.")]
        await c.close()
        c = await Client.connect(h.port)
        assert (await c.login("sa", "123456", encryption=tds.ENC_ON)).login_ack
        assert c.tls is not None
        r = await c.request(batch("select 7"))
        assert r.rows == [[7]]
        await c.close()
        await h.wait_disconnects(2)
        assert h.sensor.tls_live == 0 and h.sensor.buffered == 0


async def test_prelogin_reply_shape_with_mars_and_fedauth() -> None:
    reply = tds.build_prelogin_reply((15, 0, 4375, 4), tds.ENC_OFF, mars=0, fedauth=False)
    assert len(reply) + 8 == 43
    assert len(tds.build_prelogin_reply((15, 0, 4375, 4), tds.ENC_OFF, 0, True)) + 8 == 49
    parsed = tds.parse_prelogin(reply)
    assert parsed.options == [0, 1, 2, 3, 4]


async def test_tls_garbage_and_handshake_limits(
    make_harness: HarnessFactory, tmp_path: Path
) -> None:
    async with make_harness(tls_ctx=_ctx(tmp_path)) as h:
        c = await Client.connect(h.port)
        c.writer.write(tds_prelogin(tds.ENC_ON))
        await c.read_message()
        c.writer.write(packet(tds.T_PRELOGIN, b"\x16\x03\x03\x00\x10" + b"\xde\xad" * 40))
        await c.writer.drain()
        await asyncio.wait_for(c.reader.read(1000), 3)  # alert or EOF, then the close
        end = (await h.wait_disconnects(1))[0]
        assert end.data["reason"] in {"tls_error", "client_closed"}
        assert h.sensor.tls_live == 0 and h.sensor.buffered == 0


def tds_prelogin(enc: int) -> bytes:
    from tdsclient import prelogin

    return prelogin(enc)


async def test_tls_slots_per_ip_and_global_refuse_slowly_never_not_sup(
    make_harness: HarnessFactory, tmp_path: Path
) -> None:
    async with make_harness(tls_ctx=_ctx(tmp_path), max_tls_per_ip=2, max_per_ip=20) as h:
        held = []
        for _ in range(2):
            c = await Client.connect(h.port)
            await c.prelogin(tds.ENC_OFF)
            held.append(c)
        assert h.sensor.tls_live == 2
        # third from the same IP: no NOT_SUP answer, the connection just ends (after a delay)
        t0 = time.monotonic()
        c = await Client.connect(h.port)
        c.writer.write(prelogin(tds.ENC_ON))
        await c.writer.drain()
        assert await asyncio.wait_for(c.reader.read(100), 5) == b""
        assert time.monotonic() - t0 >= 0.3
        # another source still gets TLS
        d = await Client.connect(h.port, source="127.0.0.9")
        await d.prelogin(tds.ENC_ON)
        assert d.server_encryption == tds.ENC_ON
        # a client that does not want TLS is unaffected
        e = await Client.connect(h.port)
        await e.prelogin(tds.ENC_NOT_SUP)
        assert e.server_encryption == tds.ENC_NOT_SUP
        for x in (*held, d, e):
            await x.close()
        await h.wait_disconnects(5)
        assert h.sensor.tls_live == 0 and h.sensor.tls_per_ip == {}
        ends = [x.data["reason"] for x in await h.events("disconnect")]
        assert "tls_busy" in ends


async def test_default_tls_slots_follow_the_connection_cap(tmp_path: Path) -> None:
    from dataclasses import replace

    from mssql_sensor.config import Config
    from mssql_sensor.identity import derive_profile
    from mssql_sensor.server import Sensor

    class _S:
        pass

    cfg = replace(Config(), max_connections=7, max_tls_per_ip=100)
    sensor = Sensor(cfg, _S(), derive_profile("ab" * 32))  # type: ignore[arg-type]
    assert Config().max_tls == 0
    assert [sensor.tls_acquire(f"192.0.2.{i}") for i in range(9)].count(True) == 7


async def test_trickling_prelogin_cannot_hold_a_tls_slot(
    make_harness: HarnessFactory, tmp_path: Path
) -> None:
    async with make_harness(tls_ctx=_ctx(tmp_path), tls_deadline=0.6, idle_timeout=30.0) as h:
        c = await Client.connect(h.port)
        c.writer.write(prelogin(tds.ENC_ON))
        await c.read_message()
        t0 = time.monotonic()
        for _ in range(20):  # one byte at a time keeps resetting the idle timer
            c.writer.write(b"\x12")
            await c.writer.drain()
            await asyncio.sleep(0.1)
            if c.reader.at_eof():
                break
        end = (await h.wait_disconnects(1))[0]
        assert end.data["reason"] == "tls_timeout" and time.monotonic() - t0 < 3
        assert h.sensor.tls_live == 0 and h.sensor.buffered == 0


async def test_idle_after_handshake_must_send_login7_in_time(
    make_harness: HarnessFactory, tmp_path: Path
) -> None:
    async with make_harness(tls_ctx=_ctx(tmp_path), tls_deadline=0.5, idle_timeout=30.0) as h:
        c = await Client.connect(h.port)
        await c.prelogin(tds.ENC_ON)  # handshake done, now say nothing
        end = (await h.wait_disconnects(1))[0]
        assert end.data["reason"] == "tls_timeout"
        assert h.sensor.tls_live == 0
        # a client that logs in promptly is not cut afterwards
        d = await Client.connect(h.port)
        assert (await d.login("sa", "123456", encryption=tds.ENC_ON)).login_ack
        await asyncio.sleep(0.8)
        assert (await d.request(batch("select 1"))).rows == [[1]]
        await d.close()


async def test_ntlm_challenge_and_authenticate_recorded(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        c = await Client.connect(h.port)
        await c.prelogin()
        c.writer.write(login7("", "", sspi=NTLM_NEGOTIATE))
        await c.writer.drain()
        raw = await c.read_message()
        assert raw[8] == tds.TOKEN_SSPI
        blob = raw[8 + 3 :]
        assert blob[:8] == tds.NTLM_SIG and struct.unpack_from("<I", blob, 8)[0] == 2
        assert h.profile.domain.encode("utf-16-le") in blob
        reply = await c.request(packet(tds.T_SSPI, ntlm_authenticate("CORP", "bob", "PC1")))
        assert reply.errors[0][0] == 18456 and "CORP\\bob" in reply.errors[0][1]
        await c.close()
        login = (await h.events("login_attempt"))[0]
        assert login.data["method"] == "tds-ntlm" and login.data["username"] == "CORP\\bob"
        assert (
            login.data["hash_algorithm"] == "ntlm"
            and login.data["hash_preview"] == "0001020304050607"
        )
        assert login.data["password"] is None


async def test_sspi_without_ntlm_is_a_plain_failure(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        c = await Client.connect(h.port)
        await c.prelogin()
        r = await c.request(login7("", "", sspi=b"\x60\x82junk"))
        assert r.errors and r.errors[0][0] == 18456
        await c.close()


async def test_foreign_domain_ntlm_is_untrusted_and_tree_name_present(
    make_harness: HarnessFactory,
) -> None:
    async with make_harness() as h:
        c = await Client.connect(h.port)
        await c.prelogin()
        c.writer.write(login7("", "", sspi=NTLM_NEGOTIATE))
        await c.writer.drain()
        blob = (await c.read_message())[11:]
        assert struct.pack("<H", 5) in blob and h.profile.dns_domain.encode("utf-16-le") in blob
        r = await c.request(packet(tds.T_SSPI, ntlm_authenticate("OTHERDOM", "eve", "PC9")))
        assert r.errors[0][0] == 18452 and "untrusted domain" in r.errors[0][1]
        await c.close()
        # a name from the local domain is an ordinary 18456
        c = await Client.connect(h.port)
        await c.prelogin()
        c.writer.write(login7("", "", sspi=NTLM_NEGOTIATE))
        await c.writer.drain()
        await c.read_message()
        r = await c.request(packet(tds.T_SSPI, ntlm_authenticate(h.profile.domain, "bob", "PC1")))
        assert r.errors[0][0] == 18456
        await c.close()
