"""CredSSP TSRequest unit tests and the full NTLM exchange against the real listener."""

from __future__ import annotations

import asyncio
import ssl
import struct

import rdp_client
from conftest import HarnessFactory
from suckerpot_common import Event

from rdp_sensor import credssp, ntlm
from rdp_sensor.protocol import build_connection_request

# --- unit: TSRequest build / parse -----------------------------------------------------------


def test_nego_token_round_trip() -> None:
    msg = b"NTLMSSP\x00" + struct.pack("<I", 1) + b"\x00" * 8
    ts = credssp.parse_ts_request(credssp.build_nego_token(msg, 6))
    assert ts.version == 6
    assert ts.nego_token is not None and ts.nego_token.startswith(b"NTLMSSP\x00")


def test_error_round_trip() -> None:
    ts = credssp.parse_ts_request(credssp.build_error(credssp.STATUS_LOGON_FAILURE, 6))
    assert ts.version == 6
    assert ts.error_code == credssp.STATUS_LOGON_FAILURE
    assert ts.nego_token is None


def test_parse_rejects_non_sequence() -> None:
    import pytest

    with pytest.raises(credssp.BerError):
        credssp.parse_ts_request(b"\x04\x02\x00\x00")


def test_parse_bounds_bad_length() -> None:
    import pytest

    with pytest.raises(credssp.BerError):
        credssp.parse_ts_request(b"\x30\x84\xff\xff\xff\xff")


# --- integration: full CredSSP NTLM exchange over the real listener --------------------------


def _client_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _hybrid_tls(h: object) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.open_connection("127.0.0.1", h.port)  # type: ignore[attr-defined]
    writer.write(build_connection_request(cookie=b"Cookie: mstshash=x", protocols=0x0B))
    await writer.drain()
    await reader.readexactly(19)
    await writer.start_tls(_client_ctx())
    return reader, writer


def _negotiate_tsrequest() -> bytes:
    flags = 0xE2088297
    msg = b"NTLMSSP\x00" + struct.pack("<II", 1, flags) + b"\0" * 16
    msg += struct.pack("<BBH", 10, 0, 22621) + b"\x00\x00\x00\x0f"
    return credssp.build_nego_token(msg, 6)


async def _read_ts(reader: asyncio.StreamReader) -> credssp.TSRequest:
    """Read one complete DER TSRequest from the TLS plaintext stream."""
    buf = b""
    async with asyncio.timeout(5):
        while True:
            buf += await reader.read(4096)
            if len(buf) >= 2:
                first = buf[1]
                need = 2 + first if first < 0x80 else None
                if need is None:
                    n = first & 0x7F
                    if len(buf) >= 2 + n:
                        need = 2 + n + int.from_bytes(buf[2 : 2 + n], "big")
                if need is not None and len(buf) >= need:
                    return credssp.parse_ts_request(buf[:need])


async def _run_ntlm(
    h: object, build_auth: object, user: str, password: str
) -> tuple[list[Event], credssp.TSRequest]:
    reader, writer = await _hybrid_tls(h)
    writer.write(_negotiate_tsrequest())
    await writer.drain()
    challenge_ts = await _read_ts(reader)
    assert challenge_ts.nego_token is not None
    chal = challenge_ts.nego_token
    assert ntlm.message_type(chal) == ntlm.TYPE_CHALLENGE
    server_challenge = chal[24:32]
    auth_msg = build_auth(user, "CORP", "WS01", server_challenge, password)  # type: ignore[operator]
    writer.write(credssp.build_nego_token(auth_msg, 6))
    await writer.drain()
    error_ts = await _read_ts(reader)
    writer.close()
    logins = await h.events("login_attempt")  # type: ignore[attr-defined]
    return logins, error_ts


async def test_weak_password_is_recognised(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        logins, error_ts = await _run_ntlm(
            h, rdp_client.build_authenticate_v2, "administrator", "P@ssw0rd"
        )
        ntlm_login = [e for e in logins if e.data["method"] == "rdp-ntlm"]
        assert len(ntlm_login) == 1
        data = ntlm_login[0].data
        assert data["username"] == "administrator"
        assert data["password"] == "P@ssw0rd"
        assert data["success"] is True
        assert data["ntlm_version"] == "v2"
        assert data["domain"] == "CORP"
        # The server refuses the logon with STATUS_LOGON_FAILURE, exactly like a real host.
        assert error_ts.error_code == credssp.STATUS_LOGON_FAILURE
        disc = (await h.wait_disconnects(1))[0]
        assert disc.data["reason"] == "credssp_logon_failure"
        assert "weak_password_match" in disc.data["flags"]
        assert "rdp_ntlm" in disc.data["flags"]


async def test_wrong_password_recorded_without_cleartext(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        logins, error_ts = await _run_ntlm(
            h, rdp_client.build_authenticate_v2, "administrator", "not-the-password"
        )
        data = next(e for e in logins if e.data["method"] == "rdp-ntlm").data
        assert data["username"] == "administrator"
        assert data["password"] is None  # unknown password: never guessed, never stored
        assert data["success"] is False
        assert data["nt_response_len"] > 24  # NTLMv2 response length recorded
        assert error_ts.error_code == credssp.STATUS_LOGON_FAILURE


async def test_unknown_user_is_recorded(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        logins, _ = await _run_ntlm(h, rdp_client.build_authenticate_v2, "svc-backup", "whatever")
        data = next(e for e in logins if e.data["method"] == "rdp-ntlm").data
        assert data["username"] == "svc-backup" and data["password"] is None


async def test_challenge_carries_deployment_identity(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        reader, writer = await _hybrid_tls(h)
        writer.write(_negotiate_tsrequest())
        await writer.drain()
        ts = await _read_ts(reader)
        writer.close()
        assert ts.nego_token is not None
        # The target info advertises the per-deployment NetBIOS / DNS names.
        assert h.identity.netbios_domain.encode("utf-16-le") in ts.nego_token
        assert h.identity.dns_domain.encode("utf-16-le") in ts.nego_token
        await h.wait_disconnects(1)


async def test_malformed_tsrequest_is_scanned(make_harness: HarnessFactory) -> None:
    """Regression (review LOW): a non-DER TSRequest is recorded and closed cleanly."""
    async with make_harness() as h:
        reader, writer = await _hybrid_tls(h)
        writer.write(b"\x04\x02\x00\x00")  # a complete DER element that is not a SEQUENCE
        await writer.drain()
        async with asyncio.timeout(5):
            await reader.read(4096)
        writer.close()
        disc = (await h.wait_disconnects(1))[0]
        assert disc.data["reason"] == "credssp_malformed"
        scans = [e for e in await h.events("scan") if e.data["kind"] == "credssp_malformed"]
        assert len(scans) == 1
