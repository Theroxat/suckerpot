"""MCS / GCC unit tests and the full NLA-off Client Info capture against the real listener."""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import time

import rdp_client
from conftest import HarnessFactory

from rdp_sensor import mcs
from rdp_sensor.protocol import build_connection_request

# --- unit --------------------------------------------------------------------------------------


def test_wrap_unwrap_round_trip() -> None:
    assert mcs.unwrap(mcs.wrap(b"\x04\x01\x00")) == b"\x04\x01\x00"


def test_parse_client_data_extracts_core_and_net() -> None:
    ci = rdp_client.build_connect_initial("WS-ATTACKER", 2600, ["rdpdr", "cliprdr"])
    client = mcs.parse_client_data(mcs.unwrap(ci))
    assert client.core.client_name == "WS-ATTACKER"
    assert client.core.client_build == 2600
    assert client.channel_count == 2
    assert client.channel_names == ["rdpdr", "cliprdr"]


def test_parse_channel_join_request() -> None:
    raw = mcs.unwrap(rdp_client.build_channel_join_request(1007, 1003))
    join = mcs.parse_channel_join_request(raw)
    assert join is not None and join.initiator == 1007 and join.channel_id == 1003


def test_build_connect_response_is_tpkt_with_connect_response_tag() -> None:
    pdu = mcs.build_connect_response(2, mcs.CS_NET)  # channel_count 2
    payload = mcs.unwrap(pdu)
    assert payload[:2] == b"\x7f\x66"  # Connect-Response


def test_parse_client_info_reads_credentials() -> None:
    pdu = rdp_client.build_client_info("CORP", "administrator", "S3cret!")
    channel_id, user_data = mcs.parse_send_data_request(mcs.unwrap(pdu))  # type: ignore[misc]
    assert channel_id == mcs.MCS_IO_CHANNEL
    info = mcs.parse_client_info(user_data)
    assert info is not None
    assert info.domain == "CORP" and info.username == "administrator"
    assert info.password == "S3cret!"


def test_parse_client_info_bounds_lying_lengths() -> None:
    # Security header present but the cb fields claim far more than the buffer holds.
    body = b"\x40\x00\x00\x00" + b"\x00" * 8 + b"\xff\xff" * 5
    info = mcs.parse_client_info(body)
    assert info is not None and info.username is None


# --- integration -------------------------------------------------------------------------------


def _client_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _read_tpkt(reader: asyncio.StreamReader) -> bytes:
    buf = b""
    async with asyncio.timeout(5):
        while True:
            buf += await reader.read(4096)
            if len(buf) >= 4 and len(buf) >= ((buf[2] << 8) | buf[3]):
                return buf


async def test_nla_off_captures_cleartext_password(make_harness: HarnessFactory) -> None:
    async with make_harness(nla_mode="optional") as h:
        reader, writer = await asyncio.open_connection("127.0.0.1", h.port)
        writer.write(build_connection_request(cookie=b"Cookie: mstshash=a", protocols=0x01))
        await writer.drain()
        confirm = await reader.readexactly(19)
        # SSL was selected (not HYBRID_REQUIRED): selected protocol byte is PROTOCOL_SSL.
        assert confirm[-4:] == b"\x01\x00\x00\x00"
        await writer.start_tls(_client_ctx())

        writer.write(rdp_client.build_connect_initial("EVIL-PC", 2600, ["rdpdr"]))
        await writer.drain()
        await _read_tpkt(reader)  # Connect Response
        writer.write(rdp_client.build_erect_domain())
        writer.write(rdp_client.build_attach_user_request())
        await writer.drain()
        await _read_tpkt(reader)  # Attach User Confirm
        for channel in (mcs.MCS_USER_CHANNEL, mcs.MCS_IO_CHANNEL):
            writer.write(rdp_client.build_channel_join_request(mcs.MCS_USER_CHANNEL, channel))
            await writer.drain()
            await _read_tpkt(reader)  # Channel Join Confirm
        writer.write(rdp_client.build_client_info("CORP", "administrator", "Summer2026!"))
        await writer.drain()
        with contextlib.suppress(Exception):
            await _read_tpkt(reader)  # the teardown PDU (disconnect ultimatum)
        writer.close()

        logins = await h.events("login_attempt")
        nla_off = [e for e in logins if e.data["method"] == "rdp-nla-off"]
        assert len(nla_off) == 1
        data = nla_off[0].data
        assert data["username"] == "administrator"
        assert data["password"] == "Summer2026!"
        assert data["domain"] == "CORP"
        disc = (await h.wait_disconnects(1))[0]
        assert disc.data["reason"] == "client_info_captured"
        assert "rdp_nla_off" in disc.data["flags"]
        assert disc.data["gcc"]["client_name"] == "EVIL-PC"


async def test_partial_tpkt_after_tls_closes_within_deadline(make_harness: HarnessFactory) -> None:
    """Regression (review HIGH): a client that sends a TPKT header then stalls must not spin.

    It promises 100 bytes, sends only the 4-byte header, then goes quiet. The MCS read must
    hit the deadline and close, instead of looping on sleep(0) for the whole session, and the
    loop must stay responsive to other clients the entire time.
    """
    async with make_harness(nla_mode="optional", mcs_timeout=1.0, max_session=30.0) as h:
        reader, writer = await asyncio.open_connection("127.0.0.1", h.port)
        writer.write(build_connection_request(cookie=b"Cookie: mstshash=a", protocols=0x01))
        await writer.drain()
        await reader.readexactly(19)
        await writer.start_tls(_client_ctx())
        writer.write(b"\x03\x00\x00\x64")  # TPKT header promising 100 bytes, then nothing
        await writer.drain()

        t0 = time.monotonic()
        # The loop stays responsive: a second client gets its confirm quickly meanwhile.
        async with asyncio.timeout(2.0):
            r2, w2 = await asyncio.open_connection("127.0.0.1", h.port)
            w2.write(build_connection_request(protocols=0))
            assert len(await r2.readexactly(19)) == 19
            assert time.monotonic() - t0 < 1.0
            w2.close()

        disc = await h.wait_disconnects(2, timeout=5.0)
        stalled = next(d for d in disc if d.data.get("stage") == "mcs")
        assert time.monotonic() - t0 < 4.0  # closed near mcs_timeout, not after max_session
        assert stalled.data["reason"] in ("mcs_closed", "mcs_max_pdus")
        writer.close()
