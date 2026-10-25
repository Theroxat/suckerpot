from __future__ import annotations

import asyncio
import contextlib
import struct

import smb_client
from conftest import HarnessFactory

from smb_sensor import framing, ntlm, smb


def _status(payload: bytes) -> int:
    return int(struct.unpack_from("<I", payload, 8)[0])


def _command(payload: bytes) -> int:
    return int(struct.unpack_from("<H", payload, 12)[0])


def _session_id(payload: bytes) -> int:
    return int(struct.unpack_from("<Q", payload, 40)[0])


async def test_negotiate_answers_like_smb2(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        reply = await smb_client.exchange(
            h.port, smb_client.negotiate_request([0x0202, 0x0210, 0x0300, 0x0302, 0x0311])
        )
        assert reply[:4] == smb.SMB2_MAGIC
        assert _command(reply) == smb.SMB2_NEGOTIATE
        assert _status(reply) == smb.STATUS_SUCCESS
        dialect = struct.unpack_from("<H", reply, smb.SMB2_HEADER_LEN + 4)[0]
        assert dialect == smb.DIALECT_3_1_1
        connects = await h.events("connect")
        assert len(connects) == 1
        assert connects[0].sensor.value == "smb"
        assert connects[0].dst_port == 445


async def test_full_ntlm_session_records_credentials(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        conn = await smb_client.Conn.open(h.port)
        try:
            await conn.send(smb_client.negotiate_request([0x0311]))
            challenge = await conn.send(
                smb_client.session_setup_request(smb_client.ntlm_negotiate(), message_id=1)
            )
            assert _status(challenge) == smb.STATUS_MORE_PROCESSING_REQUIRED
            session_id = _session_id(challenge)
            assert session_id != 0
            idx = challenge.find(b"NTLMSSP\x00")
            assert idx > 0
            assert ntlm.message_type(challenge[idx:]) == ntlm.TYPE_CHALLENGE
            auth = smb_client.ntlm_authenticate("CORP", "svc-backup", "DESKTOP-9")
            final = await conn.send(
                smb_client.session_setup_request(auth, message_id=2, session_id=session_id)
            )
            assert _status(final) == smb.STATUS_LOGON_FAILURE
        finally:
            await conn.close()
        logins = await h.wait_events("login_attempt", 1)
        login = logins[0]
        assert login.data["username"] == "svc-backup"
        assert login.data["domain"] == "CORP"
        assert login.data["workstation"] == "DESKTOP-9"
        assert login.data["success"] is False
        assert login.data["method"] == "ntlm"
        assert login.data["password"] is None
        assert "nt_response_preview" in login.data
        assert login.data["nt_response_len"] == 24


async def test_null_session_is_flagged(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        conn = await smb_client.Conn.open(h.port)
        try:
            await conn.send(smb_client.negotiate_request([0x0311]))
            challenge = await conn.send(
                smb_client.session_setup_request(smb_client.ntlm_negotiate(), message_id=1)
            )
            sid = _session_id(challenge)
            auth = smb_client.ntlm_authenticate("", "", "", nt_response=b"")
            await conn.send(smb_client.session_setup_request(auth, message_id=2, session_id=sid))
        finally:
            await conn.close()
        logins = await h.wait_events("login_attempt", 1)
        assert "null_session" in logins[0].data["flags"]


async def test_smb1_negotiate_steers_to_smb2(make_harness: HarnessFactory) -> None:
    # An SMB1 NEGOTIATE with a multi-protocol dialect list.
    header = b"\xffSMB" + bytes([smb.SMB1_NEGOTIATE]) + b"\x00" * 27
    dialects = b"\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00"
    body = b"\x00" + struct.pack("<H", len(dialects)) + dialects
    from smb_sensor import framing

    async with make_harness() as h:
        reply = await smb_client.exchange(h.port, framing.build_message(header + body))
        assert reply[:4] == smb.SMB2_MAGIC  # answered in SMB2
        dialect = struct.unpack_from("<H", reply, smb.SMB2_HEADER_LEN + 4)[0]
        assert dialect == smb.DIALECT_WILDCARD
        scans = await h.wait_events("scan", 1)
        kinds = {s.data["kind"] for s in scans}
        assert "smb1_negotiate" in kinds
        assert any("smbv1" in s.data.get("flags", []) for s in scans)


async def test_non_smb_traffic_is_a_scan(make_harness: HarnessFactory) -> None:
    from smb_sensor import framing

    async with make_harness() as h:
        conn = await smb_client.Conn.open(h.port)
        try:
            await conn.send_raw(framing.build_message(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
        finally:
            await conn.close()
        scans = await h.wait_events("scan", 1)
        assert scans[0].data["kind"] == "non_smb"
        assert scans[0].data["protocol_guess"] == "http"


async def test_unexpected_command_is_recorded_and_denied(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        conn = await smb_client.Conn.open(h.port)
        try:
            await conn.send(smb_client.negotiate_request([0x0311]))
            header = smb_client.client_header(smb.SMB2_TREE_CONNECT, 5)
            body = struct.pack("<HHH", 9, 0, 0)  # minimal tree-connect-ish body
            reply = await conn.send(framing.build_message(header + body))
            assert _status(reply) == smb.STATUS_ACCESS_DENIED
        finally:
            await conn.close()
        scans = await h.wait_events("scan", 1)
        assert any(s.data["kind"] == "unexpected_command" for s in scans)


async def test_disconnect_event_has_summary(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        await smb_client.exchange(h.port, smb_client.negotiate_request([0x0302]))
        disconnects = await h.wait_events("disconnect", 1)
        d = disconnects[0]
        assert d.data["bytes_in"] > 0
        assert d.data["bytes_out"] > 0
        assert d.data["pdus"] >= 1
        assert d.data["dialect"] == "3.0.2"


def _smb1_negotiate(dialects: list[str]) -> bytes:
    from smb_sensor import framing

    header = b"\xffSMB" + bytes([smb.SMB1_NEGOTIATE]) + b"\x00" * 27
    blob = b"".join(b"\x02" + d.encode() + b"\x00" for d in dialects)
    return framing.build_message(header + b"\x00" + struct.pack("<H", len(blob)) + blob)


async def test_smb1_offering_only_2002_gets_a_real_202_negotiate(
    make_harness: HarnessFactory,
) -> None:
    async with make_harness() as h:
        reply = await smb_client.exchange(h.port, _smb1_negotiate(["NT LM 0.12", "SMB 2.002"]))
        assert reply[:4] == smb.SMB2_MAGIC
        dialect = struct.unpack_from("<H", reply, smb.SMB2_HEADER_LEN + 4)[0]
        assert dialect == smb.DIALECT_2_0_2
        scans = await h.wait_events("scan", 1)
        assert scans[0].data["smb1_outcome"] == "smb2_002"


async def test_smb1_only_negotiate_is_recorded_and_reset(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        conn = await smb_client.Conn.open(h.port)
        try:
            await conn.send_raw(_smb1_negotiate(["PC NETWORK PROGRAM 1.0", "NT LM 0.12"]))
            # No SMB answer at all: the connection is reset, like Windows with SMB1 disabled.
            data = b""
            with contextlib.suppress(ConnectionError, OSError):
                data = await asyncio.wait_for(conn.reader.read(64), 3.0)
            assert data == b""
        finally:
            await conn.close()
        scans = await h.wait_events("scan", 1)
        assert scans[0].data["smb1_outcome"] == "reset"
        disconnects = await h.wait_events("disconnect", 1)
        assert disconnects[0].data["reason"] == "smb1_reset"


async def test_keepalive_then_negotiate_is_answered(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        conn = await smb_client.Conn.open(h.port)
        try:
            await conn.send_raw(b"\x85\x00\x00\x00")  # NetBIOS keepalive
            reply = await conn.send(smb_client.negotiate_request([0x0202]))
            assert _command(reply) == smb.SMB2_NEGOTIATE
        finally:
            await conn.close()


async def test_unauthenticated_logoff_is_session_deleted(make_harness: HarnessFactory) -> None:
    from smb_sensor import framing

    async with make_harness() as h:
        conn = await smb_client.Conn.open(h.port)
        try:
            await conn.send(smb_client.negotiate_request([0x0311]))
            header = smb_client.client_header(smb.SMB2_LOGOFF, 1, session_id=0x1234)
            reply = await conn.send(framing.build_message(header + struct.pack("<HH", 4, 0)))
            assert _status(reply) == smb.STATUS_USER_SESSION_DELETED
        finally:
            await conn.close()


async def test_cpu_limited_client_gets_insufficient_resources(
    make_harness: HarnessFactory,
) -> None:
    async with make_harness(cpu_per_sec_per_ip=0.01, cpu_burst_per_ip=1.0) as h:
        conn = await smb_client.Conn.open(h.port)
        try:
            await conn.send(smb_client.negotiate_request([0x0311]))  # spends the only token
            reply = await conn.send(smb_client.negotiate_request([0x0311]))
            assert _status(reply) == smb.STATUS_INSUFFICIENT_RESOURCES
        finally:
            await conn.close()
