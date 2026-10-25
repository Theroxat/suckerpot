from __future__ import annotations

import struct

from smb_sensor import identity, messages, smb


def _parse_negotiate_response(message: bytes) -> dict[str, int]:
    body = message[smb.SMB2_HEADER_LEN :]
    (
        structure_size,
        security_mode,
        dialect,
        context_count,
    ) = struct.unpack_from("<HHHH", body, 0)
    capabilities = struct.unpack_from("<I", body, 24)[0]
    sec_offset, sec_len = struct.unpack_from("<HH", body, 56)
    context_offset = struct.unpack_from("<I", body, 60)[0]
    return {
        "structure_size": structure_size,
        "security_mode": security_mode,
        "dialect": dialect,
        "context_count": context_count,
        "capabilities": capabilities,
        "sec_offset": sec_offset,
        "sec_len": sec_len,
        "context_offset": context_offset,
    }


def test_choose_dialect_picks_highest() -> None:
    assert smb.choose_dialect([0x0202, 0x0210, 0x0300, 0x0311]) == smb.DIALECT_3_1_1
    assert smb.choose_dialect([0x0202]) == smb.DIALECT_2_0_2
    assert smb.choose_dialect([0x0210]) == smb.DIALECT_2_1_0
    assert smb.choose_dialect([0x9999]) is None


def test_negotiate_response_looks_like_windows(identity: identity.Identity) -> None:
    message = messages.build_negotiate_response(identity, smb.DIALECT_3_0_2)
    parsed = _parse_negotiate_response(message)
    assert parsed["structure_size"] == 65
    assert parsed["dialect"] == smb.DIALECT_3_0_2
    assert parsed["security_mode"] == messages.SECURITY_MODE_SIGNING_ENABLED
    # ServerGuid: 16 bytes at body offset 8.
    server_guid = message[smb.SMB2_HEADER_LEN + 8 : smb.SMB2_HEADER_LEN + 24]
    assert server_guid == identity.server_guid
    assert len(server_guid) == 16
    assert parsed["sec_offset"] == smb.SMB2_HEADER_LEN + 64
    assert parsed["sec_len"] > 0
    assert parsed["context_count"] == 0  # no negotiate contexts below 3.1.1


def test_negotiate_311_includes_contexts(identity: identity.Identity) -> None:
    message = messages.build_negotiate_response(identity, smb.DIALECT_3_1_1)
    parsed = _parse_negotiate_response(message)
    assert parsed["dialect"] == smb.DIALECT_3_1_1
    assert parsed["context_count"] == 2
    # The context list must start 8-byte aligned, after the security buffer.
    assert parsed["context_offset"] % 8 == 0
    assert parsed["context_offset"] >= parsed["sec_offset"] + parsed["sec_len"]
    ctx = message[parsed["context_offset"] :]
    ctx_type = struct.unpack_from("<H", ctx, 0)[0]
    assert ctx_type == smb.CTX_PREAUTH_INTEGRITY


def test_wildcard_steer_response(identity: identity.Identity) -> None:
    message = messages.build_negotiate_response(identity, smb.DIALECT_WILDCARD)
    parsed = _parse_negotiate_response(message)
    assert parsed["dialect"] == smb.DIALECT_WILDCARD
    assert parsed["context_count"] == 0


def test_choose_cipher_prefers_offered() -> None:
    assert messages.choose_cipher([messages.CIPHER_AES_256_GCM]) == messages.CIPHER_AES_256_GCM
    assert messages.choose_cipher([]) == messages.CIPHER_AES_128_GCM
    assert messages.choose_cipher([0xBEEF]) == messages.CIPHER_AES_128_GCM


def test_parse_negotiate_request_reads_dialects_and_contexts() -> None:
    from smb_client import negotiate_request

    payload = negotiate_request([0x0202, 0x0210, 0x0300, 0x0302, 0x0311], contexts=True)
    request = smb.parse_negotiate_request(payload[4:])  # strip NetBIOS header
    assert request.dialects == [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]
    assert smb.CTX_ENCRYPTION in request.context_types
    assert 0x0002 in request.ciphers


def test_parse_negotiate_request_truncated_is_safe() -> None:
    header = b"\xfeSMB" + b"\x00" * 60
    assert smb.parse_negotiate_request(header + b"\x24\x00\x05\x00").dialects == []


def test_encryption_context_only_when_client_sent_one(identity: identity.Identity) -> None:
    message = messages.build_negotiate_response(identity, smb.DIALECT_3_1_1, cipher=None)
    assert _parse_negotiate_response(message)["context_count"] == 1


def test_capabilities_follow_dialect_and_client() -> None:
    from smb_sensor.messages import _capabilities

    assert _capabilities(smb.DIALECT_2_0_2, 0xFFFFFFFF) == 0x01
    assert _capabilities(smb.DIALECT_2_1_0, 0) == 0x07
    assert _capabilities(smb.DIALECT_3_0_2, 0x47) == 0x47  # encryption when asked
    assert _capabilities(smb.DIALECT_3_0_2, 0x00) == 0x07  # no encryption unless asked
    assert _capabilities(smb.DIALECT_3_1_1, 0x7F) == 0x07  # 3.1.1 uses contexts, not the bit
    assert _capabilities(smb.DIALECT_WILDCARD, 0) == 0x07
