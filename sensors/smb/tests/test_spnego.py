from __future__ import annotations

from smb_sensor import spnego


def test_der_len_short_and_long() -> None:
    assert spnego._der_len(5) == b"\x05"
    assert spnego._der_len(127) == b"\x7f"
    assert spnego._der_len(128) == b"\x81\x80"
    assert spnego._der_len(300) == b"\x82\x01\x2c"


def test_neg_token_init_is_gssapi_wrapped_and_names_ntlmssp() -> None:
    token = spnego.build_neg_token_init()
    assert token[0] == 0x60  # [APPLICATION 0] GSSAPI
    assert spnego.OID_SPNEGO in token
    assert spnego.OID_NTLMSSP in token


def test_neg_token_resp_carries_token() -> None:
    inner = b"NTLMSSP\x00challenge-bytes"
    token = spnego.build_neg_token_resp(inner)
    assert token[0] == 0xA1  # [1] negTokenResp
    assert inner in token


def test_find_ntlm_message_in_spnego() -> None:
    inner = b"NTLMSSP\x00" + b"\x03\x00\x00\x00" + b"payload"
    wrapped = spnego.build_neg_token_resp(inner)
    found = spnego.find_ntlm_message(wrapped)
    assert found is not None
    assert found.startswith(b"NTLMSSP\x00")


def test_find_ntlm_message_absent() -> None:
    assert spnego.find_ntlm_message(b"\x60\x06no ntlm here") is None


def test_find_ntlm_message_bounded() -> None:
    blob = b"A" * 100_000 + b"NTLMSSP\x00rest"
    # The signature is past the scan limit, so it is not found (bounded search).
    assert spnego.find_ntlm_message(blob, scan_limit=1024) is None
