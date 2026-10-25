"""Just enough SPNEGO/DER to look like Windows GSS-API.

We build two tokens: the ``negTokenInit`` that goes in the NEGOTIATE response (advertising
NTLMSSP as the supported mechanism) and the ``negTokenResp`` that carries our NTLM CHALLENGE in
a SESSION_SETUP response. We never parse SPNEGO on the way in: to read the client's NTLM
message we just locate the ``NTLMSSP\\x00`` signature in the raw security buffer (bounded
search) and hand the slice to :mod:`smb_sensor.ntlm`. This keeps inbound handling to opaque
byte scanning rather than a real ASN.1 decoder.
"""

from __future__ import annotations

from typing import Final

# OIDs, pre-encoded as DER OID contents.
OID_SPNEGO: Final = bytes.fromhex("2b0601050502")  # 1.3.6.1.5.5.2
OID_NTLMSSP: Final = bytes.fromhex("2b06010401823702020a")  # 1.3.6.1.4.1.311.2.2.10

NTLMSSP_SIGNATURE: Final = b"NTLMSSP\x00"

# negState values.
ACCEPT_COMPLETED: Final = 0
ACCEPT_INCOMPLETE: Final = 1
REJECT: Final = 2


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes((n,))
    out = []
    while n:
        out.append(n & 0xFF)
        n >>= 8
    out.reverse()
    return bytes((0x80 | len(out), *out))


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes((tag,)) + _der_len(len(content)) + content


def _oid(contents: bytes) -> bytes:
    return _tlv(0x06, contents)


def build_neg_token_init() -> bytes:
    """A GSS-API-wrapped SPNEGO ``negTokenInit`` advertising NTLMSSP (Windows style)."""
    mech_types = _tlv(0x30, _oid(OID_NTLMSSP))  # MechTypeList (SEQUENCE OF OID)
    mech_types_ctx = _tlv(0xA0, mech_types)  # [0] mechTypes
    neg_token_init = _tlv(0x30, mech_types_ctx)  # NegTokenInit SEQUENCE
    inner = _tlv(0xA0, neg_token_init)  # [0] negTokenInit
    spnego = _oid(OID_SPNEGO) + inner
    return _tlv(0x60, spnego)  # [APPLICATION 0] GSSAPI


def build_neg_token_resp(ntlm_token: bytes, neg_state: int = ACCEPT_INCOMPLETE) -> bytes:
    """A SPNEGO ``negTokenResp`` carrying ``ntlm_token`` (our NTLM CHALLENGE)."""
    state = _tlv(0xA0, _tlv(0x0A, bytes((neg_state,))))  # [0] negState ENUMERATED
    supported = _tlv(0xA1, _oid(OID_NTLMSSP))  # [1] supportedMech
    response = _tlv(0xA2, _tlv(0x04, ntlm_token))  # [2] responseToken OCTET STRING
    seq = _tlv(0x30, state + supported + response)
    return _tlv(0xA1, seq)  # [1] negTokenResp


def find_ntlm_message(security_buffer: bytes, scan_limit: int = 16 * 1024) -> bytes | None:
    """Return the NTLM message slice from a security buffer, or None.

    We locate the ``NTLMSSP\\x00`` signature (the token may be raw NTLM or SPNEGO-wrapped) and
    return everything from there, capped. No ASN.1 is interpreted.
    """
    region = security_buffer[:scan_limit]
    idx = region.find(NTLMSSP_SIGNATURE)
    if idx < 0:
        return None
    return security_buffer[idx : idx + scan_limit]
