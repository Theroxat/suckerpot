"""CredSSP ``TSRequest`` handling (MS-CSSP 2.2.1): strict, bounded, hand-written BER.

The client and server exchange NTLM tokens wrapped in ``TSRequest`` structures over the TLS
channel. We only ever need to:

* read the client's ``TSRequest`` and pull out the NTLM message from ``negoTokens`` (plus the
  protocol ``version``, and whether ``pubKeyAuth`` / ``authInfo`` is present);
* build a ``TSRequest`` carrying our NTLM CHALLENGE in ``negoTokens``;
* build a ``TSRequest`` carrying an ``errorCode`` (an NTSTATUS) to refuse the logon, exactly as
  a real server does on a failed CredSSP authentication.

``TSRequest ::= SEQUENCE { [0] version INTEGER, [1] negoTokens NegoData OPTIONAL,
[2] authInfo OCTET STRING OPTIONAL, [3] pubKeyAuth OCTET STRING OPTIONAL,
[4] errorCode INTEGER OPTIONAL, [5] clientNonce OCTET STRING OPTIONAL }``.

Every length is read with a cap, nothing is indexed past the buffer end, and the whole input
is bounded by the caller (the CredSSP plaintext cap). No regex, no recursion on attacker depth.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

NTLMSSP: Final = b"NTLMSSP\x00"
MAX_LEN_BYTES: Final = 4  # refuse absurd BER length encodings
STATUS_LOGON_FAILURE: Final = 0xC000006D
_SCAN_LIMIT: Final = 16 * 1024


class BerError(ValueError):
    """The bytes are not a well-formed BER element we accept."""


def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes((n,))
    out = []
    while n:
        out.append(n & 0xFF)
        n >>= 8
    out.reverse()
    return bytes((0x80 | len(out), *out))


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes((tag,)) + _enc_len(len(content)) + content


def _enc_int(value: int) -> bytes:
    if value == 0:
        body = b"\x00"
    else:
        length = (value.bit_length() + 8) // 8  # keep a leading 0 for the sign bit
        body = value.to_bytes(length, "big")
    return _tlv(0x02, body)


def _read_tlv(data: bytes, pos: int, end: int) -> tuple[int, int, int]:
    """Read one BER element header at ``pos``. Returns ``(tag, content_start, content_end)``."""
    if pos + 2 > end:
        raise BerError("truncated_header")
    tag = data[pos]
    first = data[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    else:
        n = first & 0x7F
        if n == 0 or n > MAX_LEN_BYTES or pos + n > end:
            raise BerError("bad_length")
        length = int.from_bytes(data[pos : pos + n], "big")
        pos += n
    if length < 0 or pos + length > end:
        raise BerError("length_overflow")
    return tag, pos, pos + length


@dataclass(frozen=True)
class TSRequest:
    version: int | None = None
    nego_token: bytes | None = None  # the NTLM message from the first negoToken
    has_pub_key_auth: bool = False
    has_auth_info: bool = False
    error_code: int | None = None


def _find_ntlm(data: bytes) -> bytes | None:
    idx = data[:_SCAN_LIMIT].find(NTLMSSP)
    if idx < 0:
        return None
    return data[idx : idx + _SCAN_LIMIT]


def parse_ts_request(data: bytes) -> TSRequest:
    """Parse one ``TSRequest``. Framing errors raise :class:`BerError`.

    The NTLM message inside ``negoTokens`` is located by its ``NTLMSSP\\x00`` signature (the
    token may be raw NTLM or SPNEGO-wrapped), which keeps inbound handling to a bounded scan
    rather than a deep ASN.1 descent.
    """
    end = len(data)
    tag, start, seq_end = _read_tlv(data, 0, end)
    if tag != 0x30:
        raise BerError("not_sequence")
    version: int | None = None
    has_pub = False
    has_auth = False
    error_code: int | None = None
    pos = start
    fields = 0
    while pos < seq_end and fields < 8:
        fields += 1
        ctag, cstart, cend = _read_tlv(data, pos, seq_end)
        if ctag == 0xA0:  # [0] version INTEGER
            itag, istart, iend = _read_tlv(data, cstart, cend)
            if itag == 0x02 and iend > istart:
                version = data[iend - 1]
        elif ctag == 0xA2:
            has_auth = True
        elif ctag == 0xA3:
            has_pub = True
        elif ctag == 0xA4:  # [4] errorCode INTEGER
            itag, istart, iend = _read_tlv(data, cstart, cend)
            if itag == 0x02:
                error_code = int.from_bytes(data[istart:iend], "big")
        pos = cend
    return TSRequest(
        version=version,
        nego_token=_find_ntlm(data),
        has_pub_key_auth=has_pub,
        has_auth_info=has_auth,
        error_code=error_code,
    )


def build_nego_token(ntlm_message: bytes, version: int) -> bytes:
    """A ``TSRequest`` whose ``negoTokens`` carries ``ntlm_message`` (our NTLM CHALLENGE)."""
    nego_item = _tlv(0x30, _tlv(0xA0, _tlv(0x04, ntlm_message)))  # NegoData item
    nego_tokens = _tlv(0xA1, _tlv(0x30, nego_item))  # [1] negoTokens SEQUENCE OF
    version_el = _tlv(0xA0, _enc_int(version))  # [0] version
    return _tlv(0x30, version_el + nego_tokens)


def build_error(error_code: int, version: int) -> bytes:
    """A ``TSRequest`` carrying an NTSTATUS ``errorCode`` (how a server refuses the logon).

    The NTSTATUS is written as a plain 4-byte INTEGER (no DER sign-padding byte): that is how
    Windows and FreeRDP encode it, and FreeRDP rejects a 5-byte errorCode.
    """
    version_el = _tlv(0xA0, _enc_int(version))
    error_el = _tlv(0xA4, _tlv(0x02, (error_code & 0xFFFFFFFF).to_bytes(4, "big")))
    return _tlv(0x30, version_el + error_el)
