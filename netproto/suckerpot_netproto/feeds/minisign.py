"""minisign signing and verification with ``cryptography`` (design M30 section 6.5).

Format (https://jedisct1.github.io/minisign/):

* public key  = base64( "Ed" || key_id[8] || ed25519_public[32] ), the ``RW...`` string;
* signature   = ``ED`` (pre-hashed): Ed25519 over BLAKE2b-512 of the file;
* signature file, four lines::

      untrusted comment: <text>
      base64( "ED" || key_id[8] || signature[64] )
      trusted comment: <text>
      base64( global_signature[64] )

  where ``global_signature`` is Ed25519 over ``signature[64] || trusted_comment`` (the comment
  without its ``trusted comment: `` prefix and without a newline);
* the key id prints as upper case hex of its bytes in reverse order.

The legacy ``Ed`` signature algorithm (the whole file is signed) is refused: feed files can be
large and there is one way to sign. Secret keys are read and written unencrypted only (the key
lives in a Docker secret); an encrypted key file is refused with a clear error.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
from dataclasses import dataclass
from typing import Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .errors import FeedError

ALG_PREHASHED: Final = b"ED"
ALG_LEGACY: Final = b"Ed"
MAX_SIG_BYTES: Final = 1024
MAX_COMMENT: Final = 256
UNTRUSTED_PREFIX: Final = "untrusted comment: "
TRUSTED_PREFIX: Final = "trusted comment: "
DEFAULT_UNTRUSTED: Final = "signature from minisign secret key"

_PRINTABLE = re.compile(r"^[\x20-\x7e]*$")
_TRUSTED = re.compile(
    r"^timestamp:(?P<ts>\d{1,12}) file:(?P<file>[a-z0-9][a-z0-9._-]{0,63}) "
    r"serial:(?P<serial>\d{1,16})$"
)


@dataclass(frozen=True)
class PublicKey:
    key_id: bytes  # 8 bytes, as stored
    raw: bytes  # 32 bytes

    @property
    def key_id_hex(self) -> str:
        """Upper case hex of the key id bytes in reverse order (what minisign prints)."""
        return self.key_id[::-1].hex().upper()

    @property
    def encoded(self) -> str:
        """The ``RW...`` string."""
        return base64.b64encode(ALG_LEGACY + self.key_id + self.raw).decode("ascii")

    def to_file(self) -> str:
        return f"{UNTRUSTED_PREFIX}minisign public key {self.key_id_hex}\n{self.encoded}\n"


@dataclass(frozen=True)
class SecretKey:
    seed: bytes = b""  # 32 bytes
    key_id: bytes = b""  # 8 bytes

    @property
    def public(self) -> PublicKey:
        return PublicKey(self.key_id, _public_raw(self.seed))


@dataclass(frozen=True)
class TrustedComment:
    timestamp: int
    file: str
    serial: int

    def __str__(self) -> str:
        return f"timestamp:{self.timestamp} file:{self.file} serial:{self.serial}"


def _public_raw(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def _b64(line: str, length: int) -> bytes:
    try:
        raw = base64.b64decode(line, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise FeedError("bad_format", "invalid base64") from exc
    if len(raw) != length or base64.b64encode(raw).decode("ascii") != line:
        raise FeedError("bad_format", "unexpected length")
    return raw


def _prehash(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=64).digest()


# --- keys ---------------------------------------------------------------------------------------


def generate_keypair() -> SecretKey:
    seed = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    return SecretKey(seed, os.urandom(8))


def parse_public_key(text: str) -> PublicKey:
    """Accepts the bare ``RW...`` string or the two-line public key file."""
    text = text.strip()
    if len(text) > 512:
        raise FeedError("bad_format", "public key too long")
    lines = text.split("\n")
    if len(lines) == 2 and lines[0].startswith(UNTRUSTED_PREFIX):
        text = lines[1]
    elif len(lines) != 1:
        raise FeedError("bad_format", "public key layout")
    raw = _b64(text.strip(), 42)
    if raw[:2] != ALG_LEGACY:
        raise FeedError("bad_format", "unsupported public key algorithm")
    return PublicKey(raw[2:10], raw[10:])


def serialize_secret_key(secret: SecretKey) -> str:
    """The unencrypted minisign secret key file (kdf algorithm bytes are zero)."""
    sk = secret.seed + secret.public.raw
    checksum = hashlib.blake2b(ALG_LEGACY + secret.key_id + sk, digest_size=32).digest()
    blob = ALG_LEGACY + b"\x00\x00" + b"B2" + bytes(32) + bytes(8) + bytes(8)
    blob += secret.key_id + sk + checksum
    return (
        "untrusted comment: minisign secret key\n" + base64.b64encode(blob).decode("ascii") + "\n"
    )


def parse_secret_key(text: str) -> SecretKey:
    lines = text.strip().split("\n")
    if len(lines) != 2 or not lines[0].startswith(UNTRUSTED_PREFIX):
        raise FeedError("bad_format", "secret key layout")
    raw = _b64(lines[1].strip(), 158)
    if raw[:2] != ALG_LEGACY or raw[4:6] != b"B2":
        raise FeedError("bad_format", "unsupported secret key")
    if raw[2:4] != b"\x00\x00":
        raise FeedError("bad_format", "encrypted secret keys are not supported")
    key_id, sk, checksum = raw[54:62], raw[62:126], raw[126:]
    expect = hashlib.blake2b(ALG_LEGACY + key_id + sk, digest_size=32).digest()
    # Upstream writes an all-zero checksum for the unencrypted keys of `minisign -G -W`.
    if checksum not in (expect, bytes(32)) or sk[32:] != _public_raw(sk[:32]):
        raise FeedError("bad_format", "secret key checksum")
    return SecretKey(sk[:32], key_id)


# --- signing ------------------------------------------------------------------------------------


def _check_comment(text: str) -> str:
    if len(text.encode("ascii", "replace")) > MAX_COMMENT or not _PRINTABLE.fullmatch(text):
        raise FeedError("bad_format", "comment must be printable ASCII, one line, 256 bytes max")
    return text


def sign(
    data: bytes,
    secret: SecretKey,
    trusted_comment: str,
    *,
    untrusted_comment: str = DEFAULT_UNTRUSTED,
) -> str:
    """The text of a ``.minisig`` file for ``data``."""
    trusted_comment = _check_comment(trusted_comment)
    untrusted_comment = _check_comment(untrusted_comment)
    key = Ed25519PrivateKey.from_private_bytes(secret.seed)
    sig = key.sign(_prehash(data))
    global_sig = key.sign(sig + trusted_comment.encode("ascii"))
    return (
        f"{UNTRUSTED_PREFIX}{untrusted_comment}\n"
        f"{base64.b64encode(ALG_PREHASHED + secret.key_id + sig).decode('ascii')}\n"
        f"{TRUSTED_PREFIX}{trusted_comment}\n"
        f"{base64.b64encode(global_sig).decode('ascii')}\n"
    )


def sign_feed_file(
    data: bytes, name: str, serial: int, secret: SecretKey, *, timestamp: int
) -> str:
    """Sign a feed file with the trusted comment ``timestamp:<unix> file:<name> serial:<n>``."""
    comment = TrustedComment(timestamp, name, serial)
    if not _TRUSTED.fullmatch(str(comment)):
        raise FeedError("bad_format", "file name or serial not allowed in a trusted comment")
    return sign(data, secret, str(comment))


# --- verification -------------------------------------------------------------------------------


@dataclass(frozen=True)
class _ParsedSig:
    key_id: bytes
    signature: bytes
    trusted_comment: str
    global_signature: bytes


def _parse_sig(text: str) -> _ParsedSig:
    if len(text) > MAX_SIG_BYTES or not text.isascii():
        raise FeedError("bad_format", "signature file too large or not ASCII")
    lines = text.split("\n")
    if len(lines) == 5 and lines[4] == "":
        lines = lines[:4]
    if len(lines) != 4:
        raise FeedError("bad_format", "signature layout")
    if not lines[0].startswith(UNTRUSTED_PREFIX) or not lines[2].startswith(TRUSTED_PREFIX):
        raise FeedError("bad_format", "signature layout")
    if not _PRINTABLE.fullmatch(lines[0]) or not _PRINTABLE.fullmatch(lines[2]):
        raise FeedError("bad_format", "control characters in a comment")
    trusted = lines[2][len(TRUSTED_PREFIX) :]
    if len(trusted) > MAX_COMMENT:
        raise FeedError("bad_format", "trusted comment too long")
    raw = _b64(lines[1], 74)
    if raw[:2] == ALG_LEGACY:
        raise FeedError("bad_format", "legacy (non pre-hashed) signatures are not accepted")
    if raw[:2] != ALG_PREHASHED:
        raise FeedError("bad_format", "unknown signature algorithm")
    return _ParsedSig(raw[2:10], raw[10:], trusted, _b64(lines[3], 64))


def signature_key_id(sig_text: str) -> str:
    """The key id (printed form) a signature file claims, to pick the key during a rotation."""
    return PublicKey(_parse_sig(sig_text).key_id, bytes(32)).key_id_hex


def verify(data: bytes, sig_text: str, public: PublicKey) -> str:
    """Verify both signatures. Returns the trusted comment. Raises ``FeedError``."""
    parsed = _parse_sig(sig_text)
    if parsed.key_id != public.key_id:
        raise FeedError("wrong_key", "signature made by another key")
    try:
        key = Ed25519PublicKey.from_public_bytes(public.raw)
        key.verify(parsed.signature, _prehash(data))
        key.verify(parsed.global_signature, parsed.signature + parsed.trusted_comment.encode())
    except InvalidSignature as exc:
        raise FeedError("bad_signature", "signature does not verify") from exc
    return parsed.trusted_comment


def parse_trusted_comment(text: str) -> TrustedComment:
    m = _TRUSTED.fullmatch(text)
    if m is None:
        raise FeedError("bad_format", "trusted comment layout")
    return TrustedComment(int(m["ts"]), m["file"], int(m["serial"]))


def verify_feed_file(
    data: bytes, sig_text: str, public: PublicKey, *, name: str, serial: int
) -> TrustedComment:
    """Verify a feed file and that the signed comment names this file and this serial."""
    comment = parse_trusted_comment(verify(data, sig_text, public))
    if comment.file != name:
        raise FeedError("wrong_file", "signature belongs to another file")
    if comment.serial != serial:
        raise FeedError("wrong_serial", "signature belongs to another serial")
    return comment
