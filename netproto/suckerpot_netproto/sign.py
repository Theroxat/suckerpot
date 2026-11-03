"""Ed25519 request and response signatures (spec section 5.2).

All cryptography is the ``cryptography`` library (Ed25519, SHA-256). This module only builds the
canonical strings and encodes keys.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .errors import ProtoError

MAX_SKEW_S = 300
NONCE_BYTES = 16
PAD_BLOCK = 4096
H_KEY = "X-SPN-Key"
H_TIMESTAMP = "X-SPN-Timestamp"
H_NONCE = "X-SPN-Nonce"
H_SIGNATURE = "X-SPN-Signature"
H_HUB_SIGNATURE = "X-SPN-Hub-Signature"
H_HUB_SIGNATURE_ALT = "X-SPN-Hub-Signature-Alt"
MAX_PINNED_KEYS = 3

_B64U = re.compile(r"^[A-Za-z0-9_-]*$")


def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    """Strict base64url without padding. Raises ValueError on anything non-canonical."""
    if not _B64U.fullmatch(text) or len(text) % 4 == 1:
        raise ValueError("invalid base64url")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64u_encode(raw) != text:  # trailing bits must be zero
        raise ValueError("non-canonical base64url")
    return raw


def generate_private_key() -> bytes:
    """A fresh Ed25519 private key as its 32-byte seed."""
    return Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def public_key_of(private: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(private)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def node_key(public: bytes) -> str:
    """The ``node_key`` of a 32-byte public key (base64url, no padding)."""
    if len(public) != 32:
        raise ValueError("public key must be 32 bytes")
    return b64u_encode(public)


def parse_node_key(text: str) -> bytes:
    raw = b64u_decode(text)
    if len(raw) != 32:
        raise ValueError("public key must be 32 bytes")
    return raw


def fingerprint(public: bytes) -> str:
    """First 8 hex characters of sha256(public key)."""
    return hashlib.sha256(public).hexdigest()[:8]


def new_nonce() -> str:
    return b64u_encode(os.urandom(NONCE_BYTES))


def body_sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def canonical_request(
    method: str, target: str, timestamp: int | str, nonce: str, body: bytes
) -> str:
    """The string a node signs. ``target`` is the path with query exactly as sent."""
    return "\n".join(("SPN1-REQ", method.upper(), target, str(timestamp), nonce, body_sha256(body)))


@dataclass(frozen=True)
class RequestBinding:
    """The request an answer belongs to. The hub signs it into every answer.

    ``node`` is the ``X-SPN-Key`` of a signed request and ``-`` for an unsigned one. ``digest``
    is the sha256 (hex) of the request signature for a signed request, and the sha256 of the
    request body for an unsigned one. Binding the whole request stops a man in the middle from
    collecting a hub-signed answer with its own request and replaying it to a victim's nonce.
    """

    method: str
    target: str
    nonce: str
    node: str
    digest: str

    @classmethod
    def signed(
        cls, method: str, target: str, key: str, nonce: str, signature: str
    ) -> RequestBinding:
        digest = hashlib.sha256(signature.encode("ascii")).hexdigest()
        return cls(method.upper(), target, nonce, key, digest)

    @classmethod
    def unsigned(cls, method: str, target: str, nonce: str, body: bytes = b"") -> RequestBinding:
        return cls(method.upper(), target, nonce, "-", body_sha256(body))


def canonical_response(binding: RequestBinding, status: int, body: bytes) -> str:
    return "\n".join(
        (
            "SPN1-RESP",
            binding.method,
            binding.target,
            binding.node,
            binding.nonce,
            binding.digest,
            str(status),
            body_sha256(body),
        )
    )


def _sign(private: bytes, message: str) -> str:
    key = Ed25519PrivateKey.from_private_bytes(private)
    return b64u_encode(key.sign(message.encode("utf-8")))


def _verify(public: bytes, signature_b64u: str, message: str) -> bool:
    try:
        sig = b64u_decode(signature_b64u)
        if len(sig) != 64 or len(public) != 32:
            return False
        Ed25519PublicKey.from_public_bytes(public).verify(sig, message.encode("utf-8"))
    except (ValueError, InvalidSignature):
        return False
    return True


@dataclass(frozen=True)
class SignedHeaders:
    key: str
    timestamp: str
    nonce: str
    signature: str

    def as_dict(self) -> dict[str, str]:
        return {
            H_KEY: self.key,
            H_TIMESTAMP: self.timestamp,
            H_NONCE: self.nonce,
            H_SIGNATURE: self.signature,
        }


def sign_request(
    private: bytes,
    method: str,
    target: str,
    body: bytes,
    *,
    timestamp: int,
    nonce: str | None = None,
) -> SignedHeaders:
    nonce = nonce or new_nonce()
    sig = _sign(private, canonical_request(method, target, timestamp, nonce, body))
    return SignedHeaders(
        key=node_key(public_key_of(private)),
        timestamp=str(timestamp),
        nonce=nonce,
        signature=sig,
    )


def verify_request(
    public: bytes,
    signature: str,
    method: str,
    target: str,
    timestamp: str,
    nonce: str,
    body: bytes,
) -> bool:
    return _verify(public, signature, canonical_request(method, target, timestamp, nonce, body))


def sign_response(hub_private: bytes, binding: RequestBinding, status: int, body: bytes) -> str:
    return _sign(hub_private, canonical_response(binding, status, body))


def verify_response(
    hub_key: str, signature: str | None, binding: RequestBinding, status: int, body: bytes
) -> bool:
    """True when ``signature`` is the hub's signature of this answer. Never raises."""
    if not signature:
        return False
    try:
        public = parse_node_key(hub_key)
    except ValueError:
        return False
    return _verify(public, signature, canonical_response(binding, status, body))


def require_response(
    hub_key: str, signature: str | None, binding: RequestBinding, status: int, body: bytes
) -> None:
    if not verify_response(hub_key, signature, binding, status, body):
        raise ProtoError("hub_signature")


def parse_key_set(text: str) -> tuple[str, ...]:
    """Parse a pinned key set: 1 to 3 distinct comma-separated ``node_key`` texts (design M32 6.4).

    Whitespace around entries is ignored. Raises ValueError on an empty set, an empty entry, a
    duplicate, a malformed key or more than ``MAX_PINNED_KEYS`` keys. Placeholders are malformed.
    """
    parts = [p.strip() for p in text.split(",")]
    if not 1 <= len(parts) <= MAX_PINNED_KEYS:
        raise ValueError(f"expected 1 to {MAX_PINNED_KEYS} keys")
    for part in parts:
        parse_node_key(part)  # also refuses an empty entry
    if len(set(parts)) != len(parts):
        raise ValueError("duplicate key in the key set")
    return tuple(parts)


def verify_response_any(
    hub_keys: Sequence[str],
    signatures: Sequence[str | None],
    binding: RequestBinding,
    status: int,
    body: bytes,
) -> bool:
    """True when any of ``signatures`` verifies under any key of the pinned set. Never raises.

    ``signatures`` are the values of ``X-SPN-Hub-Signature`` and ``X-SPN-Hub-Signature-Alt``
    (either may be missing). A set of more than ``MAX_PINNED_KEYS`` keys is refused.
    """
    if not 1 <= len(hub_keys) <= MAX_PINNED_KEYS:
        return False
    return any(
        verify_response(key, sig, binding, status, body) for sig in signatures for key in hub_keys
    )


def require_response_any(
    hub_keys: Sequence[str],
    signatures: Sequence[str | None],
    binding: RequestBinding,
    status: int,
    body: bytes,
) -> None:
    if not verify_response_any(hub_keys, signatures, binding, status, body):
        raise ProtoError("hub_signature")


def key_in_set(hub_keys: Sequence[str], key: str) -> bool:
    """True when ``key`` (for example ``hub_key`` of ``/v1/info``) is one of the pinned keys."""
    return key in hub_keys


# --- request header checks (hub side, steps 2 and 3 of section 5.2) ---


@dataclass(frozen=True)
class ParsedHeaders:
    public: bytes
    key: str
    timestamp: int
    nonce: str
    signature: str


def parse_request_headers(
    key: str | None, timestamp: str | None, nonce: str | None, signature: str | None
) -> ParsedHeaders:
    """Check that the four headers are present and well formed. Raises ``invalid_payload``."""
    if not key or not timestamp or not nonce or not signature:
        raise ProtoError("invalid_payload", "missing signature header")
    try:
        public = parse_node_key(key)
        nonce_raw = b64u_decode(nonce)
        sig_raw = b64u_decode(signature)
    except ValueError as exc:
        raise ProtoError("invalid_payload", "malformed signature header") from exc
    if len(nonce_raw) != NONCE_BYTES or len(sig_raw) != 64:
        raise ProtoError("invalid_payload", "malformed signature header")
    if not re.fullmatch(r"[0-9]{1,12}", timestamp):
        raise ProtoError("invalid_payload", "malformed timestamp")
    return ParsedHeaders(public, key, int(timestamp), nonce, signature)


def check_timestamp(timestamp: int, now: float) -> None:
    if abs(now - timestamp) > MAX_SKEW_S:
        raise ProtoError("stale_timestamp")


# --- body padding (section 5.1) ---


def pad_body(obj: Mapping[str, object]) -> bytes:
    """Serialise a request body as compact ASCII JSON padded with spaces in ``"pad"``.

    The length is a multiple of 4096. Any ``pad`` key already present is replaced.
    """
    data = {k: v for k, v in obj.items() if k != "pad"}
    base = len(json.dumps({**data, "pad": ""}, separators=(",", ":")).encode("ascii"))
    fill = -base % PAD_BLOCK
    out = json.dumps({**data, "pad": " " * fill}, separators=(",", ":"), ensure_ascii=True)
    raw = out.encode("ascii")
    assert len(raw) % PAD_BLOCK == 0  # noqa: S101
    return raw


def is_padded(body: bytes) -> bool:
    return len(body) > 0 and len(body) % PAD_BLOCK == 0
