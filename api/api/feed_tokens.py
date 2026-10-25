"""Feed bearer tokens: 256 random bits, shown once, stored only as a sha256 hash.

The token text is the URL-safe base64 of 32 random bytes (43 characters, no padding). The
database keeps ``sha256(raw bytes)`` and the first six characters as a hint to tell tokens
apart. A token is compared by looking its hash up, so there is nothing to time. Anyone who reads
the database learns no usable token.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import secrets

TOKEN_CHARS = 43
HINT_CHARS = 6
_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def new_token() -> tuple[str, bytes, str]:
    """(token text, hash to store, hint)."""
    raw = secrets.token_bytes(32)
    text = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    return text, hashlib.sha256(raw).digest(), text[:HINT_CHARS]


def hash_token(text: str) -> bytes | None:
    """The hash to look up, or ``None`` when the text cannot be a token."""
    if len(text) != TOKEN_CHARS or not set(text) <= _ALPHABET:
        return None
    try:
        raw = base64.urlsafe_b64decode(text + "=")
    except (binascii.Error, ValueError):
        return None
    if len(raw) != 32 or base64.urlsafe_b64encode(raw).decode().rstrip("=") != text:
        return None  # a second spelling of the same bytes is not a token
    return hashlib.sha256(raw).digest()
