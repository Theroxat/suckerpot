"""Enrolment proof of work (spec section 5.7): sha256 with leading zero bits.

``sha256(challenge || pubkey || pow_nonce)`` must start with ``difficulty`` zero bits. The
nonce is an 8-byte big-endian counter on the solver side; the verifier accepts any 1 to 16 bytes.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable

MAX_NONCE_BYTES = 16
MAX_DIFFICULTY = 48


def leading_zero_bits(digest: bytes) -> int:
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        bits += 8 - byte.bit_length()
        break
    return bits


def pow_digest(challenge: bytes, pubkey: bytes, pow_nonce: bytes) -> bytes:
    return hashlib.sha256(challenge + pubkey + pow_nonce).digest()


def verify_pow(challenge: bytes, pubkey: bytes, pow_nonce: bytes, difficulty: int) -> bool:
    if not 1 <= len(pow_nonce) <= MAX_NONCE_BYTES or not 0 <= difficulty <= MAX_DIFFICULTY:
        return False
    return leading_zero_bits(pow_digest(challenge, pubkey, pow_nonce)) >= difficulty


def solve_pow(
    challenge: bytes,
    pubkey: bytes,
    difficulty: int,
    *,
    start: int = 0,
    max_iterations: int | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> bytes | None:
    """Search a nonce. Returns None when ``max_iterations`` is spent or ``should_stop()`` is true.

    CPU bound: callers run it in a thread (``asyncio.to_thread``).
    """
    if not 0 <= difficulty <= MAX_DIFFICULTY:
        raise ValueError("difficulty out of range")
    base = hashlib.sha256(challenge + pubkey)
    counter = start
    tried = 0
    while max_iterations is None or tried < max_iterations:
        if should_stop is not None and tried % 4096 == 0 and should_stop():
            return None
        nonce = counter.to_bytes(8, "big")
        h = base.copy()
        h.update(nonce)
        if leading_zero_bits(h.digest()) >= difficulty:
            return nonce
        counter += 1
        tried += 1
    return None
