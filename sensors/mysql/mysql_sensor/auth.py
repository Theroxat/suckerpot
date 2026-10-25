"""MySQL authentication helpers: scramble verification and RSA password decryption.

The sensor knows the passwords of the accounts it accepts, so it can *verify* a scramble
against them. It never tries to recover an unknown password from a scramble (no cracking). A
caching_sha2_password client that is not recognised and has no TLS sends its password
RSA-encrypted to the sensor's public key, exactly as it would to a real server: that is the
only way a cleartext password reaches the sensor.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

SALT_LEN = 20
RSA_BLOCK = 256  # 2048 bit key


def new_salt() -> bytes:
    """20 random bytes, each in 1..127 and never ``$``, like the MySQL server picks."""
    out = bytearray()
    while len(out) < SALT_LEN:
        b = secrets.randbits(7)
        if b not in (0, 0x24):
            out.append(b)
    return bytes(out)


def _sha1(data: bytes) -> bytes:
    return hashlib.sha1(data, usedforsecurity=False).digest()


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


def native_scramble(password: bytes, salt: bytes) -> bytes:
    """mysql_native_password: SHA1(pw) XOR SHA1(salt + SHA1(SHA1(pw)))."""
    if not password:
        return b""
    stage1 = _sha1(password)
    return _xor(stage1, _sha1(salt + _sha1(stage1)))


def verify_native(response: bytes, password: bytes, salt: bytes) -> bool:
    return len(response) == 20 and hmac.compare_digest(response, native_scramble(password, salt))


def caching_sha2_scramble(password: bytes, salt: bytes) -> bytes:
    """caching_sha2_password: SHA256(pw) XOR SHA256(SHA256(SHA256(pw)) + salt)."""
    if not password:
        return b""
    stage1 = hashlib.sha256(password).digest()
    stage2 = hashlib.sha256(stage1).digest()
    return _xor(stage1, hashlib.sha256(stage2 + salt).digest())


def verify_caching_sha2(response: bytes, password: bytes, salt: bytes) -> bool:
    return len(response) == 32 and hmac.compare_digest(
        response, caching_sha2_scramble(password, salt)
    )


def decrypt_password(key: rsa.RSAPrivateKey, blob: bytes, salt: bytes) -> bytes | None:
    """Decrypt the RSA-OAEP blob a client sends for the caching_sha2 full authentication.

    The plaintext is ``password + NUL`` XORed with the salt (repeated). Returns None when the
    blob is not a valid ciphertext.
    """
    if len(blob) != RSA_BLOCK:
        return None
    try:
        plain = key.decrypt(
            blob,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA1()),  # noqa: S303 - fixed by the protocol
                algorithm=hashes.SHA1(),  # noqa: S303
                label=None,
            ),
        )
    except ValueError:
        return None
    if len(plain) > 256:
        return None
    clear = bytes(b ^ salt[i % len(salt)] for i, b in enumerate(plain))
    return clear.split(b"\x00", 1)[0]
