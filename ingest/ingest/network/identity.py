"""The node's Ed25519 identity: generation, encrypted storage, signing (design M29, N7).

The private key is made here, stored as AES-GCM ciphertext (``SecretBox``, the Settings key) and
never leaves ingest in clear: the API role cannot select the column. Nothing in this module logs
a key.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from suckerpot_db.secretbox import Credential, SecretBox, SecretError
from suckerpot_netproto import sign

AAD = "network_node_key"


class NoSettingsKey(Exception):
    """``SETTINGS_ENCRYPTION_KEY`` is not usable, so a key cannot be stored safely."""


@dataclass(frozen=True, slots=True)
class Identity:
    """A node key pair. ``seed`` is the secret and is hidden from repr."""

    seed: bytes = field(repr=False)
    public: bytes

    @property
    def node_key(self) -> str:
        return sign.node_key(self.public)

    @property
    def fingerprint(self) -> str:
        return sign.fingerprint(self.public)


def generate() -> Identity:
    seed = sign.generate_private_key()
    return Identity(seed=seed, public=sign.public_key_of(seed))


def seal(identity: Identity, box: SecretBox | None) -> tuple[bytes, bytes]:
    """``(ciphertext, nonce)`` of the private key. Raises ``NoSettingsKey`` without a box."""
    if box is None:
        raise NoSettingsKey
    return box.encrypt(AAD, Credential(key=sign.b64u_encode(identity.seed)))


def unseal(box: SecretBox | None, ciphertext: bytes, nonce: bytes, public: bytes) -> Identity:
    """Decrypt a stored key and check it matches the stored public key."""
    if box is None:
        raise NoSettingsKey
    try:
        seed = sign.b64u_decode(box.decrypt(AAD, ciphertext, nonce).key)
        identity = Identity(seed=seed, public=sign.public_key_of(seed))
    except (SecretError, ValueError):
        raise NoSettingsKey from None
    if identity.public != public:
        raise NoSettingsKey
    return identity
