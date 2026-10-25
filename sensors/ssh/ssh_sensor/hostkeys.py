"""Host key management: generate once into a persistent volume, then reuse.

Private keys are written with mode 0600 and are never logged or emitted in events.
"""

from __future__ import annotations

import contextlib
import logging
import os
import secrets
from pathlib import Path

import asyncssh

log = logging.getLogger("ssh_sensor.hostkeys")

# (file name, asyncssh algorithm, extra generate_private_key kwargs)
_KEYS: tuple[tuple[str, str, dict[str, int]], ...] = (
    ("ssh_host_ed25519_key", "ssh-ed25519", {}),
    ("ssh_host_rsa_key", "ssh-rsa", {"key_size": 3072}),
    ("ssh_host_ecdsa_key", "ecdsa-sha2-nistp256", {}),
)


def _write_private(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
    tmp.replace(path)


def load_or_create_secret(directory: str | Path, name: str = "profile_secret") -> str:
    """Random per-deployment secret (0600) that seeds the fake host identity.

    It must never be derived from public data such as the host key fingerprint, otherwise
    anyone could predict the fake IP, MAC and uptime and recognise the sensor.
    """
    root = Path(directory)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = root / name
    try:
        value = path.read_text().strip()
    except OSError:
        value = ""
    if len(value) < 32:
        value = secrets.token_hex(32)
        _write_private(path, (value + "\n").encode())
        log.warning("generated new profile secret in %s (persist the data volume)", root)
    return value


def load_or_create_host_keys(directory: str | Path) -> list[asyncssh.SSHKey]:
    """Return ed25519, RSA 3072 and ECDSA P-256 host keys, creating missing ones."""
    root = Path(directory)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    keys: list[asyncssh.SSHKey] = []
    for name, algorithm, kwargs in _KEYS:
        path = root / name
        key: asyncssh.SSHKey | None = None
        if path.exists():
            try:
                key = asyncssh.read_private_key(str(path))
            except (asyncssh.KeyImportError, OSError, ValueError):
                log.warning("host key %s is unreadable, regenerating", name)
        if key is None:
            key = asyncssh.generate_private_key(algorithm, **kwargs)  # type: ignore[arg-type]
            _write_private(path, key.export_private_key())
            log.warning(
                "generated new host key %s in %s: if this happens on every start, the data "
                "volume is not persistent and clients will see changing host keys",
                name,
                root,
            )
        else:
            with contextlib.suppress(OSError):
                path.chmod(0o600)
        keys.append(key)
    return keys
