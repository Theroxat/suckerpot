"""Per-deployment fake identity, derived from a random profile secret.

The secret is generated once under the data directory (mode 0600) and reused. Every
attacker-visible name and the SMB server GUID are derived from it with HMAC-SHA256, so they are
stable for one deployment but cannot be predicted from outside and are never tied to public
data. Nothing here is a real host: the names only need to look like an ordinary Windows file
server.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import logging
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("smb_sensor.identity")

SECRET_FILE = "profile_secret"  # noqa: S105 - a file name, not a secret

_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_ROLES = ("APP", "FS", "FILE", "DC", "SQL", "ERP", "DATA", "BACKUP")
_PREFIXES = ("SRV", "SVR", "WIN", "FS", "HOST")
_DOMAINS = ("CORP", "AD", "OFFICE", "GROUP", "INTRA", "HQ", "ADMIN", "NET")
_TLDS = ("local", "lan", "internal", "intra")


def write_private(path: Path, data: bytes) -> None:
    """Atomically write ``data`` with mode 0600."""
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


def load_or_create_secret(directory: str | Path) -> str:
    root = Path(directory)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = root / SECRET_FILE
    try:
        value = path.read_text().strip()
    except OSError:
        value = ""
    if len(value) < 32:
        value = secrets.token_hex(32)
        write_private(path, (value + "\n").encode())
        log.warning("generated new profile secret in %s (persist the data volume)", root)
    return value


def _derive(secret: str, label: str) -> bytes:
    return hmac.new(secret.encode(), label.encode(), hashlib.sha256).digest()


def derive_computer_name(secret: str) -> str:
    """A plausible NetBIOS computer name (max 15 chars), stable for one deployment."""
    raw = _derive(secret, "smb-computer")
    if raw[0] & 1:
        return "WIN-" + "".join(_ALNUM[b % len(_ALNUM)] for b in raw[1:12])
    prefix = _PREFIXES[raw[1] % len(_PREFIXES)]
    role = _ROLES[raw[2] % len(_ROLES)]
    return f"{prefix}-{role}{1 + raw[3] % 9:02d}"[:15]


def derive_domain_name(secret: str) -> str:
    """A plausible NetBIOS domain / workgroup name."""
    raw = _derive(secret, "smb-domain")
    return _DOMAINS[raw[0] % len(_DOMAINS)]


def derive_dns_domain(secret: str, domain_name: str) -> str:
    """The AD DNS domain: the NetBIOS domain name plus a plausible private suffix,
    e.g. ``CORP`` -> ``corp.local`` (never a real or documentation domain)."""
    raw = _derive(secret, "smb-dns-domain")
    label = domain_name.lower()
    tlds = [t for t in _TLDS if t != label]
    return f"{label}.{tlds[raw[0] % len(tlds)]}"


def derive_server_guid(secret: str) -> bytes:
    """The 16-byte SMB2 ServerGuid."""
    return _derive(secret, "smb-server-guid")[:16]


@dataclass(frozen=True)
class Identity:
    computer_name: str  # NetBIOS computer name, e.g. "SRV-FS01"
    domain_name: str  # NetBIOS domain / workgroup, e.g. "CORP"
    dns_domain: str  # DNS domain, e.g. "corp.local"
    dns_computer: str  # FQDN, e.g. "srv-fs01.corp.local"
    server_guid: bytes  # 16 bytes

    @property
    def netbios_computer(self) -> str:
        return self.computer_name


def load_or_create_identity(
    directory: str | Path,
    computer_name: str | None = None,
    domain_name: str | None = None,
) -> Identity:
    """Load the profile secret from ``directory`` (or create it) and derive the identity."""
    secret = load_or_create_secret(directory)
    computer = (computer_name or derive_computer_name(secret))[:15]
    domain = domain_name or derive_domain_name(secret)
    dns_domain = derive_dns_domain(secret, domain)
    return Identity(
        computer_name=computer,
        domain_name=domain,
        dns_domain=dns_domain,
        dns_computer=f"{computer.lower()}.{dns_domain}",
        server_guid=derive_server_guid(secret),
    )
