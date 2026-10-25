"""Per-deployment fake identity: profile secret, Windows host name and the RDP certificate.

Everything is generated once under the data directory (mode 0600) and reused. The host name is
derived from a random secret, never from public data, so it cannot be predicted from outside.
The certificate mimics the self-signed one Windows creates for Remote Desktop: RSA 2048,
SHA-256, subject = issuer = CN=<host name>, valid for six months, Server Authentication EKU.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import logging
import os
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

log = logging.getLogger("rdp_sensor.identity")

CERT_FILE = "rdp_cert.pem"
KEY_FILE = "rdp_key.pem"
SECRET_FILE = "profile_secret"  # noqa: S105 - a file name, not a secret
CERT_LIFETIME = timedelta(days=182)
RENEW_BEFORE = timedelta(days=7)

_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_ROLES = ("APP", "RDS", "WEB", "FS", "SQL", "TS", "ERP", "VM")
_PREFIXES = ("SRV", "SVR", "WS", "HOST")
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


def derive_hostname(secret: str) -> str:
    """A plausible NetBIOS name (max 15 chars), stable for one deployment.

    Half of the deployments get the ``WIN-XXXXXXXXXXX`` name Windows picks at install time,
    the others a hand-named server such as ``SRV-APP02``.
    """
    raw = _derive(secret, "rdp-hostname")
    if raw[0] & 1:
        return "WIN-" + "".join(_ALNUM[b % len(_ALNUM)] for b in raw[1:12])
    prefix = _PREFIXES[raw[1] % len(_PREFIXES)]
    role = _ROLES[raw[2] % len(_ROLES)]
    return f"{prefix}-{role}{1 + raw[3] % 9:02d}"


def derive_domain_name(secret: str) -> str:
    """A plausible NetBIOS domain / workgroup name, stable for one deployment."""
    raw = _derive(secret, "rdp-domain")
    return _DOMAINS[raw[0] % len(_DOMAINS)]


def derive_dns_domain(secret: str, domain_name: str) -> str:
    """The AD DNS domain: the NetBIOS domain plus a private suffix (never a real domain)."""
    raw = _derive(secret, "rdp-dns-domain")
    label = domain_name.lower()
    tlds = [t for t in _TLDS if t != label]
    return f"{label}.{tlds[raw[0] % len(tlds)]}"


@dataclass(frozen=True)
class Identity:
    hostname: str
    cert_path: Path
    key_path: Path
    not_after: datetime
    netbios_domain: str = "WORKGROUP"
    dns_domain: str = "workgroup.local"

    @property
    def netbios_computer(self) -> str:
        """The NetBIOS computer name: the host name, capped at 15 characters."""
        return self.hostname[:15]

    @property
    def dns_computer(self) -> str:
        """The host FQDN, e.g. ``srv-rds03.corp.local``."""
        return f"{self.hostname.lower()}.{self.dns_domain}"


def _generate_cert(hostname: str, now: datetime, backdate: bool) -> tuple[bytes, bytes, datetime]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if backdate:
        # First start: Windows created its certificate when the service first ran, so pretend
        # that was a while ago, within the six-month lifetime.
        age = timedelta(days=secrets.randbelow(120) + 3, seconds=secrets.randbelow(86400))
    else:
        # Renewal: Windows regenerates the certificate shortly before it expires.
        age = timedelta(seconds=60 + secrets.randbelow(3600))
    not_before = (now - age).replace(microsecond=0)
    not_after = not_before + CERT_LIFETIME
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(int.from_bytes(secrets.token_bytes(16), "big") >> 1 or 1)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert.public_bytes(serialization.Encoding.PEM), key_pem, not_after


def load_or_create_identity(
    directory: str | Path, hostname: str | None = None, now: datetime | None = None
) -> Identity:
    """Load the certificate from ``directory`` or create it (also when expiring or renamed)."""
    root = Path(directory)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    secret = load_or_create_secret(root)
    name = hostname or derive_hostname(secret)
    netbios_domain = derive_domain_name(secret)
    dns_domain = derive_dns_domain(secret, netbios_domain)
    cert_path, key_path = root / CERT_FILE, root / KEY_FILE
    current = now or datetime.now(UTC)
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if (
            key_path.exists()
            and cn
            and cn[0].value == name
            and cert.not_valid_after_utc - RENEW_BEFORE > current
        ):
            with contextlib.suppress(OSError):
                key_path.chmod(0o600)
                cert_path.chmod(0o600)
            return Identity(
                name, cert_path, key_path, cert.not_valid_after_utc, netbios_domain, dns_domain
            )
    except (OSError, ValueError):
        pass
    cert_pem, key_pem, not_after = _generate_cert(name, current, backdate=not cert_path.exists())
    write_private(key_path, key_pem)
    write_private(cert_path, cert_pem)
    log.warning("generated new RDP certificate in %s", root)
    return Identity(name, cert_path, key_path, not_after, netbios_domain, dns_domain)
