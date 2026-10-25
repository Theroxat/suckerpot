"""Per-deployment fake identity: profile secret, host name, RSA key pair and TLS certificates.

Everything is generated once under the data directory (mode 0600) and reused. Like a stock
MySQL 8.0 server on first start, the sensor creates a CA certificate, a server certificate
signed by it (``MySQL_Server_<version>_Auto_Generated_*``) and an RSA key pair for the
caching_sha2_password exchange. The host name is derived from a random secret, never from
public data.
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
from cryptography.x509.oid import NameOID

log = logging.getLogger("mysql_sensor.identity")

SECRET_FILE = "profile_secret"  # noqa: S105 - a file name, not a secret
RSA_PRIVATE = "private_key.pem"
RSA_PUBLIC = "public_key.pem"
SERVER_CHAIN = "server-cert.pem"  # the leaf only, as the server presents it
SERVER_KEY = "server-key.pem"
CA_CERT = "ca.pem"
LIFETIME = timedelta(days=3650)
RENEW_BEFORE = timedelta(days=30)

_PREFIXES = ("srv", "db", "mysql", "app", "web")
_ROLES = ("db", "sql", "data", "main", "prod")


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
    """A plausible Linux host name such as ``srv-db03``, stable for one deployment."""
    raw = _derive(secret, "mysql-hostname")
    return (
        f"{_PREFIXES[raw[0] % len(_PREFIXES)]}-{_ROLES[raw[1] % len(_ROLES)]}{1 + raw[2] % 9:02d}"
    )


def derive_uptime_offset(secret: str) -> int:
    """Seconds the fake server claims to have been up when the sensor starts (2 to 40 days)."""
    raw = _derive(secret, "mysql-uptime")
    return 2 * 86400 + int.from_bytes(raw[:4], "big") % (38 * 86400)


@dataclass(frozen=True)
class Identity:
    hostname: str
    uptime_offset: int
    rsa_private: rsa.RSAPrivateKey
    rsa_public_pem: bytes
    tls_chain: Path
    tls_key: Path
    secret: str


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _generate_tls(directory: Path, version: str, now: datetime) -> None:
    short = version.split("-")[0]
    age = timedelta(days=20 + secrets.randbelow(380), seconds=secrets.randbelow(86400))
    not_before = (now - age).replace(microsecond=0)
    not_after = not_before + LIFETIME
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = _name(f"MySQL_Server_{short}_Auto_Generated_CA_Certificate")
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(1)  # what mysqld's auto-generated certificates use: CA 1, server 2
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(f"MySQL_Server_{short}_Auto_Generated_Server_Certificate"))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(2)
        .not_valid_before(not_before + timedelta(seconds=1))
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    pem = serialization.Encoding.PEM
    ca_pem = ca_cert.public_bytes(pem)
    write_private(directory / CA_CERT, ca_pem)
    # mysqld presents the server certificate only; the CA stays in ca.pem for clients to pin.
    write_private(directory / SERVER_CHAIN, cert.public_bytes(pem))
    write_private(
        directory / SERVER_KEY,
        key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
    )


def _tls_current(directory: Path, version: str, now: datetime) -> bool:
    try:
        cert = x509.load_pem_x509_certificate((directory / SERVER_CHAIN).read_bytes())
        if not (directory / SERVER_KEY).exists():
            return False
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        want = f"MySQL_Server_{version.split('-')[0]}_Auto_Generated_Server_Certificate"
        return (
            bool(cn)
            and cn[0].value == want
            and cert.serial_number == 2
            and cert.not_valid_after_utc - RENEW_BEFORE > now
        )
    except (OSError, ValueError):
        return False


def _load_rsa(directory: Path) -> tuple[rsa.RSAPrivateKey, bytes] | None:
    try:
        key = serialization.load_pem_private_key((directory / RSA_PRIVATE).read_bytes(), None)
        pub = (directory / RSA_PUBLIC).read_bytes()
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(key, rsa.RSAPrivateKey) or not pub.startswith(b"-----BEGIN PUBLIC KEY"):
        return None
    return key, pub


def _create_rsa(directory: Path) -> tuple[rsa.RSAPrivateKey, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    write_private(
        directory / RSA_PRIVATE,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ),
    )
    write_private(directory / RSA_PUBLIC, pub)
    return key, pub


def load_or_create_identity(
    directory: str | Path,
    version: str,
    hostname: str | None = None,
    now: datetime | None = None,
) -> Identity:
    """Load the identity from ``directory`` or create what is missing, expiring or renamed."""
    root = Path(directory)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    secret = load_or_create_secret(root)
    current = now or datetime.now(UTC)
    loaded = _load_rsa(root)
    key, pub = loaded if loaded is not None else _create_rsa(root)
    if not _tls_current(root, version, current):
        _generate_tls(root, version, current)
        log.warning("generated new TLS certificates in %s", root)
    for name in (RSA_PRIVATE, RSA_PUBLIC, SERVER_CHAIN, SERVER_KEY, CA_CERT):
        with contextlib.suppress(OSError):
            (root / name).chmod(0o600)
    return Identity(
        hostname=hostname or derive_hostname(secret),
        uptime_offset=derive_uptime_offset(secret),
        rsa_private=key,
        rsa_public_pem=pub,
        tls_chain=root / SERVER_CHAIN,
        tls_key=root / SERVER_KEY,
        secret=secret,
    )
