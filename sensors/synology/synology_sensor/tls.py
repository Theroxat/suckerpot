"""TLS: a self-signed certificate generated once, shaped like DSM's factory certificate.

DSM ships a self-signed RSA 2048 certificate for ``synology`` issued by "Synology Inc. CA",
valid for a long time. The key and certificate are created on first start below
``<data_dir>/tls`` and reused afterwards.
"""

from __future__ import annotations

import datetime as dt
import os
import ssl
from collections.abc import Callable
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from synology_sensor.profile import Profile


def _name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "TW"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Taipei"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Synology Inc."),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def ensure_certificate(data_dir: str, profile: Profile) -> tuple[Path, Path]:
    """Return (certificate, key) paths under ``data_dir``/tls, creating them on first start."""
    tls_dir = Path(data_dir) / "tls"
    cert_path = tls_dir / "server.crt"
    key_path = tls_dir / "server.key"
    if cert_path.is_file() and key_path.is_file():
        return cert_path, key_path
    tls_dir.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rng = profile.rng("tls")
    not_before = dt.datetime.fromtimestamp(profile.created - rng.randrange(1, 400) * 86400, dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("synology"))
        .issuer_name(_name("Synology Inc. CA"))
        .public_key(key.public_key())
        .serial_number(int.from_bytes(bytes(rng.randrange(256) for _ in range(16)), "big") >> 1)
        .not_valid_before(not_before)
        .not_valid_after(not_before + dt.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("synology")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key_pem)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def make_context(
    cert_path: Path, key_path: Path, on_sni: Callable[[ssl.SSLObject, str | None], None]
) -> ssl.SSLContext:
    """Server context: TLS 1.2 and 1.3, the ciphers a current DSM offers."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("HIGH:!aNULL")
    ctx.load_cert_chain(str(cert_path), str(key_path))

    def callback(sslobj: ssl.SSLObject, server_name: str | None, _ctx: ssl.SSLContext) -> None:
        try:
            on_sni(sslobj, server_name)
        except Exception:  # noqa: S110 - never fail a handshake because of bookkeeping
            pass

    ctx.sni_callback = callback
    return ctx


def load_public_key_pem(cert_path: Path) -> str:
    """The certificate's public key as PEM (served by ``SYNO.API.Encryption``)."""
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    return (
        cert.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode("ascii")
    )
