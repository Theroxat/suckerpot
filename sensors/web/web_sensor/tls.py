"""TLS: a self-signed certificate generated once, and a server context like Apache's.

The certificate mimics Debian/Ubuntu's ``ssl-cert`` "snakeoil" certificate (RSA 2048, SHA-256,
subject = issuer = the host name, ten years of validity, CA:TRUE) so it neither stands out nor
names a recognisable issuer. Dates and serial come from the per-deployment profile.
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

from web_sensor.profile import Profile


def ensure_certificate(data_dir: str, hostname: str, profile: Profile) -> tuple[Path, Path]:
    """Return (certificate, key) paths under ``data_dir``/tls, creating them on first start."""
    tls_dir = Path(data_dir) / "tls"
    cert_path = tls_dir / "server.crt"
    key_path = tls_dir / "server.key"
    if cert_path.is_file() and key_path.is_file():
        return cert_path, key_path
    tls_dir.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    rng = profile.rng("tls")
    not_before = dt.datetime.fromtimestamp(
        profile.install_ts - rng.randrange(1, 40) * 86400, dt.UTC
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(int.from_bytes(bytes(rng.randrange(256) for _ in range(20)), "big") >> 1)
        .not_valid_before(not_before)
        .not_valid_after(not_before + dt.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False
        )
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
    """Server context: TLS 1.2 and 1.3 with OpenSSL's ``HIGH:!aNULL`` list (Ubuntu's default)."""
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
