"""TLS for the login phase, driven through memory BIOs.

SQL Server wraps the TLS handshake in TDS PRELOGIN packets and, with encryption "off", drops
TLS again right after the LOGIN7 exchange. Here the handshake bytes are shuttled by the session
through a :class:`TlsStream`; there is no socket-level TLS, no ``sslproto`` and so none of its
256 KiB per-connection buffers. A stream is charged ``TLS_COST`` bytes to the memory budget.

The certificate is self-signed and generated once under the data directory (0600), named like
the fallback certificate a real instance creates when none is configured.
"""

from __future__ import annotations

import datetime as dt
import logging
import ssl
from pathlib import Path

from mssql_sensor.identity import write_private

log = logging.getLogger("mssql_sensor.tls")

TLS_COST = 48 * 1024  # budgeted bytes per live TLS stream
CERT_FILE = "tds_cert.pem"
KEY_FILE = "tds_key.pem"
READ_STEP = 16 * 1024
MAX_READ_STEPS = 64


class TlsError(Exception):
    """The handshake or a record failed; the connection is closed."""


class TlsClosed(Exception):
    """The peer sent close_notify."""


def ensure_certificate(directory: str | Path) -> tuple[Path, Path]:
    """Create a fresh self-signed pair at every start, like an instance without its own certificate.

    SQL Server generates the fallback certificate when the service starts: not-before is the start
    time and it is valid for decades. The files are rewritten (0600) because the TLS context loads
    them from disk."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    root = Path(directory)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    cert_path, key_path = root / CERT_FILE, root / KEY_FILE
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SSL_Self_Signed_Fallback")])
    now = dt.datetime.now(dt.UTC).replace(microsecond=0)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=365 * 30))
        .sign(key, hashes.SHA256())
    )
    write_private(
        key_path,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ),
    )
    write_private(cert_path, cert.public_bytes(serialization.Encoding.PEM))
    log.info("generated the self-signed TLS certificate in %s", root)
    return cert_path, key_path


# The TLS 1.2 order of Windows Server 2019 (Schannel): AES-GCM first, then CBC, RSA key exchange
# last, no ChaCha20.
CIPHERS = ":".join(
    (
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES256-SHA384",
        "ECDHE-RSA-AES128-SHA256",
        "ECDHE-RSA-AES256-SHA",
        "ECDHE-RSA-AES128-SHA",
        "AES256-GCM-SHA384",
        "AES128-GCM-SHA256",
        "AES256-SHA256",
        "AES128-SHA256",
        "AES256-SHA",
        "AES128-SHA",
    )
)


def make_context(directory: str | Path) -> ssl.SSLContext:
    cert, key = ensure_certificate(directory)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2  # no post-handshake records to place
    ctx.set_ciphers(CIPHERS)
    ctx.options |= ssl.OP_NO_TICKET | ssl.OP_CIPHER_SERVER_PREFERENCE
    ctx.load_cert_chain(cert, key)
    return ctx


class TlsStream:
    def __init__(self, ctx: ssl.SSLContext) -> None:
        self._in = ssl.MemoryBIO()
        self._out = ssl.MemoryBIO()
        self._obj = ctx.wrap_bio(self._in, self._out, server_side=True)
        self.done = False

    def handshake(self, data: bytes) -> bytes:
        """Feed handshake bytes from the client; returns the bytes to send back."""
        self._in.write(data)
        try:
            self._obj.do_handshake()
            self.done = True
        except ssl.SSLWantReadError:
            pass
        except ssl.SSLError as exc:
            raise TlsError(type(exc).__name__) from None
        return self._out.read()

    def decrypt(self, data: bytes) -> bytes:
        self._in.write(data)
        out = bytearray()
        for _ in range(MAX_READ_STEPS):
            try:
                chunk = self._obj.read(READ_STEP)
            except ssl.SSLWantReadError:
                break
            except ssl.SSLZeroReturnError:
                raise TlsClosed from None
            except ssl.SSLError as exc:
                raise TlsError(type(exc).__name__) from None
            if not chunk:
                break
            out += chunk
        return bytes(out)

    def encrypt(self, data: bytes) -> bytes:
        try:
            self._obj.write(data)
        except ssl.SSLError as exc:
            raise TlsError(type(exc).__name__) from None
        return self._out.read()
