from __future__ import annotations

import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from rdp_sensor.config import Config, valid_hostname
from rdp_sensor.identity import (
    CERT_FILE,
    KEY_FILE,
    SECRET_FILE,
    derive_hostname,
    load_or_create_identity,
)


def test_identity_created_once(tmp_path: Path) -> None:
    first = load_or_create_identity(tmp_path)
    for name in (CERT_FILE, KEY_FILE, SECRET_FILE):
        assert stat.S_IMODE((tmp_path / name).stat().st_mode) == 0o600
    pem = (tmp_path / CERT_FILE).read_bytes()
    second = load_or_create_identity(tmp_path)
    assert second.hostname == first.hostname
    assert (tmp_path / CERT_FILE).read_bytes() == pem
    cert = x509.load_pem_x509_certificate(pem)
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == first.hostname
    assert cert.issuer == cert.subject
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [ExtendedKeyUsageOID.SERVER_AUTH]
    now = datetime.now(UTC)
    assert cert.not_valid_before_utc < now < cert.not_valid_after_utc
    assert cert.not_valid_after_utc - cert.not_valid_before_utc == timedelta(days=182)
    text = pem.decode() + first.hostname
    for word in ("honeypot", "suckerpot", "python", "test"):
        assert word not in text.lower()


def test_renewed_when_expiring_or_renamed(tmp_path: Path) -> None:
    first = load_or_create_identity(tmp_path)
    pem = (tmp_path / CERT_FILE).read_bytes()
    later = first.not_after - timedelta(days=1)
    renewed = load_or_create_identity(tmp_path, now=later)
    assert (tmp_path / CERT_FILE).read_bytes() != pem
    assert renewed.not_after > later + timedelta(days=100)
    named = load_or_create_identity(tmp_path, hostname="SRV-RDS01")
    assert named.hostname == "SRV-RDS01"


def test_hostname_shapes() -> None:
    names = {derive_hostname(f"secret-{i}") for i in range(200)}
    assert len(names) > 50
    for name in names:
        assert valid_hostname(name)
        assert name.isupper() or "-" in name
        assert name.startswith(("WIN-", "SRV-", "SVR-", "WS-", "HOST-"))


def test_config_env() -> None:
    cfg = Config.from_env(
        {"RDP_HOSTNAME": "srv-app02", "RDP_PUBLIC_PORT": "13389", "RDP_ENABLE_TLS": "false"}
    )
    assert cfg.hostname == "SRV-APP02" and cfg.public_port == 13389 and not cfg.enable_tls
    assert Config.from_env({}).port == 3389
    with pytest.raises(ValueError):
        Config.from_env({"RDP_HOSTNAME": "a-very-long-hostname-x"})
    with pytest.raises(ValueError):
        Config.from_env({"RDP_HOSTNAME": "bad name"})
