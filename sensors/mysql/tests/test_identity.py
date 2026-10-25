from __future__ import annotations

import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mysql_sensor import identity
from mysql_sensor.config import Config, valid_hostname

VERSION = "8.0.43-0ubuntu0.24.04.2"


def test_files_are_private_and_stable(tmp_path: Path) -> None:
    first = identity.load_or_create_identity(tmp_path / "d", VERSION)
    for name in (
        identity.SECRET_FILE, identity.RSA_PRIVATE, identity.RSA_PUBLIC,
        identity.SERVER_CHAIN, identity.SERVER_KEY, identity.CA_CERT,
    ):  # fmt: skip
        mode = stat.S_IMODE(os.stat(tmp_path / "d" / name).st_mode)
        assert mode == 0o600, name
    assert stat.S_IMODE(os.stat(tmp_path / "d").st_mode) == 0o700
    second = identity.load_or_create_identity(tmp_path / "d", VERSION)
    assert first.hostname == second.hostname and first.uptime_offset == second.uptime_offset
    assert first.rsa_public_pem == second.rsa_public_pem
    assert first.tls_chain.read_bytes() == second.tls_chain.read_bytes()
    assert isinstance(first.rsa_private, rsa.RSAPrivateKey)
    assert first.rsa_public_pem.startswith(b"-----BEGIN PUBLIC KEY-----")


def test_certificates_follow_the_mysql_auto_generated_pattern(tmp_path: Path) -> None:
    ident = identity.load_or_create_identity(tmp_path, VERSION)
    chain = x509.load_pem_x509_certificates(ident.tls_chain.read_bytes())
    assert len(chain) == 1  # the leaf only, as mysqld presents it
    (leaf,) = chain
    ca = x509.load_pem_x509_certificate((tmp_path / "ca.pem").read_bytes())
    assert (leaf.serial_number, ca.serial_number) == (2, 1)
    assert (
        leaf.subject.rfc4514_string() == "CN=MySQL_Server_8.0.43_Auto_Generated_Server_Certificate"
    )
    assert ca.subject.rfc4514_string() == "CN=MySQL_Server_8.0.43_Auto_Generated_CA_Certificate"
    assert leaf.issuer == ca.subject
    assert leaf.not_valid_after_utc - leaf.not_valid_before_utc >= timedelta(days=3649)
    assert leaf.not_valid_before_utc < datetime.now(UTC)  # created in the past


def test_certificate_is_renewed_for_a_new_version(tmp_path: Path) -> None:
    a = identity.load_or_create_identity(tmp_path, VERSION)
    before = a.tls_chain.read_bytes()
    identity.load_or_create_identity(tmp_path, "8.0.44-0ubuntu0.24.04.1")
    assert a.tls_chain.read_bytes() != before


def test_hostname_derivation_is_plausible_and_secret_dependent() -> None:
    names = {identity.derive_hostname(f"{i:064x}") for i in range(40)}
    assert len(names) > 5
    assert all(valid_hostname(n) for n in names)
    assert identity.derive_hostname("a" * 64) == identity.derive_hostname("a" * 64)
    assert "honeypot" not in "".join(names)


def test_old_random_serial_certificates_are_replaced(tmp_path: Path) -> None:
    ident = identity.load_or_create_identity(tmp_path, VERSION)
    old = ident.tls_chain.read_bytes()
    cert = x509.load_pem_x509_certificate(old)
    assert identity._tls_current(tmp_path, VERSION, datetime.now(UTC))
    assert cert.serial_number == 2
    # A volume written by an older build holds a random serial: it must be regenerated.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    legacy = (
        x509.CertificateBuilder()
        .subject_name(cert.subject)
        .issuer_name(cert.issuer)
        .public_key(key.public_key())
        .serial_number(123456789)
        .not_valid_before(cert.not_valid_before_utc)
        .not_valid_after(cert.not_valid_after_utc)
        .sign(key, hashes.SHA256())
    )
    ident.tls_chain.write_bytes(legacy.public_bytes(serialization.Encoding.PEM))
    assert not identity._tls_current(tmp_path, VERSION, datetime.now(UTC))
    again = identity.load_or_create_identity(tmp_path, VERSION)
    assert x509.load_pem_x509_certificate(again.tls_chain.read_bytes()).serial_number == 2


def test_config_sensor_names_win_over_legacy_names() -> None:
    cfg = Config.from_env(
        {"SENSOR_PORT": "3310", "MYSQL_PORT": "3311", "SENSOR_MAX_PER_IP": "3"}
        | {"SENSOR_MYSQL_VERSION": "8.0.44-0ubuntu0.24.04.1", "SENSOR_MYSQL_ACCOUNTS": "u:p"}
    )
    assert (cfg.port, cfg.max_per_ip, cfg.version) == (3310, 3, "8.0.44-0ubuntu0.24.04.1")
    assert cfg.accounts == {"u": (b"p",)}
    assert Config.from_env({"MYSQL_PORT": "3311"}).port == 3311  # the old spelling still works
    assert Config.from_env({}).rsa_per_sec == 30 and Config.from_env({}).max_packet == 64 << 20


def test_config_validation() -> None:
    cfg = Config.from_env({"MYSQL_ACCOUNTS": "a:b", "MYSQL_PUBLIC_PORT": "3307"})
    assert cfg.accounts == {"a": (b"b",)} and cfg.public_port == 3307
    assert cfg.clear_password_switch is False
    assert Config.from_env({"MYSQL_CLEAR_PASSWORD_SWITCH": "true"}).clear_password_switch
    for bad in ({"MYSQL_DEFAULT_PLUGIN": "sha256_password"}, {"MYSQL_VERSION": "5.7.1"},
                {"MYSQL_HOSTNAME": "bad name!"}):  # fmt: skip
        with pytest.raises(ValueError):
            Config.from_env(bad)
