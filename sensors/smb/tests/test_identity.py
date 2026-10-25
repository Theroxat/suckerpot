from __future__ import annotations

from pathlib import Path

from smb_sensor import config, identity


def test_secret_is_created_and_reused(tmp_path: Path) -> None:
    first = identity.load_or_create_secret(tmp_path)
    second = identity.load_or_create_secret(tmp_path)
    assert first == second
    assert len(first) >= 32
    assert (tmp_path / identity.SECRET_FILE).stat().st_mode & 0o777 == 0o600


def test_derivation_is_deterministic_per_secret() -> None:
    secret = "a" * 64
    assert identity.derive_computer_name(secret) == identity.derive_computer_name(secret)
    assert identity.derive_server_guid(secret) == identity.derive_server_guid(secret)


def test_derivation_differs_between_secrets() -> None:
    guids = {identity.derive_server_guid("x" * 64 + str(i)) for i in range(50)}
    assert len(guids) == 50  # no collisions


def test_identity_fields_are_plausible(tmp_path: Path) -> None:
    ident = identity.load_or_create_identity(tmp_path)
    assert config.valid_hostname(ident.computer_name)
    assert len(ident.computer_name) <= 15
    assert len(ident.server_guid) == 16
    assert ident.dns_computer.startswith(ident.computer_name.lower())
    assert "." in ident.dns_domain
    # No giveaways and no documentation ranges in attacker-visible names.
    for name in (ident.computer_name, ident.domain_name, ident.dns_domain, ident.dns_computer):
        low = name.lower()
        assert "honeypot" not in low
        assert "suckerpot" not in low
        assert "example" not in low


def test_explicit_names_override(tmp_path: Path) -> None:
    ident = identity.load_or_create_identity(tmp_path, "SRV-FILE07", "CORP")
    assert ident.computer_name == "SRV-FILE07"
    assert ident.domain_name == "CORP"


def test_dns_domain_follows_netbios_domain(tmp_path: Path) -> None:
    ident = identity.load_or_create_identity(tmp_path, "FS01", "CORP")
    assert ident.dns_domain.startswith("corp.")
    assert ident.dns_computer == f"fs01.{ident.dns_domain}"
    assert "contoso" not in ident.dns_domain
