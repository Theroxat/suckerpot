"""Per-deployment fake identity, derived from a random secret kept under the data directory.

The secret is generated once (mode 0600). The machine name, the SPID base, the uptime, the data
of the fake tables and the fake password hashes are all derived from it with HMAC, so two
deployments never look alike and nothing can be predicted from public data.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import logging
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger("mssql_sensor.identity")

SECRET_FILE = "profile_secret"  # noqa: S105 - a file name, not a secret

# version -> (product year, level, KB, build date, Windows Server year, Windows build).
# Plausible release data for a banner; it is not meant to be authoritative.
RELEASES: dict[str, tuple[int, str, str, str, int, int]] = {
    "15.0.4335.1": (2019, "RTM-CU23", "KB5030333", "Sep 15 2023 10:32:22", 2019, 17763),
    "15.0.4365.2": (2019, "RTM-CU26", "KB5035123", "Feb 16 2024 14:09:41", 2019, 17763),
    "15.0.4375.4": (2019, "RTM-CU27", "KB5037331", "Apr 12 2024 12:26:19", 2019, 17763),
    "16.0.4125.3": (2022, "RTM-CU13", "KB5036432", "Apr 04 2024 12:26:02", 2022, 20348),
    "16.0.4135.4": (2022, "RTM-CU14", "KB5038325", "Jun 06 2024 14:41:49", 2022, 20348),
}
DEFAULT_VERSIONS = ("15.0.4365.2", "15.0.4375.4", "16.0.4135.4")
HOST_PREFIXES = ("SRV-SQL", "DB", "SQL", "APP-DB", "SRV-DB")
DB_NAMES = ("appdb", "inventory", "crm", "reporting", "hrdata", "webshop", "billing")


def write_private(path: Path, data: bytes) -> None:
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


def parse_version(text: str) -> tuple[int, int, int, int] | None:
    parts = text.strip().split(".")
    if len(parts) != 4 or not all(p.isdigit() and len(p) <= 5 for p in parts):
        return None
    major, minor, build, sub = (int(p) for p in parts)
    if major not in (15, 16) or minor > 255 or build > 65535 or sub > 65535:
        return None
    return major, minor, build, sub


def valid_version(text: str) -> bool:
    return parse_version(text) is not None


@dataclass(frozen=True)
class Profile:
    version_text: str
    version: tuple[int, int, int, int]
    banner: str
    server_name: str
    spid_base: int
    uptime_offset: int  # seconds the "server" was up before this process started
    databases: tuple[str, ...]
    win_build: int = 17763
    update_level: str = "RTM"
    domain: str = "WORKGROUP"
    dns_domain: str = "workgroup.local"
    _secret: str = field(repr=False, default="")

    def derive(self, label: str, n: int = 16) -> bytes:
        return hmac.new(self._secret.encode(), label.encode(), hashlib.sha256).digest()[:n]

    def number(self, label: str, low: int, high: int) -> int:
        return low + int.from_bytes(self.derive(label, 8), "big") % (high - low + 1)


def release_info(
    version_text: str, version: tuple[int, int, int, int]
) -> tuple[int, str, str, str, int, int]:
    return RELEASES.get(
        version_text,
        (
            2019 if version[0] == 15 else 2022,
            "RTM-CU",
            "KB5000000",
            "Jan 01 2024 00:00:00",
            2019 if version[0] == 15 else 2022,
            17763 if version[0] == 15 else 20348,
        ),
    )


def make_banner(version_text: str, version: tuple[int, int, int, int]) -> str:
    year, level, kb, date, win_year, win_build = release_info(version_text, version)
    return (
        f"Microsoft SQL Server {year} ({level}) ({kb}) - {version_text} (X64) \n"
        f"\t{date} \n"
        f"\tCopyright (C) {year} Microsoft Corporation\n"
        f"\tStandard Edition (64-bit) on Windows Server {win_year} Standard 10.0 <X64> "
        f"(Build {win_build}: ) (Hypervisor)\n"
    )


def derive_profile(secret: str, version: str = "") -> Profile:
    raw = hmac.new(secret.encode(), b"x", hashlib.sha256).digest()
    version = version.strip()
    if not valid_version(version):
        version = DEFAULT_VERSIONS[raw[0] % len(DEFAULT_VERSIONS)]
    parsed = parse_version(version)
    assert parsed is not None  # noqa: S101 - validated just above
    prof = Profile(version, parsed, make_banner(version, parsed), "", 0, 0, (), _secret=secret)
    prefix = HOST_PREFIXES[prof.number("hostprefix", 0, len(HOST_PREFIXES) - 1)]
    dbs = [DB_NAMES[(prof.number("db1", 0, 6) + k * 2) % len(DB_NAMES)] for k in range(2)]
    _year, level, _kb, _date, _wy, win_build = release_info(version, parsed)
    domain = ("CORP", "INTRA", "LAB", "OFFICE", "HQ")[prof.number("domain", 0, 4)]
    return Profile(
        version_text=version,
        version=parsed,
        banner=prof.banner,
        server_name=f"{prefix}{prof.number('hostnum', 1, 19):02d}",
        spid_base=prof.number("spid", 51, 64),
        uptime_offset=prof.number("uptime", 2 * 86400, 120 * 86400),
        databases=tuple(dict.fromkeys(dbs)),
        win_build=win_build,
        update_level=level.split("-", 1)[-1],
        domain=domain,
        dns_domain=domain.lower() + ".local",
        _secret=secret,
    )


def load_profile(directory: str | Path, version: str = "") -> Profile:
    return derive_profile(load_or_create_secret(directory), version)
