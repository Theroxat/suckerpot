"""Local GeoIP + ASN lookups from MMDB files (MaxMind GeoLite2 or DB-IP Lite).

Lookups are local and cheap (memory-mapped databases plus a small cache); when no database is
available every field is None. Both providers use the same MMDB layout.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import maxminddb

log = logging.getLogger(__name__)

CITY_FILES = ("GeoLite2-City.mmdb", "dbip-city-lite.mmdb")
ASN_FILES = ("GeoLite2-ASN.mmdb", "dbip-asn-lite.mmdb")
CACHE_MAX = 20_000

# Documentation ASNs (RFC 5398) and fictional names: only used by the demo-data switch.
_FAKE_TABLE: tuple[tuple[str, str, int, str], ...] = (
    ("NL", "Amsterdam", 64496, "Example Hosting B.V."),
    ("DE", "Frankfurt", 64497, "Beispiel Cloud GmbH"),
    ("US", "Ashburn", 64498, "Sample Networks Inc."),
    ("CN", "Beijing", 64499, "Exemplar Telecom"),
    ("RU", "Moscow", 64500, "Primer Net"),
    ("BR", "Sao Paulo", 64501, "Exemplo Provedor"),
    ("IN", "Mumbai", 64502, "Sample Broadband Ltd"),
    ("FR", "Paris", 64503, "Exemple Hebergement SAS"),
    ("VN", "Hanoi", 64504, "Mau ISP"),
    ("KR", "Seoul", 64505, "Example Korea Telecom"),
    ("GB", "London", 64506, "Sample Hosting Ltd"),
    ("ID", "Jakarta", 64507, "Contoh Net"),
)


@dataclass(frozen=True, slots=True)
class GeoInfo:
    country: str | None = None  # ISO 3166-1 alpha-2
    city: str | None = None
    asn: int | None = None
    org: str | None = None


EMPTY = GeoInfo()


def is_routable(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Only globally routable addresses are looked up (and sent to reputation providers)."""
    return addr.is_global


def _clip(value: Any, limit: int) -> str | None:
    return value[:limit] if isinstance(value, str) and value else None


class GeoResolver:
    def __init__(self, directory: Path, *, fake_for_private: bool = False) -> None:
        self.directory = directory
        self.fake_for_private = fake_for_private
        self._city: maxminddb.Reader | None = None
        self._asn: maxminddb.Reader | None = None
        self._cache: dict[str, GeoInfo] = {}
        self.files: dict[str, str] = {}
        self.reload()

    @property
    def available(self) -> bool:
        return self._city is not None or self._asn is not None or self.fake_for_private

    def reload(self) -> None:
        """(Re)open the databases found in the directory; missing files are fine."""
        old = (self._city, self._asn)
        self._city = self._open(CITY_FILES)
        self._asn = self._open(ASN_FILES)
        self._cache.clear()
        for reader in old:
            if reader is not None:
                reader.close()

    def _open(self, names: tuple[str, ...]) -> maxminddb.Reader | None:
        for name in names:
            path = self.directory / name
            if path.is_file():
                try:
                    reader = maxminddb.open_database(str(path))
                except (OSError, ValueError, maxminddb.InvalidDatabaseError):
                    log.warning("ignoring unreadable GeoIP database %s", name)
                    continue
                self.files[names[0].split("-")[-1].split(".")[0].lower()] = name
                return reader
        return None

    def close(self) -> None:
        for reader in (self._city, self._asn):
            if reader is not None:
                reader.close()
        self._city = self._asn = None

    def lookup(self, ip: str) -> GeoInfo:
        cached = self._cache.get(ip)
        if cached is not None:
            return cached
        info = self._lookup(ip)
        if len(self._cache) >= CACHE_MAX:
            self._cache.clear()
        self._cache[ip] = info
        return info

    def _lookup(self, ip: str) -> GeoInfo:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return EMPTY
        if not is_routable(addr):
            return self._fake(ip) if self.fake_for_private else EMPTY
        country = city = org = None
        asn: int | None = None
        try:
            if self._city is not None:
                rec: Any = self._city.get(ip)
                if isinstance(rec, dict):
                    code = (rec.get("country") or {}).get("iso_code")
                    country = code.upper() if isinstance(code, str) and len(code) == 2 else None
                    city = _clip(((rec.get("city") or {}).get("names") or {}).get("en"), 128)
            if self._asn is not None:
                rec = self._asn.get(ip)
                if isinstance(rec, dict):
                    number = rec.get("autonomous_system_number")
                    asn = number if isinstance(number, int) and 0 < number < 2**32 else None
                    org = _clip(rec.get("autonomous_system_organization"), 128)
        except (ValueError, maxminddb.InvalidDatabaseError):
            return EMPTY
        return GeoInfo(country, city, asn, org)

    @staticmethod
    def _fake(ip: str) -> GeoInfo:
        """Deterministic stand-in for demo data (documentation ranges have no real geography)."""
        idx = int.from_bytes(hashlib.sha256(ip.encode()).digest()[:4], "big") % len(_FAKE_TABLE)
        country, city, asn, org = _FAKE_TABLE[idx]
        return GeoInfo(country, city, asn, org)
