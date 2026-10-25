"""Known research scanners: harmless, self-announcing internet crawlers (M19).

The list lives in ``rules/scanners.yaml``. A scanner matches by the network that owns the address
(ASN or organisation name, both from the local GeoIP database) or by the HTTP user-agent it
sends. The user-agent is attacker-controlled, so :func:`stays_benign` is the safety net: a
session that signed in, ran a command, downloaded a file or carries an exploit tag is never
benign, whatever it claims to be. Matching is a plain substring test (no regular expressions).
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ingest.tagging import RuleError

FILE_NAME = "scanners.yaml"
MAX_SCANNERS = 100
MAX_ENTRIES = 32
MAX_NAME = 64
MAX_NEEDLE = 96
MAX_TEXT = 512  # an attacker-sized user-agent or organisation is cut before it is compared

# Tags that mean "something was attempted": a session carrying one is not a research scan.
SEVERE_TAGS = frozenset(
    {
        "php2shell", "malware-drop", "mirai", "crypto-miner", "container-escape", "sql-rce",
        "eternalblue", "db-ransom", "redis-rogue-master", "sip-fraud", "persistence",
        "exec-attempt", "credential-stuffing", "brute-force",
    }
)  # fmt: skip


@dataclass(frozen=True, slots=True)
class Scanner:
    name: str
    asns: frozenset[int] = frozenset()
    orgs: tuple[str, ...] = ()
    user_agents: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ScannerSet:
    scanners: tuple[Scanner, ...] = ()

    def match(self, *, asn: int | None, org: str | None, user_agent: object) -> str | None:
        """The name of the first scanner that matches, or None."""
        org_text = org[:MAX_TEXT].lower() if isinstance(org, str) else ""
        ua_text = user_agent[:MAX_TEXT].lower() if isinstance(user_agent, str) else ""
        for s in self.scanners:
            if asn is not None and asn in s.asns:
                return s.name
            if org_text and any(n in org_text for n in s.orgs):
                return s.name
            if ua_text and any(n in ua_text for n in s.user_agents):
                return s.name
        return None


def stays_benign(
    *, commands: int, downloads: int, login_success: bool, tags: Collection[str]
) -> bool:
    """False as soon as the session did more than look around."""
    if commands > 0 or downloads > 0 or login_success:
        return False
    return SEVERE_TAGS.isdisjoint(tags)


def _strings(raw: Any, where: str) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list) or len(raw) > MAX_ENTRIES:
        raise RuleError(f"{where}: must be a list of at most {MAX_ENTRIES} strings")
    out: list[str] = []
    for item in raw:
        if not isinstance(item, str) or not item.strip() or len(item) > MAX_NEEDLE:
            raise RuleError(f"{where}: entries must be short, non-empty strings")
        out.append(item.strip().lower())
    return tuple(out)


def _asns(raw: Any, where: str) -> frozenset[int]:
    if raw is None:
        return frozenset()
    if not isinstance(raw, list) or len(raw) > MAX_ENTRIES:
        raise RuleError(f"{where}: 'asns' must be a list of AS numbers")
    for a in raw:
        if not isinstance(a, int) or isinstance(a, bool) or not 0 < a < 2**32:
            raise RuleError(f"{where}: 'asns' must be a list of AS numbers")
    return frozenset(raw)


def _parse(raw: Any, index: int) -> Scanner:
    where = f"{FILE_NAME}: scanner #{index + 1}"
    if not isinstance(raw, Mapping):
        raise RuleError(f"{where}: must be a mapping")
    unknown = set(raw) - {"name", "asns", "orgs", "user_agents"}
    if unknown:
        raise RuleError(f"{where}: unknown keys {sorted(map(str, unknown))}")
    name = raw.get("name")
    if not isinstance(name, str) or not name.strip() or len(name) > MAX_NAME:
        raise RuleError(f"{where}: 'name' must be a string of at most {MAX_NAME} characters")
    scanner = Scanner(
        name=name.strip(),
        asns=_asns(raw.get("asns"), where),
        orgs=_strings(raw.get("orgs"), f"{where} orgs"),
        user_agents=_strings(raw.get("user_agents"), f"{where} user_agents"),
    )
    if not (scanner.asns or scanner.orgs or scanner.user_agents):
        raise RuleError(f"{where}: needs at least one of asns, orgs, user_agents")
    return scanner


def load_scanners(directory: Path) -> ScannerSet:
    """Read ``scanners.yaml``; a missing file means no scanner is labelled, a broken one raises."""
    path = directory / FILE_NAME
    if not path.is_file():
        return ScannerSet()
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RuleError(f"{FILE_NAME}: cannot read ({type(exc).__name__})") from exc
    raw = doc.get("scanners") if isinstance(doc, Mapping) else None
    if not isinstance(raw, list) or len(raw) > MAX_SCANNERS:
        raise RuleError(f"{FILE_NAME}: top level must have a 'scanners' list")
    scanners = tuple(_parse(r, i) for i, r in enumerate(raw))
    if len({s.name for s in scanners}) != len(scanners):
        raise RuleError(f"{FILE_NAME}: duplicate scanner names")
    return ScannerSet(scanners)
