"""Relevance of a CVE to the services SuckerPot emulates (declarative, see rules/cve/*.yaml)."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ingest.cve.sources import CVE_RE

MAX_SERVICES = 100
MAX_KEYWORDS = 50
RELEVANCE_WEIGHT = {"high": 3, "medium": 2, "none": 0}
FILE_NAME = "relevance.yaml"

_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
_TAG = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
_CPE = re.compile(r"^[a-z0-9_.-]{1,64}(:[a-z0-9_.-]{1,64})?$")


class RelevanceError(Exception):
    """The relevance file is unusable."""


@dataclass(frozen=True, slots=True)
class Service:
    id: str
    label: str
    sensors: tuple[str, ...]
    cpes: frozenset[str]
    keywords: tuple[re.Pattern[str], ...]


@dataclass(frozen=True, slots=True)
class Assessment:
    relevance: str
    services: list[str]
    tags: list[str]


def _word(keyword: str) -> re.Pattern[str]:
    return re.compile(rf"(?<![a-z0-9]){re.escape(keyword.lower())}(?![a-z0-9])")


def _str_list(value: object, what: str, *, limit: int) -> list[str]:
    if not isinstance(value, list) or len(value) > limit:
        raise RelevanceError(f"{what}: expected a short list")
    if not all(isinstance(v, str) and v.strip() and len(v) <= 80 for v in value):
        raise RelevanceError(f"{what}: expected short non-empty strings")
    return [v.strip() for v in value]


class RelevanceMap:
    def __init__(self, services: list[Service], cve_tags: Mapping[str, list[str]]) -> None:
        self.services = services
        self.cve_tags = dict(cve_tags)

    def assess(
        self,
        *,
        cve_id: str,
        vendor: str | None,
        product: str | None,
        title: str | None,
        description: str | None,
        cpes: Iterable[str],
    ) -> Assessment:
        names = f"{vendor or ''} {product or ''}".lower()
        prose = f"{title or ''} {description or ''}".lower()
        cpe_set = {c.lower() for c in cpes}
        cpe_vendors = {c.split(":", 1)[0] for c in cpe_set}
        high: list[str] = []
        medium: list[str] = []
        for svc in self.services:
            by_cpe = any((c in cpe_set) if ":" in c else (c in cpe_vendors) for c in svc.cpes)
            if by_cpe or any(k.search(names) for k in svc.keywords):
                high.append(svc.id)
            elif any(k.search(prose) for k in svc.keywords):
                medium.append(svc.id)
        relevance = "high" if high else "medium" if medium else "none"
        return Assessment(relevance, high + medium, self.cve_tags.get(cve_id, []))


def rank_score(relevance: str, in_kev: bool, cvss: float | None) -> int:
    """Sort key: relevance first, then KEV, then CVSS (higher is more important)."""
    return (
        RELEVANCE_WEIGHT.get(relevance, 0) * 100_000
        + (10_000 if in_kev else 0)
        + round((cvss or 0.0) * 100)
    )


def parse_relevance(doc: Any) -> RelevanceMap:
    if not isinstance(doc, Mapping):
        raise RelevanceError("top level must be a mapping")
    raw_services = doc.get("services")
    if not isinstance(raw_services, list) or not 0 < len(raw_services) <= MAX_SERVICES:
        raise RelevanceError("'services' must be a non-empty list")
    services: list[Service] = []
    seen: set[str] = set()
    for raw in raw_services:
        if not isinstance(raw, Mapping):
            raise RelevanceError("each service must be a mapping")
        sid, label = raw.get("id"), raw.get("label")
        if not isinstance(sid, str) or not _ID.match(sid) or sid in seen:
            raise RelevanceError("service ids must be unique lowercase slugs")
        if not isinstance(label, str) or not 0 < len(label) <= 80:
            raise RelevanceError(f"{sid}: label is required")
        seen.add(sid)
        cpes = _str_list(raw.get("cpes", []), f"{sid}.cpes", limit=MAX_KEYWORDS)
        if not all(_CPE.match(c.lower()) for c in cpes):
            raise RelevanceError(f"{sid}.cpes: use 'vendor:product' or 'vendor'")
        keywords = _str_list(raw.get("keywords", []), f"{sid}.keywords", limit=MAX_KEYWORDS)
        services.append(
            Service(
                id=sid,
                label=label,
                sensors=tuple(_str_list(raw.get("sensors", []), f"{sid}.sensors", limit=11)),
                cpes=frozenset(c.lower() for c in cpes),
                keywords=tuple(_word(k) for k in keywords),
            )
        )
    cve_tags: dict[str, list[str]] = {}
    for entry in doc.get("cve_tags") or []:
        if not isinstance(entry, Mapping):
            raise RelevanceError("each cve_tags entry must be a mapping")
        tag = entry.get("tag")
        if not isinstance(tag, str) or not _TAG.match(tag):
            raise RelevanceError("cve_tags: 'tag' must be a lowercase slug")
        for cve in _str_list(entry.get("cves"), f"cve_tags.{tag}", limit=200):
            if not CVE_RE.match(cve):
                raise RelevanceError(f"cve_tags.{tag}: bad CVE id")
            cve_tags.setdefault(cve, []).append(tag)
    return RelevanceMap(services, cve_tags)


def load_relevance(rules_dir: Path) -> RelevanceMap:
    path = rules_dir / "cve" / FILE_NAME
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RelevanceError(f"{path.name}: cannot read ({type(exc).__name__})") from exc
    return parse_relevance(doc)
