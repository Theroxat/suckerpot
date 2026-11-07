"""The packaged list of external sources, with the licence guard (design M36 section 5).

A source may be published only when it declares ``licence: CC0-1.0``; URLhaus, ThreatFox and
MalwareBazaar are refused outright, whatever they declare and wherever they are hosted. The
loader runs on every start and a static test reads the shipped file with the same function.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

SOURCES_FILE = Path(__file__).resolve().parent.parent / "data" / "external.yaml"
PUBLISHABLE_LICENCE = "CC0-1.0"
# No licence statement, and no copying or derivative works without consent: never republished.
FORBIDDEN_IDS = frozenset({"urlhaus", "threatfox", "malwarebazaar"})
FORBIDDEN_WORDS = ("urlhaus", "threatfox", "bazaar")
FORMATS = frozenset({"feodo-json"})
MAX_SOURCE_BYTES = 8 * 1024 * 1024


class SourceError(ValueError):
    """A source that may not be loaded. The message is a short code, never a value."""


@dataclass(frozen=True)
class Source:
    id: str
    name: str
    licence: str
    publish: bool
    url: str
    page: str
    format: str
    max_bytes: int
    min_count: int

    @property
    def host(self) -> str:
        return urlsplit(self.url).hostname or ""


def _plain_https(url: str) -> bool:
    parts = urlsplit(url)
    return not (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.port
        or parts.query
        or parts.fragment
    )


def _source(raw: dict[str, Any]) -> Source:
    sid = str(raw["id"])
    url = str(raw["url"])
    host = (urlsplit(url).hostname or "").lower()
    lowered = sid.lower()
    if (
        lowered in FORBIDDEN_IDS
        or any(w in lowered for w in FORBIDDEN_WORDS)
        or any(w in host for w in FORBIDDEN_WORDS)
    ):
        raise SourceError("forbidden_source")
    if not _plain_https(url):
        raise SourceError("bad_url")
    publish = raw.get("publish") is True
    licence = str(raw.get("licence", ""))
    if publish and licence != PUBLISHABLE_LICENCE:
        raise SourceError("not_cc0")
    fmt = str(raw["format"])
    if fmt not in FORMATS:
        raise SourceError("bad_format")
    max_bytes = int(raw["max_bytes"])
    if not 0 < max_bytes <= MAX_SOURCE_BYTES:
        raise SourceError("bad_cap")
    return Source(
        id=sid,
        name=str(raw["name"]),
        licence=licence,
        publish=publish,
        url=url,
        page=str(raw.get("page", "")),
        format=fmt,
        max_bytes=max_bytes,
        min_count=int(raw["min_count"]),
    )


def load_sources(path: Path = SOURCES_FILE) -> list[Source]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    out = [_source(raw) for raw in doc["sources"]]
    if len({s.id for s in out}) != len(out):
        raise SourceError("duplicate_source")
    return out


def selected(names: tuple[str, ...], path: Path = SOURCES_FILE) -> list[Source]:
    """The sources named by ``HUB_EXTERNAL_SOURCES``: known, publishable, nothing else."""
    by_id = {s.id: s for s in load_sources(path)}
    out: list[Source] = []
    for name in names:
        src = by_id.get(name)
        if src is None or not src.publish:
            raise SourceError("unknown_source")
        out.append(src)
    return out
