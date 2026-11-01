"""The exact body of a submission to URLhaus or ThreatFox (design M27 section 7.5). Pure.

Built from a fixed allow-list of fields: the indicator itself, a threat name, a Malpedia family,
at most five tags from a fixed vocabulary, the confidence and the anonymity flag. No free text, no
comment, no reference URL, no date, no session data. The serialized body goes through the
identity guard before it leaves; the Auth-Key is a header and is never part of the body.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Final

import yaml

MAX_TAGS: Final = 5
TAG_RE: Final = re.compile(r"^[a-z0-9.-]{1,32}$")
MALPEDIA_RE: Final = re.compile(r"^[a-z0-9_.-]{1,64}$")
URLHAUS_THREAT: Final = "malware_download"
THREATFOX_THREAT: Final = "botnet_cc"
THREATFOX_IOC: Final = "ip:port"
CONFIDENCE: Final = 75
MAX_URL: Final = 1024

# Architecture tags: the set of the design; ``mips`` is little-endian ``mipsel`` when the sample
# says so. Anything else is not tagged.
_ARCH: Final = {
    "arm": "arm",
    "mips": "mips",
    "x86": "x86",
    "x86-64": "x86-64",
    "ppc": "powerpc",
    "ppc64": "powerpc",
    "superh": "sh4",
}
VOCABULARY_ARCH: Final = frozenset({"arm", "mips", "mipsel", "x86", "x86-64", "powerpc", "sh4"})
VOCABULARY_KIND: Final = frozenset({"elf", "sh"})


def arch_tag(arch: str | None, endian: str | None) -> str | None:
    tag = _ARCH.get(arch or "")
    if tag == "mips" and (endian or "").lower().startswith("little"):
        return "mipsel"
    return tag


def tags_for(
    kind: str | None, arch: str | None, endian: str | None, family: str | None
) -> list[str]:
    """Tags from the fixed vocabulary only: the family, the architecture, ``elf`` or ``sh``."""
    tags: list[str] = []
    if family:
        fam = family.strip().lower()
        if TAG_RE.match(fam):
            tags.append(fam)
    if kind == "elf":
        tags.append("elf")
        if (tag := arch_tag(arch, endian)) is not None:
            tags.append(tag)
    elif kind == "script":
        tags.append("sh")
    return list(dict.fromkeys(tags))[:MAX_TAGS]


def valid_tags(tags: list[str]) -> bool:
    return len(tags) <= MAX_TAGS and all(TAG_RE.match(t) for t in tags)


def urlhaus_body(url: str, tags: list[str], *, anonymous: bool) -> bytes:
    if not valid_tags(tags) or not url or len(url) > MAX_URL:
        raise ValueError("invalid submission")
    body = {
        "anonymous": "1" if anonymous else "0",
        "submission": [{"url": url, "threat": URLHAUS_THREAT, "tags": tags}],
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def threatfox_body(ioc: str, malware: str, tags: list[str], *, anonymous: bool) -> bytes:
    if not valid_tags(tags) or not MALPEDIA_RE.match(malware) or not ioc:
        raise ValueError("invalid submission")
    body = {
        "query": "submit_ioc",
        "threat_type": THREATFOX_THREAT,
        "ioc_type": THREATFOX_IOC,
        "malware": malware,
        "confidence_level": CONFIDENCE,
        "anonymous": 1 if anonymous else 0,
        "tags": tags,
        "iocs": [ioc],
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def load_malpedia(rules_dir: Path) -> dict[str, str]:
    """Sample family (lower case) to Malpedia name. A missing file means no ThreatFox candidates;
    a malformed entry fails loudly at start-up."""
    path = rules_dir / "abusech" / "malpedia.yaml"
    if not path.is_file():
        return {}
    raw = yaml.safe_load(path.read_text()) or {}
    if not isinstance(raw, Mapping):
        raise ValueError("abusech/malpedia.yaml must be a mapping")
    out: dict[str, str] = {}
    for family, name in raw.items():
        if not isinstance(family, str) or not isinstance(name, str):
            raise ValueError("abusech/malpedia.yaml: family and Malpedia name must be strings")
        if not TAG_RE.match(family.lower()) or not MALPEDIA_RE.match(name):
            raise ValueError(f"abusech/malpedia.yaml: invalid entry {family!r}")
        out[family.lower()] = name
    return out
