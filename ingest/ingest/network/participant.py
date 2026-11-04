"""Participant mode: the consent record and the automatic join (design M32 D4, N1').

The installer writes ``NETWORK_CONSENT`` to ``.env`` after showing the consent screen (always
in participant mode, where there is no dashboard; in full mode when the owner accepts the
"Join the network?" question, M33). Ingest joins by itself from a valid record, once: a
leave stores ``network_membership.left_day`` and a restart never re-joins. A record of a version
this release does not know (``consent_outdated``) never joins; the participant re-runs
``participant.sh join`` to agree again.

Format: ``v2:sources,payloads,c2,files,rechecks[,verify_reveals]:2026-11-03``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date

CONSENT_VERSION = "v2"
REQUIRED_ITEMS = frozenset({"sources", "payloads", "c2", "files", "rechecks"})
OPTIONAL_ITEMS = frozenset({"verify_reveals"})

MISSING = "missing"
VALID = "valid"
OUTDATED = "consent_outdated"
INVALID = "consent_invalid"

_VERSION = re.compile(r"^v\d{1,3}$")


@dataclass(frozen=True, slots=True)
class Consent:
    version: str
    items: frozenset[str]
    day: date

    def has(self, item: str) -> bool:
        return item in self.items


def parse(raw: str) -> tuple[str, Consent | None]:
    """``(state, consent)``. The consent is only returned for state ``valid``."""
    text = raw.strip()
    if not text:
        return MISSING, None
    parts = text.split(":")
    if len(parts) != 3 or not _VERSION.fullmatch(parts[0]):
        return INVALID, None
    version, items_raw, day_raw = parts
    if version != CONSENT_VERSION:
        return OUTDATED, None
    items = frozenset(i.strip() for i in items_raw.split(",") if i.strip())
    if not REQUIRED_ITEMS <= items or not items <= REQUIRED_ITEMS | OPTIONAL_ITEMS:
        return INVALID, None
    try:
        day = date.fromisoformat(day_raw)
    except ValueError:
        return INVALID, None
    return VALID, Consent(version, items, day)
