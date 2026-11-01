"""Pseudonym and country rules of the Selfhostr network (design M29 section 9.7).

Shared by the API (validation when the admin joins or edits) and ingest (checked again before
anything is sent). The identity guard (owner names, addresses, domains) is a separate step:
this module only knows the shape and the reserved words.
"""

from __future__ import annotations

import re

SHAPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{1,22}[A-Za-z0-9]$")
_DIGITS = re.compile(r"\d{4}")
RESERVED = frozenset(
    "admin administrator root hub official moderator staff support system network node "
    "suckerpot selfhostr honeypot".split()
)
RESERVED_TERMS = ("suckerpot", "selfhostr", "honeypot")
COUNTRY = re.compile(r"^[A-Z]{2}$")


def clean_pseudonym(raw: str | None) -> str | None:
    """The pseudonym with surrounding spaces removed; ``None`` for empty (stays anonymous)."""
    if raw is None:
        return None
    value = raw.strip()
    return value or None


def pseudonym_problem(name: str) -> str | None:
    """A short reason code when ``name`` cannot be a pseudonym, else ``None``."""
    if not SHAPE.fullmatch(name) or "://" in name or "@" in name or "  " in name:
        return "shape"
    if _DIGITS.search(name):
        return "digits"
    squashed = re.sub(r"[ _.-]+", "", name.lower())
    spaced = re.sub(r"[ _.-]+", " ", name.strip().lower())
    if spaced in RESERVED or squashed in RESERVED or any(t in squashed for t in RESERVED_TERMS):
        return "reserved"
    return None


def valid_country(code: str) -> bool:
    return COUNTRY.fullmatch(code) is not None
