"""Pseudonym rules (design M29 section 9.7, the hub side).

The node also runs the owner-identity guard before it sends a pseudonym; the hub cannot know the
owner's names, so it enforces the shape and a reserved list.
"""

from __future__ import annotations

import re

from suckerpot_netproto import ProtoError

_SHAPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{1,22}[A-Za-z0-9]$")
_DIGITS = re.compile(r"\d{4}")
RESERVED = frozenset(
    "admin administrator root hub official moderator staff support system network node "
    "suckerpot selfhostr honeypot".split()
)
RESERVED_TERMS = ("suckerpot", "selfhostr", "honeypot")


def normalise(name: str) -> str:
    """The uniqueness key: lowercase, separators collapsed to one space."""
    return re.sub(r"[ _.-]+", " ", name.strip().lower())


def validate(name: str) -> str:
    """Return the uniqueness key of a valid pseudonym, or raise ``pseudonym_invalid``."""
    if not _SHAPE.fullmatch(name) or "://" in name or "@" in name or "  " in name:
        raise ProtoError("pseudonym_invalid")
    if _DIGITS.search(name):
        raise ProtoError("pseudonym_invalid")
    key = normalise(name)
    squashed = key.replace(" ", "")
    if key in RESERVED or squashed in RESERVED or any(t in squashed for t in RESERVED_TERMS):
        raise ProtoError("pseudonym_invalid")
    return key
