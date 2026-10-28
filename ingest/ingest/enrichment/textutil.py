"""Bounded, printable text from third-party answers."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

_SAFE_TEXT = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ._-:+/()#@,")


def clean(value: Any, limit: int) -> str | None:
    """Printable, bounded text from an answer. Anything else is dropped."""
    if not isinstance(value, str):
        return None
    out = "".join(c for c in value[: limit * 2] if c in _SAFE_TEXT).strip()[:limit]
    return out or None


def parse_when(value: Any) -> datetime | None:
    """``2026-10-20 12:00:00 UTC`` (abuse.ch) or epoch seconds (VirusTotal) -> aware UTC."""
    try:
        if isinstance(value, int | float) and not isinstance(value, bool):
            return datetime.fromtimestamp(value, UTC)
        if isinstance(value, str):
            return datetime.strptime(value.removesuffix(" UTC")[:19], "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=UTC
            )
    except (ValueError, OverflowError, OSError):
        return None
    return None
