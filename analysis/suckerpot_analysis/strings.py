"""Bounded printable-string scanner (ASCII and UTF-16LE runs)."""

from __future__ import annotations

import re

_SCAN_CAP = 16 * 1024 * 1024
_MAX_RUN = 4096  # a run longer than this is cut; avoids quadratic behaviour on huge runs


def printable_strings(
    data: bytes, *, min_len: int = 6, max_count: int = 500, max_len: int = 120
) -> list[str]:
    """First `max_count` unique runs of printable text, each cut to `max_len` chars."""
    window = data[:_SCAN_CAP]
    min_len = max(1, min_len)
    ascii_re = re.compile(rb"[\x20-\x7e\t]{%d,%d}" % (min_len, _MAX_RUN))
    wide_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,%d}" % (min_len, _MAX_RUN // 2))
    found: list[tuple[int, str]] = []
    seen: set[str] = set()

    def add(offset: int, text: str) -> None:
        text = text[:max_len]
        if text not in seen:
            seen.add(text)
            found.append((offset, text))

    for m in ascii_re.finditer(window):
        add(m.start(), m.group().decode("ascii"))
        if len(found) >= max_count * 2:
            break
    for m in wide_re.finditer(window):
        add(m.start(), m.group().decode("utf-16-le", errors="ignore"))
        if len(found) >= max_count * 2:
            break
    found.sort(key=lambda p: p[0])
    return [t for _, t in found[:max_count]]
