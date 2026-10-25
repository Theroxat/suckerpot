"""Redis glob matching (``*``, ``?``, ``[a-z]``, ``[^x]``, ``\\x``) with a hard work budget.

Hand written, no regular expressions. The matcher backtracks only to the last ``*`` (the
classic linear-ish wildcard algorithm), and every step is charged to a :class:`Budget`, so a
hostile pattern against hostile keys can never hold the event loop for long, whatever the
sizes involved. Patterns and subjects over the caps below simply do not match.
"""

from __future__ import annotations

MAX_PATTERN = 128
MAX_SUBJECT = 512


class Budget:
    """Work units shared by all matches of one command."""

    def __init__(self, units: int = 5_000) -> None:
        self.units = units
        self.left = units

    @property
    def used(self) -> int:
        return self.units - max(self.left, 0)

    @property
    def exhausted(self) -> bool:
        return self.left <= 0


def _class_end(pattern: bytes, start: int) -> int:
    """Index of the ``]`` closing the class that opens at ``start`` (or len(pattern))."""
    i = start + 1
    n = len(pattern)
    while i < n:
        if pattern[i] == 0x5C and i + 1 < n:
            i += 2
            continue
        if pattern[i] == 0x5D:
            return i
        i += 1
    return n


def _class_match(pattern: bytes, start: int, end: int, char: int) -> bool:
    i = start + 1
    negate = i < end and pattern[i] == 0x5E
    if negate:
        i += 1
    hit = False
    while i < end:
        c = pattern[i]
        if c == 0x5C and i + 1 < end:
            i += 1
            hit = hit or pattern[i] == char
        elif i + 2 < end and pattern[i + 1] == 0x2D:
            lo, hi = sorted((c, pattern[i + 2]))
            hit = hit or lo <= char <= hi
            i += 2
        else:
            hit = hit or c == char
        i += 1
    return hit != negate


def glob_match(pattern: bytes, subject: bytes, budget: Budget) -> bool:
    if len(pattern) > MAX_PATTERN or len(subject) > MAX_SUBJECT:
        return False
    budget.left -= 1
    p = s = 0
    star_p = -1
    star_s = 0
    np, ns = len(pattern), len(subject)
    while s < ns:
        budget.left -= 1
        if budget.left <= 0:
            return False
        if p < np:
            c = pattern[p]
            if c == 0x2A:  # '*'
                while p < np and pattern[p] == 0x2A:
                    p += 1
                if p == np:
                    return True
                star_p, star_s = p, s
                continue
            if c == 0x3F:  # '?'
                p += 1
                s += 1
                continue
            if c == 0x5B:  # '['
                end = _class_end(pattern, p)
                budget.left -= end - p
                if _class_match(pattern, p, end, subject[s]):
                    p = min(end + 1, np)
                    s += 1
                    continue
            elif c == 0x5C and p + 1 < np:  # backslash escape
                if pattern[p + 1] == subject[s]:
                    p += 2
                    s += 1
                    continue
            elif c == subject[s]:
                p += 1
                s += 1
                continue
        if star_p >= 0:
            star_s += 1
            s = star_s
            p = star_p
            continue
        return False
    while p < np and pattern[p] == 0x2A:
        p += 1
    return p == np
