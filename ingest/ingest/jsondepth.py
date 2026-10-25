"""Deterministic nesting guard for untrusted JSON.

``json.loads`` on deeply nested input either raises ``RecursionError`` or succeeds, depending on
the interpreter version and build. A cheap linear scan makes the outcome the same everywhere.
"""

from __future__ import annotations

MAX_JSON_DEPTH = 64


def exceeds_depth(data: bytes | bytearray, limit: int = MAX_JSON_DEPTH) -> bool:
    """True when brackets outside string literals nest deeper than ``limit``."""
    depth = 0
    in_string = False
    escaped = False
    for byte in data:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:  # backslash
                escaped = True
            elif byte == 0x22:  # closing quote
                in_string = False
        elif byte == 0x22:
            in_string = True
        elif byte in (0x5B, 0x7B):  # [ {
            depth += 1
            if depth > limit:
                return True
        elif byte in (0x5D, 0x7D):  # ] }
            depth = max(0, depth - 1)
    return False
