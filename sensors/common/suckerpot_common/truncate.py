"""Size limiting for attacker-controlled data."""

from __future__ import annotations

import json
import math
from typing import Any

DEFAULT_MAX_STRING = 4096
DEFAULT_MAX_TOTAL = 16 * 1024
_MAX_DEPTH = 6
_MAX_ITEMS = 64
_MAX_KEY = 128
_MARK = "..."


def _cap_str(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    if limit <= len(_MARK):
        return value[:limit]
    return value[: limit - len(_MARK)] + _MARK


def _clean(value: Any, limit: int, depth: int) -> Any:
    if isinstance(value, str):
        return _cap_str(value, limit)
    if isinstance(value, bytes | bytearray):
        return _cap_str(bytes(value).decode("utf-8", "replace"), limit)
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if depth >= _MAX_DEPTH:
        return _cap_str(str(value), limit)
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for i, (k, v) in enumerate(value.items()):
            if i >= _MAX_ITEMS:
                break
            out[_cap_str(str(k), _MAX_KEY)] = _clean(v, limit, depth + 1)
        return out
    if isinstance(value, list | tuple | set | frozenset):
        return [_clean(v, limit, depth + 1) for _, v in zip(range(_MAX_ITEMS), value, strict=False)]
    return _cap_str(str(value), limit)


def _size(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def truncate_data(
    data: dict[str, Any],
    *,
    max_string: int = DEFAULT_MAX_STRING,
    max_total: int = DEFAULT_MAX_TOTAL,
) -> dict[str, Any]:
    """Return a copy of ``data`` that is safe to put in an Event.

    Every string is capped to ``max_string`` characters (bytes are decoded first), keys to 128,
    containers to 64 items and nesting to 6 levels. If the JSON size is still above
    ``max_total`` bytes, the per-string cap is halved until it fits; as a last resort the
    largest top-level values are replaced by a short marker.
    """
    if max_string < 1 or max_total < 2:
        raise ValueError("limits must be positive")
    limit = max_string
    cleaned: dict[str, Any] = _clean(data, limit, 0)
    while _size(cleaned) > max_total and limit > 8:
        limit //= 2
        cleaned = _clean(data, limit, 0)
    if _size(cleaned) > max_total:
        for key in sorted(cleaned, key=lambda k: _size(cleaned[k]), reverse=True):
            cleaned[key] = "[truncated]"
            if _size(cleaned) <= max_total:
                break
    return cleaned
