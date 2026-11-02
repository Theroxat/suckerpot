"""Errors of the feed library. One exception type, a closed set of codes."""

from __future__ import annotations

CODES = frozenset(
    {
        "bad_format",  # malformed file, signature or manifest
        "bad_value",  # a value that must never reach a renderer
        "too_large",  # over a size or entry cap
        "too_many_invalid",  # more than 1 % of the entries are invalid
        "bad_signature",  # the signature does not verify
        "wrong_key",  # the signature was made by another key
        "wrong_file",  # trusted comment names another file
        "wrong_serial",  # trusted comment names another serial
        "hash_mismatch",  # bytes or sha256 differ from the manifest
        "expired",  # valid_until has passed
        "rollback",  # serial lower than the last accepted one
    }
)


class FeedError(ValueError):
    """A feed failure. ``code`` is one of ``CODES``; ``detail`` is for logs only."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail
