"""Settings of the replies worker (``ABUSE_REPLY_*``). Off until ``ABUSE_REPLIES_ENABLED=true``."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

from ingest.features import _int


@dataclass(frozen=True, slots=True)
class RepliesSettings:
    max_bytes: int = 262_144
    max_per_poll: int = 50
    daily_cap: int = 500
    poll_deadline_s: int = 120
    excerpt_chars: int = 2000
    match_days: int = 120

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> RepliesSettings:
        e = os.environ if env is None else env
        return cls(
            max_bytes=_int(e, "ABUSE_REPLY_MAX_BYTES", 262_144, 65_536, 1_048_576),
            max_per_poll=_int(e, "ABUSE_REPLY_MAX_PER_POLL", 50, 1, 500),
            daily_cap=_int(e, "ABUSE_REPLY_DAILY_CAP", 500, 1, 10_000),
            poll_deadline_s=_int(e, "ABUSE_REPLY_POLL_DEADLINE_S", 120, 30, 600),
            excerpt_chars=_int(e, "ABUSE_REPLY_EXCERPT_CHARS", 2000, 0, 2000),
            match_days=_int(e, "ABUSE_REPLY_MATCH_DAYS", 120, 1, 730),
        )
