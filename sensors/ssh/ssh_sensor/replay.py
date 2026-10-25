"""Timed terminal recording (asciicast-v2-like frames) with a bounded size."""

from __future__ import annotations

import json
import time
from collections import deque

MAX_FRAME_CHARS = 2048
MAX_BUFFER_CHARS = 96 * 1024
MERGE_WINDOW_S = 0.02


class ReplayRecorder:
    """Collects ``[delta_seconds, "o"|"i", text]`` frames.

    ``"o"`` is data sent to the client (including the echo), ``"i"`` is data typed by the
    client. The oldest frames are dropped once the buffer exceeds ``MAX_BUFFER_CHARS``.
    """

    def __init__(self) -> None:
        self._frames: deque[list[object]] = deque()
        self._last = time.monotonic()
        self._chars = 0
        self.dropped = False

    def add(self, kind: str, text: str) -> None:
        if not text:
            return
        now = time.monotonic()
        delta = round(now - self._last, 3)
        self._last = now
        text = text[:MAX_FRAME_CHARS]
        if self._frames and delta <= MERGE_WINDOW_S and self._frames[-1][1] == kind:
            prev = self._frames[-1]
            merged = str(prev[2]) + text
            if len(merged) <= MAX_FRAME_CHARS:
                prev[2] = merged
                self._chars += len(text)
                self._trim()
                return
        self._frames.append([delta, kind, text])
        self._chars += len(text)
        self._trim()

    def _trim(self) -> None:
        while self._chars > MAX_BUFFER_CHARS and len(self._frames) > 1:
            first = self._frames.popleft()
            self._chars -= len(str(first[2]))
            self.dropped = True

    @property
    def size(self) -> int:
        """Approximate bytes held by the buffered frames."""
        return self._chars * 2 + len(self._frames) * 120

    def __bool__(self) -> bool:
        return bool(self._frames)

    def export(self, max_bytes: int = 12 * 1024) -> tuple[list[list[object]], bool]:
        """Return the newest frames fitting in ``max_bytes`` of compact JSON, and a flag."""
        kept: list[list[object]] = []
        size = 2
        truncated = self.dropped
        for frame in reversed(self._frames):
            cost = len(json.dumps(frame, separators=(",", ":"))) + 1
            if size + cost > max_bytes:
                truncated = True
                break
            kept.append(frame)
            size += cost
        kept.reverse()
        return kept, truncated
