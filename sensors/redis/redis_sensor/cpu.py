"""CPU accounting in "steps": a unit of glob/scan work shared by connection, source IP and process.

Time slicing in the session loop keeps the event loop responsive; this module keeps one source
from taking more than its share of the CPU over time. Each command that does variable work
(glob matching) asks for a budget, and the work done is charged back. A source whose bucket is
empty gets plain empty results (``*0``) for those commands until it refills.
"""

from __future__ import annotations

import time
from collections import OrderedDict

MAX_COMMAND_STEPS = 5_000
MIN_STEPS = 100  # below this much headroom a glob command is answered with an empty result
MAX_TRACKED = 10_000


class StepBucket:
    def __init__(self, rate: float, burst: float) -> None:
        self.rate = rate
        self.burst = burst
        self.tokens = burst
        self._at = time.monotonic()

    def available(self) -> float:
        now = time.monotonic()
        self.tokens = min(self.burst, self.tokens + (now - self._at) * self.rate)
        self._at = now
        return self.tokens

    def charge(self, steps: float) -> None:
        self.tokens = max(-self.burst, self.tokens - steps)


class IpSteps:
    """Step buckets per source IP, bounded in size (oldest evicted)."""

    def __init__(self, rate: float, burst: float) -> None:
        self.rate, self.burst = rate, burst
        self._items: OrderedDict[str, StepBucket] = OrderedDict()

    def get(self, ip: str) -> StepBucket:
        bucket = self._items.get(ip)
        if bucket is None:
            bucket = self._items[ip] = StepBucket(self.rate, self.burst)
            while len(self._items) > MAX_TRACKED:
                self._items.popitem(last=False)
        else:
            self._items.move_to_end(ip)
        return bucket


class CpuAccount:
    """The buckets one connection draws from: its own, its IP's and the process-wide one."""

    def __init__(self, *buckets: StepBucket) -> None:
        self.buckets = buckets

    def headroom(self) -> int:
        if not self.buckets:
            return MAX_COMMAND_STEPS
        return int(max(0.0, min(MAX_COMMAND_STEPS, *(b.available() for b in self.buckets))))

    def charge(self, steps: int) -> None:
        for b in self.buckets:
            b.charge(steps)
