"""Process-level memory guard.

The per-connection byte budget (``Sensor.buffered``) bounds what the sensor *knows* it holds.
This guard is the backstop for everything else (allocator fragmentation, kernel socket
buffers charged to the container, library internals): about once per second it reads the
container's memory usage and

* above ``refuse`` (70 % of the limit) new connections are refused (slow reject);
* above ``shed`` (85 %) the connections holding the most buffered bytes are aborted.

Usage is the cgroup v2 ``memory.current`` minus reclaimable page cache (``inactive_file``),
which is what ``docker stats`` shows and what the OOM killer acts on. Without cgroup v2 the
process RSS is used against the configured limit.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

_CGROUP = Path("/sys/fs/cgroup")


def _read_int(path: Path) -> int | None:
    try:
        raw = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError):
        return None
    return int(raw) if raw.isdigit() else None


def _inactive_file(stat: Path) -> int:
    try:
        with stat.open(encoding="ascii") as fh:
            for line in fh:
                key, _, value = line.partition(" ")
                if key == "inactive_file":
                    value = value.strip()
                    return int(value) if value.isdigit() else 0
    except (OSError, UnicodeDecodeError):
        pass
    return 0


def _rss() -> int | None:
    try:
        fields = Path("/proc/self/statm").read_text(encoding="ascii").split()
        return int(fields[1]) * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError, IndexError):
        return None


class MemoryGuard:
    """Samples memory usage and turns it into ``refusing`` / ``shedding`` decisions."""

    def __init__(
        self,
        fallback_limit: int,
        *,
        refuse: float = 0.70,
        shed: float = 0.85,
        cgroup: Path = _CGROUP,
    ) -> None:
        self._cgroup = cgroup
        self._use_cgroup = (cgroup / "memory.current").is_file()
        limit = _read_int(cgroup / "memory.max") if self._use_cgroup else None
        # "max" (no limit) is not an int: use the configured limit instead.
        self.limit = limit if limit and limit < 1 << 50 else fallback_limit
        self.refuse_at = int(self.limit * refuse)
        self.shed_at = int(self.limit * shed)
        self.usage = 0
        self._sampled = 0.0
        self.refusing = False
        self.peak = 0
        self.refused = 0
        self.shed_events = 0
        self.aborted = 0

    @property
    def source(self) -> str:
        return "cgroup" if self._use_cgroup else "rss"

    def read(self) -> int:
        if self._use_cgroup:
            current = _read_int(self._cgroup / "memory.current")
            if current is not None:
                return max(0, current - _inactive_file(self._cgroup / "memory.stat"))
        return _rss() or 0

    def sample(self) -> bool:
        """Update the state from a fresh reading; True when connections must be shed."""
        self.usage = self.read()
        self.peak = max(self.peak, self.usage)
        self.refusing = self.usage >= self.refuse_at
        return self.usage >= self.shed_at

    def check(self, max_age: float = 0.25) -> bool:
        """Re-sample when the last reading is older than ``max_age``; True while refusing."""
        now = time.monotonic()
        if now - self._sampled >= max_age:
            self._sampled = now
            self.sample()
        return self.refusing

    def excess(self) -> int:
        """Bytes to free to get back under the refuse threshold."""
        return max(0, self.usage - self.refuse_at)
