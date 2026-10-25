"""Process memory usage and limit, for the memory guard.

The container's cgroup v2 files are used when present (``memory.current`` minus the inactive
page cache, like ``docker stats``; ``memory.max``). Without them, the resident set size of the
process is compared with a configured limit. Only small, fixed files are read.
"""

from __future__ import annotations

import contextlib
from pathlib import Path

_CGROUP = Path("/sys/fs/cgroup")
_PROC_STATUS = Path("/proc/self/status")
_MAX_READ = 64 * 1024


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="ascii", errors="replace")[:_MAX_READ]  # small kernel files
    except OSError:
        return None


class MemoryProbe:
    def __init__(
        self,
        fallback_limit: int,
        *,
        cgroup: Path = _CGROUP,
        proc_status: Path = _PROC_STATUS,
    ) -> None:
        self._fallback = max(1, fallback_limit)
        self._cgroup = cgroup
        self._status = proc_status
        self._limit: int | None = None

    def limit(self) -> int:
        """The memory limit in bytes (cgroup ``memory.max``, else the configured fallback)."""
        if self._limit is None:
            limit = self._fallback
            raw = _read(self._cgroup / "memory.max")
            if raw is not None and raw.strip().isdigit():
                limit = min(int(raw.strip()), 1 << 50) or self._fallback
            self._limit = limit
        return self._limit

    def usage(self) -> int:
        """Bytes in use: cgroup memory without inactive page cache, else the process RSS."""
        raw = _read(self._cgroup / "memory.current")
        if raw is not None and raw.strip().isdigit():
            used = int(raw.strip())
            stat = _read(self._cgroup / "memory.stat") or ""
            for line in stat.splitlines():
                key, _, value = line.partition(" ")
                if key == "inactive_file" and value.strip().isdigit():
                    used -= int(value.strip())
                    break
            return max(0, used)
        return self.rss()

    def rss(self) -> int:
        for line in (_read(self._status) or "").splitlines():
            if line.startswith("VmRSS:"):
                with contextlib.suppress(IndexError, ValueError):
                    return int(line.split()[1]) * 1024
        return 0
