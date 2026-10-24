"""Container healthcheck: exit 0 if the heartbeat file is fresh."""

from __future__ import annotations

import sys
import time

from ingest.config import Settings

MAX_AGE_S = 30.0


def is_healthy(path_age: float | None) -> bool:
    return path_age is not None and path_age < MAX_AGE_S


def main() -> int:
    path = Settings.from_env().heartbeat_path
    try:
        age: float | None = time.time() - path.stat().st_mtime
    except OSError:
        age = None
    return 0 if is_healthy(age) else 1


if __name__ == "__main__":
    sys.exit(main())
