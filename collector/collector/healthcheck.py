"""Container healthcheck: exit 0 if the heartbeat file is fresh."""

from __future__ import annotations

import sys

from collector.config import CollectorSettings
from collector.status import MAX_HEARTBEAT_AGE_S, heartbeat_age


def main() -> int:
    age = heartbeat_age(CollectorSettings.from_env().heartbeat_path)
    return 0 if age is not None and age < MAX_HEARTBEAT_AGE_S else 1


if __name__ == "__main__":
    sys.exit(main())
