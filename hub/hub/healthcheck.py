"""Container healthcheck: GET /healthz on the loopback interface."""

from __future__ import annotations

import sys
import urllib.request


def main() -> int:
    try:
        with urllib.request.urlopen("http://127.0.0.1:8080/healthz", timeout=4) as resp:
            return 0 if resp.status == 200 else 1
    except Exception:
        return 1


if __name__ == "__main__":
    sys.exit(main())
