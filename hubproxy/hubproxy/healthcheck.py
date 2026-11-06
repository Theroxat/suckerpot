"""Container healthcheck: the local control endpoint must answer ``ok``."""

from __future__ import annotations

import http.client
import json
import sys


def check(port: int = 8000) -> bool:
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        conn.request("GET", "/status")
        resp = conn.getresponse()
        data = json.loads(resp.read(4096))
        conn.close()
    except OSError, ValueError, http.client.HTTPException:
        return False
    return resp.status == 200 and isinstance(data, dict) and data.get("ok") is True


if __name__ == "__main__":
    sys.exit(0 if check() else 1)
