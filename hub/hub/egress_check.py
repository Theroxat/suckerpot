"""Start-up check for tunnel mode: a proxy is set, so there must be no direct route out.

The egress network is meant to be ``internal: true`` with the proxy as its only uplink. If a proxy
variable is set and the container still has a default route, something else could reach the
internet directly (or a client could bypass the proxy), so the worker refuses to start. The check
only reads the routing table; it opens no connection. It logs a constant code, never an address.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

ROUTE_FILE: Final = Path("/proc/net/route")
CODE: Final = "egress_default_route"


def has_default_route(route_file: Path = ROUTE_FILE) -> bool:
    """True when the IPv4 routing table has a default route (destination and mask all zero)."""
    try:
        lines = route_file.read_text(encoding="ascii").splitlines()[1:]
    except OSError:
        return False  # no table to read (not Linux): nothing to refuse on
    for line in lines:
        fields = line.split()
        if len(fields) >= 8 and fields[1] == "00000000" and fields[7] == "00000000":
            return True
    return False


def egress_ok(proxy_url: str | None, route_file: Path = ROUTE_FILE) -> bool:
    """False only when a proxy is configured and a default route exists."""
    return not (proxy_url and has_default_route(route_file))
