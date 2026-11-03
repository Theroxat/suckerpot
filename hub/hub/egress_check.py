"""Start-up check for tunnel mode: a proxy is set, so there must be no direct route out.

The egress network is meant to be ``internal: true`` with the proxy as its only uplink. If a proxy
variable is set and the container still has a default route (IPv4 or IPv6), something else could
reach the internet directly, so the worker and the online admin commands refuse to run. It fails
closed: with a proxy set and no readable IPv4 routing table, the answer is no. The check only
reads the routing tables; it opens no connection. It logs a constant code, never an address.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

ROUTE_FILE: Final = Path("/proc/net/route")
ROUTE6_FILE: Final = Path("/proc/net/ipv6_route")
CODE: Final = "egress_default_route"
RTF_REJECT: Final = 0x200


def _lines(path: Path) -> list[str] | None:
    try:
        return path.read_text(encoding="ascii").splitlines()
    except OSError:
        return None


def has_default_route(route_file: Path | None = None) -> bool | None:
    """True when the IPv4 table has a default route (destination and mask all zero), ``None``
    when the table cannot be read."""
    lines = _lines(route_file or ROUTE_FILE)
    if lines is None:
        return None
    for line in lines[1:]:
        fields = line.split()
        if len(fields) >= 8 and fields[1] == "00000000" and fields[7] == "00000000":
            return True
    return False


def has_default_route6(route_file: Path | None = None) -> bool:
    """True when the IPv6 table has a real default route. A missing file (IPv6 off) has none;
    the kernel's reject entries do not count."""
    lines = _lines(route_file or ROUTE6_FILE) or []
    for line in lines:
        fields = line.split()
        if len(fields) >= 10 and fields[0] == "0" * 32 and fields[1] == "00":
            if not int(fields[8], 16) & RTF_REJECT:
                return True
    return False


def egress_ok(
    proxy_url: str | None, route_file: Path | None = None, route6_file: Path | None = None
) -> bool:
    """False when a proxy is configured and a default route exists or the table is unreadable."""
    if not proxy_url:
        return True
    v4 = has_default_route(route_file)
    if v4 is None or v4:
        return False
    return not has_default_route6(route6_file)
