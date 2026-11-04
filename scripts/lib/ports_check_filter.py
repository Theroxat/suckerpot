"""Counts the public source addresses per sensor. Standard library only.

Used by scripts/lib/ports-check.sh, which runs it INSIDE the ingest container (like
status_render.py): `python -I -c "$(cat ports_check_filter.py)"`. It reads "sensor address" lines
on stdin and prints "sensor count" lines (count = distinct public addresses). It never prints an
address. Anything that does not parse is skipped (fail closed).
"""

import ipaddress
import sys


def is_public(text: str) -> bool:
    """True for a routable unicast address of the internet.

    RFC 1918, loopback, link-local, CGNAT, documentation, multicast and the other special ranges
    are all handled by the standard library's `is_global`.
    """
    try:
        ip = ipaddress.ip_address(text.strip())
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return bool(ip.is_global and not ip.is_multicast)


def count_public(lines: list[str]) -> dict[str, int]:
    """Maps each sensor to the number of distinct public addresses seen on it."""
    seen: dict[str, set[str]] = {}
    for line in lines:
        parts = line.split()
        if len(parts) != 2 or not parts[0].replace("-", "").replace("_", "").isalnum():
            continue
        if is_public(parts[1]):
            seen.setdefault(parts[0], set()).add(parts[1])
    return {sensor: len(addrs) for sensor, addrs in seen.items()}


def main() -> int:
    for sensor, n in sorted(count_public(sys.stdin.read().splitlines()).items()):
        print(sensor, n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
