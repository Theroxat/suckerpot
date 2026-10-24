"""Synthetic but plausible public IPv4 addresses.

Addresses are drawn at runtime from pools of first octets that are allocated to regional
registries and hosting/ISP ranges. Reserved, private, loopback, multicast, shared-space and
documentation ranges are rejected, so nothing in the demo data looks fake in the UI and nothing
points at a documentation block. No real attacker address is hardcoded anywhere.
"""

from __future__ import annotations

import ipaddress
import random

# (first octets, weight): loosely "where attacks come from" without naming anyone.
_POOLS: list[tuple[list[int], int]] = [
    ([36, 39, 42, 58, 59, 60, 61, 101, 106, 110, 111, 112, 113, 114, 115, 116, 117], 22),
    ([118, 119, 120, 121, 122, 123, 124, 125, 175, 180, 182, 183, 218, 219, 220, 221], 18),
    ([45, 46, 77, 78, 80, 83, 84, 85, 89, 91, 92, 93, 94, 95, 109, 141, 146, 176, 178], 22),
    ([185, 188, 193, 194, 195, 212, 213, 217, 31, 37, 62, 79, 81, 82, 86, 87, 88], 12),
    ([64, 66, 67, 68, 69, 70, 71, 72, 73, 74, 104, 134, 137, 142, 143, 147, 159, 162], 12),
    ([164, 165, 167, 170, 198, 199, 205, 206, 207, 209], 5),
    ([177, 179, 181, 186, 187, 189, 190, 191, 200, 201], 5),
    ([41, 102, 105, 154, 196, 197], 2),
    ([1, 14, 27, 49, 103, 150, 202, 203, 210, 211, 222, 223], 8),
]
_DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
_EXTRA_BAD = [ipaddress.ip_network(n) for n in ("100.64.0.0/10", "198.18.0.0/15", "192.88.99.0/24")]


def is_acceptable(ip: str) -> bool:
    """True for a global unicast IPv4 outside every documentation or special-use block."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    if not addr.is_global or addr.is_multicast:
        return False
    return not any(addr in net for net in _DOC_NETS + _EXTRA_BAD)


def random_public_ip(rng: random.Random) -> str:
    octets_pool = [p[0] for p in _POOLS]
    weights = [p[1] for p in _POOLS]
    while True:
        first = rng.choice(rng.choices(octets_pool, weights)[0])
        ip = f"{first}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        if is_acceptable(ip):
            return ip


def random_src_port(rng: random.Random) -> int:
    if rng.random() < 0.7:
        return rng.randint(32768, 60999)
    return rng.randint(1024, 65535)
