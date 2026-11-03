"""Egress settings, read from the environment."""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from ipaddress import IPv4Network, IPv6Network
from urllib.parse import urlsplit

DEFAULT_PROXY_URL = "http://vpn:8888"
DEFAULT_CONTROL_URL = "http://vpn:8000"
DEFAULT_ECHO_URLS = ("https://api.ipify.org", "https://icanhazip.com")
DEFAULT_INTERVAL_S = 300
PROXY_USER = "egress"
MODE_VPN = "vpn"
MODE_DIRECT = "direct"
HUBPROXY_PORT = 443  # the only port the direct-mode proxy tunnels to

type Network = IPv4Network | IPv6Network


def _split(value: str) -> list[str]:
    return [p.strip() for p in value.split(",") if p.strip()]


def derive_allowed_cidrs(endpoint_ip: str) -> tuple[Network, ...]:
    """The /24 around the WireGuard endpoint (IPv4 only). Empty when there is no endpoint."""
    if not endpoint_ip.strip():
        return ()
    addr = ipaddress.ip_address(endpoint_ip.strip())
    if addr.version != 4:
        return ()
    return (ipaddress.ip_network(f"{addr}/24", strict=False),)


def parse_asns(value: str) -> frozenset[int]:
    """A comma list of AS numbers (``AS64500`` or ``64500``). Anything else is ignored."""
    out: set[int] = set()
    for part in _split(value):
        digits = part.upper().removeprefix("AS")
        if digits.isdigit() and 0 < int(digits) < 2**32:
            out.add(int(digits))
    return frozenset(out)


def _host_of(url: str) -> str | None:
    """The lower-cased host of an https URL, or None when there is none."""
    try:
        host = urlsplit(url.strip()).hostname
    except ValueError:
        return None
    return host.lower().rstrip(".") if host else None


def scope_from_env(e: Mapping[str, str]) -> frozenset[str]:
    """Direct mode: the hub host and the feed host, from their URLs. Nothing else."""
    hosts = (_host_of(e.get("NETWORK_HUB_URL", "")), _host_of(e.get("NETWORK_FEED_URL", "")))
    return frozenset(h for h in hosts if h)


@dataclass(frozen=True)
class EgressSettings:
    proxy_url: str = DEFAULT_PROXY_URL
    proxy_user: str = PROXY_USER
    proxy_password: str = field(default="", repr=False)
    control_url: str = DEFAULT_CONTROL_URL
    echo_urls: tuple[str, ...] = DEFAULT_ECHO_URLS
    allowed_cidrs: tuple[Network, ...] = ()
    check_interval_s: int = DEFAULT_INTERVAL_S
    deny_asns: frozenset[int] = frozenset()  # exit ASNs that close the gate (EGRESS_DENY_ASNS)
    # EGRESS_MODE (M32): "vpn" (default, unchanged) or "direct" (hubproxy, host scope only).
    mode: str = MODE_VPN
    scope_hosts: frozenset[str] = frozenset()  # direct mode: the only hosts the gate opens for

    @property
    def direct(self) -> bool:
        return self.mode == MODE_DIRECT

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> EgressSettings:
        e = os.environ if env is None else env
        explicit = _split(e.get("EGRESS_ALLOWED_CIDRS", ""))
        if explicit:
            cidrs: tuple[Network, ...] = tuple(
                ipaddress.ip_network(c, strict=False) for c in explicit
            )
        else:
            cidrs = derive_allowed_cidrs(e.get("VPN_WG_ENDPOINT_IP", ""))
        echo = tuple(_split(e.get("EGRESS_ECHO_URLS", ""))) or DEFAULT_ECHO_URLS
        try:
            interval = int(e.get("EGRESS_CHECK_INTERVAL_S", "") or DEFAULT_INTERVAL_S)
        except ValueError:
            interval = DEFAULT_INTERVAL_S
        mode = (e.get("EGRESS_MODE", "") or MODE_VPN).strip().lower()
        if mode not in (MODE_VPN, MODE_DIRECT):
            raise ValueError("EGRESS_MODE must be 'vpn' or 'direct'")
        return cls(
            proxy_url=e.get("EGRESS_PROXY_URL", "") or DEFAULT_PROXY_URL,
            proxy_password=e.get("EGRESS_PROXY_PASSWORD", ""),
            control_url=(e.get("EGRESS_CONTROL_URL", "") or DEFAULT_CONTROL_URL).rstrip("/"),
            echo_urls=echo,
            allowed_cidrs=cidrs,
            check_interval_s=max(10, interval),
            deny_asns=parse_asns(e.get("EGRESS_DENY_ASNS", "")),
            mode=mode,
            scope_hosts=scope_from_env(e) if mode == MODE_DIRECT else frozenset(),
        )
