"""Anti-reflection and anti-amplification gate for UDP replies.

UDP source addresses can be spoofed, so a reply is only ever sent when ALL of these hold:

* the source address is a plausible public unicast address (no private, bogon, multicast,
  broadcast, link-local, unspecified, reserved range; not one of our own addresses; port > 0);
* the per-source reply bucket has a token (default 2/s, burst 5);
* the global reply bucket and the global byte bucket allow it;
* the reply is not larger than the datagram it answers (enforced in ``sip.build_response``,
  re-checked here).
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass

from sip_sensor.config import Config
from sip_sensor.events import Buckets


def source_allowed(ip: str, port: int, cfg: Config) -> bool:
    """May we send anything to this (claimed) source?"""
    if port <= 0 or port > 65535:
        return False
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if ip in cfg.own_ips or str(addr) in cfg.own_ips:
        return False
    if addr.is_unspecified or addr.is_multicast:
        return False
    if addr.is_loopback:
        return cfg.allow_loopback
    if isinstance(addr, ipaddress.IPv4Address) and addr == ipaddress.IPv4Address("255.255.255.255"):
        return False
    if cfg.allow_private:
        return not (addr.is_link_local or addr.is_reserved)
    return addr.is_global


@dataclass
class GateStats:
    sent: int = 0
    bytes_sent: int = 0
    bytes_in: int = 0
    denied_source: int = 0
    denied_rate: int = 0
    denied_size: int = 0


class ReplyGate:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self._per_ip = Buckets(cfg.reply_per_ip_rate, cfg.reply_per_ip_burst)
        self._global = Buckets(cfg.reply_global_rate, cfg.reply_global_burst, max_keys=1)
        self._bytes = Buckets(cfg.reply_bytes_rate, cfg.reply_bytes_burst, max_keys=1)
        self.stats = GateStats()

    def source_ok(self, ip: str, port: int) -> bool:
        if source_allowed(ip, port, self.cfg):
            return True
        self.stats.denied_source += 1
        return False

    def permit(
        self, ip: str, port: int, request_size: int, reply_size: int, now: float | None = None
    ) -> bool:
        """Final decision, called once per reply that is about to be sent. Consumes tokens."""
        now = time.monotonic() if now is None else now
        if reply_size > request_size:
            self.stats.denied_size += 1
            return False
        if not self.source_ok(ip, port):
            return False
        # Loopback (healthcheck) cannot be spoofed from outside: it skips the global buckets
        # so a spoofed flood cannot make the container unhealthy, but keeps its own bucket.
        local = ip == "::1" or ip.startswith("127.")
        if not (
            self._per_ip.allow(ip, now=now)
            and (local or self._global.allow("*", now=now))
            and (local or self._bytes.allow("*", cost=float(reply_size), now=now))
        ):
            self.stats.denied_rate += 1
            return False
        self.stats.sent += 1
        self.stats.bytes_sent += reply_size
        self.stats.bytes_in += request_size
        return True
