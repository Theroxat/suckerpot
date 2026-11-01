"""Settings of the network worker (design M29 section 9.1).

``NETWORK_ENABLED`` is the master switch and defaults to off. The hub address and key ship empty:
without both the network cannot be joined. Nothing here is a secret (the hub key is public).
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from suckerpot_netproto import sign

TRUE_VALUES = {"1", "true", "yes", "on"}


@dataclass(frozen=True, slots=True)
class NetworkSettings:
    enabled: bool = False
    hub_url: str = ""
    hub_key: str = ""
    interval_s: int = 900
    delay_min_h: float = 2.0
    delay_max_h: float = 20.0
    max_sources: int = 5000

    @property
    def hub_configured(self) -> bool:
        return bool(self.hub_url and self.hub_key)

    @property
    def hub_host(self) -> str:
        return urlsplit(self.hub_url).hostname or ""

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> NetworkSettings:
        e = os.environ if env is None else env
        url = e.get("NETWORK_HUB_URL", "").strip().rstrip("/")
        key = e.get("NETWORK_HUB_KEY", "").strip()
        settings = cls(
            enabled=e.get("NETWORK_ENABLED", "false").strip().lower() in TRUE_VALUES,
            hub_url=url,
            hub_key=key,
            interval_s=_int(e, "NETWORK_INTERVAL_S", 900, 30, 86_400),
            delay_min_h=float(_int(e, "NETWORK_SUBMIT_DELAY_MIN_H", 2, 0, 23)),
            delay_max_h=float(_int(e, "NETWORK_SUBMIT_DELAY_MAX_H", 20, 1, 23)),
            max_sources=_int(e, "NETWORK_MAX_SOURCES", 5000, 1, 5000),
        )
        if settings.delay_min_h >= settings.delay_max_h:
            raise ValueError("NETWORK_SUBMIT_DELAY_MIN_H must be below NETWORK_SUBMIT_DELAY_MAX_H")
        if bool(url) != bool(key):
            raise ValueError("NETWORK_HUB_URL and NETWORK_HUB_KEY must be set together")
        if url:
            parts = urlsplit(url)
            if parts.scheme != "https" or not parts.hostname or parts.path or parts.query:
                raise ValueError("NETWORK_HUB_URL must be an https URL without a path")
            if parts.username or parts.password or parts.fragment:
                raise ValueError("NETWORK_HUB_URL must not hold credentials")
            try:
                sign.parse_node_key(key)
            except ValueError:
                raise ValueError("NETWORK_HUB_KEY must be a base64url public key") from None
        return settings


def _int(env: Mapping[str, str], name: str, default: int, low: int, high: int) -> int:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer") from None
    if not low <= value <= high:
        raise ValueError(f"{name} must be between {low} and {high}")
    return value
