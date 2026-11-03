"""Settings from the environment, validated strictly: a bad value stops the process at start."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass

MAX_ALLOW = 2
MIN_PASSWORD_LEN = 16
HTTPS_PORT = 443

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_LOCAL_SUFFIXES = frozenset(
    {
        "local",
        "localhost",
        "internal",
        "lan",
        "home",
        "corp",
        "intranet",
        "private",
        "localdomain",
        "arpa",
        "test",
        "invalid",
        "example",
    }
)


class ConfigError(ValueError):
    """Raised for any invalid setting; the message never contains the password."""


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return False
    return True


def parse_allow_entry(entry: str) -> str:
    """Return the canonical ``host:443`` form of one allow-list entry or raise ConfigError."""
    raw = entry.strip().lower()
    if not raw or len(raw) > 260:
        raise ConfigError("empty or oversized allow entry")
    if raw.startswith("["):
        raise ConfigError("allow entries must be DNS names, not IP literals")
    host, sep, port = raw.rpartition(":")
    if not sep:
        host, port = raw, str(HTTPS_PORT)
    if port != str(HTTPS_PORT):
        raise ConfigError("allow entries must use port 443")
    if not host or _is_ip_literal(host):
        raise ConfigError("allow entries must be DNS names, not IP literals")
    if len(host) > 253:
        raise ConfigError("allow name too long")
    labels = host.split(".")
    if len(labels) < 2:
        raise ConfigError("allow names need at least two labels")
    if not all(_LABEL.match(label) for label in labels):
        raise ConfigError("allow name has an invalid label")
    tld = labels[-1]
    if tld.isdigit() or tld in _LOCAL_SUFFIXES:
        raise ConfigError("allow name must be a public DNS name")
    return f"{host}:{HTTPS_PORT}"


def parse_allow(value: str) -> tuple[str, ...]:
    entries = [item for item in (part.strip() for part in value.split(",")) if item]
    if not entries:
        raise ConfigError("HUBPROXY_ALLOW is empty")
    if len(entries) > MAX_ALLOW:
        raise ConfigError(f"HUBPROXY_ALLOW has more than {MAX_ALLOW} entries")
    return tuple(dict.fromkeys(parse_allow_entry(item) for item in entries))


@dataclass(frozen=True)
class Settings:
    allow: tuple[str, ...]
    password: str
    max_conns: int = 8
    bind: str = "0.0.0.0"  # noqa: S104 - internal network only, compose publishes nothing
    # When set, listeners bind only to the single address this name resolves to (the internal
    # network alias in compose) instead of ``bind``.
    bind_host: str = ""
    proxy_port: int = 8888
    control_port: int = 8000

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> Settings:
        allow = parse_allow(env.get("HUBPROXY_ALLOW", ""))
        password = env.get("HUBPROXY_PASSWORD", "")
        if len(password) < MIN_PASSWORD_LEN:
            raise ConfigError(f"HUBPROXY_PASSWORD must be at least {MIN_PASSWORD_LEN} characters")
        try:
            max_conns = int(env.get("HUBPROXY_MAX_CONNS", "8"))
        except ValueError as exc:
            raise ConfigError("HUBPROXY_MAX_CONNS must be an integer") from exc
        if not 1 <= max_conns <= 64:
            raise ConfigError("HUBPROXY_MAX_CONNS must be between 1 and 64")
        bind_host = env.get("HUBPROXY_BIND_HOST", "").strip().lower()
        if bind_host and not re.fullmatch(r"[a-z0-9.-]{1,253}", bind_host):
            raise ConfigError("HUBPROXY_BIND_HOST is not a valid host name or address")
        return cls(allow=allow, password=password, max_conns=max_conns, bind_host=bind_host)
