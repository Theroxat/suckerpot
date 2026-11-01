"""Blinding of URLs and domain names (spec section 5.6).

``value_b = sha256("spn/1|" + kind + "|" + canonical(value))`` in lowercase hex. Canonical forms
are strict and deterministic: a value that cannot be canonicalised raises ``ValueError``.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re

from .enums import PROTOCOL

_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]{0,15}$")
_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")
_FORBIDDEN = re.compile(r"[\x00-\x20\x7f]")
DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21}
MAX_URL = 2048


def canonical_host(host: str) -> str:
    """Lowercase IDNA host name, or a normalised IP literal. Raises ValueError."""
    host = host.strip()
    if host.startswith("[") and host.endswith("]"):
        return "[" + str(ipaddress.IPv6Address(host[1:-1])) + "]"
    try:
        return str(ipaddress.IPv4Address(host))
    except ValueError:
        pass
    name = canonical_domain(host)
    return name


def canonical_domain(value: str) -> str:
    """Lowercase IDNA (IDNA 2003 codec of the standard library), no trailing dot."""
    name = value.strip().lower()
    if name.endswith("."):
        name = name[:-1]
    if not name or len(name) > 253 or _FORBIDDEN.search(name):
        raise ValueError("invalid domain")
    try:
        ascii_name = name.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid domain") from exc
    ascii_name = ascii_name.lower()
    labels = ascii_name.split(".")
    if len(ascii_name) > 253 or not all(_LABEL.fullmatch(label) for label in labels):
        raise ValueError("invalid domain")
    try:
        ipaddress.ip_address(ascii_name)
    except ValueError:
        return ascii_name
    raise ValueError("an address is not a domain")


def canonical_url(raw: str) -> str:
    """Scheme and host lowercased, IDNA host, default port removed, fragment removed.

    Path and query are kept byte for byte (an empty path stays empty). User information is
    refused, as are spaces and control characters.
    """
    if not raw or len(raw) > MAX_URL or _FORBIDDEN.search(raw):
        raise ValueError("invalid url")
    raw = raw.split("#", 1)[0]
    scheme, sep, rest = raw.partition("://")
    scheme = scheme.lower()
    if not sep or not _SCHEME.fullmatch(scheme):
        raise ValueError("invalid url")
    end = len(rest)
    for ch in "/?":
        pos = rest.find(ch)
        if pos != -1:
            end = min(end, pos)
    authority, tail = rest[:end], rest[end:]
    if not authority or "@" in authority:
        raise ValueError("invalid url")
    port: int | None = None
    if authority.startswith("["):
        close = authority.find("]")
        if close == -1:
            raise ValueError("invalid url")
        host_part, port_part = authority[: close + 1], authority[close + 1 :]
        if port_part:
            if not port_part.startswith(":"):
                raise ValueError("invalid url")
            port_part = port_part[1:]
        else:
            port_part = ""
    else:
        host_part, _, port_part = authority.partition(":")
    if port_part:
        if not re.fullmatch(r"[0-9]{1,5}", port_part):
            raise ValueError("invalid url")
        port = int(port_part)
        if not 1 <= port <= 65535:
            raise ValueError("invalid url")
    host = canonical_host(host_part)
    if port is not None and port == DEFAULT_PORTS.get(scheme):
        port = None
    return f"{scheme}://{host}{f':{port}' if port is not None else ''}{tail}"


def url_host(canonical: str) -> str:
    """The host (without port) of a canonical URL; IPv6 keeps its brackets."""
    rest = canonical.partition("://")[2]
    end = len(rest)
    for ch in "/?":
        pos = rest.find(ch)
        if pos != -1:
            end = min(end, pos)
    authority = rest[:end]
    if authority.startswith("["):
        return authority[: authority.find("]") + 1]
    return authority.partition(":")[0]


def blind_canonical(kind: str, canonical: str) -> str:
    if kind not in ("url", "domain"):
        raise ValueError("only urls and domains are blinded")
    return hashlib.sha256(f"{PROTOCOL}|{kind}|{canonical}".encode()).hexdigest()


def blind_url(raw: str) -> str:
    return blind_canonical("url", canonical_url(raw))


def blind_domain(raw: str) -> str:
    return blind_canonical("domain", canonical_domain(raw))


def blind(kind: str, value: str) -> str:
    """Canonicalise and blind a url or a domain."""
    if kind == "url":
        return blind_url(value)
    if kind == "domain":
        return blind_domain(value)
    raise ValueError("only urls and domains are blinded")


def verify_reveal(kind: str, value: str, value_b: str) -> str | None:
    """The canonical value when ``value`` blinds to ``value_b``, else None."""
    try:
        canonical = canonical_url(value) if kind == "url" else canonical_domain(value)
    except ValueError:
        return None
    if kind not in ("url", "domain"):
        return None
    return canonical if blind_canonical(kind, canonical) == value_b else None
