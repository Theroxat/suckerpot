"""Indicator extraction: URLs, hosts and file hashes found in events we already store.

Passive by design. Nothing here opens a connection, resolves a name or runs anything: the
functions look at strings that sensors recorded and return normalised values.

Attacker-controlled text is only scanned with bounded, linear-time string primitives (``find``,
slicing, character sets, ``ipaddress``). There is no regular expression anywhere, every scanned
string is capped, and the number of strings, tokens and results per event is capped too, so no
input can make this slow or large.

What is kept
------------
* ``url``     a normalised URL (credentials removed, host lower-cased, length capped);
* ``domain``  the host of a URL, or a bare host after a network tool (``wget``, ``nc``, ...);
* ``ip``      a global IPv4/IPv6 address from a URL, ``/dev/tcp/...`` or a bare token;
* ``hash``    an md5/sha1/sha256 from an explicit data key, or a bare sha256 in a command.

What is dropped: private, loopback, link-local, reserved and documentation addresses, hosts
without a dot, reserved names (``localhost``, ``.local``, ``.internal``, ...), the documentation
domains (``example.com``, ``.test``, ...) and anything in ``INDICATORS_IGNORE`` (the owner's
own names and addresses). ``INDICATORS_KEEP_DOCUMENTATION=true`` keeps documentation addresses
and domains, which is how the demo data shows up.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from functools import lru_cache
from typing import Any
from urllib.parse import urlsplit

log = logging.getLogger(__name__)

MAX_FIELD = 4096  # characters scanned per string
MAX_STRINGS = 32  # strings scanned per event
MAX_URLS_PER_STRING = 8
MAX_TOKENS = 256  # tokens examined per command-like string
MAX_HITS_PER_EVENT = 16
MAX_URL_SCAN = 1024  # characters examined after "://"
MAX_URL = 512  # stored URL length
MAX_HOST = 253
MAX_DEPTH = 2

URL_SCHEMES = ("https", "sftp", "tftp", "http", "ftps", "ftp", "ldaps", "ldap", "rmi")
# ^ longest suffix first. ldap/ldaps/rmi are there for JNDI-style payloads (log4shell).
DEFAULT_PORTS = {
    "http": 80, "https": 443, "ftp": 21, "ftps": 990, "sftp": 22, "tftp": 69,
    "ldap": 389, "ldaps": 636, "rmi": 1099,
}  # fmt: skip
_URL_STOP = frozenset(" \t\r\n\x0b\x0c\"'`\\|;<>()[]{}^")
_URL_TRAIL = ".,;:!?"
_TOKEN_SEP = str.maketrans(dict.fromkeys(";|&()`$<>=\"'{}[]\t\n\r\x0b\x0c,\\", " "))
_HOST_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-.")
_HEX = frozenset("0123456789abcdef")
_DIGITS = frozenset("0123456789")

# Keys whose string values get the full token treatment (bare hosts, bare hashes). Every other
# string is only scanned for ``scheme://`` URLs, which keeps header values such as ``Host``
# (our own address) out of the results.
_COMMAND_KEYS = frozenset({"input", "command", "body_preview", "payload", "statement", "script"})
_OWN_HOST_KEYS = frozenset({"host", "hostname", "server_name", "servername", "sni"})
# Fields the attacker or a proxy fills with our own name or an unrelated page: never indicators.
_SKIP_KEYS = _OWN_HOST_KEYS | frozenset(
    {
        "password_hash", "nt_response_preview", "referer", "referrer", "origin", "forwarded",
        "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-server",
        "x-real-ip", "x-original-url", "x-original-host", "via",
    }
)  # fmt: skip
_HASH_KEYS = {"sha256": 64, "sha1": 40, "md5": 32, "hash": 0, "sha256_hex": 64}
_EMPTY_HASHES = frozenset(
    {
        "d41d8cd98f00b204e9800998ecf8427e",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }
)

_DOWNLOADERS = frozenset({"wget", "curl", "tftp", "ftpget", "fetch", "lwp-download"})
_NET_TOOLS = _DOWNLOADERS | frozenset(
    {"nc", "ncat", "netcat", "ping", "ssh", "telnet", "scp", "ftp", "socat", "nslookup", "dig"}
    | {"host", "rsync", "traceroute", "mtr"}
)
_RESERVED_TLDS = frozenset(
    {"local", "localhost", "internal", "lan", "home", "corp", "intranet", "private", "arpa"}
)
_DOC_TLDS = frozenset({"test", "invalid", "example"})
_DOC_DOMAINS = ("example.com", "example.net", "example.org")
# Words that end like a domain but are file names in a command: only used for bare tokens.
_FILE_EXTENSIONS = frozenset(
    {
        "sh", "py", "pl", "so", "txt", "conf", "cfg", "log", "php", "js", "exe", "bin", "elf",
        "dll", "tar", "gz", "tgz", "zip", "rar", "md", "rs", "cc", "c", "h", "o", "a", "ko",
        "json", "xml", "yml", "yaml", "ini", "db", "sql", "bak", "tmp", "out", "pid", "lock",
        "jpg", "png", "gif", "html", "htm", "css", "pem", "key", "crt", "pub", "service",
        "mips", "mpsl", "arm", "arm5", "arm6", "arm7", "x86", "ppc", "sparc", "m68k", "sh4",
    }
)  # fmt: skip
_DOC_NETS = tuple(
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)
_ROLE_RANK = {"contacted_host": 0, "download_host": 1}


def _flag(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True, slots=True)
class IndicatorSettings:
    enabled: bool = True
    ignore: tuple[str, ...] = ()
    keep_documentation: bool = False
    link_cap: int = 500

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> IndicatorSettings:
        e = os.environ if env is None else env
        raw = e.get("INDICATORS_IGNORE", "")
        names = [p.strip().lower().strip(".") for p in raw.split(",") if p.strip()]
        # The names this deployment answers to are never attack infrastructure.
        names += [h.strip().lower().strip(".") for h in e.get("API_ALLOWED_HOSTS", "").split(",")]
        for origin in e.get("API_ALLOWED_ORIGINS", "").split(","):
            try:
                names.append((urlsplit(origin.strip()).hostname or "").lower())
            except ValueError:
                continue
        ignore = tuple(dict.fromkeys(n for n in names if n and n != "*"))[:128]
        return cls(
            enabled=_flag(e.get("INDICATORS_ENABLED", "true")),
            ignore=ignore,
            keep_documentation=_flag(e.get("INDICATORS_KEEP_DOCUMENTATION", "false")),
            link_cap=min(5000, max(1, int(e.get("INDICATORS_LINK_CAP", "500")))),
        )


@dataclass(frozen=True, slots=True)
class Hit:
    type: str  # url | domain | ip | hash
    value: str
    role: str  # download_host | contacted_host | hash
    host: str | None = None
    trusted: bool = False  # a hash computed by a sensor (download or upload digest)
    demo: bool = False  # the event came from the demo generator


# ---- normalisation -----------------------------------------------------------------------


def is_documentation_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(addr in net for net in _DOC_NETS if net.version == addr.version)


def _is_documentation_domain(host: str) -> bool:
    tld = host.rsplit(".", 1)[-1]
    return tld in _DOC_TLDS or any(host == d or host.endswith("." + d) for d in _DOC_DOMAINS)


@lru_cache(maxsize=256)
def _network(entry: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """``entry`` as an address or CIDR block, or None when it is a host name."""
    try:
        return ipaddress.ip_network(entry.strip("[]"), strict=False)
    except ValueError:
        return None


def _ignored(host: str, ignore: Sequence[str]) -> bool:
    """Host names (and their subdomains), addresses and CIDR blocks from ``INDICATORS_IGNORE``."""
    addr = parse_ip(host)
    for entry in ignore:
        net = _network(entry)
        if net is not None:
            if addr is not None and addr.version == net.version and addr in net:
                return True
        elif host == entry or host.endswith("." + entry):
            return True
    return False


_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")
_TEREDO = ipaddress.ip_network("2001::/32")
_SIX_TO_FOUR = ipaddress.ip_network("2002::/16")


def unwrap_ipv6(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The IPv4 address hidden in a mapped, NAT64, Teredo or 6to4 address, so it is checked as IPv4.

    Local-use NAT64 (``64:ff9b:1::/48``) carries no fixed embedding: it is dropped (None).
    """
    if not isinstance(addr, ipaddress.IPv6Address):
        return addr
    if addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    if addr in _NAT64:
        return ipaddress.IPv4Address(addr.packed[-4:])
    if addr in _NAT64_LOCAL:
        return None
    if addr in _TEREDO and addr.teredo is not None:
        return addr.teredo[1]
    if addr in _SIX_TO_FOUR and addr.sixtofour is not None:
        return addr.sixtofour
    return addr


def parse_ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """An IP address from dotted-quad IPv4, bracket-free IPv6 or a single decimal/hex integer."""
    if not text or len(text) > 45 or "%" in text:  # a zone id (fe80::1%eth0) is never public
        return None
    try:
        if ":" in text:
            return ipaddress.IPv6Address(text)
        if text[0] in _DIGITS and "." in text:
            return ipaddress.IPv4Address(text)
        if text.isdigit() and len(text) <= 10:
            n = int(text)
            return ipaddress.IPv4Address(n) if n < 2**32 else None
        if text.startswith("0x") and 2 < len(text) <= 10:
            return ipaddress.IPv4Address(int(text, 16))
    except ValueError:
        return None
    return None


def normalize_host(
    raw: str, settings: IndicatorSettings, *, bare: bool = False
) -> tuple[str, str] | None:
    """``(kind, value)`` for a usable public host, or None. Never resolves anything."""
    host = raw.strip().lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    host = host.rstrip(".")
    if not host or len(host) > MAX_HOST:
        return None
    keep_doc = settings.keep_documentation
    addr = parse_ip(host)
    if addr is not None:
        unwrapped = unwrap_ipv6(addr)
        if unwrapped is None:
            return None
        addr = unwrapped
        value = str(addr)
        if _ignored(value, settings.ignore):
            return None
        if addr.is_global or (keep_doc and is_documentation_ip(addr)):
            return "ip", value
        return None
    if not set(host) <= _HOST_CHARS:
        return None
    labels = host.split(".")
    if len(labels) < 2 or any(not 0 < len(x) <= 63 for x in labels):
        return None
    if any(x[0] == "-" or x[-1] == "-" for x in labels):
        return None
    tld = labels[-1]
    if not (tld.isalpha() or (tld.startswith("xn--") and len(tld) > 4)) or not 2 <= len(tld) <= 24:
        return None
    if tld in _RESERVED_TLDS or (bare and tld in _FILE_EXTENSIONS):
        return None
    if _is_documentation_domain(host) and not keep_doc:
        return None
    if _ignored(host, settings.ignore):
        return None
    return "domain", host


def normalize_url(raw: str, settings: IndicatorSettings) -> tuple[str, str, str] | None:
    """``(url, host_kind, host_value)``: credentials and fragment removed, bounded length."""
    scheme = ""
    low = raw[:12].lower()
    for candidate in URL_SCHEMES:
        if low.startswith(candidate + "://"):
            scheme = candidate
            break
    if not scheme:
        return None
    rest = raw[len(scheme) + 3 :]
    cut = len(rest)
    for ch in "/?#":
        i = rest.find(ch)
        if 0 <= i < cut:
            cut = i
    authority, tail = rest[:cut], rest[cut:]
    authority = authority[authority.rfind("@") + 1 :]  # drop user:password@
    if authority.startswith("["):
        close = authority.find("]")
        if close < 0:
            return None
        host_part, port_part = authority[: close + 1], authority[close + 1 :]
        port_part = port_part[1:] if port_part.startswith(":") else port_part
        if port_part and not port_part.isdigit():
            return None
    else:
        host_part, _, port_part = authority.partition(":")
    port = ""
    if port_part:
        if not port_part.isdigit() or not 0 < int(port_part) < 65536:
            return None
        if int(port_part) != DEFAULT_PORTS[scheme]:
            port = ":" + str(int(port_part))
    norm = normalize_host(host_part, settings)
    if norm is None:
        return None
    kind, host = norm
    shown = f"[{host}]" if kind == "ip" and ":" in host else host
    tail = "".join(c for c in tail.split("#", 1)[0][:MAX_URL] if 0x21 <= ord(c) < 0x7F)
    url = f"{scheme}://{shown}{port}{tail or '/'}"[:MAX_URL]
    return url, kind, host


def normalize_hash(raw: str, expected_len: int = 0) -> str | None:
    h = raw.strip().lower()
    if len(h) not in (32, 40, 64) or (expected_len and len(h) != expected_len):
        return None
    if not set(h) <= _HEX or h in _EMPTY_HASHES or len(set(h)) < 4:
        return None
    return h


# ---- bounded scanners -----------------------------------------------------------------------


def find_urls(text: str) -> list[str]:
    """Candidate ``scheme://...`` substrings (at most 8), found without regular expressions."""
    text = text[:MAX_FIELD]
    out: list[str] = []
    pos = 0
    while len(out) < MAX_URLS_PER_STRING:
        i = text.find("://", pos)
        if i < 0:
            break
        pos = i + 3
        start = -1
        for scheme in URL_SCHEMES:
            n = len(scheme)
            if i >= n and text[i - n : i].lower() == scheme:
                start = i - n
                break
        if start < 0:
            continue
        end = pos
        if text[end : end + 1] == "[":  # bracketed IPv6 host
            close = text.find("]", end, end + 48)
            if close > 0:
                end = close + 1
        limit = min(len(text), pos + MAX_URL_SCAN)
        while end < limit and text[end] not in _URL_STOP:
            end += 1
        candidate = text[start:end].rstrip(_URL_TRAIL)
        out.append(candidate)
        pos = max(pos, end)
    return out


def _host_from_token(token: str) -> str:
    """``user@host:port/path`` -> ``host`` (best effort, bounded)."""
    token = token[:300]
    if "://" in token:
        return ""
    token = token.split("/", 1)[0]
    token = token[token.rfind("@") + 1 :]
    if token.count(":") == 1:
        token = token.split(":", 1)[0]
    return token


def scan_command(text: str, settings: IndicatorSettings) -> list[Hit]:
    """Bare hosts after network tools, ``/dev/tcp/host/port``, bare IPv4 and sha256 tokens."""
    text = text[:MAX_FIELD]
    hits: list[Hit] = []
    # /dev/tcp/HOST/PORT and /dev/udp/HOST/PORT
    pos = 0
    for _ in range(4):
        i = text.find("/dev/", pos)
        if i < 0:
            break
        pos = i + 5
        kind = text[pos : pos + 4]
        if kind not in ("tcp/", "udp/"):
            continue
        host = text[pos + 4 : pos + 4 + 64].split("/", 1)[0]
        norm = normalize_host(host, settings, bare=True)
        if norm is not None:
            hits.append(Hit(norm[0], norm[1], "contacted_host"))
    tokens = text.translate(_TOKEN_SEP).split(None, MAX_TOKENS)[:MAX_TOKENS]
    expect = 0
    downloader = False
    for token in tokens:
        low = token.lower()
        base = low.rsplit("/", 1)[-1]
        if base in _NET_TOOLS:
            expect, downloader = 2, base in _DOWNLOADERS
            continue
        if low.startswith("-"):
            continue
        digest = normalize_hash(token, 64) if len(token) == 64 else None
        if digest is not None:
            hits.append(Hit("hash", digest, "hash"))
            continue
        candidate = _host_from_token(low)
        if expect > 0 and candidate:
            norm = normalize_host(candidate, settings, bare=True)
            if norm is not None:
                role = "download_host" if downloader else "contacted_host"
                hits.append(Hit(norm[0], norm[1], role))
                expect = 0
                continue
            expect -= 1
        elif candidate.count(".") == 3 and candidate[0] in _DIGITS and candidate[-1] in _DIGITS:
            norm = normalize_host(candidate, settings, bare=True)
            if norm is not None and norm[0] == "ip":
                hits.append(Hit("ip", norm[1], "contacted_host"))
    return hits


def _iter_strings(data: Mapping[str, Any], budget: list[int]) -> Iterator[tuple[str, str]]:
    """``(innermost key, string)`` pairs from ``data``, at most ``MAX_STRINGS`` in total."""

    def walk(key: str, value: Any, depth: int) -> Iterator[tuple[str, str]]:
        if budget[0] <= 0:
            return
        if isinstance(value, str):
            budget[0] -= 1
            yield key, value
        elif depth < MAX_DEPTH and isinstance(value, Mapping):
            for k, v in list(value.items())[:MAX_STRINGS]:
                if str(k).lower() not in _SKIP_KEYS:
                    yield from walk(str(k).lower(), v, depth + 1)
        elif depth < MAX_DEPTH and isinstance(value, list):
            for v in value[:MAX_STRINGS]:
                yield from walk(key, v, depth + 1)

    for k, v in list(data.items())[:MAX_STRINGS]:
        if str(k).lower() in _SKIP_KEYS:
            continue
        yield from walk(str(k).lower(), v, 0)


def own_hosts(data: Mapping[str, Any]) -> frozenset[str]:
    """The name the attacker connected to (Host header, SNI): ours, not theirs."""
    found: set[str] = set()
    sources: list[Mapping[str, Any]] = [data]
    headers = data.get("headers")
    if isinstance(headers, Mapping):
        sources.append(headers)
    for src in sources:
        for k, v in list(src.items())[:MAX_STRINGS]:
            if str(k).lower() in _OWN_HOST_KEYS and isinstance(v, str):
                h = v.strip().lower()[:MAX_HOST]
                if h.count(":") == 1:
                    h = h.split(":", 1)[0]
                found.add(h.strip("[]"))
    return frozenset(found)


class IndicatorExtractor:
    def __init__(self, settings: IndicatorSettings | None = None) -> None:
        self.settings = settings or IndicatorSettings()

    def extract(self, event_type: str, data: Mapping[str, Any]) -> list[Hit]:
        """Indicators of one event: at most ``MAX_HITS_PER_EVENT``, deduplicated."""
        s = self.settings
        if not s.enabled:
            return []
        # Demo events (data.demo is true) keep documentation values and are flagged, so they are
        # shown but never sent to an intel service.
        demo = data.get("demo") is True
        if demo and not s.keep_documentation:
            s = replace(s, keep_documentation=True)
        own = own_hosts(data)
        out: dict[tuple[str, str], Hit] = {}

        def add(hit: Hit) -> None:
            if hit.value in own or (hit.host is not None and hit.host in own):
                return
            if demo:
                hit = replace(hit, demo=True)
            key = (hit.type, hit.value)
            old = out.get(key)
            if old is None:
                if len(out) < MAX_HITS_PER_EVENT:
                    out[key] = hit
            elif _ROLE_RANK.get(hit.role, 0) > _ROLE_RANK.get(old.role, 0):
                out[key] = hit

        url_role = "download_host" if event_type == "download_attempt" else "contacted_host"
        for key, value in _iter_strings(data, [MAX_STRINGS]):
            if key in _HASH_KEYS:
                digest = normalize_hash(value, _HASH_KEYS[key])
                if digest is not None:
                    add(Hit("hash", digest, "hash", trusted=True))
                continue
            for raw in find_urls(value):
                norm = normalize_url(raw, s)
                if norm is None:
                    continue
                url, kind, host = norm
                add(Hit("url", url, url_role, host))
                add(Hit(kind, host, url_role, host))
            if key in _COMMAND_KEYS:
                for hit in scan_command(value, s):
                    add(hit)
        return list(out.values())


# ---- batch aggregation ------------------------------------------------------------------------


@dataclass(slots=True)
class Aggregate:
    type: str
    value: str
    role: str
    host: str | None
    first_seen: datetime
    last_seen: datetime
    sightings: int = 0
    trusted: bool = False
    demo: bool = True
    sensors: set[str] = field(default_factory=set)
    sessions: dict[str, tuple[str, str, datetime]] = field(default_factory=dict)


MAX_AGGREGATES_PER_BATCH = 800


def aggregate_batch(events: Sequence[Any], extractor: IndicatorExtractor) -> list[Aggregate]:
    """Fold the indicators of a batch of ``Event`` objects into one row per (type, value)."""
    agg: dict[tuple[str, str], Aggregate] = {}
    for ev in events:
        hits = extractor.extract(str(ev.type), ev.data)
        for hit in hits:
            key = (hit.type, hit.value)
            a = agg.get(key)
            if a is None:
                if len(agg) >= MAX_AGGREGATES_PER_BATCH:
                    continue
                a = agg[key] = Aggregate(hit.type, hit.value, hit.role, hit.host, ev.ts, ev.ts, 0)
                a.demo = hit.demo
            elif _ROLE_RANK.get(hit.role, 0) > _ROLE_RANK.get(a.role, 0):
                a.role = hit.role
            a.sightings += 1
            a.trusted = a.trusted or hit.trusted
            a.demo = a.demo and hit.demo
            a.first_seen = min(a.first_seen, ev.ts)
            a.last_seen = max(a.last_seen, ev.ts)
            a.sensors.add(str(ev.sensor))
            if ev.session_id not in a.sessions:
                a.sessions[ev.session_id] = (str(ev.src_ip), str(ev.sensor), ev.ts)
    return sorted(agg.values(), key=lambda a: (a.type, a.value))
