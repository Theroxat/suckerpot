"""The redaction pass (design M22, section 4.3).

Free text from an attacker (a command, a URL, a user agent, a username) is copied into
evidence only after this pass. It is deliberately blunt: a line that mentions anything
identifying is removed whole, because masking one word would leave its context behind.
Counters are returned, never the removed values.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from .evidence import RedactionStats
from .guard import GuardContext, scan_text
from .normalize import (
    Candidate,
    candidates,
    clean,
    is_documentation,
    is_forbidden_range,
    to_ascii,
    views,
)
from .terms import SelfTerms

MAX_INPUT = 4096
MAX_LINE = 200

_DENY_CODES: Final = frozenset(
    {
        "self_address",
        "vpn_address",
        "self_name",
        "owner_domain",
        "project_term",
        "dashboard_path",
        "internal_id",
    }
)
_PRIVATE_TLDS: Final = frozenset(
    {
        "local",
        "localhost",
        "internal",
        "lan",
        "home",
        "corp",
        "intranet",
        "localdomain",
        "private",
        "arpa",
        "invalid",
        "test",
        "onion",
    }
)
_URL: Final = re.compile(
    r"(?i)\b([a-z][a-z0-9+.\-]{1,15}://)([^/\s?#@\[\]]*@)?(\[[0-9a-f:.]+\]|[^/\s?#:@\[\]]+)(:\d{1,5})?"
)
_EMAIL: Final = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")
_HOST_OK: Final = re.compile(
    r"^[a-z0-9]([a-z0-9\-_]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-_]*[a-z0-9])?)*$"
)


@dataclass(frozen=True)
class RedactionContext:
    """What a report may name (its subjects) and what it must never name."""

    terms: SelfTerms
    allowed_addresses: frozenset[str] = frozenset()
    allowed_hosts: frozenset[str] = frozenset()
    internal_ids: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Redacted:
    text: str
    addresses_masked: int = 0
    lines_dropped: int = 0

    @property
    def stats(self) -> RedactionStats:
        return RedactionStats(
            addresses_masked=self.addresses_masked, lines_dropped=self.lines_dropped
        )


def _version_like(cand: Candidate, text: str) -> bool:
    """``Chrome/120.0.0.0``: a four-part version after ``name/`` is not an address."""
    if cand.form != "dotted" or cand.start < 2:
        return False
    before = text[cand.start - 2 : cand.start]
    return (
        before[0].isalpha()
        and before[1] == "/"
        and not is_forbidden_range(cand.address)
        and not is_documentation(cand.address)
    )


def _allowed(cand: Candidate, ctx: RedactionContext, text: str = "") -> bool:
    if cand.form in ("dotted", "v6") and str(cand.address) in ctx.allowed_addresses:
        return True
    return _version_like(cand, text)


def _mask_addresses(line: str, ctx: RedactionContext) -> tuple[str, int]:
    found = [c for c in candidates(line) if c.judged(line)]
    found.sort(key=lambda c: (c.start, -(c.end - c.start)))
    out: list[str] = []
    pos = 0
    masked = 0
    for cand in found:
        if cand.start < pos:
            continue
        if _allowed(cand, ctx, line):
            continue
        out.append(line[pos : cand.start])
        out.append("[address]")
        pos = cand.end
        masked += 1
    out.append(line[pos:])
    return "".join(out), masked


def _public_name(host: str) -> bool:
    if not _HOST_OK.match(host) or "." not in host:
        return False
    tld = host.rsplit(".", 1)[1]
    return tld not in _PRIVATE_TLDS and not tld.isdigit()


def _mask_urls(line: str, ctx: RedactionContext) -> tuple[str, int]:
    count = 0

    def repl(m: re.Match[str]) -> str:
        nonlocal count
        scheme, userinfo, host, port = m.group(1), m.group(2), m.group(3), m.group(4) or ""
        if userinfo:
            count += 1
        low = host.casefold()
        if host == "[address]" or host.startswith("[") or low in ctx.allowed_hosts:
            return f"{scheme}{host}{port}"
        if low in ctx.allowed_addresses or _public_name(low):
            return f"{scheme}{host}{port}"
        count += 1
        return f"{scheme}[host]{port}"

    return _URL.sub(repl, line), count


def _residual_address(line: str, ctx: RedactionContext) -> bool:
    """True when any decoding of the line still shows an address that is not allowed."""
    for view in views(line):
        for cand in candidates(view):
            if cand.judged(view) and not _allowed(cand, ctx, view):
                return True
    return False


def _denied(line: str, ctx: RedactionContext) -> bool:
    counts: dict[str, int] = {}
    scan_text(line, ctx.terms, GuardContext(internal_ids=ctx.internal_ids), counts)
    return bool(_DENY_CODES & counts.keys())


def redact(
    text: str,
    ctx: RedactionContext,
    *,
    max_len: int = MAX_LINE,
    single_line: bool = False,
) -> Redacted:
    """Return ``text`` safe for a report: printable ASCII, bounded, identifying lines removed."""
    cleaned = clean(text[:MAX_INPUT])
    kept: list[str] = []
    masked_total = 0
    dropped = 0
    for raw in cleaned.split("\n"):
        line = raw.strip()
        if not line:
            continue
        if _denied(line, ctx):
            dropped += 1
            continue
        line, masked = _mask_addresses(line, ctx)
        line, url_masked = _mask_urls(line, ctx)
        line, email_count = re.subn(_EMAIL, "[email]", line)
        line = to_ascii(line)
        if _residual_address(line, ctx) or _denied(line, ctx):
            dropped += 1
            continue
        if len(line) > max_len:
            line = line[: max_len - 3] + "..."
        masked_total += masked + url_masked + email_count
        kept.append(line)
    joined = "; ".join(kept) if single_line else "\n".join(kept)
    return Redacted(text=joined, addresses_masked=masked_total, lines_dropped=dropped)


# --- defanging (bodies only) ---------------------------------------------------------------

_SCHEMES: Final = {"http": "hxxp", "https": "hxxps", "ftp": "fxp", "ftps": "fxps"}
_DOTTED: Final = re.compile(r"(?<![0-9.\[])(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})(?![0-9])")


def _defang_host(host: str) -> str:
    if "." not in host or host.startswith("["):
        return host
    head, _, tail = host.rpartition(".")
    return f"{head}[.]{tail}"


def defang(text: str) -> str:
    """``http`` becomes ``hxxp`` and the last dot of every host or address becomes ``[.]``."""

    def url(m: re.Match[str]) -> str:
        scheme = m.group(1)[:-3]
        new = _SCHEMES.get(scheme.lower(), scheme)
        return f"{new}://{_defang_host(m.group(2))}{m.group(3) or ''}"

    text = re.sub(r"(?i)\b([a-z][a-z0-9+.\-]{1,15}://)([^/\s?#:@\[\]]+)(:\d{1,5})?", url, text)
    return _DOTTED.sub(lambda m: f"{m.group(1)}[.]{m.group(2)}", text)
