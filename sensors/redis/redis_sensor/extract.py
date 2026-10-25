"""Pull indicators out of attacker-supplied text: download URLs, droppers, payload hints.

Everything here is plain ``str`` scanning (find, slicing, character sets): no regular
expressions, linear in the input, and the input is capped by the callers. Nothing is ever
fetched; the URLs only end up in ``download_attempt`` events.
"""

from __future__ import annotations

from dataclasses import dataclass, field

MAX_TEXT = 16 * 1024
MAX_URL = 2048
MAX_URLS = 8
MAX_TOOL_HITS = 32  # curl/wget words examined per tool, whatever the text

_SCHEMES = frozenset({"http", "https", "ftp", "tftp", "sftp", "ftps"})
_URL_STOP = frozenset(" \t\r\n\"'`\\|;<>()[]{}^")
_TOOLS = ("curl", "wget", "tftp", "fetch", "ftpget", "lwp-download", "python", "perl", "php")
_OPT_WITH_VALUE = frozenset(
    {"-o", "-O", "-P", "-H", "-A", "-e", "-u", "-T", "-w", "-x", "-U", "-m", "--output", "--proxy"}
)
_TOKEN_SEP = frozenset(" \t\r\n|;&\"'`(){}")
_ALNUM = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_HOSTISH = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:[]@/")

# Payload hints: (needle, flag), matched case-insensitively with str.find.
_HINTS: tuple[tuple[str, str], ...] = (
    ("/dev/tcp/", "reverse_shell"),
    ("nc -e", "reverse_shell"),
    ("bash -i", "reverse_shell"),
    ("xmrig", "miner"),
    ("minerd", "miner"),
    ("stratum+tcp", "miner"),
    ("kinsing", "kinsing"),
    ("kdevtmpfsi", "kinsing"),
    ("ssh-rsa ", "ssh_key_payload"),
    ("ssh-ed25519 ", "ssh_key_payload"),
    ("ecdsa-sha2-", "ssh_key_payload"),
    ("<?php", "webshell_payload"),
    ("bitcoin", "ransom_note"),
    ("send btc", "ransom_note"),
    ("your data", "ransom_note"),
    ("* * * *", "cron_payload"),
    ("chmod +x", "dropper"),
    ("| sh", "dropper"),
    ("|sh", "dropper"),
    ("| bash", "dropper"),
    ("|bash", "dropper"),
)


@dataclass
class Download:
    url: str
    tool: str


@dataclass
class TextFindings:
    downloads: list[Download] = field(default_factory=list)
    flags: set[str] = field(default_factory=set)


def _tool_before(lowered: str, start: int) -> str:
    window = lowered[max(0, start - 240) : start]
    best, best_at = "unknown", -1
    for tool in _TOOLS:
        at = window.rfind(tool)
        if at > best_at:
            best, best_at = tool, at
    return best


def _scheme_urls(text: str, lowered: str, out: list[Download], seen: set[str]) -> None:
    pos = 0
    while len(out) < MAX_URLS:
        at = text.find("://", pos)
        if at < 0:
            return
        pos = at + 3
        begin = at
        while begin > 0 and text[begin - 1] in _ALNUM and at - begin < 8:
            begin -= 1
        if text[begin:at].lower() not in _SCHEMES:
            continue
        end = pos
        limit = min(len(text), pos + MAX_URL)
        while end < limit and text[end] not in _URL_STOP:
            end += 1
        if end == pos:
            continue
        url = text[begin:end]
        if url not in seen:
            seen.add(url)
            out.append(Download(url, _tool_before(lowered, begin)))
        pos = end


def _bare_downloads(text: str, lowered: str, out: list[Download], seen: set[str]) -> None:
    """``curl -fsSL 198.51.100.9/x.sh | sh`` and ``wget host/file``: no scheme given."""
    for tool in ("curl", "wget"):
        pos = 0
        hits = 0
        while len(out) < MAX_URLS and hits < MAX_TOOL_HITS:
            at = lowered.find(tool, pos)
            if at < 0:
                break
            pos = at + len(tool)
            hits += 1
            if at > 0 and lowered[at - 1] in _ALNUM:
                continue
            tokens = _tokens(text, pos, 12)
            skip = False
            for tok in tokens:
                if skip:
                    skip = False
                    continue
                if tok.startswith("-"):
                    skip = tok in _OPT_WITH_VALUE
                    continue
                if "://" in tok:
                    break  # handled by the scheme scan
                if ("." in tok or "/" in tok) and set(tok) <= _HOSTISH and len(tok) > 3:
                    url = tok[:MAX_URL]
                    if url not in seen:
                        seen.add(url)
                        out.append(Download(url, tool))
                break


def _tokens(text: str, start: int, limit: int) -> list[str]:
    out: list[str] = []
    i, n = start, min(len(text), start + 512)
    while i < n and len(out) < limit:
        while i < n and text[i] in _TOKEN_SEP:
            if text[i] in "|;&":
                return out  # end of this command
            i += 1
        j = i
        while j < n and text[j] not in _TOKEN_SEP:
            j += 1
        if j > i:
            out.append(text[i:j])
        i = j
    return out


def analyze(text: str) -> TextFindings:
    """Scan (at most ``MAX_TEXT`` characters of) ``text``."""
    text = text[:MAX_TEXT]
    lowered = text.lower()
    found = TextFindings()
    seen: set[str] = set()
    _scheme_urls(text, lowered, found.downloads, seen)
    _bare_downloads(text, lowered, found.downloads, seen)
    for needle, flag in _HINTS:
        if lowered.find(needle) >= 0:
            found.flags.add(flag)
    if found.downloads:
        found.flags.add("download")
    return found
