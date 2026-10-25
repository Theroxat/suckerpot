"""Shell command normaliser shared by campaign clustering (M15) and the script library (M17).

Two sessions that ran "the same script" with different addresses, ports or payload names must
end up with the same normalised sequence, and so the same fingerprint. The normaliser keeps the
shape of the commands (names, flags, paths) and replaces the volatile parts with placeholders:

* ``<url>``  anything with a ``scheme://``;
* ``<ip>``   an IPv4 address, with an optional port or path;
* ``<host>`` a dotted host name that is not a file name;
* ``<n>``    a number;
* ``<blob>`` a long hex string, a long base64-looking string or an oversized token.

It is deliberately bounded and uses no regular expression: the input is attacker-controlled, so
it is cut at 8 KiB and 64 commands, and every step is a linear scan.
"""

from __future__ import annotations

import hashlib
import unicodedata
from collections.abc import Iterable

MAX_INPUT_CHARS = 8192
MAX_COMMANDS = 64
MAX_TOKENS = 32
MAX_TOKEN_CHARS = 256
MIN_BLOB_HEX = 16
MIN_BLOB_B64 = 24

#: Commands that carry no meaning for a fingerprint: they only move around or print state.
NOOP_COMMANDS = frozenset({"cd", "pwd", "true", ":", "clear"})
#: Splits one input line into several commands.
_SEPARATORS = (";", "&&", "||", "|")

_HEX = frozenset("0123456789abcdefABCDEF")
_DIGITS = frozenset("0123456789")
_B64 = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_HOST_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
_QUOTES = "\"'`"
#: Extensions that make "name.ext" a file, not a host name.
_FILE_EXTENSIONS = frozenset(
    {
        "sh", "bash", "py", "pl", "rb", "php", "js", "txt", "bin", "elf", "exe", "dll", "so",
        "tar", "gz", "tgz", "zip", "bz2", "xz", "conf", "cfg", "log", "json", "yaml", "yml",
        "xml", "html", "htm", "c", "o", "a", "ko", "out", "tmp", "bak", "pid", "lock", "db",
        "key", "pub", "pem", "crt", "service", "timer", "x86", "arm", "mips", "mpsl",
    }
)  # fmt: skip


def _strip_controls(text: str) -> str:
    """Drop control and format characters (Cc, Cf) except line breaks and tabs: invisible
    characters must not make two copies of one script look different."""
    return "".join(c for c in text if c in "\n\r\t" or unicodedata.category(c) not in ("Cc", "Cf"))


def _split_commands(line: str) -> list[str]:
    """Split on ``;``, ``&&``, ``||``, ``|`` (not quote aware: stable is what matters here)."""
    parts = [line]
    for sep in _SEPARATORS:
        parts = [piece for part in parts for piece in part.split(sep)]
    return parts


def _is_ipv4(text: str) -> bool:
    parts = text.split(".")
    return (
        len(parts) == 4
        and all(p and len(p) <= 3 and set(p) <= _DIGITS for p in parts)
        and all(int(p) <= 255 for p in parts)
    )


def _looks_like_ip(token: str) -> bool:
    head = token.split("/", 1)[0].split(":", 1)[0]
    return _is_ipv4(head)


def _looks_like_host(token: str) -> bool:
    if "/" in token or token.startswith(("-", ".")) or "=" in token:
        return False
    head = token.split(":", 1)[0]
    labels = head.lower().split(".")
    if len(labels) < 2 or any(not label or len(label) > 63 for label in labels):
        return False
    if not all(set(label) <= _HOST_CHARS for label in labels):
        return False
    tld = labels[-1]
    return tld.isalpha() and 2 <= len(tld) <= 24 and tld not in _FILE_EXTENSIONS


def _is_blob(token: str) -> bool:
    if len(token) > MAX_TOKEN_CHARS:
        return True
    if len(token) >= MIN_BLOB_HEX and set(token) <= _HEX:
        return True
    if len(token) >= MIN_BLOB_B64 and set(token) <= _B64 and token[0] not in "/.":
        has_digit = any(c in _DIGITS for c in token)
        mixed_case = token != token.lower() and token != token.upper()
        return has_digit or mixed_case
    return False


def _normalize_token(token: str) -> str:
    bare = token.strip(_QUOTES)
    if not bare:
        return ""
    if "://" in bare:
        return "<url>"
    if _is_blob(bare):
        return "<blob>"
    if set(bare) <= _DIGITS:
        return "<n>"
    if _looks_like_ip(bare):
        return "<ip>"
    if _looks_like_host(bare):
        return "<host>"
    return bare


def normalize_token(token: str) -> str:
    """One word, normalised (public for callers that normalise paths or fields)."""
    return _normalize_token(token)


def normalize_command(command: str) -> str | None:
    """One command, normalised; ``None`` for an empty or no-op command."""
    tokens = command.split()[:MAX_TOKENS]
    if not tokens:
        return None
    name = tokens[0].strip(_QUOTES).lower()
    if not name or name in NOOP_COMMANDS:
        return None
    rest = [t for t in (_normalize_token(tok) for tok in tokens[1:]) if t]
    head = _normalize_token(name) if "://" in name or _is_blob(name) else name
    return " ".join([head, *rest])


def normalize_commands(commands: Iterable[str]) -> list[str]:
    """Normalise a command sequence (one entry per typed line, or per script line)."""
    out: list[str] = []
    budget = MAX_INPUT_CHARS
    for line in commands:
        if budget <= 0 or len(out) >= MAX_COMMANDS:
            break
        chunk = _strip_controls(line[:budget])
        budget -= len(chunk)
        for piece in _split_commands(chunk.replace("\r", "\n").replace("\n", ";")):
            normalized = normalize_command(piece)
            if normalized is not None:
                out.append(normalized)
                if len(out) >= MAX_COMMANDS:
                    break
    return out


def normalize_text(text: str) -> list[str]:
    """Normalise a multi-line script."""
    return normalize_commands([text[:MAX_INPUT_CHARS]])


def meaningful_count(normalized: list[str]) -> int:
    """How many commands count as evidence: at least two are needed to fingerprint a session."""
    return len(normalized)


def fingerprint(normalized: list[str]) -> str:
    """Stable sha256 (hex) of a normalised sequence."""
    return hashlib.sha256("\n".join(normalized).encode("utf-8", "replace")).hexdigest()
