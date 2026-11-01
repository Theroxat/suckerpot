"""Text normalisation shared by the redaction pass and the identity guard.

Everything here is a pure function over ``str``. The guard and the redactor must see text the
same way, so the folding, the decoding views and the address candidate extraction live in one
place.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from collections.abc import Iterator
from typing import Final

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# Characters that carry no visible text: zero-width, joiners, soft hyphen, BOM, bidi controls.
_INVISIBLE: Final[frozenset[int]] = frozenset(
    {0x00AD, 0x034F, 0x061C, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180E, 0x2028, 0x2029, 0x2060}
    | set(range(0x200B, 0x2010))
    | set(range(0x202A, 0x202F))
    | set(range(0x2061, 0x2065))
    | set(range(0x2066, 0x206A))
    | {0x3164, 0xFEFF, 0xFFA0}
    | set(range(0xFE00, 0xFE10))
)

# Characters kept as whitespace when removing controls.
_KEEP_CONTROLS: Final[frozenset[str]] = frozenset("\n\t")

_ANSI: Final = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])")

# Confusable letters folded to ASCII. NFKC already handles fullwidth and mathematical forms.
_CONFUSABLES: Final[dict[int, str]] = {
    ord(k): v
    for k, v in {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
        "у": "y",
        "і": "i",
        "ѕ": "s",
        "ј": "j",
        "ԁ": "d",
        "һ": "h",
        "ԛ": "q",
        "ԝ": "w",
        "ѵ": "v",
        "к": "k",
        "м": "m",
        "н": "h",
        "т": "t",
        "в": "b",
        "ɡ": "g",
        "ո": "n",
        "ս": "u",
        "ɩ": "i",
        "ӏ": "l",
        "ℓ": "l",
        "ο": "o",
        "ν": "v",
        "ρ": "p",
        "τ": "t",
        "κ": "k",
        "ι": "i",
        "α": "a",
        "υ": "u",
        "ε": "e",
        "η": "n",
        "ĸ": "k",
        "ı": "i",
        "ƅ": "b",
        "ʜ": "h",
        "ꜱ": "s",
        "ᴄ": "c",
        "ᴇ": "e",
        "ᴋ": "k",
        "ᴘ": "p",
        "ᴜ": "u",
        "ᴏ": "o",
        "ɴ": "n",
        "ʏ": "y",
        "ᴛ": "t",
        "ᴍ": "m",
        "ʀ": "r",
        "ʟ": "l",
    }.items()
}


# Full stops that NFKC leaves alone: ideographic, halfwidth ideographic and small full stop.
_DOTS: Final = {0x3002: ".", 0xFF61: ".", 0xFE52: "."}


def strip_invisible(text: str) -> str:
    """Remove zero-width, bidi and control characters (newline and tab survive)."""
    out: list[str] = []
    for ch in text:
        cp = ord(ch)
        if cp in _INVISIBLE:
            continue
        if ch in _KEEP_CONTROLS:
            out.append(ch)
            continue
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf"):
            if ch == "\r":
                out.append("\n")
            continue
        out.append(ch)
    return "".join(out)


def clean(text: str) -> str:
    """NFKC, ANSI sequences, invisible characters and controls removed. Case is preserved."""
    text = _ANSI.sub("", text)
    text = unicodedata.normalize("NFKC", text).translate(_DOTS)
    text = strip_invisible(text)
    # NFKC can expose new invisible characters (compatibility decompositions).
    return unicodedata.normalize("NFKC", text).translate(_DOTS)


def skeleton(text: str) -> str:
    """Lower-cased text with confusable letters folded to ASCII."""
    return clean(text).casefold().translate(_CONFUSABLES)


def collapse(text: str) -> str:
    """Skeleton reduced to ASCII letters and digits, for separator-insensitive term matching."""
    return re.sub(r"[^a-z0-9]+", "", skeleton(text))


def to_ascii(text: str) -> str:
    """Printable ASCII; every other character becomes ``\\uXXXX`` (or ``\\UXXXXXXXX``)."""
    out: list[str] = []
    for ch in text:
        cp = ord(ch)
        if ch in "\n\t\r" or 0x20 <= cp < 0x7F:
            out.append(ch)
        elif cp <= 0xFFFF:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(f"\\U{cp:08x}")
    return "".join(out)


_PCT: Final = re.compile(r"%([0-9a-fA-F]{2})")
_ESC_HEX: Final = re.compile(r"\\x([0-9a-fA-F]{2})")
_ESC_UNI: Final = re.compile(r"\\u([0-9a-fA-F]{4})")
_ESC_OCT: Final = re.compile(r"\\([0-3][0-7]{2})")
_DEFANG: Final = (
    (re.compile(r"\s?[\[({]\s?\.\s?[\])}]\s?"), "."),
    (re.compile(r"\s?[\[({]\s?dot\s?[\])}]\s?", re.IGNORECASE), "."),
    (re.compile(r"hxxp", re.IGNORECASE), "http"),
    (re.compile(r"fxp://", re.IGNORECASE), "ftp://"),
)


def pct_decode(text: str) -> str:
    return _PCT.sub(lambda m: chr(int(m.group(1), 16)), text)


def unescape(text: str) -> str:
    """Decode ``\\xNN``, ``\\uNNNN`` and octal escapes (as shells and JSON strings write them)."""
    text = _ESC_UNI.sub(lambda m: chr(int(m.group(1), 16)), text)
    text = _ESC_HEX.sub(lambda m: chr(int(m.group(1), 16)), text)
    return _ESC_OCT.sub(lambda m: chr(int(m.group(1), 8)), text)


def undefang(text: str) -> str:
    for pattern, repl in _DEFANG:
        text = pattern.sub(repl, text)
    return text


def views(text: str) -> list[str]:
    """Distinct scanning views of one string, case preserved.

    Original, percent-decoded once and twice, escape-decoded, and each of those with defanging
    undone. Callers lower-case or fold as needed.
    """
    base = clean(text)
    p1 = pct_decode(base)
    p2 = pct_decode(p1)
    chain = [base, p1, p2, unescape(base), unescape(p2)]
    out: list[str] = []
    for item in chain:
        item = clean(item)
        for cand in (item, undefang(item)):
            if cand not in out:
                out.append(cand)
    return out


# --- address candidates -------------------------------------------------------------------

_V4_SEP: Final = re.compile(r"(?<![0-9])(\d{1,3})([.\-_])(\d{1,3})\2(\d{1,3})\2(\d{1,3})(?![0-9])")
_V4_INT: Final = re.compile(r"(?<![0-9a-zA-Z])(\d{8,10})(?![0-9a-zA-Z])")
_V4_HEX: Final = re.compile(r"(?<![0-9a-zA-Z])0x([0-9a-fA-F]{8})(?![0-9a-zA-Z])")
_V6: Final = re.compile(r"(?<![\w:.])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?:\.\d{1,3}){0,3}")

# 6to4 and NAT64 embed an IPv4 address.
_NAT64: Final = ipaddress.ip_network("64:ff9b::/96")
_SIXTOFOUR: Final = ipaddress.ip_network("2002::/16")


class Candidate:
    """One address found in text, with how it was written."""

    __slots__ = ("address", "end", "form", "parts", "start")

    def __init__(self, address: IPAddress, form: str, start: int, end: int, parts: int = 4) -> None:
        self.address = address
        # dotted | dashed | underscored | reversed | int | hex | hexbare | inet | v6
        self.form = form
        self.start = start
        self.end = end
        self.parts = parts

    def judged(self, text: str) -> bool:
        """Whether the address is judged (private, documentation, allowed) and not only compared.

        Bare numbers and look-alike forms are compared with the self terms but are judged only
        when written as an address: dotted, IPv6, or any numeric form after ``//`` or ``@``.
        """
        if self.form in ("dotted", "dashed", "underscored", "v6"):
            return True
        if self.form in ("int", "hex", "inet"):
            if self.form == "inet" and self.parts == 4:
                return True
            return text[max(0, self.start - 2) : self.start].endswith(("//", "@"))
        return False

    def embedded(self) -> list[IPAddress]:
        """Addresses to test: itself plus any IPv4 it embeds (mapped, 6to4, NAT64)."""
        out: list[IPAddress] = [self.address]
        a = self.address
        if isinstance(a, ipaddress.IPv6Address):
            if a.ipv4_mapped is not None:
                out.append(a.ipv4_mapped)
            elif a in _NAT64:
                out.append(ipaddress.IPv4Address(int(a) & 0xFFFFFFFF))
            elif a in _SIXTOFOUR:
                out.append(ipaddress.IPv4Address((int(a) >> 80) & 0xFFFFFFFF))
        return out


def _octets_ok(parts: tuple[str, ...]) -> bool:
    return all(0 <= int(p) <= 255 and len(p) <= 3 for p in parts)


def ipv4_candidates(text: str) -> Iterator[Candidate]:
    """IPv4 addresses in dotted, dashed, underscored, reversed, integer and 0x forms."""
    for m in _V4_SEP.finditer(text):
        parts = (m.group(1), m.group(3), m.group(4), m.group(5))
        if not _octets_ok(parts):
            continue
        sep = m.group(2)
        form = {".": "dotted", "-": "dashed", "_": "underscored"}[sep]
        nums = [int(p) for p in parts]
        yield Candidate(ipaddress.IPv4Address(".".join(map(str, nums))), form, m.start(), m.end())
        if sep == ".":
            yield Candidate(
                ipaddress.IPv4Address(".".join(map(str, reversed(nums)))),
                "reversed",
                m.start(),
                m.end(),
            )
    for m in _V4_INT.finditer(text):
        value = int(m.group(1))
        if value < 2**32:
            yield Candidate(ipaddress.IPv4Address(value), "int", m.start(), m.end())
    for m in _V4_HEX.finditer(text):
        yield Candidate(ipaddress.IPv4Address(int(m.group(1), 16)), "hex", m.start(), m.end())


def ipv6_candidates(text: str) -> Iterator[Candidate]:
    for m in _V6.finditer(text):
        token = m.group(0)
        if len(token) < 3 or token.count(":") < 2:
            continue
        try:
            addr = ipaddress.IPv6Address(token)
        except ValueError:
            continue
        yield Candidate(addr, "v6", m.start(), m.end())


_INET: Final = re.compile(
    r"(?<![0-9A-Za-z.])(?:0[xX][0-9a-fA-F]+|\d+)(?:\.(?:0[xX][0-9a-fA-F]+|\d+)){0,3}(?![0-9A-Za-z])"
)
_HEX8: Final = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{8}(?![0-9A-Za-z])")


def _readings(part: str) -> list[int]:
    """Values of one inet_aton part: ``0x`` hex, leading-zero octal, or decimal."""
    if part[:2].lower() == "0x":
        return [int(part, 16)] if len(part) > 2 else []
    if len(part) > 1 and part[0] == "0":
        out = [int(part, 10)]
        if all(c in "01234567" for c in part):
            out.insert(0, int(part, 8))
        return out
    return [int(part, 10)]


def inet_candidates(text: str) -> Iterator[Candidate]:
    """Every inet_aton reading: 1 to 4 parts, each decimal, octal or hex."""
    for m in _INET.finditer(text):
        raw = m.group(0).split(".")
        n = len(raw)
        plain = all(p.isdigit() and not (len(p) > 1 and p[0] == "0") for p in raw)
        if plain and (n == 4 or (n == 1 and not 8 <= len(raw[0]) <= 10 and len(raw[0]) < 8)):
            continue  # dotted quads and short bare numbers are covered elsewhere or are noise
        if len(raw[0]) > 40:
            continue
        options = [_readings(p) for p in raw]
        seen: set[int] = set()
        combos: list[list[int]] = [[]]
        for opts in options:
            combos = [[*c, v] for c in combos for v in opts][:16]
        for combo in combos:
            if any(v > 255 for v in combo[:-1]) or combo[-1] >= 256 ** (5 - n):
                continue
            value = sum(v << (8 * (3 - i)) for i, v in enumerate(combo[:-1])) + combo[-1]
            if value >= 2**32 or value in seen:
                continue
            seen.add(value)
            yield Candidate(ipaddress.IPv4Address(value), "inet", m.start(), m.end(), n)
    for m in _HEX8.finditer(text):
        yield Candidate(ipaddress.IPv4Address(int(m.group(0), 16)), "hexbare", m.start(), m.end())


def candidates(text: str) -> Iterator[Candidate]:
    yield from ipv4_candidates(text)
    yield from inet_candidates(text)
    yield from ipv6_candidates(text)


_DOC_NETS: Final = tuple(
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "3fff::/20")
)


def is_documentation(addr: IPAddress) -> bool:
    return any(addr in net for net in _DOC_NETS if net.version == addr.version)


def is_forbidden_range(addr: IPAddress) -> bool:
    """Private, loopback, link-local, CGNAT, ULA, multicast, reserved and unspecified."""
    if is_documentation(addr):
        return False
    return not addr.is_global or addr.is_multicast


def addr_key(addr: IPAddress) -> str:
    """Canonical text of an address (compressed IPv6, no leading zeros)."""
    return str(addr)
