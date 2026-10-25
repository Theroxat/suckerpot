"""Safe text for alerts: attacker-controlled values are cleaned, indicators defanged, IPs masked.

Everything an alert shows about an attack passes through here. Nothing in an alert is a live
link to attacker infrastructure: a chat client or mail reader must not turn a malware host into
a clickable (or auto-fetched) URL.
"""

from __future__ import annotations

import ipaddress
import unicodedata

ELLIPSIS = "…"


def clean(value: object, limit: int = 120) -> str:
    """One printable line: control and format characters removed, spaces collapsed, truncated."""
    text = str(value)
    kept = []
    for ch in text:
        cat = unicodedata.category(ch)
        if ch in "\r\n\t" or cat in ("Zs", "Zl", "Zp"):
            kept.append(" ")
        elif cat[0] != "C":  # drops control, format (bidi marks), surrogate and unassigned
            kept.append(ch)
    out = " ".join("".join(kept).split())
    if len(out) > limit:
        out = out[: limit - 1].rstrip() + ELLIPSIS
    return out


def defang(value: str, limit: int = 120) -> str:
    """``http://evil.example/x`` becomes ``hxxp[://]evil[.]example/x`` (also for bare hosts)."""
    text = clean(value, limit)
    lower = text.lower()
    prefix = ""
    for real, fake in (
        ("https://", "hxxps[://]"),
        ("http://", "hxxp[://]"),
        ("ftp://", "fxp[://]"),
    ):
        if lower.startswith(real):
            prefix, text = fake, text[len(real) :]
            break
    host, sep, rest = text.partition("/")
    return prefix + host.replace(".", "[.]").replace(":", "[:]") + sep + rest.replace(".", "[.]")


def mask_ip(value: str) -> str:
    """``203.0.113.7`` becomes ``203.0.x.x`` and an IPv6 address keeps its first two groups."""
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return "x.x.x.x"
    if isinstance(ip, ipaddress.IPv4Address):
        a, b, *_ = str(ip).split(".")
        return f"{a}.{b}.x.x"
    first = ip.exploded.split(":")[:2]
    return ":".join(first) + "::x"


def show_ip(value: str, mask: bool) -> str:
    """An IP address as the channel wants it: masked, or defanged when unmasked."""
    if mask:
        return mask_ip(value)
    try:
        return str(ipaddress.ip_address(value.strip())).replace(".", "[.]").replace(":", "[:]")
    except ValueError:
        return "x.x.x.x"
