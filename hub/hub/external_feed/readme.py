"""The README.txt of the external tier (design M36 X6). Plain text, no template file."""

from __future__ import annotations

from collections.abc import Sequence

from suckerpot_netproto.feeds.external import NOTICE

from ..config import Settings
from .sources import Source


def render_readme(s: Settings, public_key: str, sources: Sequence[Source]) -> bytes:
    names = ", ".join(src.name for src in sources)
    lines = [
        "SuckerPot external feed",
        "=======================",
        "",
        f"This directory republishes {names} (licence CC0-1.0), filtered and signed.",
        f"{NOTICE}",
        "It is a copy of public third-party data. Nothing in it comes from, or is checked",
        "against, what members of the network see: it is the same file with zero members.",
        "It is separate from the network blocklists in the parent directory and has its own",
        "index.json and serial. Do not mix the two tiers up.",
        "",
        "Sources",
        *[f"  {src.name}: {src.page or src.url}" for src in sources],
        "",
        "Files",
        "  index.json                 signed manifest (schema selfhostr-external/1)",
        "  external-outbound.<fmt>    botnet command and control addresses",
        "                             txt, v4.txt, v6.txt, nft, ipset, rsc, csv, json",
        "  every file has a .minisig signature and a .gz copy",
        "",
        "Verify with minisign. Public key of the feed (same key as the network feeds):",
        f"  {public_key}",
        "  minisign -V -P <key> -m index.json",
        "Check the signed serial, the valid_until date and the sha256 of every file against",
        "index.json, and refuse a serial lower than the one you last saw.",
        "",
        "Addresses are removed within one cycle when the source drops them, and the whole",
        "list expires 7 days after the last successful fetch. A wrong entry has to be",
        f"corrected at the source (see the page above). Feed host: {s.feeds_domain}",
        "",
    ]
    return "\n".join(lines).encode("utf-8")
