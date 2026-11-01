"""Frozen list of the wording this package used to ship (design M22 review, HIGH-2).

The package now ships no prose: every sentence comes from the owner's settings. These phrases
were once public defaults, so a report that still contains one can be found with a web search
for it. ``guard`` fails with ``default_wording`` when any of them appears. Do not edit the list
to add new defaults; add owner-facing settings instead.
"""

from __future__ import annotations

import re
from typing import Final

LEGACY_PHRASES: Final[tuple[str, ...]] = (
    "the addresses below, announced by your network, attacked a monitored system",
    "the hosts below, in your network, served malicious files that attackers asked a monitored system to download",
    "the hosts below, in your network, appear to act as command-and-control servers for malware seen on a monitored system",
    "please investigate and stop this activity",
    "all times are utc. the destination address is withheld",
    "source ports are given so you can match your flow records",
    "rounded to the minute. the destination",
    "abuse report:",
    "in your network attacked a monitored system",
    "brute force from",
    "malware distribution from",
    "malware command-and-control server",
    "in your network distributed malware",
    "in your network run malware command-and-control",
    "indicators from a monitored system",
    "observed by a monitored system",
    "source of attack traffic",
    "host serving malicious files",
    "xarf-report/0.2",
    "logged in, then ran:",
    "sent an exploit attempt",
    "sent an http request",
    "tried to download",
    "(usernames tried:",
    "more entries are listed in evidence.csv",
    "previously reported on",
    "reply contact:",
    "subject_type,subject,asn,network,country,time_utc,protocol,src_port,dst_port,service,action,count,usernames,detail,user_agent,sha256",
)

# The old fixed MIME boundary: "=_" followed by 24 hex digits.
LEGACY_BOUNDARY: Final = re.compile(r"=_[0-9a-f]{24}\b")


def legacy_hit(text: str) -> bool:
    flat = " ".join(text.casefold().split())
    return any(p in flat for p in LEGACY_PHRASES) or LEGACY_BOUNDARY.search(flat) is not None
