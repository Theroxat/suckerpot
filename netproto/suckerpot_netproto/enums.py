"""Closed vocabularies of protocol spn/1. Anything outside these lists is refused or dropped."""

from __future__ import annotations

import re
from typing import Final

PROTOCOL: Final = "spn/1"
API_PREFIX: Final = "/v1"
USER_AGENT: Final = "spn-node/1"

SERVICES: Final[frozenset[str]] = frozenset(
    "ssh telnet web rdp redis docker mysql adb mssql smb sip synology".split()
)
ACTIVITIES: Final[frozenset[str]] = frozenset(
    "connect scan login login_success command download exploit http".split()
)
# Activities that make an address reportable on their own (section 8.5).
SEVERE_ACTIVITIES: Final[frozenset[str]] = frozenset(
    {"login_success", "command", "download", "exploit"}
)
KINDS: Final[tuple[str, ...]] = ("ip", "url", "domain", "sha256", "c2_ip", "c2_domain")
BLINDED_KINDS: Final[frozenset[str]] = frozenset({"url", "domain"})
TARGET_STATES: Final[tuple[str, ...]] = (
    "confirmed",
    "reported",
    "taken_down",
    "disputed",
    "expired",
)
RECHECK_STATES: Final[frozenset[str]] = frozenset({"up", "down", "unknown"})
STANDINGS: Final[frozenset[str]] = frozenset({"new", "good", "low"})

TAGS_V1: Final[frozenset[str]] = frozenset(
    (
        "mirai crypto-miner malware-drop credential-stuffing php2shell eternalblue bluekeep "
        "sql-rce container-escape db-ransom sip-fraud persistence recon exec-attempt "
        "synology-exploit c3rb3r"
    ).split()
)
CVE_TAG: Final = re.compile(r"^cve-\d{4}-\d{4,7}$")

# Malware families from the static-analysis rules. A family outside this list is refused.
FAMILIES_V1: Final[frozenset[str]] = frozenset(
    (
        "mirai gafgyt mozi hajime tsunami kaiten xorddos dvrhelper xmrig coinminer "
        "c3rb3r botenago shellbot ddosbot generic"
    ).split()
)
# Coarse file types.
FILE_TYPES_V1: Final[frozenset[str]] = frozenset(
    (
        "elf-x86 elf-x86_64 elf-arm elf-aarch64 elf-mips elf-ppc elf-other "
        "pe script-sh script-py script-pl script-php archive other"
    ).split()
)

# Fields reserved for a later protocol version. The hub refuses them in v1.
RESERVED_FIELDS: Final[frozenset[str]] = frozenset({"credentials"})


def is_valid_tag(tag: str) -> bool:
    return tag in TAGS_V1 or CVE_TAG.fullmatch(tag) is not None
