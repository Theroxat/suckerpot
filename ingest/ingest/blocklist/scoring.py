"""Scoring of blocklist candidates (M16). Pure functions, no I/O.

A score is 0 to 100 and says how much an indicator deserves a place on a firewall list. Each
point comes with a reason code from a closed vocabulary (``REASONS``); the dashboard turns the
codes into plain-English sentences. Nothing here reads attacker text beyond the tag names that
ingest itself assigned.
"""

from __future__ import annotations

from dataclasses import dataclass, field

REASONS = (
    "brute-force",
    "login-succeeded",
    "ran-commands",
    "dropped-malware",
    "exploit-attempt",
    "reported-abusive",
    "multi-sensor",
    "campaign",
    "repeat-visitor",
    "mass-scanner",
    "download-source",
    "contacted-by-attacker",
    "known-malware",
    "malware-family",
    "seen-from-many-sources",
    "file-hash",
    "manual-block",
)

MALWARE_TAGS = frozenset({"malware-drop", "mirai", "crypto-miner"})
EXPLOIT_TAGS = frozenset(
    {
        "php2shell",
        "sql-rce",
        "eternalblue",
        "bluekeep",
        "redis-rogue-master",
        "container-escape",
        "db-ransom",
        "exec-attempt",
        "persistence",
    }
)
BRUTE_TAGS = frozenset(
    {"weak-credentials", "credential-stuffing", "wordpress-bruteforce", "phpmyadmin-bruteforce"}
)
KNOWN_SCANNER_CAP = 35
MIN_LISTED_SCORE = 10


@dataclass(frozen=True, slots=True)
class IpFacts:
    """What the sessions of one source address add up to."""

    sessions: int
    sensors: int
    login_attempts: int
    login_success: bool
    commands: int
    downloads: int
    max_abuse: int | None
    known_scanner: bool
    in_campaign: bool
    tags: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True, slots=True)
class Scored:
    score: int
    reasons: list[str]


def _clamp(points: int) -> int:
    return max(0, min(100, points))


def score_ip(f: IpFacts) -> Scored:
    points = 0
    reasons: list[str] = []
    if f.sessions >= 20:
        points += 20
    elif f.sessions >= 5:
        points += 15
    elif f.sessions >= 2:
        points += 10
    else:
        points += 5
    if f.sessions >= 3:
        reasons.append("repeat-visitor")
    if f.login_attempts >= 10 or f.tags & BRUTE_TAGS:
        points += 20
        reasons.append("brute-force")
    if f.login_success:
        points += 10
        reasons.append("login-succeeded")
    if f.commands > 0:
        points += 25
        reasons.append("ran-commands")
    dropped = f.downloads > 0 or bool(f.tags & MALWARE_TAGS)
    if dropped:
        points += 30
        reasons.append("dropped-malware")
    exploit = bool(f.tags & EXPLOIT_TAGS)
    if exploit:
        points += 20
        reasons.append("exploit-attempt")
    if f.max_abuse is not None and f.max_abuse >= 25:
        points += round(f.max_abuse * 0.3)
        if f.max_abuse >= 50:
            reasons.append("reported-abusive")
    if f.sensors >= 2:
        points += 5
        reasons.append("multi-sensor")
    if f.in_campaign:
        points += 10
        reasons.append("campaign")
    score = _clamp(points)
    if f.known_scanner:
        reasons.append("mass-scanner")
        if not (f.commands or dropped or exploit):
            score = min(score, KNOWN_SCANNER_CAP)
    return Scored(score, reasons[:16])


@dataclass(frozen=True, slots=True)
class IndicatorFacts:
    """What the indicator table knows about a URL, host or hash."""

    kind: str  # url | domain | ip | hash
    role: str  # download_host | contacted_host | hash
    sessions: int
    sources: int
    sightings: int
    trusted: bool
    known: bool  # a threat-intel service lists it
    family: str | None
    in_campaign: bool


def score_indicator(f: IndicatorFacts) -> Scored:
    points = 0
    reasons: list[str] = []
    if f.kind == "hash":
        points += 35
        reasons.append("file-hash")
        if f.trusted:
            points += 10  # computed by a sensor, not just typed in a command
    elif f.role == "download_host":
        points += 45
        reasons.append("download-source")
    else:
        points += 30
        reasons.append("contacted-by-attacker")
    if f.known:
        points += 25
        reasons.append("known-malware")
    if f.family:
        points += 10
        reasons.append("malware-family")
    if f.sources >= 3 or f.sightings >= 5:
        points += 10
        reasons.append("seen-from-many-sources")
    elif f.sources >= 2:
        points += 5
    if f.in_campaign:
        points += 10
        reasons.append("campaign")
    return Scored(_clamp(points), reasons[:16])
