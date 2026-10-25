"""Deterministic campaign names, severity and stages.

The name never comes from attacker input beyond a malware family label, which is reduced to
letters, digits and a few separators first. Same inputs, same name.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping

from ingest.attack.mapping import STAGES

#: What a campaign is "about", most telling first. Used to pick the dominant objective tag.
OBJECTIVE_TAGS = (
    "php2shell",
    "eternalblue",
    "sql-rce",
    "container-escape",
    "crypto-miner",
    "mirai",
    "malware-drop",
    "db-ransom",
    "redis-rogue-master",
    "sip-fraud",
    "credential-stuffing",
    "wordpress-bruteforce",
    "phpmyadmin-bruteforce",
    "bluekeep",
    "weak-credentials",
    "persistence",
    "env-file-probe",
    "scanner",
    "recon",
)
OBJECTIVE_NAMES = {
    "php2shell": "PHP2Shell exploitation",
    "eternalblue": "EternalBlue exploitation",
    "sql-rce": "SQL command execution",
    "container-escape": "Container escape",
    "crypto-miner": "Crypto-miner drop",
    "mirai": "Mirai-style loader",
    "malware-drop": "Malware dropper",
    "db-ransom": "Database ransom",
    "redis-rogue-master": "Redis rogue master",
    "sip-fraud": "Phone fraud",
    "credential-stuffing": "Credential stuffing",
    "wordpress-bruteforce": "WordPress password guessing",
    "phpmyadmin-bruteforce": "phpMyAdmin password guessing",
    "bluekeep": "BlueKeep probing",
    "weak-credentials": "Weak password guessing",
    "persistence": "Persistence setup",
    "env-file-probe": "Secrets hunting",
    "scanner": "Scanning",
    "recon": "Reconnaissance",
}
FAMILY_NOUNS = {
    "crypto-miner": "miner",
    "mirai": "loader",
    "malware-drop": "dropper",
    "db-ransom": "ransom",
}
SENSOR_LABELS = {
    "ssh": "SSH", "telnet": "Telnet", "web": "HTTP", "rdp": "RDP", "redis": "Redis",
    "docker": "Docker", "mysql": "MySQL", "mssql": "SQL Server", "adb": "ADB", "smb": "SMB",
    "sip": "SIP",
}  # fmt: skip
SEVERE_TAGS = frozenset(
    {
        "php2shell", "crypto-miner", "mirai", "malware-drop", "container-escape", "sql-rce",
        "eternalblue",
    }
)  # fmt: skip
WARNING_TAGS = frozenset({"db-ransom", "redis-rogue-master", "sip-fraud", "persistence"})
NAME_MAX = 100


def clean_family(label: str) -> str:
    """A malware family label reduced to a safe display name."""
    kept = "".join(c for c in label.strip() if c.isalnum() or c in " ._-+")[:32].strip()
    return kept[:1].upper() + kept[1:] if kept else ""


def dominant(tags: Iterable[str]) -> str | None:
    """The objective tag that tells the story: most sessions first, then the priority order."""
    counts = Counter(t for t in tags if t in OBJECTIVE_NAMES)
    if not counts:
        return None
    rank = {t: i for i, t in enumerate(OBJECTIVE_TAGS)}
    return min(counts, key=lambda t: (-counts[t], rank[t]))


def campaign_name(
    families: Iterable[str],
    tags: Iterable[str],
    sensors: Iterable[str],
    campaign_id: int | None = None,
) -> str:
    """``<Family> loader over Telnet #41``: family, else objective, else just the sensor."""
    objective = dominant(tags)
    family = Counter(f for f in (clean_family(x) for x in families) if f)
    sensor_counts = Counter(sensors)
    top_sensor = min(sensor_counts, key=lambda s: (-sensor_counts[s], s)) if sensor_counts else None
    if family:
        label = min(family, key=lambda f: (-family[f], f))
        base = f"{label} {FAMILY_NOUNS.get(objective or '', 'campaign')}"
    elif objective:
        base = OBJECTIVE_NAMES[objective]
    else:
        base = "Shared activity"
    where = f" over {SENSOR_LABELS.get(top_sensor, top_sensor)}" if top_sensor else ""
    suffix = f" #{campaign_id}" if campaign_id is not None else ""
    return f"{base}{where}{suffix}"[:NAME_MAX]


def severity_of(tags: Iterable[str], commands: int = 0, login_attempts: int = 0) -> str:
    """info / notice / warning / severe, the same meaning as a session's severity."""
    tagset = set(tags)
    if tagset & SEVERE_TAGS:
        return "severe"
    if tagset & WARNING_TAGS or commands > 0:
        return "warning"
    if login_attempts > 0 or tagset:
        return "notice"
    return "info"


def stages_of(technique_ids: Iterable[str], stage_by_technique: Mapping[str, str]) -> list[str]:
    """The stages the techniques cover, in story order."""
    present = {stage_by_technique[t] for t in technique_ids if t in stage_by_technique}
    return [s for s in STAGES if s in present]
