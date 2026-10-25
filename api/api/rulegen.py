"""Text of Sigma and Suricata rules built from what the honeypot recorded (M16). Pure code.

Everything that comes from an attacker (paths, commands, host names, URLs) is untrusted. The rules
therefore never carry it anywhere but inside one quoted value, after these steps:

* it must be printable ASCII (0x20 to 0x7E) and is cut to a fixed length, else it is dropped;
* in Sigma it becomes a single-quoted YAML scalar (the only character that needs care there is
  the quote itself, which is doubled); it can never start a new key or a new document;
* in Suricata it becomes a ``content`` value in which every character outside a small safe set
  is written as ``|hex|`` bytes, so a quote, semicolon, backslash or pipe cannot end the option
  or add one.

Titles, messages and descriptions are built from fixed text and the tag names ingest assigned
(checked to be ``[a-z0-9-]``), never from captured strings. Every rule says in its description
and in its message that it must be reviewed before it is deployed.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import date
from typing import Literal

RuleKind = Literal["sigma", "suricata"]
Severity = Literal["notice", "warning", "severe"]

NAMESPACE = uuid.UUID("5f0c7f2e-3f64-4a6e-9a43-2d6f1a0c9b11")
REVIEW = "Review before deploying"
SID_BASE = 4_100_000
SID_SPAN = 899_999
SAFE_CONTENT = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._~/-:=")
TAG_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
MAX_VALUE = 160
MIN_PATH = 6
GENERIC_PATHS = frozenset({"/", "/index.php", "/index.html", "/robots.txt", "/favicon.ico"})

ATTACK_TAGS: dict[str, tuple[str, ...]] = {
    "php2shell": ("attack.initial-access", "attack.t1190"),
    "sql-rce": ("attack.initial-access", "attack.t1190"),
    "env-file-probe": ("attack.reconnaissance", "attack.t1595"),
    "wordpress-bruteforce": ("attack.credential-access", "attack.t1110"),
    "phpmyadmin-bruteforce": ("attack.credential-access", "attack.t1110"),
    "crypto-miner": ("attack.impact", "attack.t1496"),
    "malware-drop": ("attack.command-and-control", "attack.t1105"),
    "mirai": ("attack.command-and-control", "attack.t1105"),
}
LEVELS = {"notice": "low", "warning": "medium", "severe": "high"}
SEVERE_TAGS = frozenset({"php2shell", "malware-drop", "mirai", "crypto-miner", "eternalblue"})


@dataclass(frozen=True, slots=True)
class Generated:
    """One generated rule with the evidence behind it."""

    key: str
    kind: RuleKind
    title: str
    severity: Severity
    source: str
    rationale: str
    text: str
    sessions: int
    sources: int


def printable(value: object, limit: int = MAX_VALUE) -> str | None:
    """The value cut to ``limit`` characters if it is printable ASCII, else ``None``."""
    if not isinstance(value, str):
        return None
    text = value.strip()[:limit]
    if not text or any(not 0x20 <= ord(c) <= 0x7E for c in text):
        return None
    return text


def safe_tag(tag: str) -> bool:
    return 0 < len(tag) <= 32 and set(tag) <= TAG_CHARS


def severity_of(tag: str, score: int = 0) -> Severity:
    if tag in SEVERE_TAGS or score >= 85:
        return "severe"
    return "warning" if score >= 60 or tag in ATTACK_TAGS else "notice"


def yaml_scalar(value: str) -> str:
    """A single-quoted YAML scalar. ``value`` must already be printable ASCII."""
    return "'" + value.replace("'", "''") + "'"


def sigma_escape(value: str) -> str:
    """Make ``* ? \\`` literal: in a Sigma ``contains`` or ``endswith`` match they are wildcards."""
    return value.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")


def suricata_content(value: str) -> str:
    """The inside of ``content:"..."``: safe characters as they are, the rest as |hex| bytes."""
    out: list[str] = []
    run: list[str] = []
    for ch in value:
        if ch in SAFE_CONTENT:
            if run:
                out.append("|" + " ".join(run) + "|")
                run = []
            out.append(ch)
        else:
            run.append(f"{ord(ch):02x}")
    if run:
        out.append("|" + " ".join(run) + "|")
    return "".join(out)


def sigma_id(key: str) -> str:
    return str(uuid.uuid5(NAMESPACE, key))


def sid_for(key: str, taken: set[int]) -> int:
    n = SID_BASE + int(hashlib.sha256(key.encode()).hexdigest()[:8], 16) % SID_SPAN
    while n in taken:
        n += 1
    taken.add(n)
    return n


def _sigma(
    key: str,
    title: str,
    description: str,
    logsource: Sequence[tuple[str, str]],
    field: str,
    values: Iterable[str],
    level: str,
    tags: Sequence[str],
    falsepositive: str,
    today: date,
    exact: Sequence[str] = (),
) -> str:
    lines = [
        f"title: {yaml_scalar(title)}",
        f"id: {sigma_id(key)}",
        "status: experimental",
        f"description: {yaml_scalar(description)}",
        "author: SuckerPot (generated)",
        f"date: {today.isoformat()}",
    ]
    if tags:
        lines.append("tags:")
        lines += [f"    - {t}" for t in tags]
    lines.append("logsource:")
    lines += [f"    {k}: {v}" for k, v in logsource]
    lines += ["detection:", "    selection:", f"        {field}:"]
    lines += [f"            - {yaml_scalar(sigma_escape(v))}" for v in values]
    condition = "selection"
    if exact:
        condition = "selection or exact"
        lines += ["    exact:", "        query:"]
        lines += [f"            - {yaml_scalar(sigma_escape(v))}" for v in exact]
    lines += [
        f"    condition: {condition}",
        "falsepositives:",
        f"    - {yaml_scalar(falsepositive)}",
        f"level: {level}",
    ]
    return "\n".join(lines) + "\n"


def _clean_all(values: Iterable[object], limit: int = MAX_VALUE) -> list[str]:
    seen: dict[str, None] = {}
    for v in values:
        c = printable(v, limit)
        if c is not None:
            seen.setdefault(c)
    return list(seen)


def sigma_web_paths(
    tag: str, paths: Sequence[str], severity: Severity, sessions: int, sources: int, today: date
) -> Generated | None:
    """Web server log rule: requests for paths that attackers used with this technique."""
    values = [p for p in _clean_all(paths) if p.startswith("/") and p not in GENERIC_PATHS]
    values = [p for p in values if len(p) >= MIN_PATH][:20]
    if not safe_tag(tag) or not values:
        return None
    key = f"sigma:web:{tag}"
    title = f"SuckerPot: web requests seen with {tag} attacks"
    description = (
        f"{REVIEW}. Request paths that attackers used in {tag} attempts against a decoy web "
        "server. They may also match your own pages."
    )
    text = _sigma(
        key, title, description, [("category", "webserver")], "c-uri|contains", values,
        LEVELS[severity], ATTACK_TAGS.get(tag, ()),
        "Your own application may use the same path. Check the hits before blocking.",
        today,
    )  # fmt: skip
    return Generated(
        key, "sigma", title, severity, "web-paths",
        f"{len(values)} request path(s) seen in {tag} attempts.", text, sessions, sources,
    )  # fmt: skip


def sigma_commands(
    tag: str, commands: Sequence[str], severity: Severity, sessions: int, sources: int, today: date
) -> Generated | None:
    """Linux process rule: command lines typed by attackers in sessions with this tag."""
    values = [c for c in _clean_all(commands, 120) if len(c) >= 12][:20]
    if not safe_tag(tag) or not values:
        return None
    key = f"sigma:cmd:{tag}"
    title = f"SuckerPot: shell commands seen with {tag} attacks"
    description = (
        f"{REVIEW}. Command lines that attackers typed on decoy servers in {tag} sessions. "
        "Matching is by substring, so short or common text can match harmless activity."
    )
    text = _sigma(
        key, title, description, [("category", "process_creation"), ("product", "linux")],
        "CommandLine|contains", values, LEVELS[severity], ATTACK_TAGS.get(tag, ()),
        "Administrators may run similar commands. Check the user and the parent process.",
        today,
    )  # fmt: skip
    return Generated(
        key, "sigma", title, severity, "commands",
        f"{len(values)} command line(s) seen in {tag} sessions.", text, sessions, sources,
    )  # fmt: skip


def sigma_domains(
    domains: Sequence[str], sessions: int, sources: int, today: date
) -> Generated | None:
    values = _clean_all(domains, 253)[:50]
    if not values:
        return None
    key = "sigma:dns"
    title = "SuckerPot: DNS lookups of hosts used by attackers"
    description = (
        f"{REVIEW}. Host names that attackers used to download malware or to call back. "
        "A hit means a machine of yours looked one up."
    )
    text = _sigma(
        key, title, description, [("category", "dns")], "query|endswith",
        ["." + v for v in values], "high", ("attack.command-and-control",),
        "A host name may be reused by a legitimate site later. Check its age before acting.",
        today, exact=values,
    )  # fmt: skip
    return Generated(
        key, "sigma", title, "severe", "domains",
        f"{len(values)} host name(s) with a high blocklist score.", text, sessions, sources,
    )  # fmt: skip


def sigma_urls(urls: Sequence[str], sessions: int, sources: int, today: date) -> Generated | None:
    values = []
    for u in _clean_all(urls, 300):
        rest = u.split("://", 1)[-1]
        if len(rest) >= 8:
            values.append(rest)
    values = values[:50]
    if not values:
        return None
    key = "sigma:proxy"
    title = "SuckerPot: proxy requests for download URLs used by attackers"
    description = (
        f"{REVIEW}. Download addresses that attackers used to fetch malware. "
        "Match them against your web proxy log."
    )
    text = _sigma(
        key, title, description, [("category", "proxy")], "c-uri|contains", values, "high",
        ("attack.command-and-control", "attack.t1105"),
        "Very short addresses can match unrelated traffic. Check the full URL.",
        today,
    )  # fmt: skip
    return Generated(
        key, "sigma", title, "severe", "urls",
        f"{len(values)} download address(es) with a high blocklist score.", text, sessions, sources,
    )  # fmt: skip


def sigma_hashes(
    hashes: Sequence[str], sessions: int, sources: int, today: date
) -> Generated | None:
    values = []
    for h in _clean_all(hashes, 64):
        if set(h) <= set("0123456789abcdef"):
            label = {32: "MD5", 40: "SHA1", 64: "SHA256"}.get(len(h))
            if label:
                values.append(f"{label}={h}")
    values = values[:50]
    if not values:
        return None
    key = "sigma:hash"
    title = "SuckerPot: files with hashes seen in attacks"
    description = (
        f"{REVIEW}. Hashes of files that attackers dropped on decoy servers. "
        "The field name may differ in your log source."
    )
    text = _sigma(
        key, title, description, [("category", "process_creation"), ("product", "windows")],
        "Hashes|contains", values, "high", ("attack.execution",),
        "A hash shared with a legitimate tool is unlikely but possible. Confirm with a scanner.",
        today,
    )  # fmt: skip
    return Generated(
        key, "sigma", title, "severe", "hashes",
        f"{len(values)} file hash(es) with a blocklist score.", text, sessions, sources,
    )  # fmt: skip


def _suricata(
    sid: int, msg: str, header: str, options: Sequence[str], classtype: str, today: date
) -> str:
    opts = "; ".join(
        [f'msg:"{msg}"', *options, f"classtype:{classtype}", f"sid:{sid}", "rev:1",
         f'metadata:created_at {today.strftime("%Y_%m_%d")}, review_before_deploying'],
    )  # fmt: skip
    return f"alert {header} ({opts};)\n"


def suricata_web_path(
    tag: str, path: str, severity: Severity, sessions: int, sources: int, today: date,
    taken: set[int],
) -> Generated | None:  # fmt: skip
    value = printable(path)
    if not safe_tag(tag) or value is None or not value.startswith("/") or len(value) < MIN_PATH:
        return None
    if value in GENERIC_PATHS:
        return None
    key = f"suricata:web:{tag}:{value}"
    msg = f"SuckerPot ({REVIEW.lower()}) web request seen with {tag} attacks"
    text = _suricata(
        sid_for(key, taken), msg, "http $EXTERNAL_NET any -> $HOME_NET any",
        ["flow:established,to_server", "http.uri", f'content:"{suricata_content(value)}"'],
        "web-application-attack", today,
    )  # fmt: skip
    return Generated(
        key, "suricata", f"Web request for a path seen in {tag} attacks", severity, "web-paths",
        "An inbound request for a path that attackers used.", text, sessions, sources,
    )  # fmt: skip


def suricata_static_body(
    tag: str, marker: str, sessions: int, sources: int, today: date, taken: set[int]
) -> Generated | None:
    """A fixed request-body marker that belongs to a technique (never taken from captures)."""
    value = printable(marker, 64)
    if not safe_tag(tag) or value is None:
        return None
    key = f"suricata:body:{tag}:{value}"
    msg = f"SuckerPot ({REVIEW.lower()}) request body typical of {tag} attacks"
    text = _suricata(
        sid_for(key, taken), msg, "http $EXTERNAL_NET any -> $HOME_NET any",
        ["flow:established,to_server", "http.request_body", f'content:"{suricata_content(value)}"'],
        "web-application-attack", today,
    )  # fmt: skip
    return Generated(
        key, "suricata", f"Request body typical of {tag} attacks", "severe", "static",
        "A marker the technique needs; common in scans, so it may be noisy.", text, sessions,
        sources,
    )  # fmt: skip


def suricata_domain(
    domain: str, score: int, sessions: int, sources: int, today: date, taken: set[int]
) -> list[Generated]:
    value = printable(domain, 253)
    if value is None:
        return []
    out: list[Generated] = []
    sev = severity_of("", score)
    msg = f"SuckerPot ({REVIEW.lower()}) host used by attackers"
    dns_key = f"suricata:dns:{value}"
    dns = _suricata(
        sid_for(dns_key, taken), msg + " (DNS)", "dns $HOME_NET any -> any any",
        ["dns.query", "dotprefix", f'content:".{suricata_content(value)}"', "nocase", "endswith"],
        "trojan-activity", today,
    )  # fmt: skip
    out.append(
        Generated(
            dns_key,
            "suricata",
            "DNS lookup of a host used by attackers",
            sev,
            "domains",
            "A machine of yours asked for the address of a host that attackers used.",
            dns,
            sessions,
            sources,
        )
    )
    http_key = f"suricata:host:{value}"
    http = _suricata(
        sid_for(http_key, taken), msg + " (HTTP)", "http $HOME_NET any -> $EXTERNAL_NET any",
        ["flow:established,to_server", "http.host", "dotprefix",
         f'content:".{suricata_content(value)}"', "nocase", "endswith"],
        "trojan-activity", today,
    )  # fmt: skip
    out.append(
        Generated(
            http_key,
            "suricata",
            "HTTP request to a host used by attackers",
            sev,
            "domains",
            "A machine of yours sent a web request to a host that attackers used.",
            http,
            sessions,
            sources,
        )
    )
    return out


def suricata_file(rules: Sequence[Generated]) -> str:
    head = (
        "# SuckerPot generated Suricata rules\n"
        f"# {REVIEW.upper()}: built from honeypot traffic, not tested against your network.\n"
        "# Start them in alert mode, read the hits, and tune or remove noisy ones.\n"
        "# Sids are in the local range 4100000 to 4999999.\n\n"
    )
    return head + "".join(r.text for r in rules)


def sigma_file(rules: Sequence[Generated]) -> str:
    head = (
        "# SuckerPot generated Sigma rules\n"
        f"# {REVIEW.upper()}: built from honeypot traffic, not tested against your logs.\n"
        "# Convert them with your Sigma backend, run them as searches first, then decide.\n"
    )
    return head + "".join("---\n" + r.text for r in rules)
