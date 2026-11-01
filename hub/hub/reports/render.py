"""Report text and X-ARF (v0.2 fields) for a group of targets.

Evidence is deliberately coarse: a day range, services, activity, tags, families, the number of
sensors as a bucket label and the number of countries (only from three). Never a node id, a
pseudonym, a fingerprint or an exact count. The wording comes from a template file on the hub
machine; without one the report states the facts only.
"""

from __future__ import annotations

import ipaddress
import re
import string
from dataclasses import dataclass
from datetime import UTC, date, datetime, time
from email.utils import format_datetime

import yaml
from suckerpot_netproto import blind, buckets

KIND_NOUN = {
    "attack_source": ("address", "addresses"),
    "c2": ("command-and-control endpoint", "command-and-control endpoints"),
    "malware_host": ("malware download location", "malware download locations"),
}
XARF_TYPES = {
    "attack_source": ("abuse", "login-attack"),
    "c2": ("malware", "malware-distribution"),
    "malware_host": ("malware", "malware-distribution"),
}
XARF_SCHEMA = "http://www.x-arf.org/schema/{category}_{report_type}_0.1.2.json"
_SELF_TERMS = re.compile(r"suckerpot|selfhostr|honeypot", re.IGNORECASE)


@dataclass(frozen=True)
class ReportTarget:
    id: str
    kind: str  # ip | url | domain | sha256 | c2_ip | c2_domain
    value: str
    first_day: date
    last_day: date
    services: tuple[str, ...]
    activity: tuple[str, ...]
    tags: tuple[str, ...]
    families: tuple[str, ...]
    node_count: int
    country_count: int
    port: int | None = None


@dataclass(frozen=True)
class RenderedReport:
    subject: str
    body: str
    xarf: str | None


def defang(value: str) -> str:
    """Make a URL or host inert in a mail body: hxxp and [.]."""
    out = re.sub(r"^http", "hxxp", value, flags=re.IGNORECASE)
    return out.replace(".", "[.]")


def _line(t: ReportTarget) -> str:
    value = t.value if t.kind in ("ip", "c2_ip") else defang(t.value)
    parts = [value if t.port is None else f"{value} (port {t.port})"]
    if t.services:
        parts.append("services " + ", ".join(t.services))
    if t.activity:
        parts.append("activity " + ", ".join(t.activity))
    if t.tags:
        parts.append("tags " + ", ".join(t.tags))
    if t.families:
        parts.append("families " + ", ".join(t.families))
    parts.append(f"first {t.first_day.isoformat()}, last {t.last_day.isoformat()}")
    return "- " + "; ".join(parts)


def sensors_label(counts: list[int]) -> str:
    low = min(counts)
    return buckets.NODES_BUCKET_LABELS[buckets.nodes_bucket(max(low, 5))].replace("-", " to ")


def facts(report_kind: str, targets: list[ReportTarget]) -> str:
    one, many = KIND_NOUN[report_kind]
    noun = one if len(targets) == 1 else many
    first = min(t.first_day for t in targets)
    last = max(t.last_day for t in targets)
    sensors = sensors_label([t.node_count for t in targets])
    countries = min(t.country_count for t in targets)
    where = f" in {countries} or more countries" if countries >= buckets.MIN_COUNTRIES_SHOWN else ""
    head = (
        f"The following {noun} {'was' if len(targets) == 1 else 'were'} observed by "
        f"{sensors} independent sensors{where} between {first.isoformat()} and "
        f"{last.isoformat()} (UTC)."
    )
    lines = [_line(t) for t in sorted(targets, key=lambda x: x.value)]
    return head + "\n\n" + "\n".join(lines)


def render(
    report_kind: str,
    targets: list[ReportTarget],
    *,
    template: str = "",
    reply_to: str = "",
    sent_at: date | None = None,
) -> RenderedReport:
    first = min(t.first_day for t in targets)
    last = max(t.last_day for t in targets)
    one, many = KIND_NOUN[report_kind]
    subject = (
        f"Abuse report: {len(targets)} {one if len(targets) == 1 else many}, "
        f"{first.isoformat()} to {last.isoformat()}"
    )
    body_facts = facts(report_kind, targets)
    if template.strip():
        body = string.Template(template).safe_substitute(
            facts=body_facts,
            count=str(len(targets)),
            first_day=first.isoformat(),
            last_day=last.isoformat(),
            reply_to=reply_to,
        )
    else:
        body = body_facts + (f"\n\nReply to: {reply_to}" if reply_to else "")
    xarf = None
    if len(targets) == 1:
        xarf = render_xarf(report_kind, targets[0], reply_to=reply_to, sent_at=sent_at)
    for text in (subject, body, xarf or ""):
        if _SELF_TERMS.search(text):
            raise ValueError("report text names the project")
    return RenderedReport(subject=subject, body=body, xarf=xarf)


def _source(t: ReportTarget) -> tuple[str, str]:
    """(X-ARF Source-Type, Source) of a target."""
    if t.kind == "url":
        return "uri", t.value
    if t.kind in ("domain", "c2_domain"):
        return "domain", t.value
    version = ipaddress.ip_address(t.value).version
    return ("ipv6" if version == 6 else "ipv4"), t.value


def render_xarf(
    report_kind: str, t: ReportTarget, *, reply_to: str = "", sent_at: date | None = None
) -> str:
    category, report_type = XARF_TYPES[report_kind]
    source_type, source = _source(t)
    service = (
        blind.canonical_url(t.value).split(":", 1)[0]
        if t.kind == "url"
        else (t.services[0] if t.services else "unknown")
    )
    when = datetime.combine(sent_at or t.last_day, time(), UTC)
    report: dict[str, object] = {}
    if reply_to:
        report["Reported-From"] = reply_to
    report.update(
        {
            "Category": category,
            "Report-Type": report_type,
            "Service": service,
            "Version": 0.2,
            "User-Agent": "abuse-reporter/1",
            "Date": format_datetime(when),
            "Source-Type": source_type,
            "Source": source,
            "Attachment": "text/plain",
            "Schema-URL": XARF_SCHEMA.format(category=category, report_type=report_type),
            "Occurrences": 1,
        }
    )
    return yaml.safe_dump(report, sort_keys=False, default_flow_style=False, width=1000)
