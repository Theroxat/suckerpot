"""What an alert says, and how each channel kind shows it.

``build_message`` turns a candidate (raw facts from the database) into a neutral message: plain
English sentence first, a few facts, one next action. It is built per channel, because the
"mask IP addresses" choice is per channel, and the stored outbox payload never holds an unmasked
address. The renderers only format; every value was cleaned by ``ingest.alerts.text`` already and
the renderers escape it again for their medium.
"""

from __future__ import annotations

import html
from dataclasses import dataclass, field
from typing import Any

from ingest.alerts.text import clean_text, defang, show_ip

SEVERITIES = ("info", "notice", "warning", "severe")
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}
COLORS = {"info": 0x6B7280, "notice": 0x3B82F6, "warning": 0xF59E0B, "severe": 0xDC2626}
MAX_FACTS = 8
MAX_DIGEST_ITEMS = 10
MD_SPECIAL = set("\\*_~`>|[]()#@<")


@dataclass(frozen=True, slots=True)
class Candidate:
    """One thing worth an alert, before it is formatted for a channel."""

    rule: str
    key: str  # deduplication key, at most 128 characters
    severity: str
    data: dict[str, Any] = field(default_factory=dict)


def _join(values: list[Any], limit: int = 4) -> str:
    items = [clean_text(v, 40) for v in values[:limit] if str(v)]
    extra = len(values) - limit
    return ", ".join(items) + (f" and {extra} more" if extra > 0 else "")


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n:,} {one if n == 1 else (many or one + 's')}"


def build_message(c: Candidate, *, mask_ips: bool) -> dict[str, Any]:
    d = c.data
    facts: list[list[str]] = []
    link: str | None = None
    if c.rule == "new_campaign":
        sources = int(d.get("sources", 0))
        title = f"New campaign: {clean_text(d.get('name', 'unnamed'), 80)}"
        summary = (
            f"A new coordinated campaign appeared: {_plural(sources, 'address', 'addresses')} "
            f"are running the same attack against the honeypot."
        )
        facts = [
            ["Sessions", f"{int(d.get('sessions', 0)):,}"],
            ["Sources", f"{sources:,}"],
            ["Sensors", _join(list(d.get("sensors") or []))],
            ["Countries", _join(list(d.get("countries") or []))],
            ["Techniques", _join(list(d.get("techniques") or []), 5)],
        ]
        action = "Open the campaign, then check whether your own services expose the same thing."
        link = f"/campaigns/{int(d['id'])}" if "id" in d else None
    elif c.rule == "new_download_host":
        host = defang(str(d.get("host", "")), 100)
        title = f"New malware download host: {host}"
        summary = "A host never seen before was used to serve a payload to the honeypot."
        facts = [
            ["Host (defanged)", host],
            ["Times seen", f"{int(d.get('sightings', 1)):,}"],
            ["Sensors", _join(list(d.get("sensors") or []))],
        ]
        if d.get("family"):
            facts.append(["Known as", clean_text(d["family"], 60)])
        action = "Block this host on your web proxy or DNS filter."
        link = "/malware"
    elif c.rule == "malware_drop":
        title = "Malware was dropped on the honeypot"
        summary = (
            "An attacker downloaded or ran a payload in a session on the "
            f"{clean_text(d.get('sensor', ''), 20)} sensor."
        )
        facts = [
            ["Source", show_ip(str(d.get("src_ip", "")), mask_ips)],
            ["Country", clean_text(d.get("country") or "unknown", 40)],
            ["Network", clean_text(d.get("org") or "unknown", 60)],
            ["Tags", _join(list(d.get("tags") or []), 5)],
        ]
        action = "Open the session to see the commands and the download URL."
        link = (
            f"/attacks/{clean_text(d.get('session_id', ''), 64)}" if d.get("session_id") else None
        )
    elif c.rule == "watched_cve_seen":
        cve = clean_text(d.get("cve_id", ""), 24)
        n = int(d.get("sessions", 0))
        title = f"{cve} is being exploited against the honeypot"
        summary = f"A vulnerability you watch was tried in {_plural(n, 'session')} today."
        facts = [["CVE", cve], ["Sessions", f"{n:,}"]]
        if d.get("title"):
            facts.append(["About", clean_text(d["title"], 100)])
        action = "Check that your own systems are patched against this vulnerability."
        link = "/cves"
    elif c.rule == "weekly_report":
        week = clean_text(d.get("week_start", ""), 12)
        title = f"Weekly report for the week of {week}"
        summary = clean_text(d.get("headline", "Your weekly honeypot report is ready."), 200)
        facts = [
            [clean_text(k, 40), clean_text(v, 80)]
            for k, v in list(d.get("facts") or [])[:MAX_FACTS]
        ]
        action = "Open the report for what changed and what to do next."
        link = f"/reports/{week}"
    else:
        raise ValueError("unknown rule kind")
    return {
        "v": 1,
        "rule": c.rule,
        "severity": c.severity,
        "title": title,
        "summary": summary,
        "facts": [f for f in facts if f[1]][:MAX_FACTS],
        "action": action,
        "link": link,
    }


def build_digest(messages: list[dict[str, Any]], period: str) -> dict[str, Any]:
    """One message that stands for several that could not be sent one by one."""
    worst = max((m.get("severity", "info") for m in messages), key=lambda s: SEVERITY_RANK[s])
    shown = messages[:MAX_DIGEST_ITEMS]
    return {
        "v": 1,
        "rule": messages[0]["rule"] if messages else "new_campaign",
        "severity": worst,
        "title": f"{_plural(len(messages), 'alert')} {period}",
        "summary": (
            "Too many alerts arrived at once, so here is a short list instead of one message each."
        ),
        "facts": [[m["severity"], clean_text(m["title"], 100)] for m in shown],
        "action": "Open Alerts and reports in the dashboard for the full list.",
        "link": "/defend/alerts",
        "digest": True,
    }


def sample_message() -> dict[str, Any]:
    return {
        "v": 1,
        "rule": "new_campaign",
        "severity": "info",
        "title": "Test message",
        "summary": "This channel works. Real alerts will look like this one.",
        "facts": [["Sent by", "alerts test"]],
        "action": "Nothing to do.",
        "link": "/defend/alerts",
    }


def _md(value: str) -> str:
    return "".join("\\" + ch if ch in MD_SPECIAL else ch for ch in value)


def _url(base: str, link: str | None) -> str | None:
    return base + link if base and link else None


def render_discord(msg: dict[str, Any], base_url: str = "") -> dict[str, Any]:
    fields = [
        {"name": _md(clean_text(k, 60)), "value": _md(clean_text(v, 200)) or "-", "inline": True}
        for k, v in msg.get("facts", [])
    ]
    embed: dict[str, Any] = {
        "title": _md(clean_text(msg["title"], 200)),
        "description": _md(clean_text(msg["summary"], 500))
        + "\n\n**Next:** "
        + _md(clean_text(msg["action"], 200)),
        "color": COLORS.get(msg["severity"], COLORS["info"]),
        "fields": fields[:MAX_FACTS],
    }
    url = _url(base_url, msg.get("link"))
    if url:
        embed["url"] = url
    # No mention of anyone or anything: attacker-controlled text must never ping a role.
    return {"username": "Honeypot alerts", "allowed_mentions": {"parse": []}, "embeds": [embed]}


def render_teams(msg: dict[str, Any], base_url: str = "") -> dict[str, Any]:
    body: list[dict[str, Any]] = [
        {
            "type": "TextBlock",
            "text": _md(clean_text(msg["title"], 200)),
            "weight": "Bolder",
            "size": "Medium",
            "wrap": True,
        },
        {"type": "TextBlock", "text": _md(clean_text(msg["summary"], 500)), "wrap": True},
    ]
    if msg.get("facts"):
        body.append(
            {
                "type": "FactSet",
                "facts": [
                    {"title": _md(clean_text(k, 60)), "value": _md(clean_text(v, 200))}
                    for k, v in msg["facts"]
                ],
            }
        )
    body.append(
        {"type": "TextBlock", "text": "Next: " + _md(clean_text(msg["action"], 200)), "wrap": True}
    )
    card: dict[str, Any] = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": body,
    }
    url = _url(base_url, msg.get("link"))
    if url:
        card["actions"] = [{"type": "Action.OpenUrl", "title": "Open in dashboard", "url": url}]
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": card,
            }
        ],
    }


def render_email(msg: dict[str, Any], base_url: str = "") -> tuple[str, str, str]:
    """Return ``(subject, plain text, html)``. The HTML escapes every value."""
    subject = clean_text(f"[{msg['severity']}] {msg['title']}", 150)
    url = _url(base_url, msg.get("link"))
    lines = [clean_text(msg["title"], 200), "", clean_text(msg["summary"], 500), ""]
    lines += [f"{clean_text(k, 60)}: {clean_text(v, 200)}" for k, v in msg.get("facts", [])]
    lines += ["", "Next: " + clean_text(msg["action"], 200)]
    if url:
        lines += ["", f"Open: {url}"]
    text = "\n".join(lines) + "\n"
    esc = html.escape
    rows = "".join(
        f'<tr><td style="padding:2px 12px 2px 0;color:#555">{esc(clean_text(k, 60))}</td>'
        f'<td style="padding:2px 0">{esc(clean_text(v, 200))}</td></tr>'
        for k, v in msg.get("facts", [])
    )
    link = f'<p><a href="{esc(url, quote=True)}">Open in the dashboard</a></p>' if url else ""
    body = (
        '<div style="font-family:system-ui,sans-serif;max-width:560px">'
        f'<h2 style="margin:0 0 8px">{esc(clean_text(msg["title"], 200))}</h2>'
        f"<p>{esc(clean_text(msg['summary'], 500))}</p><table>{rows}</table>"
        f"<p><strong>Next:</strong> {esc(clean_text(msg['action'], 200))}</p>{link}</div>"
    )
    return subject, text, body
