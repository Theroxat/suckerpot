# ruff: noqa: E501
"""Renders a weekly summary as one self-contained, printable HTML page.

* Built from the summary only, and every value goes through ``html.escape``: whatever an attacker
  managed to put into a campaign name or a tag is text, never markup.
* No script, no external file, no image: the API serves it with ``default-src 'none'`` and only
  allows the one inline style block. It fits on one A4 page when printed ("Print to PDF").
"""

from __future__ import annotations

import html
from typing import Any

STYLE = """
:root{color-scheme:light}
*{box-sizing:border-box}
body{margin:0;background:#f4f5f7;color:#16181d;font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:800px;margin:0 auto;padding:32px 28px;background:#fff}
h1{font-size:22px;margin:0 0 4px}
h2{font-size:13px;letter-spacing:.06em;text-transform:uppercase;color:#4b5563;margin:26px 0 8px;border-bottom:1px solid #e5e7eb;padding-bottom:4px}
.lead{font-size:16px;margin:12px 0 18px}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
.kpi{border:1px solid #e5e7eb;border-radius:8px;padding:10px 12px}
.kpi b{display:block;font-size:22px;font-variant-numeric:tabular-nums}
.kpi span{color:#4b5563;font-size:12px}
ol,ul{margin:0;padding-left:20px}
li{margin:3px 0}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:4px 8px 4px 0;border-bottom:1px solid #f0f1f3;vertical-align:top}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:20px}
.muted{color:#6b7280;font-size:12px}
code{font:12px ui-monospace,Menlo,monospace}
footer{margin-top:28px;color:#6b7280;font-size:12px}
@media (max-width:600px){.kpis{grid-template-columns:repeat(2,1fr)}.cols{grid-template-columns:1fr}}
@media print{body{background:#fff}main{padding:0;max-width:none}@page{size:A4;margin:14mm}h2{break-after:avoid}table,.kpi{break-inside:avoid}}
"""

esc = html.escape


def _n(value: Any) -> str:
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return "0"


def _table(headers: tuple[str, str], rows: list[tuple[str, str]]) -> str:
    if not rows:
        return '<p class="muted">Nothing this week.</p>'
    head = f'<tr><th>{esc(headers[0])}</th><th class="n">{esc(headers[1])}</th></tr>'
    body = "".join(f'<tr><td>{esc(a)}</td><td class="n">{esc(b)}</td></tr>' for a, b in rows)
    return f"<table>{head}{body}</table>"


def render_report(summary: dict[str, Any], generated_at: str = "") -> str:
    t = summary.get("totals", {})
    change = t.get("change_pct")
    change_text = "no comparison" if change is None else f"{change:+d}% vs previous week"
    kpis = [
        ("Attack sessions", _n(t.get("sessions")), change_text),
        ("Different addresses", _n(t.get("sources")), "unique sources"),
        ("Ran commands", _n(t.get("with_commands")), "got past the login"),
        ("Dropped malware", _n(t.get("malware")), "sessions"),
    ]
    kpi_html = "".join(
        f'<div class="kpi"><b>{esc(v)}</b>{esc(label)}<br><span>{esc(sub)}</span></div>'
        for label, v, sub in kpis
    )
    actions = "".join(f"<li>{esc(str(a))}</li>" for a in summary.get("actions", []))
    sensors = [
        (str(r.get("sensor", "")), _n(r.get("sessions"))) for r in summary.get("by_sensor", [])
    ]
    countries = [
        (str(r.get("country", "")), _n(r.get("sessions"))) for r in summary.get("countries", [])
    ]
    tags = [(str(r.get("tag", "")), _n(r.get("sessions"))) for r in summary.get("tags", [])]
    campaigns = [
        (f"{r.get('name', '')} ({r.get('severity', '')}, {_n(r.get('sources'))} sources)",
         _n(r.get("sessions")))
        for r in summary.get("campaigns", [])
    ]  # fmt: skip
    hosts = [
        (str(r.get("host", "")), _n(r.get("sightings"))) for r in summary.get("download_hosts", [])
    ]
    cves = [
        (str(r.get("cve_id", "")), _n(r.get("sessions"))) for r in summary.get("watched_cves", [])
    ]
    title = f"Weekly report, {summary.get('week_start', '')} to {summary.get('week_end', '')}"
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta name="referrer" content="no-referrer">'
        f"<title>{esc(title)}</title><style>{STYLE}</style></head><body><main>"
        f"<h1>{esc(title)}</h1>"
        f'<div class="muted">Times in {esc(str(summary.get("timezone", "UTC")))}</div>'
        f'<p class="lead">{esc(str(summary.get("headline", "")))}</p>'
        f'<div class="kpis">{kpi_html}</div>'
        f"<h2>What to do next</h2><ol>{actions}</ol>"
        f'<div class="cols"><div><h2>Services attacked</h2>{_table(("Service", "Sessions"), sensors)}</div>'
        f"<div><h2>Where attacks came from</h2>{_table(('Country', 'Sessions'), countries)}</div></div>"
        f"<h2>What attackers did</h2>{_table(('Behaviour', 'Sessions'), tags)}"
        f"<h2>New campaigns</h2>{_table(('Campaign', 'Sessions'), campaigns)}"
        f"<h2>New malware download hosts (defanged)</h2>{_table(('Host', 'Times seen'), hosts)}"
        f"<h2>Watched vulnerabilities seen</h2>{_table(('CVE', 'Sessions'), cves)}"
        "<footer>IP addresses are not included in this report. Indicators are defanged: "
        "replace [.] with . only in a safe tool. "
        f"{esc('Generated ' + generated_at + '.' if generated_at else '')}</footer>"
        "</main></body></html>"
    )
