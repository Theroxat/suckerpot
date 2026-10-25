# ruff: noqa: E501
"""Renders a weekly summary as one self-contained, printable HTML page.

* Built from the summary only, and every value goes through ``html.escape``: whatever an attacker
  managed to put into a campaign name or a tag is text, never markup.
* No script, no external file, no image: the API serves it with ``default-src 'none'`` and only
  allows the one inline style block.
* Made to be forwarded as is: it fits on one A4 page when printed ("Print to PDF") and reads in
  black and white. Nothing relies on colour; every table is capped at ``ROWS`` rows, with the
  remainder folded into one "N more" line, so the page cannot spill over.
"""

from __future__ import annotations

import html
from datetime import date
from typing import Any

from ingest.reports.build import sensor_label

ROWS = 7

STYLE = """
:root{color-scheme:light}
*{box-sizing:border-box}
body{margin:0;background:#f4f4f5;color:#111214;font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;font-variant-numeric:tabular-nums;-webkit-print-color-adjust:exact;print-color-adjust:exact}
main{max-width:820px;margin:24px auto;padding:36px 40px;background:#fff;border:1px solid #e4e4e7;border-radius:12px}
header{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:baseline;gap:4px 16px;border-bottom:2px solid #111214;padding-bottom:10px}
.brand{font-size:12px;font-weight:600;letter-spacing:.08em;text-transform:uppercase}
.meta{font-size:12px;color:#52525b}
h1{font-size:24px;font-weight:600;line-height:1.25;letter-spacing:-.01em;margin:18px 0 6px}
.lead{font-size:16px;color:#27272a;margin:0 0 18px;max-width:64ch}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:0 0 4px}
.kpi{border:1px solid #d4d4d8;border-radius:8px;padding:10px 12px}
.kpi b{display:block;font-size:24px;line-height:1.2;font-weight:600;letter-spacing:-.01em}
.kpi .l{display:block;font-size:13px;font-weight:500}
.kpi .s{display:block;font-size:12px;color:#52525b}
h2{font-size:12px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;margin:22px 0 6px;padding-bottom:4px;border-bottom:1px solid #a1a1aa}
.todo{margin:0;padding-left:22px}
.todo li{margin:3px 0;padding-left:2px}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:0 28px}
table{border-collapse:collapse;width:100%;font-size:13px}
th{font-size:11px;font-weight:600;color:#52525b;text-align:left;padding:2px 0 3px}
td{padding:3px 8px 3px 0;border-top:1px solid #e4e4e7;vertical-align:top;overflow-wrap:anywhere}
th.n,td.n{text-align:right;padding-right:0;white-space:nowrap;width:1%}
td.more{color:#52525b;font-style:italic}
.mono{font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace;font-size:12px}
.none{font-size:13px;color:#52525b;margin:4px 0}
footer{margin-top:22px;padding-top:8px;border-top:1px solid #a1a1aa;color:#52525b;font-size:11px}
@media (max-width:640px){main{margin:0;border:0;border-radius:0;padding:24px 16px}.kpis{grid-template-columns:repeat(2,1fr)}.cols{grid-template-columns:1fr}}
@media print{
@page{size:A4;margin:12mm 14mm}
body{background:#fff;font-size:11.5px;line-height:1.4}
main{max-width:none;margin:0;padding:0;border:0;border-radius:0}
h1{font-size:19px;margin:12px 0 4px}
.lead{font-size:13px;margin-bottom:12px}
.kpi{padding:7px 10px}.kpi b{font-size:19px}.kpi .l{font-size:11.5px}.kpi .s{font-size:10.5px}
h2{font-size:10.5px;margin:14px 0 4px;break-after:avoid}
table{font-size:11px;table-layout:fixed}th{font-size:9.5px;padding:0 0 2px}td{padding:1.5px 6px 1.5px 0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}th.n,td.n{width:5.5em}.mono{font-size:10.5px}
.todo li{margin:1px 0}
footer{margin-top:14px;font-size:9.5px}
table,.kpi,.todo{break-inside:avoid}
}
"""

esc = html.escape


def _n(value: Any) -> str:
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return "0"


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _table(
    headers: tuple[str, str], rows: list[tuple[str, Any]], *, mono: bool = False, empty: str
) -> str:
    """A two-column table, at most ``ROWS`` rows; the rest folds into one "N more" line."""
    if not rows:
        return f'<p class="none">{esc(empty)}</p>'
    shown, rest = rows[:ROWS], rows[ROWS:]
    cell = ' class="mono"' if mono else ""
    head = f'<tr><th>{esc(headers[0])}</th><th class="n">{esc(headers[1])}</th></tr>'
    body = "".join(f'<tr><td{cell}>{esc(a)}</td><td class="n">{_n(b)}</td></tr>' for a, b in shown)
    if rest:
        total = sum(_int(b) for _, b in rest)
        body += f'<tr><td class="more">{len(rest)} more</td><td class="n">{_n(total)}</td></tr>'
    return f"<table>{head}{body}</table>"


def _day(value: Any, year: bool = False) -> str:
    """Oct 19, or Oct 25, 2026 with the year; anything that is not an ISO date is kept as text."""
    try:
        d = date.fromisoformat(str(value))
    except ValueError:
        return str(value)
    return f"{d:%b} {d.day}" + (f", {d.year}" if year else "")


def _section(title: str, content: str) -> str:
    return f"<section><h2>{esc(title)}</h2>{content}</section>"


def render_report(summary: dict[str, Any], generated_at: str = "") -> str:
    t = summary.get("totals", {})
    change = t.get("change_pct")
    if change is None:
        change_text = "no earlier week to compare"
    elif abs(_int(change)) < 5:
        change_text = "about the same as the week before"
    else:
        change_text = (
            f"{'up' if _int(change) > 0 else 'down'} {abs(_int(change))}% on the week before"
        )
    kpis = [
        ("Attack sessions", _n(t.get("sessions")), change_text),
        ("Different addresses", _n(t.get("sources")), "unique sources"),
        ("Ran commands", _n(t.get("with_commands")), "sessions that got past the login"),
        ("Dropped malware", _n(t.get("malware")), "sessions with a download"),
    ]
    kpi_html = "".join(
        f'<div class="kpi"><b>{esc(v)}</b><span class="l">{esc(label)}</span><span class="s">{esc(sub)}</span></div>'
        for label, v, sub in kpis
    )
    actions = "".join(f"<li>{esc(str(a))}</li>" for a in summary.get("actions", []))
    sensors = [
        (sensor_label(r.get("sensor", "")), r.get("sessions")) for r in summary.get("by_sensor", [])
    ]
    countries = [
        (str(r.get("country", "")), r.get("sessions")) for r in summary.get("countries", [])
    ]
    tags = [(str(r.get("tag", "")), r.get("sessions")) for r in summary.get("tags", [])]
    campaigns = [
        (
            f"{r.get('name', '')} ({r.get('severity', '')}, {_n(r.get('sources'))} sources)",
            r.get("sessions"),
        )
        for r in summary.get("campaigns", [])
    ]
    hosts = [
        (str(r.get("host", "")), r.get("sightings")) for r in summary.get("download_hosts", [])
    ]
    cves = [(str(r.get("cve_id", "")), r.get("sessions")) for r in summary.get("watched_cves", [])]
    start, end = str(summary.get("week_start", "")), str(summary.get("week_end", ""))
    title = f"Week of {_day(start)} to {_day(end, year=True)}"
    meta = f"{start} to {end} · times in {summary.get('timezone', 'UTC')}"
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta name="referrer" content="no-referrer">'
        f"<title>{esc('Weekly report, ' + title)}</title><style>{STYLE}</style></head><body><main>"
        f'<header><span class="brand">SuckerPot · Weekly attack report</span><span class="meta">{esc(meta)}</span></header>'
        f"<h1>{esc(title)}</h1>"
        f'<p class="lead">{esc(str(summary.get("headline", "")))}</p>'
        f'<div class="kpis">{kpi_html}</div>'
        f'<h2>What to do next</h2><ol class="todo">{actions}</ol>'
        '<div class="cols">'
        + _section(
            "Services attacked",
            _table(("Service", "Sessions"), sensors, empty="No sessions this week."),
        )
        + _section(
            "Where attacks came from",
            _table(("Country", "Sessions"), countries, empty="No located sessions this week."),
        )
        + _section(
            "What attackers did",
            _table(
                ("Behaviour", "Sessions"), tags, mono=True, empty="No tagged behaviour this week."
            ),
        )
        + _section(
            "Watched vulnerabilities seen",
            _table(
                ("CVE", "Sessions"), cves, mono=True, empty="None of your watched CVEs was tried."
            ),
        )
        + _section(
            "New campaigns",
            _table(("Campaign", "Sessions"), campaigns, empty="No new campaign this week."),
        )
        + _section(
            "New malware download hosts",
            _table(
                ("Host (defanged)", "Times seen"),
                hosts,
                mono=True,
                empty="No new download host this week.",
            ),
        )
        + "</div>"
        "<footer>IP addresses are not included in this report. Indicators are defanged: "
        "replace [.] with . only in a safe tool. "
        f"{esc('Generated ' + generated_at + '.' if generated_at else '')}</footer>"
        "</main></body></html>"
    )
