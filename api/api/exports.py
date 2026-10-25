"""Text exports of the blocklists: plain lists, firewall URL-alias text and CSV.

Everything in the exports started as attacker-controlled text, so it is checked again here, at the
last moment: a value must still pass ``normalize_value`` to reach a list, and every CSV cell is
defused against spreadsheet formula injection (a cell that starts with ``=``, ``+``, ``-``, ``@``,
a tab or a carriage return gets a leading apostrophe, and control characters are removed).

* ``txt``: one value per line, nothing else (squid, dnsmasq, EDR import lists, ...).
* ``alias``: the same for IP addresses only, which is what the "URL Table (IPs)" alias of
  OPNsense and pfSense reads: one address per line, no comments, no blank lines.
* ``csv``: all columns, header line, CRLF line ends (RFC 4180).
"""

from __future__ import annotations

import csv
import io
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from typing import Any, Literal

from suckerpot_db.blocklist_values import normalize_value

ExportFormat = Literal["txt", "alias", "csv"]
FORMATS: tuple[ExportFormat, ...] = ("txt", "alias", "csv")
MAX_EXPORT_ROWS = 50_000
CSV_COLUMNS = (
    "kind", "value", "score", "reasons", "first_seen", "last_seen", "sessions", "sources",
    "benign",
)  # fmt: skip
_FORMULA_STARTS = ("=", "+", "-", "@", "\t", "\r")


def csv_cell(value: object) -> str:
    """One spreadsheet-safe cell."""
    if isinstance(value, datetime):
        text = value.isoformat()
    elif isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, list | tuple):
        text = ";".join(csv_cell(v) for v in value)
    else:
        text = str(value)
    text = "".join(c for c in text if c in "\t\r\n" or (ord(c) >= 0x20 and ord(c) != 0x7F))
    if text.startswith(_FORMULA_STARTS):
        text = "'" + text
    return text.replace("\t", " ").replace("\r", " ").replace("\n", " ")


def render_csv(rows: Iterable[Mapping[str, Any]]) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n", quoting=csv.QUOTE_MINIMAL)
    writer.writerow(CSV_COLUMNS)
    for row in rows:
        if normalize_value(str(row.get("kind", "")), str(row.get("value", ""))) is None:
            continue  # re-checked at the last moment, like the plain lists
        writer.writerow([csv_cell(row.get(c, "")) for c in CSV_COLUMNS])
    return out.getvalue()


def render_lines(kind: str, rows: Iterable[Mapping[str, Any]]) -> str:
    """Validated values, one per line, de-duplicated, in the order given."""
    seen: set[str] = set()
    lines: list[str] = []
    for row in rows:
        value = normalize_value(kind, str(row["value"]))
        if value is None or value in seen:
            continue
        seen.add(value)
        lines.append(value)
    return "".join(f"{line}\n" for line in lines)


def render(fmt: str, kind: str, rows: Sequence[Mapping[str, Any]]) -> tuple[str, str]:
    """(body, media type) for ``fmt``. ``alias`` needs ``kind == "ip"``."""
    if fmt == "csv":
        return render_csv(rows), "text/csv; charset=utf-8"
    if fmt == "alias" and kind != "ip":
        raise ValueError("alias lists hold IP addresses only")
    return render_lines(kind, rows), "text/plain; charset=utf-8"


def filename(kind: str, fmt: str) -> str:
    return f"suckerpot-{kind}.{'csv' if fmt == 'csv' else 'txt'}"
