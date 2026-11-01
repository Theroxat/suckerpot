"""Names a sensor presents as its own (``connect.data.self_identity``), for the deny set.

Trusted only when the event came from that sensor's own stream (the consumer already drops an
event whose ``sensor`` field does not match its stream) and the field is exactly this key. The
values are validated hard: a few short host-name-like strings, nothing else. Rows are stored with
``source = 'sensor'`` and are refreshed on every connect, so a name that stops appearing ages out.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Iterable, Mapping
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_common import Event

log = logging.getLogger(__name__)

IDENTITY_SENSORS = frozenset({"smb", "rdp", "mssql", "synology", "telnet", "adb", "mysql"})
MAX_NAMES = 4
MAX_LEN = 64
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{1,63}$")
REFRESH_S = 600.0

_recent: dict[str, float] = {}


def extract(sensor: str, event_type: str, data: Mapping[str, Any]) -> list[str]:
    """The valid names of one event, or an empty list."""
    if sensor not in IDENTITY_SENSORS or event_type != "connect":
        return []
    ident = data.get("self_identity")
    names = ident.get("names") if isinstance(ident, Mapping) else None
    if not isinstance(names, list) or len(names) > MAX_NAMES:
        return []
    out: list[str] = []
    for item in names:
        if isinstance(item, str) and len(item) <= MAX_LEN and _NAME.match(item):
            out.append(item.lower())
    return list(dict.fromkeys(out))


def names_of(events: Iterable[Event]) -> list[str]:
    found: list[str] = []
    for ev in events:
        found += extract(str(ev.sensor), str(ev.type), ev.data)
    return list(dict.fromkeys(found))


async def record(session: AsyncSession, events: Iterable[Event]) -> None:
    """Upsert the names of a batch. Best effort: it never fails the batch."""
    now = time.monotonic()
    fresh = [n for n in names_of(events) if now - _recent.get(n, -REFRESH_S) >= REFRESH_S]
    if not fresh:
        return
    try:
        async with session.begin_nested():
            for name in fresh:
                await session.execute(
                    text(
                        """
                        INSERT INTO report_self_terms (kind, value, source, confirmed)
                        VALUES ('name', :v, 'sensor', true)
                        ON CONFLICT (kind, value) DO UPDATE SET last_seen = now()
                        WHERE report_self_terms.source = 'sensor'
                        """
                    ),
                    {"v": name},
                )
        for name in fresh:
            _recent[name] = now
        if len(_recent) > 1000:
            _recent.clear()
    except Exception as exc:
        log.warning("sensor identity not recorded (%s)", type(exc).__name__)
