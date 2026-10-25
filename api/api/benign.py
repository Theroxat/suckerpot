"""Research scanners (M19): the ``include_benign`` query parameter and its SQL filters.

Ingest labels sessions from known research scanners ``benign``. Every list and chart endpoint
hides them unless the caller asks for them with ``include_benign=true`` (the sidebar switch in the
web UI). The filters are partial-index friendly: ``sessions.benign`` is NOT NULL and
``ix_sessions_not_benign`` covers ``WHERE NOT benign``. ``events.benign`` is nullable (old rows
were never labelled), so "visible" means not true.

Known limitation: the continuous aggregates are not split by ``benign``.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Query
from sqlalchemy import ColumnElement
from suckerpot_db.models import EventRow, SessionRow

IncludeBenign = Annotated[
    bool,
    Query(description="Also count sessions and events from known research scanners."),
]


def visible_sessions(include_benign: bool) -> list[ColumnElement[bool]]:
    """WHERE conditions that hide research-scanner sessions (empty when they are wanted)."""
    return [] if include_benign else [~SessionRow.benign]


def visible_events(include_benign: bool) -> list[ColumnElement[bool]]:
    """WHERE conditions that hide research-scanner events (empty when they are wanted)."""
    return [] if include_benign else [EventRow.benign.is_not(True)]
