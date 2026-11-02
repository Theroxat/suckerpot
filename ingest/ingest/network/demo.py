"""The one place the network node looks at events: whether a session is demo data.

``just demo`` pushes events with random global addresses and ``data.demo = true``. Such a session
must never become a signed claim about a real third party. This fragment reads that single boolean
flag and nothing else of an event (the static test pins it). The window keeps the hypertable scan
on the chunks of the period being read.
"""

from __future__ import annotations


def not_demo(session_alias: str, lo: str, hi: str) -> str:
    """SQL condition: the session has no demo event between the SQL expressions ``lo`` and ``hi``.

    Arguments are code constants (an alias and bound-parameter or ``now()`` expressions), never
    request data.
    """
    return (
        "NOT EXISTS (SELECT 1 FROM events e "  # noqa: S608  (code constants only, see above)
        f"WHERE e.session_id = {session_alias}.session_id "
        f"AND e.ts >= {lo} AND e.ts < {hi} "
        "AND coalesce(e.data ->> 'demo', 'false') = 'true')"
    )
