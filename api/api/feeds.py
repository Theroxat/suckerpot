"""Machine-readable blocklist feeds (M16), for firewalls and other tools.

Mounted only when ``FEEDS_ENABLED=true``, and outside ``/api/v1``: it does not use the dashboard
session. Access is by a bearer token whose sha256 is stored in ``feed_tokens``.

Routes arrive in Phase 2.
"""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()
