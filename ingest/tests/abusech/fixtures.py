"""Expected answers of the abuse.ch submission endpoints, as fixtures.

The published API pages of URLhaus and ThreatFox document the request but not the answer of a
submission, so these are the shapes the client is written to tolerate (a ``query_status`` string at
the top level or in the first result item, as the lookup endpoints use). Check them against a real
answer before relying on one particular code; the mapping lives in ``client.classify_answer``.
"""

from __future__ import annotations

from typing import Any

# (HTTP status, JSON body or None, expected code)
ANSWERS: list[tuple[int, Any, str]] = [
    (200, {"query_status": "ok"}, "inserted"),
    (200, {"query_status": "ok", "data": [{"status": "inserted"}]}, "inserted"),
    (200, {"query_status": "inserted"}, "inserted"),
    (200, {"query_status": "ok", "data": [{"result": "already_known"}]}, "already_known"),
    (200, {"query_status": "url_already_known"}, "already_known"),
    (200, {"query_status": "duplicate"}, "already_known"),
    (200, {"query_status": "invalid_url"}, "invalid"),
    (200, {"query_status": "illegal_ioc"}, "invalid"),
    (200, {"query_status": "ok", "data": [{"status": "invalid_threat"}]}, "invalid"),
    (200, {"query_status": "blacklisted"}, "blacklisted"),
    (200, {"query_status": "unauthorized"}, "auth_failed"),
    (200, {"query_status": "invalid_auth_key"}, "auth_failed"),
    (401, None, "auth_failed"),
    (403, {"query_status": "forbidden"}, "auth_failed"),
    (429, None, "rate_limited"),
    (500, None, "http_error"),
    (404, {"query_status": "ok"}, "http_error"),
    (200, {"something": "else"}, "unknown_outcome"),
    (200, {"query_status": "unknown"}, "unknown_outcome"),
    (200, None, "unknown_outcome"),
]
