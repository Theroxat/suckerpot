"""Regression tests for the security review (logging, compose, summary after leave)."""

from __future__ import annotations

import io
import json
import logging
import re
from pathlib import Path

import pytest
from sqlalchemy import text

from hub import logging as hub_logging

from .conftest import Env
from .seed import TODAY

HUB = Path(__file__).resolve().parent.parent
ADDR = "203.0.113.77"


def test_server_loggers_carry_the_privacy_filter() -> None:
    stream = io.StringIO()
    server = logging.getLogger("uvicorn.error")
    handler = logging.StreamHandler(stream)  # what uvicorn installs: its own handler
    server.addHandler(handler)
    try:
        hub_logging.configure()
        for name in hub_logging.SERVER_LOGGERS:
            assert all(
                any(isinstance(f, hub_logging.PrivacyFilter) for f in h.filters)
                for h in logging.getLogger(name).handlers
            ), name
        try:
            raise ValueError(f"connection from {ADDR}:51234 failed")
        except ValueError:
            server.exception("request from %s failed", ADDR)
        logging.getLogger("uvicorn").error("peer [2001:db8::7]:443 reset")
    finally:
        server.removeHandler(handler)
    out = stream.getvalue()
    assert ADDR not in out and "2001:db8::7" not in out and "Traceback" not in out
    assert "ValueError" in out  # the type is kept, nothing else


def test_database_does_not_log_failing_statements() -> None:
    compose = (HUB / "docker-compose.yml").read_text()
    assert "log_min_error_statement=panic" in compose and "log_error_verbosity=terse" in compose


def test_edge_and_helpers_are_healthchecked_and_limited() -> None:
    compose = (HUB / "docker-compose.yml").read_text()
    blocks = re.split(r"\n  (?=[a-z-]+:\n)", compose)
    by_name = {b.split(":", 1)[0]: b for b in blocks}
    for name in ("caddy", "hub-backup", "hub-worker", "hub-api", "hub-db"):
        assert "healthcheck:" in by_name[name] or "HEALTHCHECK" in (HUB / "Dockerfile").read_text()
    for name in ("hub-backup", "hub-admin"):
        assert "cpus:" in by_name[name], name
    assert "max_size 1MiB" in (HUB / "Caddyfile").read_text()
    # the key written by the admin container lands on a mounted host directory
    assert ":/keys" in by_name["hub-admin"]
    assert "/keys/hub_signing_key" in (HUB / ".env.example").read_text()


@pytest.mark.integration
async def test_a_member_who_left_disappears_from_the_cached_summary(env: Env) -> None:
    nodes = await env.enrolled(2)
    fps = [n.fingerprint for n in nodes]
    members = [
        {
            "fingerprint": fp,
            "pseudonym": None,
            "country": None,
            "member_since": "2026-10",
            "active_days": 3,
            "tier": 1,
        }
        for fp in fps
    ]
    summary = {
        "generated_day": TODAY.isoformat(),
        "totals": {
            "members": 2,
            "active_7d": 2,
            "countries": 0,
            "confirmed_30d": 0,
            "reported_30d": 0,
            "taken_down_30d": 0,
            "median_days_to_takedown": None,
        },
        "weekly": [],
        "countries": [],
        "members": members,
    }
    async with env.worker() as s:
        await s.execute(
            text("INSERT INTO network_summary VALUES (1, :d, CAST(:j AS jsonb))"),
            {"d": TODAY, "j": json.dumps(summary)},
        )
        await s.commit()
    before = (await nodes[0].call("GET", "/v1/network")).json
    assert {m["fingerprint"] for m in before["members"]} == set(fps)
    await nodes[1].call("DELETE", "/v1/node")
    after = (await nodes[0].call("GET", "/v1/network")).json
    assert [m["fingerprint"] for m in after["members"]] == [fps[0]]
    assert after["totals"]["members"] == 1
