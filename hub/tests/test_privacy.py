"""Hub invariants H1 and H2: no client address stored or logged, no analytics."""

from __future__ import annotations

import ast
import logging
import re
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import CIDR, INET, MACADDR

from hub import models
from hub.logging import PrivacyFilter, scrub

from .conftest import Env
from .helpers import batch, source

HUB = Path(__file__).resolve().parent.parent
PKG = HUB / "hub"
CLIENT_ADDR = "203.0.113.77"  # the address the test transport presents as the peer


# --- static ---


def _python_files() -> list[Path]:
    return [p for p in PKG.rglob("*.py")]


def test_only_ratelimit_reads_the_client_address() -> None:
    offenders: list[str] = []
    for path in _python_files():
        if path.name == "ratelimit.py":
            continue
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in {"client", "remote_addr"}:
                offenders.append(f"{path.name}:{node.lineno} .{node.attr}")
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                low = node.value.lower()
                if any(
                    h in low for h in ("x-forwarded", "x-real-ip", "forwarded-for", "cf-connecting")
                ):
                    offenders.append(f"{path.name}:{node.lineno} {node.value!r}")
                if low in {"client", "forwarded"}:
                    offenders.append(f"{path.name}:{node.lineno} {node.value!r}")
    assert offenders == []


def test_ratelimit_is_the_one_module_that_does() -> None:
    src = (PKG / "ratelimit.py").read_text()
    assert "request.client" in src and "x-forwarded-for" in src


def test_no_address_column_in_any_table() -> None:
    bad_types = (INET, CIDR, MACADDR)
    for table in models.Base.metadata.tables.values():
        for column in table.columns:
            assert not isinstance(column.type, bad_types), (table.name, column.name)
            assert not re.search(r"(^|_)(ip|addr|address|remote|client|host)(_|$)", column.name), (
                table.name,
                column.name,
            )


@pytest.mark.parametrize("name", ["Caddyfile", "Caddyfile.tunnel"])
def test_caddy_logs_nowhere(name: str) -> None:
    caddyfile = "\n".join(
        line for line in (HUB / name).read_text().splitlines() if not line.strip().startswith("#")
    )
    blocks = re.findall(r"\blog\s*\{([^}]*)\}", caddyfile)
    assert blocks, "a log block must exist so the default logger is disabled"
    assert all("output discard" in b for b in blocks)
    assert len(re.findall(r"\blog\b", caddyfile)) == len(blocks)


def test_server_runs_without_access_log() -> None:
    dockerfile = (HUB / "Dockerfile").read_text()
    assert "--no-access-log" in dockerfile and "--no-server-header" in dockerfile


def test_database_does_not_log_connections_or_statements() -> None:
    compose = (HUB / "docker-compose.yml").read_text()
    for setting in ("log_connections=off", "log_statement=none", "log_hostname=off"):
        assert setting in compose


def test_no_third_party_resources_or_analytics() -> None:
    for path in [*_python_files(), HUB / "Caddyfile", HUB / "Caddyfile.tunnel"]:
        src = path.read_text().lower()
        for word in (
            "google-analytics",
            "sentry",
            "segment.io",
            "matomo",
            "plausible",
            "set-cookie",
        ):
            assert word not in src, (path.name, word)


# --- scrubber ---


@pytest.mark.parametrize(
    "line",
    [
        f"failed for {CLIENT_ADDR}",
        "peer 2001:db8::7 closed",
        "key " + "A" * 43,
        "digest " + "ab" * 32,
        f"connect {CLIENT_ADDR}:443 refused",
    ],
)
def test_scrub_removes_addresses_and_keys(line: str) -> None:
    out = scrub(line)
    assert (
        CLIENT_ADDR not in out
        and "2001:db8" not in out
        and "A" * 43 not in out
        and "ab" * 32 not in out
    )


def test_filter_rewrites_records_and_drops_tracebacks() -> None:
    record = logging.LogRecord("x", logging.ERROR, __file__, 1, "bad %s", (CLIENT_ADDR,), None)
    try:
        raise ValueError(CLIENT_ADDR)
    except ValueError:
        import sys

        record.exc_info = sys.exc_info()
    assert PrivacyFilter().filter(record)
    assert CLIENT_ADDR not in record.getMessage() and record.exc_info is None
    assert "ValueError" in record.getMessage()


# --- behaviour (database) ---


@pytest.mark.integration
async def test_flow_logs_and_stores_no_client_address(
    env: Env, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    (node,) = await env.enrolled(pseudonym="quiet owl", country="CH")
    await env.client.unsigned("GET", "/v1/info")
    await node.call("GET", "/v1/node")
    await node.call("POST", "/v1/observations", batch("2026-10-31", sources=[source("192.0.2.4")]))
    await node.call("GET", "/v1/targets")
    await node.call("GET", "/v1/node", timestamp=1)  # an error path
    await env.node().call("GET", "/v1/node")  # another one
    await node.call("DELETE", "/v1/node")

    text_logs = "\n".join(r.getMessage() + " " + str(r.args) for r in caplog.records)
    assert CLIENT_ADDR not in text_logs
    assert node.key not in text_logs

    # database: no text or bytea column anywhere holds the address
    async with env.worker() as s:
        tables = (
            await s.execute(
                text(
                    "SELECT table_name, column_name FROM information_schema.columns "
                    "WHERE table_schema = 'public' AND data_type IN ('text','character varying','character','jsonb','ARRAY')"
                )
            )
        ).all()
        for table, column in tables:
            hit = (
                await s.execute(
                    text(f"SELECT count(*) FROM {table} WHERE CAST({column} AS text) LIKE :p"),
                    {"p": f"%{CLIENT_ADDR}%"},
                )
            ).scalar_one()
            assert hit == 0, (table, column)


@pytest.mark.integration
async def test_responses_never_echo_the_client_address(env: Env) -> None:
    (node,) = await env.enrolled()
    for reply in (
        await env.client.unsigned("GET", "/v1/info"),
        await node.call("GET", "/v1/node"),
        await node.call("GET", "/v1/targets"),
        await node.call("GET", "/v1/network"),
    ):
        assert CLIENT_ADDR not in reply.raw.decode()
        assert all(CLIENT_ADDR not in v for v in reply.headers.values())
