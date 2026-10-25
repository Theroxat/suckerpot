"""Least-privilege database roles, applied idempotently on every migrate run.

``suckerpot_ingest`` may read and write events/sessions; ``suckerpot_api`` is read-only, except
for the encrypted provider keys it manages (``provider_secrets``) and the dashboard accounts and
audit log (``users``, ``audit_log``); ingest has no access to those two. From M15 on, the
campaign, defend, script and alert tables follow the matrix in the migrations' docstrings.
Names and passwords come from POSTGRES_INGEST_USER/PASSWORD and POSTGRES_API_USER/PASSWORD.

Passwords never reach the server as plain text: a SCRAM-SHA-256 verifier is computed here and
sent instead (PostgreSQL accepts pre-hashed passwords), so server logs and error CONTEXT
lines cannot contain the real password. Errors are re-raised without the original
exception chain for the same reason.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from collections.abc import Mapping

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError

INGEST_DEFAULT = "suckerpot_ingest"
API_DEFAULT = "suckerpot_api"
SCRAM_ITERATIONS = 4096


class RoleError(RuntimeError):
    """Raised with a sanitized message (never contains a password)."""


def scram_verifier(password: str, salt: bytes | None = None) -> str:
    """PostgreSQL SCRAM-SHA-256 verifier for ``password`` (ASCII only, no SASLprep needed)."""
    if not password.isascii():
        raise RoleError("database role passwords must be ASCII")
    salt = salt if salt is not None else os.urandom(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, SCRAM_ITERATIONS)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    b64 = base64.b64encode
    return (
        f"SCRAM-SHA-256${SCRAM_ITERATIONS}:{b64(salt).decode()}$"
        f"{b64(stored_key).decode()}:{b64(server_key).decode()}"
    )


_UPSERT_ROLE = """
DO $$
DECLARE
    r text := current_setting('suckerpot.role_name');
    pw text := current_setting('suckerpot.role_verifier');
    t text := current_setting('suckerpot.role_timeout');
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
        EXECUTE format(
            'ALTER ROLE %I WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE '
            'NOREPLICATION NOBYPASSRLS', r, pw);
    ELSE
        EXECUTE format(
            'CREATE ROLE %I WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE '
            'NOREPLICATION NOBYPASSRLS', r, pw);
    END IF;
    EXECUTE format('ALTER ROLE %I SET statement_timeout = %L', r, t);
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), r);
    EXECUTE format('GRANT USAGE ON SCHEMA public TO %I', r);
    -- Grants are explicit per table; earlier revisions used default privileges: remove them.
    EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM %I', r);
    EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM %I', r);
END
$$
"""

_GRANTS_INGEST = """
DO $$
DECLARE
    r text := current_setting('suckerpot.role_name');
    _tables text := (
        SELECT string_agg(format('%I', c), ', ') FROM unnest(
            ARRAY['events', 'sessions', 'ip_reputation', 'enrichment_quota', 'enrichment_status',
                  'sessions_daily', 'events_hourly', 'events_daily_tags', 'events_daily_country',
                  'events_daily_ip', 'system_status', 'maintenance_log', 'provider_secrets',
                  'provider_test_requests', 'cve', 'cve_sync_state', 'indicators',
                  'indicator_sessions', 'indicator_intel', 'users', 'audit_log',
                  'attack_techniques', 'technique_daily', 'campaigns', 'campaign_keys',
                  'campaign_sessions', 'blocklist_entries', 'blocklist_overrides', 'feed_tokens',
                  'inventory_services', 'scripts', 'script_sessions', 'script_explanations',
                  'llm_requests', 'alert_channels', 'alert_rules', 'watched_cves',
                  'alert_outbox', 'alert_cursors', 'weekly_reports', 'alert_test_requests']
        ) AS c WHERE to_regclass('public.' || c) IS NOT NULL
    );
BEGIN
    EXECUTE format('REVOKE ALL ON %s FROM %I', _tables, r);
    EXECUTE format('GRANT SELECT, INSERT ON events TO %I', r);
    -- A scanner that turns out to do more loses the benign flag on its earlier events (M19).
    -- (A column grant would be tighter, but PostgreSQL cannot propagate it to compressed chunks.)
    EXECUTE format('GRANT UPDATE ON events TO %I', r);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE ON sessions TO %I', r);
    IF to_regclass('public.ip_reputation') IS NOT NULL THEN
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE ON ip_reputation, enrichment_quota, enrichment_status '
            'TO %I', r);
    END IF;
    IF to_regclass('public.system_status') IS NOT NULL THEN
        EXECUTE format('GRANT SELECT, INSERT, UPDATE ON system_status TO %I', r);
    END IF;
    IF to_regclass('public.provider_secrets') IS NOT NULL THEN
        -- Keys are written by the API only; ingest reads them and answers test requests.
        EXECUTE format('GRANT SELECT ON provider_secrets TO %I', r);
        EXECUTE format('GRANT SELECT, UPDATE ON provider_test_requests TO %I', r);
    END IF;
    IF to_regclass('public.cve') IS NOT NULL THEN
        -- The CVE watch job is the only writer; it prunes old, irrelevant CVEs (retention).
        EXECUTE format('GRANT SELECT, INSERT, UPDATE ON cve, cve_sync_state TO %I', r);
        EXECUTE format('GRANT DELETE ON cve TO %I', r);
    END IF;
    IF to_regclass('public.indicators') IS NOT NULL THEN
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE ON indicators, indicator_sessions, indicator_intel '
            'TO %I', r);
        EXECUTE format(
            'GRANT USAGE ON SEQUENCE %s TO %I', pg_get_serial_sequence('public.indicators', 'id'),
            r);
    END IF;
    IF to_regclass('public.campaigns') IS NOT NULL THEN
        -- M15: ingest is the only writer of the ATT&CK catalogue, counters and campaigns.
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE ON attack_techniques, technique_daily, campaigns, '
            'campaign_keys, campaign_sessions TO %I', r);
        EXECUTE format('GRANT DELETE ON campaign_keys TO %I', r);
    END IF;
    IF to_regclass('public.blocklist_entries') IS NOT NULL THEN
        -- M16: ingest recomputes the blocklist (stale rows are deleted); it only reads what
        -- the API manages. feed_tokens: no access at all.
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE, DELETE ON blocklist_entries TO %I', r);
        EXECUTE format('GRANT SELECT ON blocklist_overrides, inventory_services TO %I', r);
    END IF;
    IF to_regclass('public.scripts') IS NOT NULL THEN
        -- M17: the script library is written by ingest; LLM requests are inserted by the API.
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE ON scripts, script_sessions, script_explanations '
            'TO %I', r);
        EXECUTE format('GRANT SELECT, UPDATE ON llm_requests TO %I', r);
    END IF;
    IF to_regclass('public.alert_channels') IS NOT NULL THEN
        -- M18: the API manages channels, rules and watched CVEs; ingest sends and records.
        EXECUTE format(
            'GRANT SELECT ON alert_channels, alert_rules, watched_cves TO %I', r);
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE ON alert_outbox, alert_cursors, weekly_reports TO %I',
            r);
        EXECUTE format('GRANT SELECT, UPDATE ON alert_test_requests TO %I', r);
    END IF;
    EXECUTE format(
        'GRANT USAGE ON SEQUENCE %s TO %I', pg_get_serial_sequence('public.events', 'id'), r);
END
$$
"""

_GRANTS_API = """
DO $$
DECLARE
    r text := current_setting('suckerpot.role_name');
    _tables text := (
        SELECT string_agg(format('%I', c), ', ') FROM unnest(
            ARRAY['events', 'sessions', 'ip_reputation', 'enrichment_quota', 'enrichment_status',
                  'sessions_daily', 'events_hourly', 'events_daily_tags', 'events_daily_country',
                  'events_daily_ip', 'system_status', 'maintenance_log', 'provider_secrets',
                  'provider_test_requests', 'cve', 'cve_sync_state', 'indicators',
                  'indicator_sessions', 'indicator_intel', 'users', 'audit_log',
                  'attack_techniques', 'technique_daily', 'campaigns', 'campaign_keys',
                  'campaign_sessions', 'blocklist_entries', 'blocklist_overrides', 'feed_tokens',
                  'inventory_services', 'scripts', 'script_sessions', 'script_explanations',
                  'llm_requests', 'alert_channels', 'alert_rules', 'watched_cves',
                  'alert_outbox', 'alert_cursors', 'weekly_reports', 'alert_test_requests']
        ) AS c WHERE to_regclass('public.' || c) IS NOT NULL
    );
BEGIN
    EXECUTE format('REVOKE ALL ON %s FROM %I', _tables, r);
    EXECUTE format('GRANT SELECT ON events, sessions TO %I', r);
    IF to_regclass('public.ip_reputation') IS NOT NULL THEN
        EXECUTE format(
            'GRANT SELECT ON ip_reputation, enrichment_quota, enrichment_status TO %I', r);
    END IF;
    IF to_regclass('public.sessions_daily') IS NOT NULL THEN
        -- Rollups kept forever: the API reads them for windows beyond raw retention.
        EXECUTE format(
            'GRANT SELECT ON sessions_daily, events_hourly, events_daily_tags, '
            'events_daily_country, events_daily_ip TO %I', r);
    END IF;
    IF to_regclass('public.system_status') IS NOT NULL THEN
        EXECUTE format('GRANT SELECT ON system_status, maintenance_log TO %I', r);
    END IF;
    IF to_regclass('public.provider_secrets') IS NOT NULL THEN
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON provider_secrets TO %I', r);
        EXECUTE format('GRANT SELECT, INSERT, UPDATE ON provider_test_requests TO %I', r);
    END IF;
    IF to_regclass('public.cve') IS NOT NULL THEN
        EXECUTE format('GRANT SELECT ON cve, cve_sync_state TO %I', r);
    END IF;
    IF to_regclass('public.indicators') IS NOT NULL THEN
        EXECUTE format('GRANT SELECT ON indicators, indicator_sessions, indicator_intel TO %I', r);
    END IF;
    IF to_regclass('public.users') IS NOT NULL THEN
        -- Dashboard accounts: the API manages them (deleting a user is allowed). The audit log
        -- is append-only for the API; the retention job, owned by the migration role, prunes it.
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON users TO %I', r);
        EXECUTE format('GRANT SELECT, INSERT ON audit_log TO %I', r);
    END IF;
    IF to_regclass('public.campaigns') IS NOT NULL THEN
        EXECUTE format(
            'GRANT SELECT ON attack_techniques, technique_daily, campaigns, campaign_keys, '
            'campaign_sessions TO %I', r);
    END IF;
    IF to_regclass('public.blocklist_entries') IS NOT NULL THEN
        EXECUTE format('GRANT SELECT ON blocklist_entries TO %I', r);
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE, DELETE ON blocklist_overrides, inventory_services '
            'TO %I', r);
        -- Feed tokens are revoked (UPDATE), never deleted.
        EXECUTE format('GRANT SELECT, INSERT, UPDATE ON feed_tokens TO %I', r);
    END IF;
    IF to_regclass('public.scripts') IS NOT NULL THEN
        EXECUTE format(
            'GRANT SELECT ON scripts, script_sessions, script_explanations TO %I', r);
        EXECUTE format('GRANT SELECT, INSERT ON llm_requests TO %I', r);
    END IF;
    IF to_regclass('public.alert_channels') IS NOT NULL THEN
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE, DELETE ON alert_channels, watched_cves TO %I', r);
        EXECUTE format('GRANT SELECT, UPDATE ON alert_rules TO %I', r);
        EXECUTE format('GRANT SELECT ON alert_outbox, weekly_reports TO %I', r);
        EXECUTE format('GRANT SELECT, INSERT ON alert_test_requests TO %I', r);
    END IF;
END
$$
"""

_DROP_ROLE = """
DO $$
DECLARE r text := current_setting('suckerpot.role_name');
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
        EXECUTE format('DROP OWNED BY %I', r);
        EXECUTE format('DROP ROLE %I', r);
    END IF;
END
$$
"""


def _role(env: Mapping[str, str], kind: str, default_name: str) -> tuple[str, str]:
    return (
        env.get(f"POSTGRES_{kind}_USER", default_name),
        env.get(f"POSTGRES_{kind}_PASSWORD", ""),
    )


def _set(conn: Connection, name: str, verifier: str, timeout: str) -> None:
    # is_local=true: the settings vanish at the end of the transaction.
    for key, value in (
        ("suckerpot.role_name", name),
        ("suckerpot.role_verifier", verifier),
        ("suckerpot.role_timeout", timeout),
    ):
        conn.execute(text("SELECT set_config(:k, :v, true)"), {"k": key, "v": value})


def apply_roles(conn: Connection, env: Mapping[str, str] | None = None) -> None:
    """Create or update both roles (password, attributes, timeouts, grants). Idempotent."""
    e = os.environ if env is None else env
    owner = e.get("POSTGRES_USER", "")
    roles = {
        "INGEST": _role(e, "INGEST", INGEST_DEFAULT),
        "API": _role(e, "API", API_DEFAULT),
    }
    for kind, (name, password) in roles.items():
        if not password:
            raise RoleError(f"POSTGRES_{kind}_PASSWORD must be set to create the {kind} role")
        if name == owner:
            raise RoleError(f"POSTGRES_{kind}_USER must differ from POSTGRES_USER")
    if roles["INGEST"][0] == roles["API"][0]:
        raise RoleError("POSTGRES_INGEST_USER and POSTGRES_API_USER must differ")

    steps = (
        ("INGEST", "30s", _GRANTS_INGEST),
        ("API", "5s", _GRANTS_API),
    )
    try:
        for kind, timeout, grants in steps:
            name, password = roles[kind]
            _set(conn, name, scram_verifier(password), timeout)
            conn.execute(text(_UPSERT_ROLE))
            conn.execute(text(grants))
    except DBAPIError as exc:
        code = getattr(exc.orig, "sqlstate", None)
        raise RoleError(f"applying database roles failed (SQLSTATE {code})") from None


def drop_roles(conn: Connection, env: Mapping[str, str] | None = None) -> None:
    e = os.environ if env is None else env
    for kind, default in (("INGEST", INGEST_DEFAULT), ("API", API_DEFAULT)):
        name, _ = _role(e, kind, default)
        _set(conn, name, "", "")
        conn.execute(text(_DROP_ROLE))
