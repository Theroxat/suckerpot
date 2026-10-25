"""Indicators extracted from recorded events, their session links and threat-intel answers.

Revision ID: 0009
Revises: 0008

* ``indicators``: one row per distinct (type, value): URL, domain, IP address or file hash.
* ``indicator_sessions``: bounded links from an indicator to the sessions that showed it.
* ``indicator_intel``: the 24 h cache of answers from the intel providers (one row per source).
* ``suckerpot_indicator_prune``: retention, aligned with raw events (job created by
  ``suckerpot_db.retention.apply_policies``).

Grants are applied by ``suckerpot_db.roles``: ingest reads and writes, the API reads.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PRUNE = """
CREATE OR REPLACE PROCEDURE suckerpot_indicator_prune(job_id integer, config jsonb)
LANGUAGE plpgsql AS $$
DECLARE
    days integer := COALESCE((config ->> 'retention_days')::integer, 90);
    cutoff timestamptz := now() - make_interval(days => days);
    max_rows bigint := COALESCE((config ->> 'max_rows')::bigint, 500000);
    guard_active boolean := COALESCE(
        (SELECT (value ->> 'active')::boolean FROM system_status WHERE key = 'disk_guard'), false);
    total bigint;
BEGIN
    DELETE FROM indicator_sessions WHERE seen_at < cutoff;
    -- Links and intel rows go with the indicator (ON DELETE CASCADE).
    DELETE FROM indicators WHERE last_seen < cutoff;
    -- A hard ceiling on the table, halved while the database disk guard is trimming: the least
    -- sighted and oldest single-source indicators go first.
    IF guard_active THEN
        max_rows := max_rows / 2;
    END IF;
    SELECT count(*) INTO total FROM indicators;
    IF total > max_rows THEN
        DELETE FROM indicators WHERE id IN (
            SELECT i.id FROM indicators i
            ORDER BY ((SELECT count(DISTINCT s.src_ip) FROM indicator_sessions s
                       WHERE s.indicator_id = i.id) >= 2),
                     i.sightings, i.last_seen, i.id
            LIMIT total - max_rows);
    END IF;
END
$$
"""

_PROVIDERS_NEW = "('abuseipdb', 'greynoise', 'maxmind', 'nvd', 'github', 'abusech', 'virustotal')"
_PROVIDERS_OLD = "('abuseipdb', 'greynoise', 'maxmind', 'nvd', 'github')"


def _provider_check(table: str, providers: str) -> None:
    op.execute(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {table}_provider_check")
    op.execute(
        f"ALTER TABLE {table} ADD CONSTRAINT {table}_provider_check CHECK (provider IN {providers})"
    )


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE indicators (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            type text NOT NULL CHECK (type IN ('url', 'domain', 'ip', 'hash')),
            value text NOT NULL CHECK (char_length(value) BETWEEN 1 AND 512),
            role text NOT NULL CHECK (role IN ('download_host', 'contacted_host', 'hash')),
            host text CHECK (host IS NULL OR char_length(host) <= 255),
            first_seen timestamptz NOT NULL,
            last_seen timestamptz NOT NULL,
            sightings bigint NOT NULL DEFAULT 1,
            sensors text[] NOT NULL DEFAULT '{}',
            trusted boolean NOT NULL DEFAULT false,
            demo boolean NOT NULL DEFAULT false,
            CHECK ((type = 'hash') = (role = 'hash')),
            UNIQUE (type, value)
        )
        """
    )
    op.execute("CREATE INDEX ix_indicators_last_seen ON indicators (last_seen DESC, id DESC)")
    op.execute("CREATE INDEX ix_indicators_role_last_seen ON indicators (role, last_seen DESC)")
    op.execute(
        """
        CREATE TABLE indicator_sessions (
            indicator_id bigint NOT NULL REFERENCES indicators (id) ON DELETE CASCADE,
            session_id text NOT NULL,
            src_ip inet NOT NULL,
            sensor text NOT NULL,
            seen_at timestamptz NOT NULL,
            PRIMARY KEY (indicator_id, session_id)
        )
        """
    )
    op.execute("CREATE INDEX ix_indicator_sessions_seen_at ON indicator_sessions (seen_at)")
    op.execute("CREATE INDEX ix_indicator_sessions_src_ip ON indicator_sessions (src_ip)")
    op.execute(
        """
        CREATE TABLE indicator_intel (
            indicator_id bigint NOT NULL REFERENCES indicators (id) ON DELETE CASCADE,
            source text NOT NULL CHECK (source IN ('urlhaus', 'threatfox', 'virustotal')),
            known boolean NOT NULL,
            family text CHECK (family IS NULL OR char_length(family) <= 64),
            threat_type text CHECK (threat_type IS NULL OR char_length(threat_type) <= 64),
            tags text[] NOT NULL DEFAULT '{}',
            first_seen_ext timestamptz,
            reference text CHECK (reference IS NULL OR char_length(reference) <= 256),
            checked_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (indicator_id, source)
        )
        """
    )
    op.execute("CREATE INDEX ix_indicator_intel_family ON indicator_intel (family)")
    op.execute(_PRUNE)
    # The two new key providers: widen the CHECK constraints of the M11 tables.
    _provider_check("provider_secrets", _PROVIDERS_NEW)
    _provider_check("provider_test_requests", _PROVIDERS_NEW)


def downgrade() -> None:
    op.execute("DELETE FROM provider_test_requests WHERE provider IN ('abusech', 'virustotal')")
    op.execute("DELETE FROM provider_secrets WHERE provider IN ('abusech', 'virustotal')")
    _provider_check("provider_secrets", _PROVIDERS_OLD)
    _provider_check("provider_test_requests", _PROVIDERS_OLD)
    op.execute(
        "SELECT delete_job(job_id) FROM timescaledb_information.jobs "
        "WHERE proc_name = 'suckerpot_indicator_prune'"
    )
    op.execute("DROP PROCEDURE IF EXISTS suckerpot_indicator_prune(integer, jsonb)")
    op.execute("DROP TABLE IF EXISTS indicator_intel")
    op.execute("DROP TABLE IF EXISTS indicator_sessions")
    op.execute("DROP TABLE IF EXISTS indicators")
