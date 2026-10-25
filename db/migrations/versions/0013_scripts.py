"""Script library and explanations (M17).

Revision ID: 0013
Revises: 0012

* ``scripts``: one row per distinct normalised command sequence (the fingerprint is also the
  campaign key of kind ``script``); ``script_sessions`` holds bounded links to the sessions.
* ``script_explanations``: per-line explanations, from the built-in annotations or from the LLM.
* ``llm_requests``: "explain this script with the LLM" requests (the API inserts, ingest answers).
* The provider CHECK constraints of ``provider_secrets`` and ``provider_test_requests`` accept
  ``anthropic`` and ``smtp`` (the keys of M17 and M18), so 0014 does not touch them again.
* ``suckerpot_script_prune``: retention (job created by ``suckerpot_db.retention``).

Grants are applied by ``suckerpot_db.roles``.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PROVIDERS_NEW = (
    "('abuseipdb', 'greynoise', 'maxmind', 'nvd', 'github', 'abusech', 'virustotal', "
    "'anthropic', 'smtp')"
)
_PROVIDERS_OLD = "('abuseipdb', 'greynoise', 'maxmind', 'nvd', 'github', 'abusech', 'virustotal')"

_PRUNE = """
CREATE OR REPLACE PROCEDURE suckerpot_script_prune(job_id integer, config jsonb)
LANGUAGE plpgsql AS $$
DECLARE
    days integer := COALESCE((config ->> 'retention_days')::integer, 90);
    cutoff timestamptz := now() - make_interval(days => days);
    max_rows bigint := COALESCE((config ->> 'max_rows')::bigint, 100000);
    guard_active boolean := COALESCE(
        (SELECT (value ->> 'active')::boolean FROM system_status WHERE key = 'disk_guard'), false);
    total bigint;
BEGIN
    -- Links go with the raw events; the scripts and their counters stay.
    DELETE FROM script_sessions WHERE seen_at < cutoff;
    DELETE FROM llm_requests WHERE requested_at < now() - INTERVAL '30 days';
    IF guard_active THEN
        max_rows := max_rows / 2;
    END IF;
    SELECT count(*) INTO total FROM scripts;
    IF total > max_rows THEN
        -- Single-source, rarely seen and old scripts first. Explanations and links cascade.
        DELETE FROM scripts WHERE id IN (
            SELECT s.id FROM scripts s
            ORDER BY (s.sources >= 2), s.sessions, s.last_seen, s.id
            LIMIT total - max_rows);
    END IF;
END
$$
"""


def _provider_check(table: str, providers: str) -> None:
    op.execute(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {table}_provider_check")
    op.execute(
        f"ALTER TABLE {table} ADD CONSTRAINT {table}_provider_check CHECK (provider IN {providers})"
    )


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE scripts (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            fingerprint bytea NOT NULL UNIQUE CHECK (octet_length(fingerprint) = 32),
            normalized_text text NOT NULL CHECK (char_length(normalized_text) <= 8192),
            sample_text text NOT NULL CHECK (char_length(sample_text) <= 8192),
            line_count smallint NOT NULL DEFAULT 0 CHECK (line_count >= 0),
            first_seen timestamptz NOT NULL,
            last_seen timestamptz NOT NULL,
            sessions bigint NOT NULL DEFAULT 0,
            sources integer NOT NULL DEFAULT 0,
            sensors text[] NOT NULL DEFAULT '{}' CHECK (cardinality(sensors) <= 16),
            campaign_id bigint REFERENCES campaigns (id) ON DELETE SET NULL,
            techniques text[] NOT NULL DEFAULT '{}' CHECK (cardinality(techniques) <= 64),
            demo boolean NOT NULL DEFAULT false
        )
        """
    )
    op.execute("CREATE INDEX ix_scripts_last_seen ON scripts (last_seen DESC, id DESC)")
    op.execute("CREATE INDEX ix_scripts_campaign_id ON scripts (campaign_id)")
    op.execute(
        """
        CREATE TABLE script_sessions (
            script_id bigint NOT NULL REFERENCES scripts (id) ON DELETE CASCADE,
            session_id text NOT NULL CHECK (char_length(session_id) <= 128),
            src_ip inet NOT NULL,
            sensor text NOT NULL CHECK (char_length(sensor) BETWEEN 1 AND 32),
            seen_at timestamptz NOT NULL,
            PRIMARY KEY (script_id, session_id)
        )
        """
    )
    op.execute("CREATE INDEX ix_script_sessions_seen_at ON script_sessions (seen_at)")
    op.execute("CREATE INDEX ix_script_sessions_session_id ON script_sessions (session_id)")
    op.execute(
        """
        CREATE TABLE script_explanations (
            script_id bigint NOT NULL REFERENCES scripts (id) ON DELETE CASCADE,
            source text NOT NULL CHECK (source IN ('annotations', 'llm')),
            prompt_version smallint NOT NULL DEFAULT 1,
            model text CHECK (model IS NULL OR char_length(model) <= 64),
            lines jsonb NOT NULL CHECK (octet_length(lines::text) <= 65536),
            summary text NOT NULL CHECK (char_length(summary) <= 600),
            created_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (script_id, source)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE llm_requests (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            script_id bigint NOT NULL REFERENCES scripts (id) ON DELETE CASCADE,
            requested_by text NOT NULL CHECK (char_length(requested_by) <= 128),
            requested_at timestamptz NOT NULL DEFAULT now(),
            state text NOT NULL DEFAULT 'queued'
                CHECK (state IN ('queued', 'done', 'refused', 'failed')),
            detail text CHECK (detail IS NULL OR char_length(detail) <= 128)
        )
        """
    )
    op.execute("CREATE INDEX ix_llm_requests_state ON llm_requests (state, requested_at)")
    op.execute(_PRUNE)
    _provider_check("provider_secrets", _PROVIDERS_NEW)
    _provider_check("provider_test_requests", _PROVIDERS_NEW)


def downgrade() -> None:
    op.execute("DELETE FROM provider_test_requests WHERE provider IN ('anthropic', 'smtp')")
    op.execute("DELETE FROM provider_secrets WHERE provider IN ('anthropic', 'smtp')")
    _provider_check("provider_secrets", _PROVIDERS_OLD)
    _provider_check("provider_test_requests", _PROVIDERS_OLD)
    op.execute(
        "SELECT delete_job(job_id) FROM timescaledb_information.jobs "
        "WHERE proc_name = 'suckerpot_script_prune'"
    )
    op.execute("DROP PROCEDURE IF EXISTS suckerpot_script_prune(integer, jsonb)")
    op.execute("DROP TABLE IF EXISTS llm_requests")
    op.execute("DROP TABLE IF EXISTS script_explanations")
    op.execute("DROP TABLE IF EXISTS script_sessions")
    op.execute("DROP TABLE IF EXISTS scripts")
