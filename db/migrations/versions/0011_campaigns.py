"""Campaigns and the MITRE ATT&CK mapping (M15).

Revision ID: 0011
Revises: 0010

* ``events.techniques`` (nullable, no default: a metadata-only ADD COLUMN, safe on the compressed
  hypertable) and ``sessions.techniques`` / ``campaign_id`` / ``clustered_at``.
* ``attack_techniques``: the technique catalogue, upserted by ingest from YAML at start-up.
* ``technique_daily``: per-day technique counters, kept forever (heatmap beyond raw retention).
* ``campaigns``, ``campaign_keys``, ``campaign_sessions``: the clustering result. Counters live
  on the campaign, so they survive the deletion of the sessions behind them.
* ``suckerpot_campaign_prune``: retention (job created by ``suckerpot_db.retention``).

Grants are applied by ``suckerpot_db.roles``: ingest reads and writes, the API reads.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PRUNE = """
CREATE OR REPLACE PROCEDURE suckerpot_campaign_prune(job_id integer, config jsonb)
LANGUAGE plpgsql AS $$
DECLARE
    days integer := COALESCE((config ->> 'retention_days')::integer, 90);
    cutoff timestamptz := now() - make_interval(days => days);
    max_rows bigint := COALESCE((config ->> 'max_rows')::bigint, 50000);
    guard_active boolean := COALESCE(
        (SELECT (value ->> 'active')::boolean FROM system_status WHERE key = 'disk_guard'), false);
    total bigint;
BEGIN
    -- Links go with the raw events; the campaign counters stay.
    DELETE FROM campaign_sessions WHERE seen_at < cutoff;
    -- Keys seen from one source only are weak evidence: they do not outlive the raw events.
    DELETE FROM campaign_keys WHERE sources < 2 AND last_seen < cutoff;
    IF guard_active THEN
        max_rows := max_rows / 2;
    END IF;
    SELECT count(*) INTO total FROM campaigns;
    IF total > max_rows THEN
        -- Least evidence first (few sources, few sessions), then the oldest: a flood of cheap
        -- single-source campaigns can never push out a well-evidenced one.
        DELETE FROM campaigns WHERE id IN (
            SELECT c.id FROM campaigns c
            ORDER BY c.sources, c.sessions, c.last_seen, c.id
            LIMIT total - max_rows);
    END IF;
END
$$
"""


def upgrade() -> None:
    op.execute("ALTER TABLE events ADD COLUMN techniques text[]")
    op.execute("ALTER TABLE sessions ADD COLUMN techniques text[] NOT NULL DEFAULT '{}'")
    op.execute("ALTER TABLE sessions ADD COLUMN campaign_id bigint")
    op.execute("ALTER TABLE sessions ADD COLUMN clustered_at timestamptz")
    op.execute(
        "ALTER TABLE sessions ADD CONSTRAINT sessions_techniques_size "
        "CHECK (cardinality(techniques) <= 64)"
    )
    op.execute(
        """
        CREATE TABLE attack_techniques (
            id text PRIMARY KEY CHECK (id ~ '^T[0-9]{4}(\\.[0-9]{3})?$'),
            name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
            tactic text NOT NULL CHECK (char_length(tactic) BETWEEN 1 AND 64),
            stage text NOT NULL
                CHECK (stage IN ('recon', 'access', 'execution', 'persistence',
                                 'tool_transfer', 'objective')),
            url text NOT NULL CHECK (char_length(url) <= 256)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE technique_daily (
            day date NOT NULL,
            technique text NOT NULL CHECK (technique ~ '^T[0-9]{4}(\\.[0-9]{3})?$'),
            sensor text NOT NULL CHECK (char_length(sensor) BETWEEN 1 AND 32),
            sessions integer NOT NULL DEFAULT 0,
            events integer NOT NULL DEFAULT 0,
            sources integer NOT NULL DEFAULT 0,
            PRIMARY KEY (day, technique, sensor)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE campaigns (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
            status text NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'quiet', 'merged')),
            merged_into bigint REFERENCES campaigns (id) ON DELETE SET NULL,
            first_seen timestamptz NOT NULL,
            last_seen timestamptz NOT NULL,
            sessions bigint NOT NULL DEFAULT 0,
            sources integer NOT NULL DEFAULT 0,
            countries text[] NOT NULL DEFAULT '{}' CHECK (cardinality(countries) <= 64),
            asns integer[] NOT NULL DEFAULT '{}' CHECK (cardinality(asns) <= 64),
            sensors text[] NOT NULL DEFAULT '{}' CHECK (cardinality(sensors) <= 16),
            techniques text[] NOT NULL DEFAULT '{}' CHECK (cardinality(techniques) <= 64),
            stages text[] NOT NULL DEFAULT '{}' CHECK (cardinality(stages) <= 8),
            tags text[] NOT NULL DEFAULT '{}' CHECK (cardinality(tags) <= 64),
            families text[] NOT NULL DEFAULT '{}' CHECK (cardinality(families) <= 16),
            severity text NOT NULL DEFAULT 'info'
                CHECK (severity IN ('info', 'notice', 'warning', 'severe')),
            rep_session_id text
                CHECK (rep_session_id IS NULL OR char_length(rep_session_id) <= 128),
            demo boolean NOT NULL DEFAULT false,
            updated_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute("CREATE INDEX ix_campaigns_last_seen ON campaigns (last_seen DESC, id DESC)")
    op.execute("CREATE INDEX ix_campaigns_status ON campaigns (status)")
    op.execute(
        "ALTER TABLE sessions ADD CONSTRAINT sessions_campaign_id_fkey "
        "FOREIGN KEY (campaign_id) REFERENCES campaigns (id) ON DELETE SET NULL"
    )
    op.execute("CREATE INDEX ix_sessions_techniques ON sessions USING gin (techniques)")
    op.execute("CREATE INDEX ix_sessions_campaign_id ON sessions (campaign_id)")
    op.execute(
        "CREATE INDEX ix_sessions_unclustered ON sessions (last_event_at) "
        "WHERE clustered_at IS NULL"
    )
    op.execute(
        """
        CREATE TABLE campaign_keys (
            kind text NOT NULL
                CHECK (kind IN ('script', 'payload_host', 'hash', 'family', 'exploit', 'credlist')),
            value text NOT NULL CHECK (char_length(value) BETWEEN 1 AND 128),
            campaign_id bigint REFERENCES campaigns (id) ON DELETE CASCADE,
            sources integer NOT NULL DEFAULT 0,
            first_seen timestamptz NOT NULL,
            last_seen timestamptz NOT NULL,
            PRIMARY KEY (kind, value)
        )
        """
    )
    op.execute("CREATE INDEX ix_campaign_keys_campaign_id ON campaign_keys (campaign_id)")
    op.execute("CREATE INDEX ix_campaign_keys_last_seen ON campaign_keys (last_seen)")
    op.execute(
        """
        CREATE TABLE campaign_sessions (
            campaign_id bigint NOT NULL REFERENCES campaigns (id) ON DELETE CASCADE,
            session_id text NOT NULL CHECK (char_length(session_id) <= 128),
            src_ip inet NOT NULL,
            sensor text NOT NULL CHECK (char_length(sensor) BETWEEN 1 AND 32),
            seen_at timestamptz NOT NULL,
            PRIMARY KEY (campaign_id, session_id)
        )
        """
    )
    op.execute("CREATE INDEX ix_campaign_sessions_seen_at ON campaign_sessions (seen_at)")
    op.execute("CREATE INDEX ix_campaign_sessions_session_id ON campaign_sessions (session_id)")
    op.execute(_PRUNE)


def downgrade() -> None:
    op.execute(
        "SELECT delete_job(job_id) FROM timescaledb_information.jobs "
        "WHERE proc_name = 'suckerpot_campaign_prune'"
    )
    op.execute("DROP PROCEDURE IF EXISTS suckerpot_campaign_prune(integer, jsonb)")
    op.execute("DROP TABLE IF EXISTS campaign_sessions")
    op.execute("DROP TABLE IF EXISTS campaign_keys")
    op.execute("ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_campaign_id_fkey")
    op.execute("DROP TABLE IF EXISTS campaigns")
    op.execute("DROP TABLE IF EXISTS technique_daily")
    op.execute("DROP TABLE IF EXISTS attack_techniques")
    op.execute("DROP INDEX IF EXISTS ix_sessions_unclustered")
    op.execute("DROP INDEX IF EXISTS ix_sessions_campaign_id")
    op.execute("DROP INDEX IF EXISTS ix_sessions_techniques")
    op.execute("ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_techniques_size")
    op.execute("ALTER TABLE sessions DROP COLUMN IF EXISTS clustered_at")
    op.execute("ALTER TABLE sessions DROP COLUMN IF EXISTS campaign_id")
    op.execute("ALTER TABLE sessions DROP COLUMN IF EXISTS techniques")
    op.execute("ALTER TABLE events DROP COLUMN IF EXISTS techniques")
