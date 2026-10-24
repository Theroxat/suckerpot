"""Retention: continuous aggregates, daily session rollup, compression, maintenance job.

Revision ID: 0004
Revises: 0003

The background jobs themselves (retention, compression, refresh, maintenance) are created by
``suckerpot_db.retention.apply_policies`` with the RETENTION_DAYS of the environment; this
revision calls it with the current value and the migrate entrypoint calls it again after every
upgrade so a changed RETENTION_DAYS takes effect.
"""

from collections.abc import Sequence

from alembic import op

from suckerpot_db.retention import AGGREGATES, MAINTENANCE_PROC, apply_policies, retention_days

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_CAGG = "WITH (timescaledb.continuous, timescaledb.materialized_only = false)"

_MAINTENANCE = f"""
CREATE OR REPLACE PROCEDURE {MAINTENANCE_PROC}(job_id integer, config jsonb)
LANGUAGE plpgsql AS $$
DECLARE
    days integer := COALESCE((config ->> 'retention_days')::integer, 90);
    cutoff timestamptz := date_trunc('day', now() - make_interval(days => days), 'UTC');
BEGIN
    -- Whole UTC days only, so each day is rolled up exactly once and then removed.
    INSERT INTO sessions_daily AS d (
        day, sensor, sessions, events, login_attempts, logins_succeeded, commands, downloads,
        http_requests, unique_ips
    )
    SELECT (started_at AT TIME ZONE 'UTC')::date, sensor, count(*), sum(event_count),
           sum(login_attempts), count(*) FILTER (WHERE login_success), sum(commands),
           sum(downloads), sum(http_requests), count(DISTINCT src_ip)
    FROM sessions WHERE started_at < cutoff
    GROUP BY 1, 2
    ON CONFLICT (day, sensor) DO UPDATE SET
        sessions = d.sessions + EXCLUDED.sessions,
        events = d.events + EXCLUDED.events,
        login_attempts = d.login_attempts + EXCLUDED.login_attempts,
        logins_succeeded = d.logins_succeeded + EXCLUDED.logins_succeeded,
        commands = d.commands + EXCLUDED.commands,
        downloads = d.downloads + EXCLUDED.downloads,
        http_requests = d.http_requests + EXCLUDED.http_requests,
        unique_ips = d.unique_ips + EXCLUDED.unique_ips;
    DELETE FROM sessions WHERE started_at < cutoff;
    -- Enrichment caches: reputation answers live 24 h, keep a day of grace.
    DELETE FROM ip_reputation
    WHERE GREATEST(updated_at, abuse_checked_at, gn_checked_at) < now() - INTERVAL '48 hours';
    DELETE FROM enrichment_quota WHERE day < (now() AT TIME ZONE 'UTC')::date - 30;
END
$$
"""


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE sessions_daily (
            day date NOT NULL,
            sensor text NOT NULL,
            sessions bigint NOT NULL,
            events bigint NOT NULL,
            login_attempts bigint NOT NULL,
            logins_succeeded bigint NOT NULL,
            commands bigint NOT NULL,
            downloads bigint NOT NULL,
            http_requests bigint NOT NULL,
            unique_ips bigint NOT NULL,
            PRIMARY KEY (day, sensor)
        )
        """
    )
    op.execute(
        f"""
        CREATE MATERIALIZED VIEW events_hourly {_CAGG} AS
        SELECT time_bucket(INTERVAL '1 hour', ts) AS bucket, sensor, type, count(*) AS events
        FROM events GROUP BY 1, 2, 3 WITH NO DATA
        """
    )
    # One row per distinct tag set; unnest(tags) and sum(events) to count events per tag.
    op.execute(
        f"""
        CREATE MATERIALIZED VIEW events_daily_tags {_CAGG} AS
        SELECT time_bucket(INTERVAL '1 day', ts) AS bucket, sensor, tags, count(*) AS events
        FROM events WHERE tags <> '{{}}' GROUP BY 1, 2, 3 WITH NO DATA
        """
    )
    op.execute(
        f"""
        CREATE MATERIALIZED VIEW events_daily_country {_CAGG} AS
        SELECT time_bucket(INTERVAL '1 day', ts) AS bucket, sensor, country, count(*) AS events
        FROM events WHERE country IS NOT NULL GROUP BY 1, 2, 3 WITH NO DATA
        """
    )
    op.execute(
        f"""
        CREATE MATERIALIZED VIEW events_daily_ip {_CAGG} AS
        SELECT time_bucket(INTERVAL '1 day', ts) AS bucket, sensor, src_ip,
               count(*) AS events,
               count(*) FILTER (WHERE type = 'login_attempt') AS login_attempts,
               count(*) FILTER (WHERE type = 'command') AS commands,
               count(*) FILTER (WHERE type = 'download_attempt') AS downloads,
               count(*) FILTER (WHERE type = 'http_request') AS http_requests,
               min(ts) AS first_seen, max(ts) AS last_seen,
               min(country) AS country, max(asn) AS asn
        FROM events GROUP BY 1, 2, 3 WITH NO DATA
        """
    )
    op.execute(
        "ALTER TABLE events SET (timescaledb.compress, "
        "timescaledb.compress_segmentby = 'sensor', timescaledb.compress_orderby = 'ts DESC')"
    )
    op.execute(_MAINTENANCE)
    apply_policies(op.get_bind(), retention_days())


def downgrade() -> None:
    conn = op.get_bind()
    conn.exec_driver_sql(
        f"SELECT delete_job(job_id) FROM timescaledb_information.jobs "
        f"WHERE proc_name = '{MAINTENANCE_PROC}'"
    )
    conn.exec_driver_sql("SELECT remove_retention_policy('events', if_exists => true)")
    conn.exec_driver_sql("SELECT remove_compression_policy('events', if_exists => true)")
    for view in reversed(list(AGGREGATES)):
        op.execute(f"DROP MATERIALIZED VIEW IF EXISTS {view}")
    op.execute(f"DROP PROCEDURE IF EXISTS {MAINTENANCE_PROC}(integer, jsonb)")
    op.execute("DROP TABLE IF EXISTS sessions_daily")
