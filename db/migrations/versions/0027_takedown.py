"""Takedown tracking and abuse.ch submission (M27): targets, checks, submissions, roll-up.

Revision ID: 0027
Revises: 0026

* ``takedown_targets``: one row per reported target (attacking address, payload host, payload URL,
  C2). Ingest owns the state columns, the collector owns the HTTP re-check columns, the API may
  only stop tracking or ask for an early re-check (column grants in ``suckerpot_db.roles``).
* ``takedown_checks``: one row per check, constants and small numbers only.
* ``takedown_target_links``: which report or submission put a target under tracking.
* ``abusech_submission``: the single settings row (the Auth-Key is AES-GCM ciphertext written by
  the API and readable by ingest only).
* ``abusech_submissions``: audit log and queue of what was (or may be) sent to URLhaus and
  ThreatFox. ``abusech_submissions_guard`` limits what each role may do; delivery is at most once:
  ingest commits ``submitting`` before the request and never retries a ``submitting`` row.
* ``outcome_rollup_monthly``: aggregates only, kept forever.
* ``suckerpot_takedown_prune``: retention procedure (job created by ``suckerpot_db.retention``);
  it never touches the roll-up.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0027"
down_revision: str | None = "0026"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TARGET_GUARD = """
CREATE OR REPLACE FUNCTION takedown_targets_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.id <> OLD.id OR NEW.kind <> OLD.kind OR NEW.role <> OLD.role
       OR NEW.value <> OLD.value OR NEW.target_key <> OLD.target_key
       OR NEW.demo <> OLD.demo THEN
        RAISE EXCEPTION 'takedown target identity columns are immutable' USING ERRCODE = '23514';
    END IF;
    IF NEW.reported_at > OLD.reported_at THEN
        RAISE EXCEPTION 'reported_at may only move earlier' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$
"""

_SUBMISSION_GUARD = """
CREATE OR REPLACE FUNCTION abusech_submissions_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    -- Ingest is the role that may write result_code (the API only approves and cancels).
    ingest_mode boolean := has_column_privilege(
        current_user, 'public.abusech_submissions', 'result_code', 'UPDATE');
    cur_mode text;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NOT ingest_mode THEN
            RAISE EXCEPTION 'only ingest records submission candidates' USING ERRCODE = '23514';
        END IF;
        IF NEW.status NOT IN ('candidate', 'skipped_known', 'skipped_never_list', 'guard_failed')
           OR NEW.submitted_at IS NOT NULL OR NEW.started_at IS NOT NULL
           OR NEW.approved_by IS NOT NULL THEN
            RAISE EXCEPTION 'a submission starts as a candidate' USING ERRCODE = '23514';
        END IF;
        IF NEW.demo AND NEW.status <> 'candidate' THEN
            RAISE EXCEPTION 'a demo submission stays a candidate' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.id <> OLD.id OR NEW.platform <> OLD.platform OR NEW.ioc_type <> OLD.ioc_type
       OR NEW.value <> OLD.value OR NEW.threat <> OLD.threat OR NEW.demo <> OLD.demo
       OR NEW.created_at <> OLD.created_at
       OR NEW.malware IS DISTINCT FROM OLD.malware OR NEW.tags IS DISTINCT FROM OLD.tags THEN
        RAISE EXCEPTION 'submission identity columns are immutable' USING ERRCODE = '23514';
    END IF;
    IF OLD.status IN ('submitted', 'duplicate', 'rejected', 'failed', 'cancelled',
                      'skipped_known', 'skipped_never_list', 'guard_failed') THEN
        RAISE EXCEPTION 'a finished submission cannot change' USING ERRCODE = '23514';
    END IF;
    IF NEW.demo AND NEW.status <> 'candidate' THEN
        RAISE EXCEPTION 'a demo submission stays a candidate' USING ERRCODE = '23514';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
        (OLD.status = 'candidate' AND NEW.status IN
            ('pending', 'skipped_known', 'skipped_never_list', 'guard_failed'))
        OR (OLD.status = 'pending' AND NEW.status IN
            ('submitting', 'cancelled', 'guard_failed', 'failed'))
        OR (OLD.status = 'submitting' AND NEW.status IN
            ('submitted', 'duplicate', 'rejected', 'failed', 'pending'))
    ) THEN
        RAISE EXCEPTION 'invalid submission transition' USING ERRCODE = '23514';
    END IF;
    IF NOT ingest_mode THEN
        -- The API approves a candidate (review or auto mode) and cancels a pending row.
        IF OLD.status = 'candidate' AND NEW.status = 'pending' THEN
            SELECT mode INTO cur_mode FROM abusech_submission WHERE id = 1;
            IF cur_mode IS NULL OR cur_mode = 'off' THEN
                RAISE EXCEPTION 'abuse.ch submission is off' USING ERRCODE = '23514';
            END IF;
            IF OLD.lookup <> 'unknown' THEN
                RAISE EXCEPTION 'the lookup must say the value is unknown' USING ERRCODE = '23514';
            END IF;
            IF NEW.approved_by IS NULL THEN
                RAISE EXCEPTION 'approved_by is required' USING ERRCODE = '23514';
            END IF;
            NEW.approved_at := now();
        ELSIF OLD.status = 'pending' AND NEW.status = 'cancelled' THEN
            NEW.done_at := now();
        ELSE
            RAISE EXCEPTION 'the API can only approve a candidate or cancel a pending row'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        IF OLD.status = 'candidate' AND NEW.status = 'pending' THEN
            -- ingest schedules only automatic submissions; a manual approval is the API's.
            IF NOT NEW.auto OR NEW.scheduled_at IS NULL OR OLD.lookup <> 'unknown' THEN
                RAISE EXCEPTION 'ingest schedules only automatic, looked-up submissions'
                    USING ERRCODE = '23514';
            END IF;
        END IF;
        IF NEW.approved_by IS DISTINCT FROM OLD.approved_by
           OR NEW.approved_at IS DISTINCT FROM OLD.approved_at THEN
            RAISE EXCEPTION 'ingest cannot write approvals' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END
$$
"""

_PRUNE = """
CREATE OR REPLACE PROCEDURE suckerpot_takedown_prune(job_id integer, config jsonb)
LANGUAGE plpgsql AS $$
DECLARE
    check_days integer := COALESCE((config ->> 'check_days')::integer, 400);
    target_days integer := COALESCE((config ->> 'target_days')::integer, 400);
    submission_days integer := COALESCE((config ->> 'submission_days')::integer, 730);
BEGIN
    DELETE FROM takedown_checks WHERE checked_at < now() - make_interval(days => check_days);
    -- Links and checks of a target go with it (ON DELETE CASCADE).
    DELETE FROM takedown_targets
    WHERE track_until < now() - make_interval(days => target_days);
    DELETE FROM abusech_submissions
    WHERE created_at < now() - make_interval(days => submission_days);
    -- outcome_rollup_monthly is kept forever.
END
$$
"""


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE takedown_targets (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            kind text NOT NULL CHECK (kind IN ('url', 'ip', 'domain')),
            role text NOT NULL
                CHECK (role IN ('attack_source', 'payload_host', 'payload_url', 'c2')),
            value text NOT NULL CHECK (char_length(value) BETWEEN 1 AND 1024),
            target_key text NOT NULL CHECK (target_key ~ '^[0-9a-f]{64}$'),
            parent_id bigint REFERENCES takedown_targets (id) ON DELETE CASCADE,
            fetch_target_id bigint REFERENCES fetch_targets (id) ON DELETE SET NULL,
            network_id bigint REFERENCES abuse_networks (id) ON DELETE SET NULL,
            asn integer,
            country text CHECK (country IS NULL OR char_length(country) = 2),
            provider_key text NOT NULL CHECK (char_length(provider_key) BETWEEN 1 AND 64),
            provider_name text CHECK (char_length(provider_name) <= 200),
            reported_at timestamptz NOT NULL,
            channels text[] NOT NULL DEFAULT '{}'
                CHECK (channels <@ ARRAY['mail', 'urlhaus', 'threatfox']),
            demo boolean NOT NULL DEFAULT false,
            tracking boolean NOT NULL DEFAULT true,
            track_until timestamptz NOT NULL,
            stopped_at timestamptz,
            stopped_by text CHECK (char_length(stopped_by) <= 120),
            state text NOT NULL DEFAULT 'unknown'
                CHECK (state IN ('up', 'down', 'changed', 'unknown')),
            state_source text CHECK (state_source IN
                ('http', 'urlhaus', 'threatfox', 'abuseipdb', 'sightings', 'samples', 'children')),
            state_since timestamptz,
            state_updated_at timestamptz,
            down_before_report boolean NOT NULL DEFAULT false,
            last_up_at timestamptz,
            first_down_at timestamptz,
            resurrections smallint NOT NULL DEFAULT 0,
            listing_step smallint NOT NULL DEFAULT 0,
            listing_next_at timestamptz,
            http_eligible boolean NOT NULL DEFAULT false,
            baseline_sha256 text CHECK (baseline_sha256 ~ '^[0-9a-f]{64}$'),
            last_sha256 text CHECK (last_sha256 ~ '^[0-9a-f]{64}$'),
            http_step smallint NOT NULL DEFAULT 0,
            http_next_at timestamptz,
            http_last_at timestamptz,
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (kind, role, value),
            CHECK (NOT http_eligible OR kind = 'url'),
            CHECK (role <> 'payload_url' OR kind = 'url')
        )
        """
    )
    op.execute(
        "CREATE INDEX ix_takedown_http_due ON takedown_targets (http_next_at) "
        "WHERE http_eligible AND tracking AND NOT demo"
    )
    op.execute(
        "CREATE INDEX ix_takedown_listing_due ON takedown_targets (listing_next_at) "
        "WHERE tracking AND NOT demo"
    )
    op.execute("CREATE INDEX ix_takedown_provider ON takedown_targets (provider_key, reported_at)")
    op.execute("CREATE INDEX ix_takedown_state ON takedown_targets (state, reported_at DESC)")
    op.execute(
        "CREATE INDEX ix_takedown_parent ON takedown_targets (parent_id) "
        "WHERE parent_id IS NOT NULL"
    )
    op.execute(
        """
        CREATE TABLE takedown_checks (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            target_id bigint NOT NULL REFERENCES takedown_targets (id) ON DELETE CASCADE,
            checked_at timestamptz NOT NULL DEFAULT now(),
            method text NOT NULL CHECK (method IN
                ('http', 'urlhaus', 'threatfox', 'abuseipdb', 'sightings', 'samples')),
            outcome text NOT NULL CHECK (outcome ~ '^[a-z_0-9]{1,32}$'),
            http_status smallint,
            sha256 text CHECK (sha256 IS NULL OR sha256 ~ '^[0-9a-f]{64}$'),
            bytes bigint,
            duration_ms integer,
            detail jsonb NOT NULL DEFAULT '{}' CHECK (octet_length(detail::text) <= 1024)
        )
        """
    )
    op.execute(
        "CREATE INDEX ix_takedown_checks_target ON takedown_checks (target_id, checked_at DESC)"
    )
    op.execute(
        """
        CREATE TABLE abusech_submission (
            id smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
            mode text NOT NULL DEFAULT 'off' CHECK (mode IN ('off', 'review', 'auto')),
            threatfox_enabled boolean NOT NULL DEFAULT false,
            anonymous boolean NOT NULL DEFAULT true,
            auto_hold_minutes integer NOT NULL DEFAULT 60
                CHECK (auto_hold_minutes BETWEEN 10 AND 1440),
            daily_cap integer NOT NULL DEFAULT 20 CHECK (daily_cap BETWEEN 1 AND 200),
            key_ciphertext bytea,
            key_nonce bytea,
            key_set boolean GENERATED ALWAYS AS (key_ciphertext IS NOT NULL) STORED,
            key_last4 text CHECK (key_last4 IS NULL OR char_length(key_last4) = 4),
            updated_at timestamptz NOT NULL DEFAULT now(),
            updated_by text CHECK (char_length(updated_by) <= 120),
            CHECK ((key_ciphertext IS NULL) = (key_nonce IS NULL)),
            CHECK (mode <> 'auto' OR key_ciphertext IS NOT NULL)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE abusech_submissions (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            platform text NOT NULL CHECK (platform IN ('urlhaus', 'threatfox')),
            ioc_type text NOT NULL CHECK (ioc_type IN ('url', 'ip:port')),
            value text NOT NULL CHECK (char_length(value) BETWEEN 1 AND 1024),
            threat text NOT NULL CHECK (threat IN ('malware_download', 'botnet_cc')),
            malware text CHECK (char_length(malware) <= 64),
            tags text[] NOT NULL DEFAULT '{}' CHECK (cardinality(tags) <= 5),
            sample_sha256 text REFERENCES samples (sha256) ON DELETE SET NULL,
            fetch_target_id bigint REFERENCES fetch_targets (id) ON DELETE SET NULL,
            demo boolean NOT NULL DEFAULT false,
            lookup text NOT NULL DEFAULT 'pending'
                CHECK (lookup IN ('pending', 'unknown', 'known')),
            status text NOT NULL DEFAULT 'candidate' CHECK (status IN ('candidate', 'pending',
                'submitting', 'submitted', 'duplicate', 'rejected', 'failed', 'cancelled',
                'skipped_known', 'skipped_never_list', 'guard_failed')),
            result_code text CHECK (char_length(result_code) <= 120),
            reference text CHECK (reference IS NULL OR char_length(reference) <= 256),
            auto boolean NOT NULL DEFAULT false,
            created_at timestamptz NOT NULL DEFAULT now(),
            approved_at timestamptz,
            approved_by text CHECK (char_length(approved_by) <= 120),
            scheduled_at timestamptz,
            started_at timestamptz,
            submitted_at timestamptz,
            done_at timestamptz,
            UNIQUE (platform, value)
        )
        """
    )
    op.execute(
        "CREATE INDEX ix_abusech_submissions_status "
        "ON abusech_submissions (status, created_at DESC)"
    )
    op.execute(
        "CREATE INDEX ix_abusech_submissions_pending ON abusech_submissions (scheduled_at) "
        "WHERE status = 'pending'"
    )
    op.execute(
        """
        CREATE TABLE takedown_target_links (
            target_id bigint NOT NULL REFERENCES takedown_targets (id) ON DELETE CASCADE,
            report_id bigint REFERENCES abuse_reports (id) ON DELETE CASCADE,
            submission_id bigint REFERENCES abusech_submissions (id) ON DELETE CASCADE,
            linked_at timestamptz NOT NULL DEFAULT now(),
            CHECK ((report_id IS NULL) <> (submission_id IS NULL))
        )
        """
    )
    op.execute(
        "CREATE UNIQUE INDEX ux_takedown_links_report ON takedown_target_links "
        "(target_id, report_id) WHERE report_id IS NOT NULL"
    )
    op.execute(
        "CREATE UNIQUE INDEX ux_takedown_links_submission ON takedown_target_links "
        "(target_id, submission_id) WHERE submission_id IS NOT NULL"
    )
    op.execute(
        """
        CREATE TABLE outcome_rollup_monthly (
            month date NOT NULL CHECK (extract(day FROM month) = 1),
            provider_key text NOT NULL CHECK (char_length(provider_key) <= 64),
            asn integer,
            country text CHECK (country IS NULL OR char_length(country) = 2),
            kind text NOT NULL
                CHECK (kind IN ('attack_source', 'payload_host', 'payload_url', 'c2')),
            channel text NOT NULL CHECK (channel IN ('mail', 'urlhaus', 'threatfox')),
            reports_sent integer NOT NULL DEFAULT 0,
            reports_answered integer NOT NULL DEFAULT 0,
            auto_ack integer NOT NULL DEFAULT 0,
            ticket_opened integer NOT NULL DEFAULT 0,
            resolved integer NOT NULL DEFAULT 0,
            rejected integer NOT NULL DEFAULT 0,
            bounced integer NOT NULL DEFAULT 0,
            human_reply integer NOT NULL DEFAULT 0,
            targets integer NOT NULL DEFAULT 0,
            targets_eligible_48h integer NOT NULL DEFAULT 0,
            targets_down_48h integer NOT NULL DEFAULT 0,
            targets_eligible_7d integer NOT NULL DEFAULT 0,
            targets_down_7d integer NOT NULL DEFAULT 0,
            targets_eligible_30d integer NOT NULL DEFAULT 0,
            targets_down_30d integer NOT NULL DEFAULT 0,
            ttd_p50_s integer,
            first_reply_p50_s integer,
            computed_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (month, provider_key, kind, channel)
        )
        """
    )
    op.execute(_TARGET_GUARD)
    op.execute(
        "CREATE TRIGGER takedown_targets_guard BEFORE UPDATE ON takedown_targets "
        "FOR EACH ROW EXECUTE FUNCTION takedown_targets_guard()"
    )
    op.execute(_SUBMISSION_GUARD)
    op.execute(
        "CREATE TRIGGER abusech_submissions_guard BEFORE INSERT OR UPDATE ON abusech_submissions "
        "FOR EACH ROW EXECUTE FUNCTION abusech_submissions_guard()"
    )
    op.execute(_PRUNE)


def downgrade() -> None:
    # The job is scheduled by suckerpot_db.retention; without this it would outlive its procedure.
    op.execute(
        "SELECT delete_job(job_id) FROM timescaledb_information.jobs "
        "WHERE proc_name = 'suckerpot_takedown_prune'"
    )
    op.execute("DROP PROCEDURE IF EXISTS suckerpot_takedown_prune(integer, jsonb)")
    op.execute("DROP TABLE IF EXISTS outcome_rollup_monthly")
    op.execute("DROP TABLE IF EXISTS takedown_target_links")
    op.execute("DROP TABLE IF EXISTS abusech_submissions")
    op.execute("DROP TABLE IF EXISTS abusech_submission")
    op.execute("DROP TABLE IF EXISTS takedown_checks")
    op.execute("DROP TABLE IF EXISTS takedown_targets")
    op.execute("DROP FUNCTION IF EXISTS abusech_submissions_guard()")
    op.execute("DROP FUNCTION IF EXISTS takedown_targets_guard()")
