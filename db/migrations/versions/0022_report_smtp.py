"""Optional SMTP sending of abuse reports (M25): the profile, the send queue, the new rules.

Revision ID: 0022
Revises: 0021

* ``report_smtp``: one row (``CHECK id = 1``). The password is AES-GCM ciphertext written by the
  API and readable by ingest only (column grants in ``suckerpot_db.roles``; ``password_set`` is a
  generated flag the API may read).
* ``abuse_send_requests``: what the API asks ingest to send (a report or a test) and what ingest
  schedules in auto mode. The API never talks SMTP.
* ``abuse_reports.sent_via`` (``manual`` | ``smtp``) and a rewritten transition trigger. Every M22
  rule stays. New: ingest may move a report to ``sent`` only when a pending send request for it
  exists (``sent_via = 'smtp'``, guard passed); draft to sent is possible for ingest only, and
  ``reviewed_by = 'auto'`` marks an automatic send. The API can never write ``sent_via = 'smtp'``.
* ``abuse_send_requests_guard``: the API may only insert pending, non-automatic requests and may
  only cancel a pending one; ingest may only insert automatic pending ``send`` requests.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0022"
down_revision: str | None = "0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TRANSITION = """
CREATE OR REPLACE FUNCTION abuse_reports_transition() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    -- Ingest is the role that cannot write notes (the API and the owner can).
    ingest_mode boolean := NOT has_column_privilege(
        current_user, 'public.abuse_reports', 'notes', 'UPDATE');
    smtp_send boolean := false;
BEGIN
    IF NEW.id <> OLD.id OR NEW.public_id <> OLD.public_id OR NEW.id_seed <> OLD.id_seed
       OR NEW.recipient_id <> OLD.recipient_id OR NEW.kind <> OLD.kind
       OR NEW.demo <> OLD.demo THEN
        RAISE EXCEPTION 'abuse report identity columns are immutable' USING ERRCODE = '23514';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
        (OLD.status = 'draft' AND NEW.status IN ('reviewed', 'discarded', 'superseded'))
        OR (OLD.status IN ('draft', 'reviewed') AND NEW.status = 'sent' AND ingest_mode)
        OR (OLD.status = 'reviewed' AND NEW.status IN ('draft', 'sent', 'discarded'))
        OR (OLD.status = 'sent' AND NEW.status = 'closed')
    ) THEN
        RAISE EXCEPTION 'invalid abuse report transition' USING ERRCODE = '23514';
    END IF;
    IF NEW.demo AND NEW.status IN ('sent', 'closed') THEN
        RAISE EXCEPTION 'a demo abuse report cannot be sent' USING ERRCODE = '23514';
    END IF;
    IF NEW.sent_via IS DISTINCT FROM OLD.sent_via AND NOT (
        NEW.status = 'sent' AND OLD.status <> 'sent'
        AND (NEW.sent_via = 'smtp') = ingest_mode
    ) THEN
        RAISE EXCEPTION 'sent_via can only be set when the report is sent, by its sender'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.status <> 'draft' AND (
        NEW.evidence IS DISTINCT FROM OLD.evidence
        OR NEW.content_sha256 IS DISTINCT FROM OLD.content_sha256
        OR NEW.window_start IS DISTINCT FROM OLD.window_start
        OR NEW.window_end IS DISTINCT FROM OLD.window_end
        OR NEW.subject_count IS DISTINCT FROM OLD.subject_count
    ) THEN
        RAISE EXCEPTION 'only a draft abuse report can change its content'
            USING ERRCODE = '23514';
    END IF;
    IF ingest_mode THEN
        smtp_send := NEW.status = 'sent' AND OLD.status <> 'sent';
        IF smtp_send THEN
            -- Mail left through the SMTP profile: a pending request for this report must exist.
            IF NEW.sent_via IS DISTINCT FROM 'smtp' OR NOT NEW.guard_ok OR NOT EXISTS (
                SELECT 1 FROM abuse_send_requests
                WHERE report_id = OLD.id AND kind = 'send' AND status = 'pending') THEN
                RAISE EXCEPTION 'a report is sent by ingest only for a pending send request'
                    USING ERRCODE = '23514';
            END IF;
            IF NEW.evidence IS DISTINCT FROM OLD.evidence
               OR NEW.options IS DISTINCT FROM OLD.options
               OR NEW.notes IS DISTINCT FROM OLD.notes
               OR NEW.closed_at IS DISTINCT FROM OLD.closed_at
               OR NEW.closed_by IS DISTINCT FROM OLD.closed_by THEN
                RAISE EXCEPTION 'sending may not change the report' USING ERRCODE = '23514';
            END IF;
            -- Review fields: untouched, except that an automatic send of a draft is stamped.
            IF (NEW.reviewed_at IS DISTINCT FROM OLD.reviewed_at
                OR NEW.reviewed_by IS DISTINCT FROM OLD.reviewed_by
                OR NEW.reviewed_revision IS DISTINCT FROM OLD.reviewed_revision)
               AND NOT (OLD.status = 'draft' AND NEW.reviewed_by = 'auto') THEN
                RAISE EXCEPTION 'ingest may not touch review fields' USING ERRCODE = '23514';
            END IF;
        ELSE
            IF OLD.status <> 'draft' OR NEW.status NOT IN ('draft', 'superseded') THEN
                RAISE EXCEPTION 'ingest may only update drafts' USING ERRCODE = '23514';
            END IF;
            IF NEW.notes IS DISTINCT FROM OLD.notes
               OR NEW.reviewed_at IS DISTINCT FROM OLD.reviewed_at
               OR NEW.reviewed_by IS DISTINCT FROM OLD.reviewed_by
               OR NEW.reviewed_revision IS DISTINCT FROM OLD.reviewed_revision
               OR NEW.sent_at IS DISTINCT FROM OLD.sent_at
               OR NEW.sent_by IS DISTINCT FROM OLD.sent_by
               OR NEW.closed_at IS DISTINCT FROM OLD.closed_at
               OR NEW.closed_by IS DISTINCT FROM OLD.closed_by THEN
                RAISE EXCEPTION 'ingest may not touch review, sent or closed fields'
                    USING ERRCODE = '23514';
            END IF;
        END IF;
    END IF;
    RETURN NEW;
END
$$
"""

_OLD_TRANSITION = """
CREATE OR REPLACE FUNCTION abuse_reports_transition() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    ingest_mode boolean := NOT has_column_privilege(
        current_user, 'public.abuse_reports', 'notes', 'UPDATE');
BEGIN
    IF NEW.id <> OLD.id OR NEW.public_id <> OLD.public_id OR NEW.id_seed <> OLD.id_seed
       OR NEW.recipient_id <> OLD.recipient_id OR NEW.kind <> OLD.kind
       OR NEW.demo <> OLD.demo THEN
        RAISE EXCEPTION 'abuse report identity columns are immutable' USING ERRCODE = '23514';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
        (OLD.status = 'draft' AND NEW.status IN ('reviewed', 'discarded', 'superseded'))
        OR (OLD.status = 'reviewed' AND NEW.status IN ('draft', 'sent', 'discarded'))
        OR (OLD.status = 'sent' AND NEW.status = 'closed')
    ) THEN
        RAISE EXCEPTION 'invalid abuse report transition' USING ERRCODE = '23514';
    END IF;
    IF NEW.demo AND NEW.status IN ('sent', 'closed') THEN
        RAISE EXCEPTION 'a demo abuse report cannot be sent' USING ERRCODE = '23514';
    END IF;
    IF OLD.status <> 'draft' AND (
        NEW.evidence IS DISTINCT FROM OLD.evidence
        OR NEW.content_sha256 IS DISTINCT FROM OLD.content_sha256
        OR NEW.window_start IS DISTINCT FROM OLD.window_start
        OR NEW.window_end IS DISTINCT FROM OLD.window_end
        OR NEW.subject_count IS DISTINCT FROM OLD.subject_count
    ) THEN
        RAISE EXCEPTION 'only a draft abuse report can change its content'
            USING ERRCODE = '23514';
    END IF;
    IF ingest_mode THEN
        IF OLD.status <> 'draft' OR NEW.status NOT IN ('draft', 'superseded') THEN
            RAISE EXCEPTION 'ingest may only update drafts' USING ERRCODE = '23514';
        END IF;
        IF NEW.notes IS DISTINCT FROM OLD.notes
           OR NEW.reviewed_at IS DISTINCT FROM OLD.reviewed_at
           OR NEW.reviewed_by IS DISTINCT FROM OLD.reviewed_by
           OR NEW.reviewed_revision IS DISTINCT FROM OLD.reviewed_revision
           OR NEW.sent_at IS DISTINCT FROM OLD.sent_at
           OR NEW.sent_by IS DISTINCT FROM OLD.sent_by
           OR NEW.closed_at IS DISTINCT FROM OLD.closed_at
           OR NEW.closed_by IS DISTINCT FROM OLD.closed_by THEN
            RAISE EXCEPTION 'ingest may not touch review, sent or closed fields'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END
$$
"""

_REQUEST_GUARD = """
CREATE OR REPLACE FUNCTION abuse_send_requests_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    -- Ingest is the role that may write error_code (the API may only insert and cancel).
    ingest_mode boolean := has_column_privilege(
        current_user, 'public.abuse_send_requests', 'error_code', 'UPDATE');
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'pending' OR NEW.done_at IS NOT NULL OR NEW.error_code IS NOT NULL THEN
            RAISE EXCEPTION 'a send request starts pending' USING ERRCODE = '23514';
        END IF;
        IF ingest_mode AND (NOT NEW.auto OR NEW.kind <> 'send') THEN
            RAISE EXCEPTION 'ingest only schedules automatic sends' USING ERRCODE = '23514';
        END IF;
        IF NOT ingest_mode AND (NEW.auto OR NEW.scheduled_at IS NOT NULL) THEN
            RAISE EXCEPTION 'only ingest schedules automatic sends' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.id <> OLD.id OR NEW.report_id IS DISTINCT FROM OLD.report_id
       OR NEW.kind <> OLD.kind OR NEW.auto <> OLD.auto
       OR NEW.requested_by <> OLD.requested_by
       OR NEW.scheduled_at IS DISTINCT FROM OLD.scheduled_at THEN
        RAISE EXCEPTION 'a send request is immutable' USING ERRCODE = '23514';
    END IF;
    IF OLD.status <> 'pending' THEN
        RAISE EXCEPTION 'a finished send request cannot change' USING ERRCODE = '23514';
    END IF;
    IF NOT ingest_mode THEN
        IF NEW.status <> 'cancelled' THEN
            RAISE EXCEPTION 'a request can only be cancelled here' USING ERRCODE = '23514';
        END IF;
        NEW.done_at := now();  -- the API cannot write done_at itself
    END IF;
    RETURN NEW;
END
$$
"""

_PRUNE = """
CREATE OR REPLACE PROCEDURE suckerpot_abuse_prune(job_id integer, config jsonb)
LANGUAGE plpgsql AS $$
DECLARE
    unsent_days integer := COALESCE((config ->> 'unsent_days')::integer, 90);
    sent_days integer := COALESCE((config ->> 'sent_days')::integer, 730);
BEGIN
    -- Subjects and requests go with their report (ON DELETE CASCADE). Recipients are kept.
    DELETE FROM abuse_reports
    WHERE status IN ('discarded', 'superseded')
      AND updated_at < now() - make_interval(days => unsent_days);
    DELETE FROM abuse_reports
    WHERE status IN ('sent', 'closed')
      AND COALESCE(closed_at, sent_at, updated_at) < now() - make_interval(days => sent_days);
    DELETE FROM abuse_report_requests
    WHERE done_at IS NOT NULL AND done_at < now() - INTERVAL '7 days';
    -- The daily cap only looks at today; a trace of old sends is kept for a month.
    DELETE FROM abuse_send_requests
    WHERE done_at IS NOT NULL AND done_at < now() - INTERVAL '30 days';
    DELETE FROM abuse_networks WHERE expires_at < now() - INTERVAL '30 days';
    -- Learned terms nobody confirmed expire after a week; at most 200 stay pending (oldest go).
    -- Confirmed, manual and sensor rows are kept: an old home address still identifies the owner.
    DELETE FROM report_self_terms
    WHERE source = 'learned' AND NOT confirmed AND last_seen < now() - INTERVAL '7 days';
    DELETE FROM report_self_terms WHERE id IN (
        SELECT id FROM report_self_terms WHERE source = 'learned' AND NOT confirmed
        ORDER BY last_seen DESC OFFSET 200);
END
$$
"""


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE report_smtp (
            id smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
            host text NOT NULL CHECK (char_length(host) BETWEEN 4 AND 253),
            port integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
            security text NOT NULL CHECK (security IN ('starttls', 'ssl')),
            username text NOT NULL DEFAULT '' CHECK (char_length(username) <= 254),
            from_address text NOT NULL CHECK (char_length(from_address) BETWEEN 3 AND 254),
            from_name text NOT NULL DEFAULT '' CHECK (char_length(from_name) <= 100),
            password_ciphertext bytea,
            password_nonce bytea,
            password_set boolean GENERATED ALWAYS AS (password_ciphertext IS NOT NULL) STORED,
            mode text NOT NULL DEFAULT 'off' CHECK (mode IN ('off', 'click', 'auto')),
            auto_hold_minutes integer NOT NULL DEFAULT 60
                CHECK (auto_hold_minutes BETWEEN 10 AND 1440),
            daily_cap integer NOT NULL DEFAULT 20 CHECK (daily_cap BETWEEN 1 AND 200),
            updated_at timestamptz NOT NULL DEFAULT now(),
            updated_by text CHECK (char_length(updated_by) <= 120),
            CHECK ((password_ciphertext IS NULL) = (password_nonce IS NULL))
        )
        """
    )
    op.execute("ALTER TABLE abuse_reports ADD COLUMN sent_via text")
    op.execute(
        "ALTER TABLE abuse_reports ADD CONSTRAINT ck_abuse_reports_sent_via "
        "CHECK ((sent_via IN ('manual', 'smtp') AND status IN ('sent', 'closed')) "
        "OR sent_via IS NULL)"
    )
    op.execute(
        """
        CREATE TABLE abuse_send_requests (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            report_id bigint REFERENCES abuse_reports (id) ON DELETE CASCADE,
            kind text NOT NULL CHECK (kind IN ('send', 'test')),
            auto boolean NOT NULL DEFAULT false,
            requested_by text NOT NULL CHECK (char_length(requested_by) <= 120),
            requested_at timestamptz NOT NULL DEFAULT now(),
            scheduled_at timestamptz,
            status text NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'sent', 'failed', 'cancelled')),
            error_code text CHECK (char_length(error_code) <= 120),
            done_at timestamptz,
            CHECK ((kind = 'send') = (report_id IS NOT NULL)),
            CHECK ((status = 'pending') = (done_at IS NULL))
        )
        """
    )
    op.execute(
        "CREATE INDEX ix_abuse_send_requests_pending ON abuse_send_requests (id) "
        "WHERE status = 'pending'"
    )
    op.execute(
        "CREATE INDEX ix_abuse_send_requests_report ON abuse_send_requests (report_id, id DESC)"
    )
    op.execute(_TRANSITION)
    op.execute(_REQUEST_GUARD)
    op.execute(
        "CREATE TRIGGER abuse_send_requests_guard BEFORE INSERT OR UPDATE ON abuse_send_requests "
        "FOR EACH ROW EXECUTE FUNCTION abuse_send_requests_guard()"
    )
    op.execute(_PRUNE)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS abuse_send_requests")
    op.execute("DROP FUNCTION IF EXISTS abuse_send_requests_guard()")
    op.execute("DROP TABLE IF EXISTS report_smtp")
    op.execute(_OLD_TRANSITION)
    op.execute("ALTER TABLE abuse_reports DROP CONSTRAINT IF EXISTS ck_abuse_reports_sent_via")
    op.execute("ALTER TABLE abuse_reports DROP COLUMN IF EXISTS sent_via")
