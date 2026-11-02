"""Report outcomes (M26): the reply token, the IMAP profile, replies and outcomes.

Revision ID: 0026
Revises: 0025

* ``abuse_reports.reply_token``: 12 random hex digits, unique, immutable, independent of every
  internal id (O6). Existing rows get a distinct value from the volatile default.
* ``report_settings.reference_style``, ``abuse_recipients.reply_domains``,
  ``abuse_send_requests.message_id`` (written once by ingest when it claims the request).
* ``report_imap`` (the mailbox profile, password AES-GCM written by the API and readable by
  ingest only), ``report_imap_state`` (ingest), ``report_imap_requests`` (API asks, ingest
  answers), ``abuse_replies``, ``abuse_reply_imports`` (pasted mail), ``abuse_report_outcomes``
  (auto columns written by ingest, manual columns by the API: column grants).
* The transition trigger also freezes ``reply_token``; the send request guard knows
  ``message_id``; ``abuse_report_outcomes_guard`` accepts only sent or closed reports.
* ``suckerpot_abuse_prune`` expires excerpts and unmatched replies and trims work rows.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0026"
down_revision: str | None = "0025"
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
       OR NEW.demo <> OLD.demo OR NEW.reply_token <> OLD.reply_token THEN
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
            -- Mail left through the SMTP profile: a request for this report must be in 'sending'.
            IF NEW.sent_via IS DISTINCT FROM 'smtp' OR NOT NEW.guard_ok OR NOT EXISTS (
                SELECT 1 FROM abuse_send_requests
                WHERE report_id = OLD.id AND kind = 'send' AND status = 'sending') THEN
                RAISE EXCEPTION 'a report is sent by ingest only for a request being sent'
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
            -- Mail left through the SMTP profile: a request for this report must be in 'sending'.
            IF NEW.sent_via IS DISTINCT FROM 'smtp' OR NOT NEW.guard_ok OR NOT EXISTS (
                SELECT 1 FROM abuse_send_requests
                WHERE report_id = OLD.id AND kind = 'send' AND status = 'sending') THEN
                RAISE EXCEPTION 'a report is sent by ingest only for a request being sent'
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
        IF NEW.message_id IS NOT NULL THEN
            RAISE EXCEPTION 'a send request starts without a message id' USING ERRCODE = '23514';
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
    -- The Message-ID is written once, by ingest, in the update that claims the request.
    IF NEW.message_id IS DISTINCT FROM OLD.message_id AND NOT (
        OLD.message_id IS NULL AND ingest_mode AND NEW.status = 'sending'
    ) THEN
        RAISE EXCEPTION 'the message id is set once, when the request is claimed'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.status IN ('sent', 'failed', 'cancelled') THEN
        RAISE EXCEPTION 'a finished send request cannot change' USING ERRCODE = '23514';
    END IF;
    IF NOT ingest_mode THEN
        -- The API cancels a request that nobody has started. Once ingest set it to 'sending'
        -- the mail may already be on the wire: nothing changes it but ingest.
        IF OLD.status <> 'pending' OR NEW.status <> 'cancelled' THEN
            RAISE EXCEPTION 'a request can only be cancelled here' USING ERRCODE = '23514';
        END IF;
        NEW.done_at := now();  -- the API cannot write done_at itself
    ELSIF OLD.status = 'pending' AND NEW.status NOT IN ('pending', 'sending', 'failed', 'cancelled')
    THEN
        RAISE EXCEPTION 'a request is sent only after it was marked sending'
            USING ERRCODE = '23514';
    ELSIF OLD.status = 'sending' AND NEW.status NOT IN ('sending', 'sent', 'failed', 'pending')
    THEN
        RAISE EXCEPTION 'invalid send request transition' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$
"""

_OLD_REQUEST_GUARD = """
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
    IF OLD.status IN ('sent', 'failed', 'cancelled') THEN
        RAISE EXCEPTION 'a finished send request cannot change' USING ERRCODE = '23514';
    END IF;
    IF NOT ingest_mode THEN
        -- The API cancels a request that nobody has started. Once ingest set it to 'sending'
        -- the mail may already be on the wire: nothing changes it but ingest.
        IF OLD.status <> 'pending' OR NEW.status <> 'cancelled' THEN
            RAISE EXCEPTION 'a request can only be cancelled here' USING ERRCODE = '23514';
        END IF;
        NEW.done_at := now();  -- the API cannot write done_at itself
    ELSIF OLD.status = 'pending' AND NEW.status NOT IN ('pending', 'sending', 'failed', 'cancelled')
    THEN
        RAISE EXCEPTION 'a request is sent only after it was marked sending'
            USING ERRCODE = '23514';
    ELSIF OLD.status = 'sending' AND NEW.status NOT IN ('sending', 'sent', 'failed', 'pending')
    THEN
        RAISE EXCEPTION 'invalid send request transition' USING ERRCODE = '23514';
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
    excerpt_days integer := COALESCE((config ->> 'excerpt_days')::integer, 180);
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
    -- Sent 'send' rows go with their report; tests and unfinished requests are trimmed.
    DELETE FROM abuse_send_requests
    WHERE done_at IS NOT NULL AND done_at < now() - INTERVAL '30 days'
      AND (kind = 'test' OR status <> 'sent');
    -- Replies (M26): excerpts expire, unmatched replies expire, finished work rows are trimmed.
    UPDATE abuse_replies SET excerpt = NULL, excerpt_purged_at = now()
    WHERE excerpt IS NOT NULL AND received_at < now() - make_interval(days => excerpt_days);
    DELETE FROM abuse_replies
    WHERE report_id IS NULL AND received_at < now() - INTERVAL '180 days';
    DELETE FROM abuse_reply_imports
    WHERE status <> 'pending' AND done_at < now() - INTERVAL '7 days';
    DELETE FROM report_imap_requests
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

_OLD_PRUNE = """
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

_OUTCOME_GUARD = """
CREATE OR REPLACE FUNCTION abuse_report_outcomes_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    r_status text;
    r_sent_at timestamptz;
BEGIN
    SELECT status, sent_at INTO r_status, r_sent_at FROM abuse_reports WHERE id = NEW.report_id;
    IF r_status IS NULL OR r_status NOT IN ('sent', 'closed') THEN
        RAISE EXCEPTION 'an outcome exists only for a sent or closed report'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.manual_at IS NOT NULL AND r_sent_at IS NOT NULL AND NEW.manual_at < r_sent_at THEN
        RAISE EXCEPTION 'an outcome cannot be dated before the report was sent'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$
"""

_OUTCOMES = (
    "('none', 'auto_ack', 'ticket_opened', 'resolved', 'rejected', 'bounce', "
    "'human_reply', 'unknown')"
)


def upgrade() -> None:
    op.execute(
        "ALTER TABLE abuse_reports ADD COLUMN reply_token text NOT NULL "
        "DEFAULT left(replace(gen_random_uuid()::text, '-', ''), 12) "
        "CONSTRAINT ck_abuse_reports_reply_token CHECK (reply_token ~ '^[0-9a-f]{12}$')"
    )
    op.execute("CREATE UNIQUE INDEX ux_abuse_reports_reply_token ON abuse_reports (reply_token)")
    op.execute(
        "ALTER TABLE report_settings ADD COLUMN reference_style text NOT NULL DEFAULT 'subject' "
        "CONSTRAINT ck_report_settings_reference_style "
        "CHECK (reference_style IN ('subject', 'subject_and_body', 'off'))"
    )
    op.execute(
        "ALTER TABLE abuse_recipients ADD COLUMN reply_domains text[] NOT NULL DEFAULT '{}' "
        "CONSTRAINT ck_abuse_recipients_reply_domains CHECK (cardinality(reply_domains) <= 5)"
    )
    op.execute(
        "ALTER TABLE abuse_send_requests ADD COLUMN message_id text "
        "CONSTRAINT ck_abuse_send_requests_message_id "
        "CHECK (message_id IS NULL OR char_length(message_id) <= 255)"
    )
    op.execute(
        "CREATE INDEX ix_abuse_send_requests_message_id ON abuse_send_requests (message_id) "
        "WHERE message_id IS NOT NULL"
    )
    op.execute(
        """
        CREATE TABLE report_imap (
            id smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
            enabled boolean NOT NULL DEFAULT false,
            host text NOT NULL CHECK (char_length(host) BETWEEN 4 AND 253),
            port integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
            security text NOT NULL CHECK (security IN ('ssl', 'starttls')),
            username text NOT NULL CHECK (char_length(username) BETWEEN 1 AND 254),
            password_ciphertext bytea,
            password_nonce bytea,
            password_set boolean GENERATED ALWAYS AS (password_ciphertext IS NOT NULL) STORED,
            folder text NOT NULL DEFAULT 'INBOX' CHECK (char_length(folder) BETWEEN 1 AND 100),
            processed_action text NOT NULL DEFAULT 'mark_read'
                CHECK (processed_action IN ('mark_read', 'move')),
            move_folder text
                CHECK (move_folder IS NULL OR char_length(move_folder) BETWEEN 1 AND 100),
            poll_minutes integer NOT NULL DEFAULT 15 CHECK (poll_minutes BETWEEN 5 AND 1440),
            since date NOT NULL DEFAULT ((now() AT TIME ZONE 'UTC')::date),
            trusted_authserv_id text
                CHECK (trusted_authserv_id IS NULL OR trusted_authserv_id ~ '^[a-z0-9.-]{1,255}$'),
            updated_at timestamptz NOT NULL DEFAULT now(),
            updated_by text CHECK (char_length(updated_by) <= 120),
            CHECK ((password_ciphertext IS NULL) = (password_nonce IS NULL)),
            CHECK (processed_action <> 'move'
                   OR (move_folder IS NOT NULL AND move_folder <> folder))
        )
        """
    )
    op.execute(
        """
        CREATE TABLE report_imap_state (
            id smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
            profile_fingerprint text CHECK (profile_fingerprint ~ '^[0-9a-f]{64}$'),
            uidvalidity bigint,
            last_uid bigint NOT NULL DEFAULT 0,
            move_supported boolean,
            last_poll_at timestamptz,
            last_ok_at timestamptz,
            last_error text CHECK (char_length(last_error) <= 64),
            counters jsonb NOT NULL DEFAULT '{}' CHECK (octet_length(counters::text) <= 1024)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE report_imap_requests (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            kind text NOT NULL CHECK (kind IN ('test', 'poll')),
            requested_by text NOT NULL CHECK (char_length(requested_by) <= 120),
            requested_at timestamptz NOT NULL DEFAULT now(),
            status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'done', 'failed')),
            error_code text CHECK (char_length(error_code) <= 64),
            result jsonb NOT NULL DEFAULT '{}' CHECK (octet_length(result::text) <= 8192),
            done_at timestamptz,
            CHECK ((status = 'pending') = (done_at IS NULL))
        )
        """
    )
    op.execute(
        """
        CREATE TABLE abuse_replies (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            source text NOT NULL CHECK (source IN ('imap', 'paste')),
            uidvalidity bigint,
            uid bigint,
            message_id_sha256 text CHECK (message_id_sha256 ~ '^[0-9a-f]{64}$'),
            received_at timestamptz NOT NULL,
            date_header timestamptz,
            from_address text CHECK (char_length(from_address) <= 254),
            from_domain text CHECK (char_length(from_domain) <= 253),
            subject text CHECK (char_length(subject) <= 300),
            auth text NOT NULL DEFAULT 'none' CHECK (auth IN ('pass', 'fail', 'none')),
            report_id bigint REFERENCES abuse_reports (id) ON DELETE CASCADE,
            match_method text NOT NULL CHECK (match_method IN
                ('message_id', 'token', 'dsn', 'ticket', 'sender_domain', 'manual', 'none')),
            verified boolean NOT NULL DEFAULT false,
            classification text NOT NULL CHECK (classification IN
                ('auto_ack', 'ticket_opened', 'resolved', 'rejected', 'bounce', 'human_reply',
                 'unknown')),
            classification_source text NOT NULL DEFAULT 'rule'
                CHECK (classification_source IN ('rule', 'manual')),
            rule_id text CHECK (char_length(rule_id) <= 64),
            ticket_id text CHECK (char_length(ticket_id) <= 64),
            dsn_status text CHECK (dsn_status ~ '^[245][.][0-9]{1,3}[.][0-9]{1,3}$'),
            size_bytes integer NOT NULL CHECK (size_bytes >= 0),
            truncated boolean NOT NULL DEFAULT false,
            attachments jsonb NOT NULL DEFAULT '{}'
                CHECK (octet_length(attachments::text) <= 2048),
            excerpt text CHECK (excerpt IS NULL OR char_length(excerpt) <= 2000),
            excerpt_purged_at timestamptz,
            processed_at timestamptz NOT NULL DEFAULT now(),
            reviewed_at timestamptz,
            reviewed_by text CHECK (char_length(reviewed_by) <= 120),
            UNIQUE (source, uidvalidity, uid),
            UNIQUE (message_id_sha256)
        )
        """
    )
    op.execute("CREATE INDEX ix_abuse_replies_report ON abuse_replies (report_id, received_at)")
    op.execute(
        "CREATE INDEX ix_abuse_replies_unmatched ON abuse_replies (received_at DESC) "
        "WHERE report_id IS NULL"
    )
    op.execute(
        "CREATE INDEX ix_abuse_replies_ticket ON abuse_replies (from_domain, ticket_id) "
        "WHERE ticket_id IS NOT NULL"
    )
    op.execute(
        """
        CREATE TABLE abuse_reply_imports (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            report_id bigint REFERENCES abuse_reports (id) ON DELETE CASCADE,
            raw bytea NOT NULL CHECK (octet_length(raw) <= 262144),
            requested_by text NOT NULL CHECK (char_length(requested_by) <= 120),
            requested_at timestamptz NOT NULL DEFAULT now(),
            status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'done', 'failed')),
            reply_id bigint REFERENCES abuse_replies (id) ON DELETE SET NULL,
            error_code text CHECK (char_length(error_code) <= 64),
            done_at timestamptz
        )
        """
    )
    op.execute(
        "CREATE INDEX ix_abuse_reply_imports_pending ON abuse_reply_imports (id) "
        "WHERE status = 'pending'"
    )
    op.execute(
        f"""
        CREATE TABLE abuse_report_outcomes (
            report_id bigint PRIMARY KEY REFERENCES abuse_reports (id) ON DELETE CASCADE,
            auto_outcome text NOT NULL DEFAULT 'none' CHECK (auto_outcome IN {_OUTCOMES}),
            reply_count integer NOT NULL DEFAULT 0,
            first_reply_at timestamptz,
            first_human_at timestamptz,
            ticket_at timestamptz,
            resolved_at timestamptz,
            rejected_at timestamptz,
            bounced_at timestamptz,
            ticket_id text CHECK (char_length(ticket_id) <= 64),
            needs_review boolean NOT NULL DEFAULT false,
            auto_updated_at timestamptz,
            manual_outcome text CHECK (manual_outcome IN {_OUTCOMES}),
            manual_at timestamptz,
            manual_by text CHECK (char_length(manual_by) <= 120),
            note text CHECK (char_length(note) <= 1000)
        )
        """
    )
    op.execute(_OUTCOME_GUARD)
    op.execute(
        "CREATE TRIGGER abuse_report_outcomes_guard BEFORE INSERT OR UPDATE "
        "ON abuse_report_outcomes FOR EACH ROW EXECUTE FUNCTION abuse_report_outcomes_guard()"
    )
    op.execute(_TRANSITION)
    op.execute(_REQUEST_GUARD)
    op.execute(_PRUNE)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS abuse_report_outcomes")
    op.execute("DROP FUNCTION IF EXISTS abuse_report_outcomes_guard()")
    op.execute("DROP TABLE IF EXISTS abuse_reply_imports")
    op.execute("DROP TABLE IF EXISTS abuse_replies")
    op.execute("DROP TABLE IF EXISTS report_imap_requests")
    op.execute("DROP TABLE IF EXISTS report_imap_state")
    op.execute("DROP TABLE IF EXISTS report_imap")
    op.execute(_OLD_TRANSITION)
    op.execute(_OLD_REQUEST_GUARD)
    op.execute(_OLD_PRUNE)
    op.execute("DROP INDEX IF EXISTS ix_abuse_send_requests_message_id")
    op.execute("ALTER TABLE abuse_send_requests DROP COLUMN IF EXISTS message_id")
    op.execute("ALTER TABLE abuse_recipients DROP COLUMN IF EXISTS reply_domains")
    op.execute("ALTER TABLE report_settings DROP COLUMN IF EXISTS reference_style")
    op.execute("DROP INDEX IF EXISTS ux_abuse_reports_reply_token")
    op.execute("ALTER TABLE abuse_reports DROP COLUMN IF EXISTS reply_token")
