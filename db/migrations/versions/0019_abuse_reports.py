"""Anonymous abuse reporting: RDAP contacts, reports, subjects, settings, self terms (M22).

Revision ID: 0019
Revises: 0018

Ingest looks up abuse contacts (RDAP) and builds report drafts; the API lets the owner review
them and mark them sent by hand. Nothing here sends anything. Plain tables, not hypertables:
tens of rows a day. Grants and the row level security policies of ``report_self_terms`` are
applied by ``suckerpot_db.roles`` (every migrate run).

Two triggers protect the workflow (SECURITY INVOKER, so the caller's privileges still apply):

* ``abuse_reports_transition``: only the transitions of the design (doc M22 section 6.1);
  a demo report can never be sent; ingest (any role that cannot write ``notes``) may touch
  drafts only and may only keep them as drafts or supersede them; once a report left the
  draft state its content is frozen.
* ``abuse_reports_touch``: ``updated_at`` and ``revision`` (bumped when the evidence changes).

``suckerpot_abuse_prune`` is the retention procedure (job created by ``suckerpot_db.retention``).
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0019"
down_revision: str | None = "0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TRANSITION = """
CREATE OR REPLACE FUNCTION abuse_reports_transition() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    -- Ingest is the role that cannot write notes (the API and the owner can).
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

_TOUCH = """
CREATE OR REPLACE FUNCTION abuse_reports_touch() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at := now();
    IF NEW.evidence IS DISTINCT FROM OLD.evidence THEN
        NEW.revision := OLD.revision + 1;
    ELSE
        NEW.revision := OLD.revision;
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
        CREATE TABLE rdap_bootstrap (
            registry text PRIMARY KEY CHECK (registry IN ('ipv4', 'ipv6', 'asn', 'dns')),
            body jsonb NOT NULL,
            fetched_at timestamptz NOT NULL
        )
        """
    )
    op.execute(
        """
        CREATE TABLE abuse_networks (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            kind text NOT NULL CHECK (kind IN ('ip', 'domain')),
            cidr cidr,
            domain text CHECK (domain IS NULL OR char_length(domain) <= 253),
            handle text CHECK (char_length(handle) <= 100),
            name text CHECK (char_length(name) <= 200),
            country text CHECK (char_length(country) <= 2),
            rir text,
            asn integer,
            mailboxes text[] NOT NULL DEFAULT '{}' CHECK (cardinality(mailboxes) <= 5),
            source text NOT NULL CHECK (source IN (
                'rdap', 'rdap_remarks', 'ripestat', 'rdap_autnum', 'manual')),
            fetched_at timestamptz NOT NULL,
            expires_at timestamptz NOT NULL,
            CHECK ((kind = 'ip') = (cidr IS NOT NULL)),
            UNIQUE (cidr),
            UNIQUE (domain)
        )
        """
    )
    op.execute("CREATE INDEX ix_abuse_networks_cidr ON abuse_networks USING gist (cidr inet_ops)")
    op.execute(
        """
        CREATE TABLE abuse_lookups (
            subject text PRIMARY KEY CHECK (char_length(subject) <= 253),
            kind text NOT NULL CHECK (kind IN ('ip', 'domain')),
            network_id bigint REFERENCES abuse_networks (id) ON DELETE SET NULL,
            status text NOT NULL CHECK (status IN ('found', 'no_contact', 'error', 'pending')),
            attempts smallint NOT NULL DEFAULT 0,
            checked_at timestamptz,
            next_check_at timestamptz
        )
        """
    )
    op.execute(
        """
        CREATE TABLE abuse_recipients (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            -- NULL = waiting: a network without a contact, until the owner types a mailbox
            mailbox text UNIQUE CHECK (mailbox IS NULL OR char_length(mailbox) BETWEEN 3 AND 254),
            name text CHECK (char_length(name) <= 200),
            source text NOT NULL CHECK (source IN ('rdap', 'manual')),
            override_mailbox text CHECK (char_length(override_mailbox) <= 254),
            muted boolean NOT NULL DEFAULT false,
            first_seen timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    # A network without a contact points at a "waiting" recipient (no mailbox yet).
    op.execute(
        "ALTER TABLE abuse_networks ADD COLUMN recipient_id bigint "
        "REFERENCES abuse_recipients (id) ON DELETE SET NULL"
    )
    op.execute(
        """
        CREATE TABLE abuse_reports (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            public_id uuid NOT NULL UNIQUE,
            id_seed uuid NOT NULL,
            recipient_id bigint NOT NULL REFERENCES abuse_recipients (id),
            kind text NOT NULL CHECK (kind IN ('attack_source', 'payload_host', 'c2')),
            status text NOT NULL DEFAULT 'draft' CHECK (status IN (
                'draft', 'reviewed', 'sent', 'closed', 'discarded', 'superseded')),
            demo boolean NOT NULL DEFAULT false,
            window_start timestamptz NOT NULL,
            window_end timestamptz NOT NULL,
            subject_count integer NOT NULL DEFAULT 0,
            evidence jsonb NOT NULL CHECK (octet_length(evidence::text) <= 262144),
            revision integer NOT NULL DEFAULT 1,
            content_sha256 text NOT NULL,
            guard_ok boolean NOT NULL,
            guard_codes text[] NOT NULL DEFAULT '{}',
            redaction jsonb NOT NULL DEFAULT '{}',
            options jsonb NOT NULL DEFAULT '{}',
            notes text CHECK (notes IS NULL OR char_length(notes) <= 4000),
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now(),
            reviewed_at timestamptz,
            reviewed_by text,
            reviewed_revision integer,
            sent_at timestamptz,
            sent_by text,
            closed_at timestamptz,
            closed_by text,
            CHECK (NOT (demo AND status IN ('sent', 'closed')))
        )
        """
    )
    op.execute(
        "CREATE UNIQUE INDEX ux_abuse_reports_open ON abuse_reports (recipient_id, kind) "
        "WHERE status IN ('draft', 'reviewed')"
    )
    op.execute("CREATE INDEX ix_abuse_reports_status ON abuse_reports (status, updated_at DESC)")
    op.execute(
        """
        CREATE TABLE abuse_report_subjects (
            report_id bigint NOT NULL REFERENCES abuse_reports (id) ON DELETE CASCADE,
            subject_type text NOT NULL CHECK (subject_type IN ('ip', 'url', 'domain')),
            value text NOT NULL CHECK (char_length(value) <= 1024),
            network_id bigint REFERENCES abuse_networks (id) ON DELETE SET NULL,
            first_ts timestamptz NOT NULL,
            last_ts timestamptz NOT NULL,
            sessions integer NOT NULL,
            events integer NOT NULL,
            PRIMARY KEY (report_id, subject_type, value)
        )
        """
    )
    op.execute(
        "CREATE INDEX ix_abuse_report_subjects_value ON abuse_report_subjects (subject_type, value)"
    )
    op.execute(
        """
        CREATE TABLE abuse_report_requests (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            report_id bigint REFERENCES abuse_reports (id) ON DELETE CASCADE,
            action text NOT NULL CHECK (action IN ('regenerate', 'lookup_again')),
            requested_by text NOT NULL,
            requested_at timestamptz NOT NULL DEFAULT now(),
            done_at timestamptz,
            outcome text CHECK (char_length(outcome) <= 64)
        )
        """
    )
    op.execute(
        "CREATE INDEX ix_abuse_report_requests_pending ON abuse_report_requests (requested_at) "
        "WHERE done_at IS NULL"
    )
    op.execute(
        """
        CREATE TABLE report_settings (
            id smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
            reply_contact text CHECK (char_length(reply_contact) <= 254),
            signature text CHECK (char_length(signature) <= 200),
            intro text CHECK (char_length(intro) <= 1000),
            outro text CHECK (char_length(outro) <= 1000),
            note text CHECK (char_length(note) <= 1000),
            subject_template text CHECK (char_length(subject_template) <= 200),
            xarf_user_agent text CHECK (char_length(xarf_user_agent) <= 64),
            defaults jsonb NOT NULL DEFAULT '{}',
            revision integer NOT NULL DEFAULT 1,
            updated_at timestamptz,
            updated_by text
        )
        """
    )
    op.execute("INSERT INTO report_settings (id) VALUES (1)")
    op.execute(
        """
        CREATE TABLE report_self_terms (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            kind text NOT NULL CHECK (kind IN ('address', 'cidr', 'name', 'text')),
            value text NOT NULL CHECK (char_length(value) BETWEEN 2 AND 253),
            source text NOT NULL CHECK (source IN ('learned', 'manual', 'sensor')),
            distinct_sources integer NOT NULL DEFAULT 0,
            first_seen timestamptz NOT NULL DEFAULT now(),
            last_seen timestamptz NOT NULL DEFAULT now(),
            confirmed boolean NOT NULL DEFAULT false,
            UNIQUE (kind, value)
        )
        """
    )
    # Policies are created by suckerpot_db.roles; without a matching policy a role sees nothing.
    # The table owner (migrate) is exempt.
    op.execute("ALTER TABLE report_self_terms ENABLE ROW LEVEL SECURITY")
    op.execute(_TRANSITION)
    op.execute(_TOUCH)
    op.execute(
        "CREATE TRIGGER abuse_reports_transition BEFORE UPDATE ON abuse_reports "
        "FOR EACH ROW EXECUTE FUNCTION abuse_reports_transition()"
    )
    op.execute(
        "CREATE TRIGGER abuse_reports_touch BEFORE UPDATE ON abuse_reports "
        "FOR EACH ROW EXECUTE FUNCTION abuse_reports_touch()"
    )
    op.execute(_PRUNE)


def downgrade() -> None:
    op.execute(
        "SELECT delete_job(job_id) FROM timescaledb_information.jobs "
        "WHERE proc_name = 'suckerpot_abuse_prune'"
    )
    op.execute("DROP PROCEDURE IF EXISTS suckerpot_abuse_prune(integer, jsonb)")
    op.execute("DROP TABLE IF EXISTS abuse_report_requests")
    op.execute("DROP TABLE IF EXISTS abuse_report_subjects")
    op.execute("DROP TABLE IF EXISTS abuse_reports")  # drops its triggers
    op.execute("DROP FUNCTION IF EXISTS abuse_reports_transition()")
    op.execute("DROP FUNCTION IF EXISTS abuse_reports_touch()")
    op.execute("DROP TABLE IF EXISTS abuse_recipients CASCADE")
    op.execute("DROP TABLE IF EXISTS abuse_lookups")
    op.execute("DROP TABLE IF EXISTS abuse_networks")
    op.execute("DROP TABLE IF EXISTS report_settings")
    op.execute("DROP TABLE IF EXISTS report_self_terms")  # drops its policies
    op.execute("DROP TABLE IF EXISTS rdap_bootstrap")
