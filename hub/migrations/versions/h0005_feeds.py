"""Public blocklist feeds (design M30 section 7.3; numbered h0005 after the existing chain).

Revision ID: h0005
Revises: h0004

Adds the ``payload_ip`` target and observation kind (hub-internal, never sent to nodes), the
payload link table that ties a payload host to the URLs it served (for takedown removal), and the
feed tables: entries, runs, daily aggregates, the operator allow-list, the exclusion ranges and the
delisting tables. Privacy-neutral: no column holds a client address, a node id or a pseudonym,
and values are plain text (no network-address column type), like the rest of the hub schema.

Additions to the design DDL: ``feed_entries.corroborated`` and ``corroborated_day`` (cache of the
optional external lookup that the high tier needs), ``payload_links`` (the design says
"target_hosts, from payloads[]" but the hub keeps no per-payload record otherwise).
"""

from __future__ import annotations

from alembic import op

revision = "h0005"
down_revision = "h0004"
branch_labels = None
depends_on = None

KINDS_OLD = "'ip', 'url', 'domain', 'sha256', 'c2_ip', 'c2_domain'"
KINDS_NEW = KINDS_OLD + ", 'payload_ip'"


def upgrade() -> None:
    op.execute("ALTER TABLE targets DROP CONSTRAINT targets_kind")
    op.execute(f"ALTER TABLE targets ADD CONSTRAINT targets_kind CHECK (kind IN ({KINDS_NEW}))")
    op.execute("ALTER TABLE observations DROP CONSTRAINT observations_kind")
    op.execute(
        f"ALTER TABLE observations ADD CONSTRAINT observations_kind CHECK (kind IN ({KINDS_NEW}))"
    )
    op.execute(
        """
        CREATE TABLE payload_links (
            day date NOT NULL,
            kind text NOT NULL,
            value text NOT NULL,
            url_b text NOT NULL,
            PRIMARY KEY (day, kind, value, url_b),
            CONSTRAINT payload_links_kind CHECK (kind IN ('payload_ip', 'domain'))
        )
        """
    )
    op.execute(
        """
        CREATE TABLE target_hosts (
            url_target_id text NOT NULL REFERENCES targets (id) ON DELETE CASCADE,
            payload_target_id text NOT NULL REFERENCES targets (id) ON DELETE CASCADE,
            PRIMARY KEY (url_target_id, payload_target_id)
        )
        """
    )
    op.execute("CREATE INDEX ix_target_hosts_payload ON target_hosts (payload_target_id)")
    op.execute(
        """
        CREATE TABLE feed_entries (
            list text NOT NULL,
            value text NOT NULL,
            family smallint,
            tier text NOT NULL,
            state text NOT NULL,
            categories text[] NOT NULL DEFAULT '{}',
            services text[] NOT NULL DEFAULT '{}',
            tags text[] NOT NULL DEFAULT '{}',
            families text[] NOT NULL DEFAULT '{}',
            ports integer[] NOT NULL DEFAULT '{}',
            first_seen date NOT NULL,
            last_seen date NOT NULL,
            expires date NOT NULL,
            reported boolean NOT NULL DEFAULT false,
            eligible_at timestamptz,
            listed_day date,
            removed_day date,
            removed_reason text,
            corroborated boolean,
            corroborated_day date,
            target_id text REFERENCES targets (id) ON DELETE SET NULL,
            PRIMARY KEY (list, value),
            CONSTRAINT feed_entries_list CHECK (list IN ('inbound', 'outbound', 'outbound-domains')),
            CONSTRAINT feed_entries_state CHECK (state IN ('pending', 'listed', 'removed')),
            CONSTRAINT feed_entries_tier CHECK (tier IN ('standard', 'high')),
            CONSTRAINT feed_entries_family CHECK (family IS NULL OR family IN (4, 6)),
            CONSTRAINT feed_entries_reason CHECK (removed_reason IS NULL OR removed_reason IN
                ('expired', 'taken_down', 'delisted', 'excluded', 'capped'))
        )
        """
    )
    op.execute("CREATE INDEX ix_feed_entries_state ON feed_entries (state, list)")
    op.execute("CREATE INDEX ix_feed_entries_removed_day ON feed_entries (removed_day)")
    op.execute(
        """
        CREATE TABLE feed_runs (
            serial bigint PRIMARY KEY,
            run_at timestamptz NOT NULL,
            state text NOT NULL,
            counts jsonb NOT NULL DEFAULT '{}'::jsonb,
            diff jsonb,
            error_code text,
            CONSTRAINT feed_runs_state CHECK
                (state IN ('published', 'held', 'discarded', 'failed', 'unchanged'))
        )
        """
    )
    op.execute("CREATE INDEX ix_feed_runs_run_at ON feed_runs (run_at)")
    op.execute(
        """
        CREATE TABLE feed_daily (
            day date NOT NULL,
            list text NOT NULL,
            entries integer NOT NULL,
            added integer NOT NULL DEFAULT 0,
            removed_expired integer NOT NULL DEFAULT 0,
            removed_taken_down integer NOT NULL DEFAULT 0,
            removed_delisted integer NOT NULL DEFAULT 0,
            removed_excluded integer NOT NULL DEFAULT 0,
            PRIMARY KEY (day, list)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE feed_allow (
            value text PRIMARY KEY,
            kind text NOT NULL,
            reason text NOT NULL,
            note text,
            added_day date NOT NULL,
            expires_day date,
            source text NOT NULL,
            CONSTRAINT feed_allow_kind CHECK (kind IN ('ip', 'domain')),
            CONSTRAINT feed_allow_reason CHECK (reason IN
                ('owner_request', 'shared_infra', 'remediated', 'policy', 'false_positive')),
            CONSTRAINT feed_allow_source CHECK (source IN ('admin', 'delist'))
        )
        """
    )
    op.execute(
        """
        CREATE TABLE feed_auto_ranges (
            source text NOT NULL,
            prefix text NOT NULL,
            fetched_day date NOT NULL,
            PRIMARY KEY (source, prefix)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE delist_challenges (
            challenge bytea PRIMARY KEY,
            difficulty integer NOT NULL,
            expires_at timestamptz NOT NULL
        )
        """
    )
    op.execute("CREATE INDEX ix_delist_challenges_expires_at ON delist_challenges (expires_at)")
    op.execute(
        """
        CREATE TABLE delist_requests (
            id text PRIMARY KEY,
            token_hash bytea NOT NULL,
            value text NOT NULL,
            list text,
            category text NOT NULL,
            evidence text CHECK (length(evidence) <= 2000),
            contact text CHECK (length(contact) <= 254),
            state text NOT NULL,
            outcome text,
            public_note text,
            created_day date NOT NULL,
            decided_day date,
            CONSTRAINT delist_requests_state CHECK
                (state IN ('received', 'suppressed', 'accepted', 'rejected')),
            CONSTRAINT delist_requests_outcome CHECK (outcome IS NULL OR outcome IN
                ('false_positive', 'remediated', 'policy', 'rejected'))
        )
        """
    )
    op.execute("CREATE INDEX ix_delist_requests_value ON delist_requests (value)")


def downgrade() -> None:
    for table in (
        "delist_requests",
        "delist_challenges",
        "feed_auto_ranges",
        "feed_allow",
        "feed_daily",
        "feed_runs",
        "feed_entries",
        "target_hosts",
        "payload_links",
    ):
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
    op.execute("DELETE FROM observations WHERE kind = 'payload_ip'")
    op.execute("DELETE FROM targets WHERE kind = 'payload_ip'")
    op.execute("ALTER TABLE observations DROP CONSTRAINT observations_kind")
    op.execute(
        f"ALTER TABLE observations ADD CONSTRAINT observations_kind CHECK (kind IN ({KINDS_OLD}))"
    )
    op.execute("ALTER TABLE targets DROP CONSTRAINT targets_kind")
    op.execute(f"ALTER TABLE targets ADD CONSTRAINT targets_kind CHECK (kind IN ({KINDS_OLD}))")
