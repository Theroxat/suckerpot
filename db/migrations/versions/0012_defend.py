"""Blocklists, feed tokens and the exposure inventory (M16).

Revision ID: 0012
Revises: 0011

* ``blocklist_entries``: the scored indicators, recomputed by ingest (the API only reads).
* ``blocklist_overrides``: allow/block decisions of an admin; ingest reads them.
* ``feed_tokens``: bearer tokens for the machine-readable feeds. Only the sha256 of the token is
  stored; the API alone touches this table.
* ``inventory_services``: the services the owner runs, to compare with what attackers target.

Grants are applied by ``suckerpot_db.roles``.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE blocklist_entries (
            kind text NOT NULL CHECK (kind IN ('ip', 'domain', 'url', 'hash')),
            value text NOT NULL CHECK (char_length(value) BETWEEN 1 AND 512),
            score smallint NOT NULL CHECK (score BETWEEN 0 AND 100),
            reasons text[] NOT NULL DEFAULT '{}' CHECK (cardinality(reasons) <= 16),
            first_seen timestamptz NOT NULL,
            last_seen timestamptz NOT NULL,
            sessions integer NOT NULL DEFAULT 0,
            sources integer NOT NULL DEFAULT 0,
            campaign_ids bigint[] NOT NULL DEFAULT '{}' CHECK (cardinality(campaign_ids) <= 64),
            benign boolean NOT NULL DEFAULT false,
            demo boolean NOT NULL DEFAULT false,
            computed_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (kind, value)
        )
        """
    )
    op.execute(
        "CREATE INDEX ix_blocklist_entries_score ON blocklist_entries (kind, score DESC, "
        "last_seen DESC)"
    )
    op.execute("CREATE INDEX ix_blocklist_entries_last_seen ON blocklist_entries (last_seen DESC)")
    op.execute(
        """
        CREATE TABLE blocklist_overrides (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            kind text NOT NULL CHECK (kind IN ('ip', 'domain', 'url', 'hash')),
            value text NOT NULL CHECK (char_length(value) BETWEEN 1 AND 512),
            action text NOT NULL CHECK (action IN ('allow', 'block')),
            note text CHECK (note IS NULL OR char_length(note) <= 256),
            created_by text NOT NULL CHECK (char_length(created_by) <= 128),
            created_at timestamptz NOT NULL DEFAULT now(),
            expires_at timestamptz,
            UNIQUE (kind, value)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE feed_tokens (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
            token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
            token_hint text NOT NULL CHECK (char_length(token_hint) <= 8),
            kinds text[] NOT NULL DEFAULT '{ip}'
                CHECK (cardinality(kinds) BETWEEN 1 AND 4
                       AND kinds <@ ARRAY['ip', 'domain', 'url', 'hash']),
            min_score smallint NOT NULL DEFAULT 50 CHECK (min_score BETWEEN 0 AND 100),
            include_benign boolean NOT NULL DEFAULT false,
            created_by text NOT NULL CHECK (char_length(created_by) <= 128),
            created_at timestamptz NOT NULL DEFAULT now(),
            expires_at timestamptz,
            revoked_at timestamptz,
            last_used_at timestamptz,
            last_used_ip text CHECK (last_used_ip IS NULL OR char_length(last_used_ip) <= 64),
            use_count bigint NOT NULL DEFAULT 0
        )
        """
    )
    op.execute(
        """
        CREATE TABLE inventory_services (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
            service text NOT NULL
                CHECK (service IN ('ssh', 'telnet', 'adb', 'web', 'docker', 'redis', 'mysql',
                                   'mssql', 'rdp', 'smb', 'sip')),
            product text CHECK (product IS NULL OR char_length(product) <= 64),
            version text CHECK (version IS NULL OR char_length(version) <= 32),
            exposure text NOT NULL DEFAULT 'internal'
                CHECK (exposure IN ('internet', 'vpn', 'internal')),
            notes text CHECK (notes IS NULL OR char_length(notes) <= 512),
            created_by text NOT NULL CHECK (char_length(created_by) <= 128),
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute("CREATE INDEX ix_inventory_services_service ON inventory_services (service)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS inventory_services")
    op.execute("DROP TABLE IF EXISTS feed_tokens")
    op.execute("DROP TABLE IF EXISTS blocklist_overrides")
    op.execute("DROP TABLE IF EXISTS blocklist_entries")
