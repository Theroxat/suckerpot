"""Probable command-and-control addresses read from threat-intel providers.

Revision ID: 0016
Revises: 0015

* ``indicator_contacts``: for a file hash that VirusTotal or abuse.ch already recognise, the
  network addresses the providers say that malware contacted (VirusTotal relationships,
  ThreatFox ``botnet_cc`` IOCs). Rows are strings read from third-party answers: nothing ever
  connects to, resolves or fetches them. At most 40 rows per hash (enforced by ingest).
* ``indicator_contact_checks``: the 24 h cache of those lookups, one row per hash and source,
  so a hash with no contacts is not asked about again the same day.

Both tables go with their hash (``ON DELETE CASCADE``), so the indicator retention job prunes
them too. Grants are applied by ``suckerpot_db.roles``: ingest reads and writes, the API reads.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE indicator_contacts (
            hash_indicator_id bigint NOT NULL REFERENCES indicators (id) ON DELETE CASCADE,
            address text NOT NULL CHECK (char_length(address) BETWEEN 1 AND 253),
            kind text NOT NULL CHECK (kind IN ('ip', 'domain')),
            port integer CHECK (port IS NULL OR port BETWEEN 1 AND 65535),
            source text NOT NULL CHECK (source IN ('virustotal', 'threatfox')),
            confidence text NOT NULL CHECK (confidence IN ('high', 'medium', 'low')),
            family text CHECK (family IS NULL OR char_length(family) <= 64),
            provider_score smallint
                CHECK (provider_score IS NULL OR provider_score BETWEEN 0 AND 100),
            reference text CHECK (reference IS NULL OR char_length(reference) <= 256),
            first_seen timestamptz NOT NULL DEFAULT now(),
            checked_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (hash_indicator_id, address, source)
        )
        """
    )
    op.execute("CREATE INDEX ix_indicator_contacts_address ON indicator_contacts (kind, address)")
    op.execute(
        """
        CREATE TABLE indicator_contact_checks (
            indicator_id bigint NOT NULL REFERENCES indicators (id) ON DELETE CASCADE,
            source text NOT NULL CHECK (source IN ('virustotal', 'threatfox')),
            checked_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (indicator_id, source)
        )
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS indicator_contact_checks")
    op.execute("DROP TABLE IF EXISTS indicator_contacts")
