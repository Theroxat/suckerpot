"""Provider secrets (encrypted API keys set from Settings) and key-test requests.

Revision ID: 0006
Revises: 0005

Grants are applied by ``suckerpot_db.roles`` after every upgrade: the API role may read and
write ``provider_secrets``; the ingest role may only read it.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE provider_secrets (
            provider text PRIMARY KEY
                CHECK (provider IN ('abuseipdb', 'greynoise', 'maxmind')),
            ciphertext bytea NOT NULL,
            nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
            last4 text NOT NULL CHECK (char_length(last4) <= 4),
            updated_at timestamptz NOT NULL DEFAULT now(),
            updated_by text NOT NULL
        )
        """
    )
    op.execute(
        """
        CREATE TABLE provider_test_requests (
            provider text PRIMARY KEY
                CHECK (provider IN ('abuseipdb', 'greynoise', 'maxmind')),
            requested_at timestamptz NOT NULL DEFAULT now(),
            requested_by text NOT NULL,
            handled_at timestamptz,
            tests_day date NOT NULL DEFAULT current_date,
            tests_today integer NOT NULL DEFAULT 0
        )
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS provider_test_requests")
    op.execute("DROP TABLE IF EXISTS provider_secrets")
