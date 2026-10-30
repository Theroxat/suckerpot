"""Allow the Synology NAS sensor in the inventory.

Revision ID: 0017
Revises: 0016

``inventory_services.service`` lists the sensor names a defender can declare a service for
(see ``0012_defend``). The twelfth sensor, ``synology``, is added to that list. No other table
enumerates sensor names: the other tables only bound the length of the name.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_NAMES = "'ssh', 'telnet', 'adb', 'web', 'docker', 'redis', 'mysql', 'mssql', 'rdp', 'smb', 'sip'"


def upgrade() -> None:
    op.execute("ALTER TABLE inventory_services DROP CONSTRAINT inventory_services_service_check")
    op.execute(
        "ALTER TABLE inventory_services ADD CONSTRAINT inventory_services_service_check "
        f"CHECK (service IN ({_NAMES}, 'synology'))"
    )


def downgrade() -> None:
    op.execute("DELETE FROM inventory_services WHERE service = 'synology'")
    op.execute("ALTER TABLE inventory_services DROP CONSTRAINT inventory_services_service_check")
    op.execute(
        "ALTER TABLE inventory_services ADD CONSTRAINT inventory_services_service_check "
        f"CHECK (service IN ({_NAMES}))"
    )
