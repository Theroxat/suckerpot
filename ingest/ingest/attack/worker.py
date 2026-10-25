"""ATT&CK catalogue sync: ``techniques.yaml`` into ``attack_techniques``.

The YAML is the source of truth. Each cycle (and the first one, right after start-up) upserts
every technique and removes none: older sessions keep pointing at ids that stay readable.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_db.models import AttackTechniqueRow

from ingest.attack.mapping import AttackMap
from ingest.features import FeatureSettings, FeatureWorker

log = logging.getLogger(__name__)


async def sync_catalogue(factory: async_sessionmaker[AsyncSession], attack: AttackMap) -> int:
    """Upsert the catalogue; returns the number of techniques written."""
    rows = [
        {"id": t.id, "name": t.name, "tactic": t.tactic, "stage": t.stage, "url": t.url}
        for t in attack.techniques.values()
    ]
    if not rows:
        return 0
    stmt = pg_insert(AttackTechniqueRow)
    ex = stmt.excluded
    stmt = stmt.on_conflict_do_update(
        index_elements=[AttackTechniqueRow.id],
        set_={"name": ex.name, "tactic": ex.tactic, "stage": ex.stage, "url": ex.url},
    )
    async with factory() as session, session.begin():
        await session.execute(stmt, rows)
    return len(rows)


class AttackCatalogWorker(FeatureWorker):
    name = "attack"
    interval_s = 3600.0

    def __init__(
        self,
        settings: FeatureSettings,
        factory: async_sessionmaker[AsyncSession] | None = None,
        attack: AttackMap | None = None,
    ) -> None:
        super().__init__(settings, enabled=settings.attack_enabled)
        self._factory = factory
        self._attack = attack
        self.techniques = 0

    async def run_once(self) -> None:
        if self._factory is None or self._attack is None:
            return
        self.techniques = await sync_catalogue(self._factory, self._attack)

    async def status(self) -> dict[str, Any]:
        out = await super().status()
        if self.enabled:
            out[self.name]["techniques"] = self.techniques
        return out
