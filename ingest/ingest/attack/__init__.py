"""M15: ATT&CK catalogue sync (techniques.yaml into attack_techniques).

Phase 0 ships a no-op worker, disabled by default.
"""

from ingest.attack.worker import AttackCatalogWorker

__all__ = ["AttackCatalogWorker"]
