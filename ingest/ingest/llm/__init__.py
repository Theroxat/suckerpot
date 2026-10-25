"""M17: optional LLM explanation of scripts (needs the anthropic key).

Phase 0 ships a no-op worker, disabled by default.
"""

from ingest.llm.worker import ExplainerWorker

__all__ = ["ExplainerWorker"]
