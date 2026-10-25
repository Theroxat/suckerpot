"""M17: optional LLM explanation of scripts (needs the anthropic key). Off by default."""

from ingest.llm.worker import ExplainerWorker

__all__ = ["ExplainerWorker"]
