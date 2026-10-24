"""Declarative tagging rules (YAML, no regular expressions)."""

from ingest.tagging.engine import (
    Rule,
    RuleError,
    RuleSet,
    SessionFacts,
    glob_match,
    load_rules,
)

__all__ = ["Rule", "RuleError", "RuleSet", "SessionFacts", "glob_match", "load_rules"]
