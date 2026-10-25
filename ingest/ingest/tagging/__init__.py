"""Declarative tagging rules (YAML, no regular expressions)."""

from ingest.tagging.engine import (
    Cond,
    Rule,
    RuleError,
    RuleSet,
    SessionFacts,
    compile_condition,
    condition_fields,
    glob_match,
    load_rules,
    match_event_condition,
)

__all__ = [
    "Cond",
    "Rule",
    "RuleError",
    "RuleSet",
    "SessionFacts",
    "compile_condition",
    "condition_fields",
    "glob_match",
    "load_rules",
    "match_event_condition",
]
