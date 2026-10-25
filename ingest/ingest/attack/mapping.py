"""MITRE ATT&CK mapping: the technique catalogue and the rules that tag events with it.

Two kinds of files live in ``ingest/rules/attack/``:

* ``techniques.yaml``: the curated catalogue (``id``, ``name``, ``tactic``, ``stage``);
* every other ``*.yaml``: ``rules`` (the tagging-rule condition grammar, with ``technique:`` as
  the output) and/or ``from_tags`` (existing tag -> technique ids).

The rule conditions are compiled by the tagging engine, so they share its safety properties:
no regular expressions, capped text, a fixed field whitelist. A broken file raises
:class:`AttackError`, which stops ingest at start-up.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ingest.tagging.engine import (
    TAG_CHARS,
    Cond,
    RuleError,
    compile_condition,
    condition_fields,
    match_event_condition,
)

STAGES = ("recon", "access", "execution", "persistence", "tool_transfer", "objective")
#: The default stage of a tactic. A catalogue entry for one of these tactics must agree.
TACTIC_STAGE = {
    "reconnaissance": "recon",
    "discovery": "recon",
    "initial-access": "access",
    "credential-access": "access",
    "execution": "execution",
    "persistence": "persistence",
    "privilege-escalation": "persistence",
    "command-and-control": "tool_transfer",
    "impact": "objective",
    "exfiltration": "objective",
    "resource-hijacking": "objective",
}
MAX_TECHNIQUES_PER_EVENT = 8
MAX_CATALOGUE = 400
MAX_RULES = 300
CATALOGUE_FILE = "techniques.yaml"
URL_BASE = "https://attack.mitre.org/techniques/"


class AttackError(ValueError):
    """Invalid ATT&CK catalogue or mapping file."""


@dataclass(frozen=True, slots=True)
class Technique:
    id: str
    name: str
    tactic: str
    stage: str

    @property
    def url(self) -> str:
        return URL_BASE + self.id.replace(".", "/") + "/"


@dataclass(frozen=True, slots=True)
class TechniqueRule:
    id: str
    technique: str
    when: Cond


def valid_technique_id(value: object) -> bool:
    """``T`` + 4 digits, optionally ``.`` + 3 digits."""
    if not isinstance(value, str) or not value.startswith("T"):
        return False
    main, dot, sub = value[1:].partition(".")
    if len(main) != 4 or not main.isdigit() or not main.isascii():
        return False
    return not dot or (len(sub) == 3 and sub.isdigit() and sub.isascii())


class AttackMap:
    """The catalogue plus the mapping rules; pure, thread-free, built once at start-up."""

    def __init__(
        self,
        techniques: Mapping[str, Technique],
        rules: Iterable[TechniqueRule],
        from_tags: Mapping[str, tuple[str, ...]],
    ) -> None:
        self.techniques = dict(techniques)
        self.rules = list(rules)
        self.from_tags = dict(from_tags)

    def for_tags(self, tags: Iterable[str]) -> list[str]:
        """Techniques the tags imply (encounter order, unique, no cap)."""
        seen: dict[str, None] = {}
        for tag in tags:
            for tid in self.from_tags.get(tag, ()):
                seen.setdefault(tid)
        return list(seen)

    def for_event(
        self, etype: str, sensor: str, data: Mapping[str, Any], tags: Iterable[str]
    ) -> list[str]:
        """Sorted, unique technique ids of one event, at most ``MAX_TECHNIQUES_PER_EVENT``."""
        seen: dict[str, None] = {}
        for rule in self.rules:
            if rule.technique not in seen and match_event_condition(rule.when, etype, sensor, data):
                seen[rule.technique] = None
        for tid in self.for_tags(tags):
            seen.setdefault(tid)
        return sorted(list(seen)[:MAX_TECHNIQUES_PER_EVENT])

    def stage_of(self, technique_id: str) -> str | None:
        t = self.techniques.get(technique_id)
        return t.stage if t is not None else None


def _read(path: Path) -> Mapping[str, Any]:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise AttackError(f"{path.name}: cannot read ({type(exc).__name__})") from exc
    if not isinstance(doc, Mapping):
        raise AttackError(f"{path.name}: top level must be a mapping")
    return doc


def _text(raw: Mapping[str, Any], key: str, where: str, limit: int) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise AttackError(f"{where}: {key} must be a non-empty string of at most {limit} chars")
    return value.strip()


def parse_catalogue(doc: Mapping[str, Any], source: str = CATALOGUE_FILE) -> dict[str, Technique]:
    items = doc.get("techniques")
    if not isinstance(items, list) or not items:
        raise AttackError(f"{source}: 'techniques' must be a non-empty list")
    if len(items) > MAX_CATALOGUE:
        raise AttackError(f"{source}: too many techniques")
    out: dict[str, Technique] = {}
    for raw in items:
        if not isinstance(raw, Mapping):
            raise AttackError(f"{source}: each technique must be a mapping")
        tid = raw.get("id")
        where = f"{source}:{tid}"
        if not isinstance(tid, str) or not valid_technique_id(tid):
            raise AttackError(f"{where}: invalid technique id")
        if tid in out:
            raise AttackError(f"{where}: duplicate id")
        name = _text(raw, "name", where, 128)
        tactic = _text(raw, "tactic", where, 64)
        stage = raw.get("stage", TACTIC_STAGE.get(tactic))
        if stage not in STAGES:
            raise AttackError(f"{where}: stage must be one of {', '.join(STAGES)}")
        if tactic in TACTIC_STAGE and TACTIC_STAGE[tactic] != stage:
            raise AttackError(
                f"{where}: tactic {tactic!r} belongs to stage {TACTIC_STAGE[tactic]!r}"
            )
        out[tid] = Technique(tid, name, tactic, stage)
    return out


def _parse_mapping(
    doc: Mapping[str, Any], source: str, catalogue: Mapping[str, Technique]
) -> tuple[list[TechniqueRule], dict[str, tuple[str, ...]]]:
    rules: list[TechniqueRule] = []
    for raw in doc.get("rules") or []:
        if not isinstance(raw, Mapping):
            raise AttackError(f"{source}: each rule must be a mapping")
        rid = raw.get("id")
        where = f"{source}:{rid}"
        if not isinstance(rid, str) or not rid:
            raise AttackError(f"{source}: rule without id")
        technique = raw.get("technique")
        if not isinstance(technique, str) or technique not in catalogue:
            raise AttackError(f"{where}: technique {technique!r} is not in the catalogue")
        try:
            when = compile_condition(raw.get("when"), where)
        except RuleError as exc:
            raise AttackError(str(exc)) from exc
        if any(f.startswith("session.") for f in condition_fields(when)):
            raise AttackError(f"{where}: ATT&CK rules are event-scope only")
        rules.append(TechniqueRule(rid, technique, when))
    from_tags: dict[str, tuple[str, ...]] = {}
    mapping = doc.get("from_tags") or {}
    if not isinstance(mapping, Mapping):
        raise AttackError(f"{source}: 'from_tags' must be a mapping")
    for tag, techniques in mapping.items():
        if not isinstance(tag, str) or not tag or not set(tag) <= TAG_CHARS:
            raise AttackError(f"{source}: invalid tag {tag!r} in from_tags")
        if not isinstance(techniques, list) or not techniques:
            raise AttackError(f"{source}: from_tags[{tag}] must be a non-empty list")
        for tid in techniques:
            if tid not in catalogue:
                raise AttackError(f"{source}: from_tags[{tag}] names unknown technique {tid!r}")
        from_tags[tag] = tuple(dict.fromkeys(techniques))
    return rules, from_tags


def load_attack(rules_dir: Path) -> AttackMap:
    """Load ``<rules_dir>/attack``; raises :class:`AttackError` on any problem."""
    directory = rules_dir / "attack"
    catalogue_path = directory / CATALOGUE_FILE
    if not catalogue_path.is_file():
        raise AttackError(f"{catalogue_path.name}: missing in {directory}")
    catalogue = parse_catalogue(_read(catalogue_path))
    rules: list[TechniqueRule] = []
    from_tags: dict[str, tuple[str, ...]] = {}
    for path in sorted(directory.glob("*.yaml")):
        if path.name == CATALOGUE_FILE:
            continue
        file_rules, file_tags = _parse_mapping(_read(path), path.name, catalogue)
        rules.extend(file_rules)
        for tag, techniques in file_tags.items():
            from_tags[tag] = tuple(dict.fromkeys((*from_tags.get(tag, ()), *techniques)))
    if len(rules) > MAX_RULES:
        raise AttackError("too many ATT&CK rules")
    ids = [r.id for r in rules]
    if len(set(ids)) != len(ids):
        raise AttackError("duplicate ATT&CK rule ids")
    return AttackMap(catalogue, rules, from_tags)
