"""The declarative annotation base: plain-English explanations of shell commands.

Rule files live in ``ingest/rules/annotations/*.yaml`` (format documented in the first lines of
``20-recon.yaml``). They are read in file-name order and the first matching entry wins. Matching
uses substring and word tests on at most ``MAX_LINE`` characters, never a regular expression, so
attacker-controlled text cannot make it slow. A broken file raises ``AnnotationError`` and stops
ingest at start-up, like the tagging rules do.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

MAX_LINE = 1024
MAX_ENTRIES = 400
MAX_EXPLAIN = 220
MAX_PHRASE = 60
RISKS = ("info", "notice", "warning", "severe")
_TECHNIQUE = re.compile(r"^T[0-9]{4}(\.[0-9]{3})?$")  # applied to YAML written by the owner only
_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_KEYS = {
    "id", "commands", "prefixes", "args_any", "args_all", "explain", "phrase", "risk", "technique",
}  # fmt: skip


class AnnotationError(ValueError):
    """An annotation file is not valid."""


@dataclass(frozen=True, slots=True)
class Annotation:
    id: str
    explain: str
    phrase: str
    risk: str
    technique: str | None = None
    commands: frozenset[str] = frozenset()
    prefixes: tuple[str, ...] = ()
    args_any: tuple[str, ...] = ()
    args_all: tuple[str, ...] = ()

    def matches(self, name: str, base: str, args: str) -> bool:
        if self.commands:
            if base not in self.commands:
                return False
        elif not name.startswith(self.prefixes):
            return False
        if self.args_any and not any(a in args for a in self.args_any):
            return False
        return all(a in args for a in self.args_all)


@dataclass(frozen=True, slots=True)
class AnnotationBase:
    entries: tuple[Annotation, ...]
    version: int  # changes whenever any rule file changes, so explanations are rebuilt

    def lookup(self, command: str) -> Annotation | None:
        """The first entry that matches one command (a raw or a normalised line)."""
        tokens = command[:MAX_LINE].split()
        if not tokens:
            return None
        name = tokens[0].strip("\"'`").lower()
        base = name.rsplit("/", 1)[-1]
        args = " ".join(tokens[1:]).lower()
        for entry in self.entries:
            if entry.matches(name, base, args):
                return entry
        return None


def _strings(node: dict[str, Any], key: str, where: str) -> tuple[str, ...]:
    value = node.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise AnnotationError(f"{where}: {key} must be a list of non-empty strings")
    return tuple(v.lower() for v in value)


def _entry(node: Any, where: str) -> Annotation:
    if not isinstance(node, dict) or set(node) - _KEYS:
        raise AnnotationError(f"{where}: unknown or missing keys")
    ident = node.get("id")
    if not isinstance(ident, str) or not _ID.match(ident):
        raise AnnotationError(f"{where}: bad id")
    where = f"{where} ({ident})"
    commands = frozenset(_strings(node, "commands", where))
    prefixes = _strings(node, "prefixes", where)
    if bool(commands) == bool(prefixes):
        raise AnnotationError(f"{where}: give exactly one of commands or prefixes")
    explain, phrase, risk = node.get("explain"), node.get("phrase"), node.get("risk")
    if not isinstance(explain, str) or not 1 <= len(explain) <= MAX_EXPLAIN:
        raise AnnotationError(f"{where}: explain must be 1-{MAX_EXPLAIN} characters")
    if not isinstance(phrase, str) or not 1 <= len(phrase) <= MAX_PHRASE:
        raise AnnotationError(f"{where}: phrase must be 1-{MAX_PHRASE} characters")
    if risk not in RISKS:
        raise AnnotationError(f"{where}: risk must be one of {', '.join(RISKS)}")
    technique = node.get("technique")
    if technique is not None and (
        not isinstance(technique, str) or not _TECHNIQUE.match(technique)
    ):
        raise AnnotationError(f"{where}: bad technique id")
    return Annotation(
        id=ident,
        explain=explain,
        phrase=phrase,
        risk=risk,
        technique=technique,
        commands=commands,
        prefixes=prefixes,
        args_any=_strings(node, "args_any", where),
        args_all=_strings(node, "args_all", where),
    )


def load_annotations(rules_dir: Path) -> AnnotationBase:
    """Read ``<rules_dir>/annotations/*.yaml``. A missing folder gives an empty base."""
    folder = rules_dir / "annotations"
    entries: list[Annotation] = []
    digest = hashlib.sha256()
    for path in sorted(folder.glob("*.yaml")) if folder.is_dir() else []:
        raw = path.read_bytes()
        digest.update(path.name.encode() + b"\0" + raw)
        try:
            doc = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise AnnotationError(f"{path.name}: not valid YAML") from exc
        items = doc.get("annotations") if isinstance(doc, dict) else None
        if not isinstance(items, list):
            raise AnnotationError(f"{path.name}: expected a top-level 'annotations' list")
        entries.extend(_entry(item, f"{path.name}[{i}]") for i, item in enumerate(items))
    ids = [e.id for e in entries]
    if len(set(ids)) != len(ids) or len(entries) > MAX_ENTRIES:
        raise AnnotationError("annotation ids must be unique and at most 400 entries")
    version = int.from_bytes(digest.digest()[:2], "big") % 30000 + 1
    return AnnotationBase(tuple(entries), version)
