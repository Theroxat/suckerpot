"""YARA-X rule compilation and scanning (memory-safe Rust engine, scan timeout)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yara_x

from .models import Limits, YaraHit

_MAX_RULE_BYTES = 1024 * 1024


@dataclass(frozen=True)
class CompiledRules:
    rules: yara_x.Rules
    files: tuple[str, ...]


def compile_rules(directory: Path) -> CompiledRules:
    """Compile every `*.yar` in `directory` (one namespace per file). Raises on a broken rule."""
    compiler = yara_x.Compiler()
    names: list[str] = []
    for path in sorted(directory.glob("*.yar")):
        source = path.read_text(encoding="utf-8")
        if len(source.encode()) > _MAX_RULE_BYTES:
            raise ValueError(f"rule file too large: {path.name}")
        compiler.new_namespace(path.stem)
        compiler.add_source(source, origin=path.name)
        names.append(path.name)
    return CompiledRules(rules=compiler.build(), files=tuple(names))


def scan(data: bytes, rules: CompiledRules, limits: Limits) -> tuple[list[YaraHit], list[str]]:
    """Return (hits, error codes). A timeout or engine error never raises."""
    scanner = yara_x.Scanner(rules.rules)
    scanner.set_timeout(limits.yara_timeout_s)
    try:
        result = scanner.scan(data)
    except yara_x.TimeoutError:
        return [], ["yara_timeout"]
    except yara_x.ScanError:
        return [], ["yara_error"]
    hits: list[YaraHit] = []
    for rule in result.matching_rules:
        meta = {k: v for k, v in rule.metadata if isinstance(v, str | int | bool)}
        hits.append(
            YaraHit(
                rule=rule.identifier,
                namespace=rule.namespace,
                tags=list(rule.tags),
                meta=meta,
            )
        )
        if len(hits) >= limits.max_yara_hits:
            break
    return hits, []
