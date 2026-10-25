"""Pure functions of the script library: pair raw commands with their normal form, explain them.

A "script" is the ordered list of commands one session ran, normalised by
``ingest.normalize`` (so two sessions with other addresses or file names share one script).
``extract_pairs`` keeps the real command next to each normalised one: the real text is what the
page shows, and what the annotation base reads when it can (``chmod 777`` versus ``chmod 600``).
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from ingest.normalize import (
    MAX_COMMANDS,
    MAX_INPUT_CHARS,
    _split_commands,
    fingerprint,
    normalize_command,
)
from ingest.scripts.annotations import RISKS, AnnotationBase

MAX_RAW_LINE = 300
MIN_COMMANDS = 2  # a one-liner is not a script
MAX_SUMMARY = 600
MAX_PHRASES = 6
UNKNOWN = "No built-in explanation for this command yet."


@dataclass(frozen=True, slots=True)
class Pair:
    raw: str
    norm: str


def extract_pairs(commands: Iterable[str]) -> list[Pair]:
    """Same walk as ``normalize_commands``, but keeping the real command of each step."""
    out: list[Pair] = []
    budget = MAX_INPUT_CHARS
    for line in commands:
        if budget <= 0 or len(out) >= MAX_COMMANDS:
            break
        chunk = line[:budget]
        budget -= len(chunk)
        for piece in _split_commands(chunk.replace("\r", "\n").replace("\n", ";")):
            normalized = normalize_command(piece)
            if normalized is not None:
                out.append(Pair(" ".join(piece.split())[:MAX_RAW_LINE], normalized))
                if len(out) >= MAX_COMMANDS:
                    break
    return out


def script_fingerprint(pairs: list[Pair]) -> str:
    return fingerprint([p.norm for p in pairs])


MAX_LINES_JSON = 60_000  # bytes; the table refuses more than 64 KiB


def bounded_lines(lines: list[dict[str, Any]], limit: int = MAX_LINES_JSON) -> list[dict[str, Any]]:
    """The longest prefix of ``lines`` whose JSON form fits ``limit`` bytes."""
    out = list(lines)
    while out and len(json.dumps(out).encode()) > limit:
        out.pop()
    return out


def _join(phrases: list[str]) -> str:
    if len(phrases) == 1:
        return phrases[0]
    return ", ".join(phrases[:-1]) + " and " + phrases[-1]


def explain_pairs(pairs: list[Pair], base: AnnotationBase) -> dict[str, Any]:
    """Per-line explanations, a one-sentence summary and the ATT&CK ids of a script."""
    lines: list[dict[str, Any]] = []
    phrases: list[str] = []
    techniques: list[str] = []
    top = 0
    unknown = 0
    for n, pair in enumerate(pairs, start=1):
        entry = base.lookup(pair.raw) or base.lookup(pair.norm)
        item: dict[str, Any] = {"n": n, "text": pair.norm[:MAX_RAW_LINE]}
        if entry is None:
            unknown += 1
            item.update(explanation=UNKNOWN, risk=None, technique=None, rule=None)
        else:
            item.update(
                explanation=entry.explain, risk=entry.risk, technique=entry.technique, rule=entry.id
            )
            top = max(top, RISKS.index(entry.risk))
            if entry.phrase not in phrases:
                phrases.append(entry.phrase)
            if entry.technique and entry.technique not in techniques:
                techniques.append(entry.technique)
        lines.append(item)
    steps = len(pairs)
    if phrases:
        summary = f"A {steps}-step script that {_join(phrases[:MAX_PHRASES])}."
        if len(phrases) > MAX_PHRASES:
            summary = summary[:-1] + ", among other things."
    else:
        summary = f"A {steps}-step script; none of its commands are in the built-in base yet."
    return {
        "lines": lines,
        "summary": summary[:MAX_SUMMARY],
        "techniques": techniques[:64],
        "risk": RISKS[top],
        "unknown": unknown,
    }
