"""Textual shell deobfuscation. Pure string rewriting; nothing is ever evaluated or executed.

Every rewrite is bounded: input is cut to `deob_max_input`, the growth of one pass is budgeted,
the result is capped to `max_out` bytes, and every regex uses bounded quantifiers.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Callable

from .models import Deobfuscation, DeobStep

_B64_CHARS = r"[A-Za-z0-9+/=\s]{8,200000}"
_B64_PIPE = re.compile(
    r"(?:echo|printf)[ \t]+(?:-[A-Za-z]+[ \t]+){0,3}"
    rf"(?:'({_B64_CHARS})'|\"({_B64_CHARS})\"|([A-Za-z0-9+/=]{{8,200000}}))"
    r"[ \t]*\|[ \t]*base64[ \t]+(?:-d|-D|--decode)(?:[ \t]*\|[ \t]*(?:ba|da|a)?sh\b)?"
)
_B64_HERE = re.compile(
    r"base64[ \t]+(?:-d|-D|--decode)[ \t]*<<<[ \t]*"
    rf"(?:'({_B64_CHARS})'|\"({_B64_CHARS})\"|([A-Za-z0-9+/=]{{8,200000}}))"
    r"(?:[ \t]*\|[ \t]*(?:ba|da|a)?sh\b)?"
)
_ESC = re.compile(r"\\(?:x([0-9a-fA-F]{1,2})|([0-7]{1,3}))")
_ECHO_E = re.compile(
    r"(?:echo[ \t]+-[a-zA-Z]*e[a-zA-Z]*|printf)[ \t]+(?:--[ \t]+)?"
    r"(?:'([^'\n]{1,65536})'|\"([^\"\n]{1,65536})\")"
)
_DOLLAR_QUOTE = re.compile(r"\$'([^'\n]{1,65536})'")
_ASSIGN = re.compile(
    r"(?m)(?:^|[;&|(][ \t]*)(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]{0,63})="
    r"(?:'([^'\n]{0,4096})'|\"([^\"$`\n]{0,4096})\"|([^\s;|&$`'\"()<>\\]{1,4096})(?=[\s;|&)]|$))"
)
_VAR = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]{0,63})\}|([A-Za-z_][A-Za-z0-9_]{0,63}))")
_JOIN = re.compile(
    r"'([^'\n]{0,4096})''([^'\n]{0,4096})'|\"([^\"\n]{0,4096})\"\"([^\"\n]{0,4096})\""
)
_EMPTY_INSIDE = re.compile(r"(?<=\w)(?:''|\"\")(?=\w)")
_EVAL = re.compile(r"\beval[ \t]+(?:'([^'\n]{1,65536})'|\"([^\"\n]{1,65536})\")")

_Fn = Callable[[re.Match[str]], str | None]


def _sub(pattern: re.Pattern[str], text: str, fn: _Fn, allowed_growth: int) -> tuple[str, int]:
    """Like re.sub, but `fn` may veto (None) and total growth is budgeted."""
    count = 0
    growth = 0
    out: list[str] = []
    last = 0
    for m in pattern.finditer(text):
        new = fn(m)
        if new is None or new == m.group(0):
            continue
        delta = len(new) - len(m.group(0))
        if growth + max(delta, 0) > allowed_growth:
            continue
        growth += max(delta, 0)
        out.append(text[last : m.start()])
        out.append(new)
        last = m.end()
        count += 1
    if not count:
        return text, 0
    out.append(text[last:])
    return "".join(out), count


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    ok = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
    return ok / len(text)


def _decode_b64(raw: str) -> str | None:
    cleaned = "".join(raw.split())
    if len(cleaned) < 8:
        return None
    cleaned += "=" * (-len(cleaned) % 4)
    try:
        decoded = base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError):
        return None
    text = decoded.decode("utf-8", errors="replace")
    if _printable_ratio(text) < 0.9:
        return None
    return text.rstrip("\n")


def _b64_repl(m: re.Match[str]) -> str | None:
    return _decode_b64(m.group(1) or m.group(2) or m.group(3) or "")


def _decode_escapes(text: str) -> str:
    """Decode \\xHH and \\NNN to printable ASCII only (and never to a quote or backslash)."""

    def one(m: re.Match[str]) -> str:
        value = int(m.group(1), 16) if m.group(1) is not None else int(m.group(2), 8)
        if 0x20 <= value < 0x7F and chr(value) not in "'\"\\$`":
            return chr(value)
        return m.group(0)

    return _ESC.sub(one, text)


def _echo_repl(m: re.Match[str]) -> str | None:
    inner = m.group(1) if m.group(1) is not None else m.group(2)
    new = _decode_escapes(inner)
    if new == inner:
        return None
    quote = "'" if m.group(1) is not None else '"'
    return m.group(0).replace(quote + inner + quote, quote + new + quote, 1)


def _dollar_repl(m: re.Match[str]) -> str | None:
    new = _decode_escapes(m.group(1))
    return None if new == m.group(1) else f"'{new}'"


def _join_repl(m: re.Match[str]) -> str:
    if m.group(1) is not None:
        return f"'{m.group(1)}{m.group(2)}'"
    return f'"{m.group(3)}{m.group(4)}"'


def _eval_repl(m: re.Match[str]) -> str:
    return m.group(1) if m.group(1) is not None else m.group(2)


def _collect_vars(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for m in _ASSIGN.finditer(text):
        for g in (2, 3, 4):
            if m.group(g) is not None:
                values[m.group(1)] = m.group(g)
                break
    return values


def _cap(text: str, max_out: int) -> tuple[str, bool]:
    raw = text.encode("utf-8", errors="replace")
    if len(raw) <= max_out:
        return text, False
    return raw[:max_out].decode("utf-8", errors="ignore"), True


def deobfuscate_shell(
    text: str, *, max_passes: int = 5, max_out: int = 256 * 1024, max_in: int = 1024 * 1024
) -> Deobfuscation:
    """Rewrite common shell obfuscation into plain text, iterating until stable."""
    truncated = False
    if len(text) > max_in:
        text, truncated = text[:max_in], True
    steps: dict[str, int] = {}

    def record(kind: str, n: int) -> None:
        if n:
            steps[kind] = steps.get(kind, 0) + n

    for _ in range(max(0, max_passes)):
        before = text
        allowed = max(0, 2 * max_out - len(text))
        text, n = _sub(_JOIN, text, _join_repl, allowed)
        record("join_quotes", n)
        text, n = _sub(_EMPTY_INSIDE, text, lambda _m: "", allowed)
        record("join_quotes", n)
        text, n = _sub(_ECHO_E, text, _echo_repl, allowed)
        text, n2 = _sub(_DOLLAR_QUOTE, text, _dollar_repl, allowed)
        record("escapes", n + n2)
        values = _collect_vars(text)
        if values:

            def var_repl(m: re.Match[str], values: dict[str, str] = values) -> str | None:
                return values.get(m.group(1) or m.group(2))

            text, n = _sub(_VAR, text, var_repl, allowed)
            record("variables", n)
        text, n = _sub(_B64_PIPE, text, _b64_repl, allowed)
        text, n2 = _sub(_B64_HERE, text, _b64_repl, allowed)
        record("base64", n + n2)
        text, n = _sub(_EVAL, text, _eval_repl, allowed)
        record("eval", n)
        text, cut = _cap(text, max_out)
        truncated = truncated or cut
        if text == before:
            break
    return Deobfuscation(
        text=text,
        steps=[DeobStep(kind=k, count=v) for k, v in steps.items()],
        truncated=truncated,
    )
