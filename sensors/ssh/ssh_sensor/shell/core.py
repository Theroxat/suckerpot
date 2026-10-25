"""Small types shared by the interpreter and the command implementations."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from suckerpot_common import EventType


class ShellExit(Exception):
    """Raised by ``exit``/``logout`` (and by commands that end the session)."""

    def __init__(self, status: int = 0) -> None:
        super().__init__(status)
        self.status = status


@dataclass(frozen=True, slots=True)
class PendingEvent:
    """An event produced by a command (e.g. a download attempt), emitted by the session."""

    type: EventType
    data: dict[str, Any]


MAX_IO_CHARS = 256 * 1024
MAX_DIGITS = 9


def parse_uint(text: str, max_digits: int = MAX_DIGITS) -> int | None:
    """Parse ``[0-9]+`` (ASCII only, bounded length). Never raises."""
    if 0 < len(text) <= max_digits and text.isascii() and text.isdigit():
        return int(text)
    return None


def parse_int(text: str, max_digits: int = MAX_DIGITS) -> int | None:
    """Like :func:`parse_uint` with an optional leading ``-`` or ``+``."""
    if text[:1] in ("-", "+"):
        value = parse_uint(text[1:], max_digits)
        return None if value is None else (-value if text[0] == "-" else value)
    return parse_uint(text, max_digits)


@dataclass(slots=True)
class CmdIO:
    """Arguments and streams of one command invocation (all text, all in memory)."""

    args: list[str]
    stdin: str | None = None
    piped_out: bool = False
    cmdline: str = ""
    out: list[str] = field(default_factory=list)
    err: list[str] = field(default_factory=list)
    size: int = 0

    @property
    def room(self) -> int:
        """Characters that can still be written (stdout and stderr share one budget).

        Commands that produce a lot of output check this BEFORE building it, so a large result
        is never materialised only to be cut by :meth:`write`.
        """
        return max(0, MAX_IO_CHARS - self.size)

    @property
    def full(self) -> bool:
        return self.size >= MAX_IO_CHARS

    def write(self, text: str) -> None:
        """Append to stdout; silently stops at MAX_IO_CHARS so no command can balloon memory."""
        if self.size >= MAX_IO_CHARS or not text:
            return
        text = text[: MAX_IO_CHARS - self.size]
        self.size += len(text)
        self.out.append(text)

    def error(self, text: str) -> None:
        if self.size >= MAX_IO_CHARS or not text:
            return
        text = text[: MAX_IO_CHARS - self.size]
        self.size += len(text)
        self.err.append(text)

    def absorb(self, inner: CmdIO) -> None:
        """Copy another invocation's streams into this one, within this one's budget."""
        for text in inner.err:
            self.error(text)
        for text in inner.out:
            self.write(text)


def join_bounded(parts: list[str], limit: int) -> str:
    """``"".join(parts)[:limit]`` without ever building more than ``limit`` characters."""
    out: list[str] = []
    size = 0
    for part in parts:
        if size >= limit:
            break
        piece = part[: limit - size]
        out.append(piece)
        size += len(piece)
    return "".join(out)


def parse_flags(
    args: list[str], takes_value: str = ""
) -> tuple[set[str], dict[str, str], list[str]]:
    """Split short/long options from operands.

    ``takes_value`` lists short flags that consume an argument (``-n 5`` or ``-n5``).
    Returns ``(flags, values, operands)``. A lone ``-`` is an operand; ``--`` ends options.
    """
    flags: set[str] = set()
    values: dict[str, str] = {}
    operands: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            operands.extend(args[i + 1 :])
            break
        if arg.startswith("--") and len(arg) > 2:
            name, eq, val = arg[2:].partition("=")
            flags.add(name)
            if eq:
                values[name] = val
        elif arg.startswith("-") and len(arg) > 1 and parse_uint(arg[1:], 40) is None:
            j = 1
            while j < len(arg):
                ch = arg[j]
                flags.add(ch)
                if ch in takes_value:
                    rest = arg[j + 1 :]
                    if rest:
                        values[ch] = rest
                    elif i + 1 < len(args):
                        i += 1
                        values[ch] = args[i]
                    break
                j += 1
        else:
            operands.append(arg)
        i += 1
    return flags, values, operands
