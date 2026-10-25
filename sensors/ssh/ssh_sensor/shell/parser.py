"""Tokenizer and parser for a small bash subset.

The parser only builds data structures. Expansion and execution live in ``interp``.
Supported: quoting (``'``, ``"``, ``\\``, ``$'..'``), ``;`` ``&&`` ``||`` ``|`` ``&``, redirections
(``>`` ``>>`` ``<`` ``2>`` ``2>>`` ``2>&1`` ``&>``), ``#`` comments, and command substitution
text kept inside words. Not supported: here-documents, loops, ``if``, functions, subshells.
"""

from __future__ import annotations

from dataclasses import dataclass, field

MAX_TOKENS = 512


class ParseError(Exception):
    """Syntax error, message is what bash would print after ``bash: ``."""


@dataclass(frozen=True, slots=True)
class Segment:
    text: str
    quote: str  # "none" | "single" | "double"


@dataclass(frozen=True, slots=True)
class Word:
    segments: tuple[Segment, ...]

    @property
    def literal(self) -> str:
        return "".join(s.text for s in self.segments)


@dataclass(frozen=True, slots=True)
class Redir:
    op: str  # ">", ">>", "<", "2>", "2>>", "2>&1", "&>"
    target: Word | None


@dataclass(slots=True)
class Command:
    words: list[Word] = field(default_factory=list)
    redirs: list[Redir] = field(default_factory=list)


@dataclass(slots=True)
class Pipeline:
    commands: list[Command]


@dataclass(slots=True)
class Item:
    op: str  # ";" | "&&" | "||" (how it is chained to the previous item)
    pipeline: Pipeline


_OPS = ("&&", "||", ">>", "&>", ">&", ";", "|", "&", ">", "<")
_ANSI_ESC = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "\\": "\\",
    "'": "'",
    '"': '"',
    "a": "\a",
    "e": "\x1b",
}


def _decode_ansi_c(raw: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch == "\\" and i + 1 < len(raw):
            nxt = raw[i + 1]
            if nxt == "x":
                hexdigits = raw[i + 2 : i + 4]
                try:
                    out.append(chr(int(hexdigits, 16)))
                    i += 2 + len(hexdigits)
                    continue
                except ValueError:
                    pass
            if nxt in _ANSI_ESC:
                out.append(_ANSI_ESC[nxt])
                i += 2
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def _scan_substitution(src: str, i: int) -> int:
    """``src[i:]`` starts with ``$(``; return the index just after the matching ``)``."""
    depth = 0
    j = i + 1
    while j < len(src):
        if src[j] == "(":
            depth += 1
        elif src[j] == ")":
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    raise ParseError("unexpected EOF while looking for matching `)'")


def tokenize(src: str) -> list[Word | str]:
    """Split into words and operator strings."""
    tokens: list[Word | str] = []
    segs: list[Segment] = []
    buf: list[str] = []
    in_word = False

    def flush_buf(quote: str = "none") -> None:
        if buf:
            segs.append(Segment("".join(buf), quote))
            buf.clear()

    def end_word() -> None:
        nonlocal in_word
        flush_buf()
        if in_word:
            tokens.append(Word(tuple(segs)))
        segs.clear()
        in_word = False

    i, n = 0, len(src)
    while i < n:
        if len(tokens) > MAX_TOKENS:
            raise ParseError("command line too complex")
        ch = src[i]
        if ch in " \t\r\n":
            if ch == "\n":
                end_word()
                tokens.append("\n")
            else:
                end_word()
            i += 1
            continue
        if ch == "#" and not in_word:
            while i < n and src[i] != "\n":
                i += 1
            continue
        if ch == "'":
            end = src.find("'", i + 1)
            if end < 0:
                raise ParseError("unexpected EOF while looking for matching `''")
            flush_buf()
            segs.append(Segment(src[i + 1 : end], "single"))
            in_word = True
            i = end + 1
            continue
        if ch == '"':
            flush_buf()
            j = i + 1
            chunk: list[str] = []
            while j < n and src[j] != '"':
                if src[j] == "\\" and j + 1 < n and src[j + 1] in '"\\$`':
                    chunk.append("\x00" + src[j + 1])  # escaped char, protected from expansion
                    j += 2
                elif src[j] == "$" and src[j + 1 : j + 2] == "(":
                    end = _scan_substitution(src, j)
                    chunk.append(src[j:end])
                    j = end
                else:
                    chunk.append(src[j])
                    j += 1
            if j >= n:
                raise ParseError("unexpected EOF while looking for matching `\"'")
            segs.append(Segment("".join(chunk), "double"))
            in_word = True
            i = j + 1
            continue
        if ch == "$" and src[i + 1 : i + 2] == "'":
            end = i + 2
            while end < n and not (src[end] == "'" and src[end - 1] != "\\"):
                end += 1
            if end >= n:
                raise ParseError("unexpected EOF while looking for matching `''")
            flush_buf()
            segs.append(Segment(_decode_ansi_c(src[i + 2 : end]), "single"))
            in_word = True
            i = end + 1
            continue
        if ch == "$" and src[i + 1 : i + 2] == "(":
            end = _scan_substitution(src, i)
            buf.append(src[i:end])
            in_word = True
            i = end
            continue
        if ch == "`":
            end = src.find("`", i + 1)
            if end < 0:
                raise ParseError("unexpected EOF while looking for matching ``'")
            buf.append(src[i : end + 1])
            in_word = True
            i = end + 1
            continue
        if ch == "\\":
            if i + 1 < n:
                flush_buf()
                segs.append(Segment(src[i + 1], "single"))
                in_word = True
            i += 2
            continue
        if ch.isdigit() and not in_word and src[i + 1 : i + 2] == ">":
            # fd-prefixed redirection (only 1> and 2> are meaningful)
            j = i + 1
            op = ">>" if src[j : j + 2] == ">>" else ">"
            tokens.append(ch + op)
            i = j + len(op)
            if op == ">" and src[i : i + 1] == "&" and src[i + 1 : i + 2].isdigit():
                tokens[-1] = f"{ch}>&{src[i + 1]}"
                i += 2
            continue
        matched = next((op for op in _OPS if src.startswith(op, i)), None)
        if matched is not None:
            end_word()
            tokens.append(matched)
            i += len(matched)
            continue
        if ch in "()":
            raise ParseError(f"syntax error near unexpected token `{ch}'")
        buf.append(ch)
        in_word = True
        i += 1
    end_word()
    return tokens


def parse(src: str) -> list[Item]:
    """Parse a command line into chained pipelines."""
    tokens = tokenize(src)
    items: list[Item] = []
    cmd = Command()
    pipe: list[Command] = []
    chain_op = ";"
    i = 0

    def finish_cmd(token: str) -> None:
        nonlocal cmd
        if not cmd.words and not cmd.redirs:
            raise ParseError(f"syntax error near unexpected token `{token}'")
        pipe.append(cmd)
        cmd = Command()

    def finish_pipe() -> None:
        nonlocal chain_op
        items.append(Item(chain_op, Pipeline(list(pipe))))
        pipe.clear()

    while i < len(tokens):
        tok = tokens[i]
        if isinstance(tok, Word):
            cmd.words.append(tok)
            i += 1
            continue
        if tok in (">", ">>", "<", "2>", "2>>", "1>", "1>>", "&>", ">&", "0>", "0>>"):
            nxt = tokens[i + 1] if i + 1 < len(tokens) else None
            if not isinstance(nxt, Word):
                raise ParseError("syntax error near unexpected token `newline'")
            op = tok[1:] if tok[0] in "10" else tok
            op = "&>" if op == ">&" else op
            cmd.redirs.append(Redir(op, nxt))
            i += 2
            continue
        if len(tok) == 4 and tok[1:3] == ">&" and tok[0].isdigit() and tok[3].isdigit():
            cmd.redirs.append(Redir(tok, None))
            i += 1
            continue
        if tok == "|":
            finish_cmd(tok)
            i += 1
            continue
        if tok in ("&&", "||"):
            finish_cmd(tok)
            finish_pipe()
            chain_op = tok
            i += 1
            continue
        # ";", "&" (background is treated like a plain separator) or a newline
        if cmd.words or cmd.redirs:
            finish_cmd(tok)
            finish_pipe()
            chain_op = ";"
        elif pipe or chain_op != ";":
            raise ParseError(f"syntax error near unexpected token `{tok.strip() or 'newline'}'")
        elif tok != "\n":
            raise ParseError(f"syntax error near unexpected token `{tok}'")
        i += 1
    if cmd.words or cmd.redirs:
        pipe.append(cmd)
        finish_pipe()
    elif pipe:
        raise ParseError("syntax error: unexpected end of file")
    elif chain_op != ";":
        raise ParseError("syntax error: unexpected end of file")
    return items
