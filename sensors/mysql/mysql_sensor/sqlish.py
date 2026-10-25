"""A tiny SQL tokenizer plus the analysis that tags what an attacker is doing.

This is not an SQL engine: it only splits a query into tokens and statements so that the
canned responder can recognise a handful of shapes, and so that flags and URLs can be
extracted. Everything is a single linear pass over at most ``MAX_CHARS`` characters with no
regular expressions, so hostile input cannot make it slow.
"""

from __future__ import annotations

from dataclasses import dataclass

MAX_CHARS = 16 * 1024
MAX_TOKENS = 4096
MAX_STATEMENTS = 50
MAX_URL = 512
MAX_URLS = 10

WORD, STR, IDENT, NUM, SYM = "word", "str", "ident", "num", "sym"

_WORD_START = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_$@")
_URL_END = frozenset(" \t\r\n'\"`)(<>;,\\")


@dataclass(slots=True)
class Tok:
    kind: str
    text: str  # strings and identifiers without their quotes
    upper: str
    start: int
    end: int


def _is_word_char(c: str) -> bool:
    return c.isalnum() or c in "_$@"


def _skip_line(text: str, i: int) -> int:
    nl = text.find("\n", i)
    return len(text) if nl < 0 else nl + 1


def _quoted_end(text: str, i: int) -> int:
    """Index just past the closing quote of the literal starting at ``i`` (or the end)."""
    quote = text[i]
    n = len(text)
    j = i + 1
    while j < n:
        c = text[j]
        if c == "\\" and quote != "`":
            j += 2
            continue
        if c == quote:
            if j + 1 < n and text[j + 1] == quote:
                j += 2
                continue
            return j + 1
        j += 1
    return n


def tokenize(text: str) -> list[Tok]:
    """Tokens of ``text`` (first ``MAX_CHARS`` characters, at most ``MAX_TOKENS`` tokens)."""
    text = text[:MAX_CHARS]
    n = len(text)
    toks: list[Tok] = []
    i = 0
    exec_comment = False
    while i < n and len(toks) < MAX_TOKENS:
        c = text[i]
        if c.isspace():
            i += 1
        elif c == "#":
            i = _skip_line(text, i)
        elif c == "-" and text.startswith("--", i) and (i + 2 >= n or text[i + 2] in " \t\r\n"):
            i = _skip_line(text, i)
        elif c == "/" and text.startswith("/*", i):
            if text.startswith("/*!", i):  # executable comment: its content is code
                j = i + 3
                while j < n and text[j].isdigit():
                    j += 1
                exec_comment = True
                i = j
            else:
                end = text.find("*/", i + 2)
                i = n if end < 0 else end + 2
        elif c == "*" and exec_comment and text.startswith("*/", i):
            exec_comment = False
            i += 2
        elif c in "'\"`":
            j = _quoted_end(text, i)
            closed = j > i + 1 and text[j - 1] == c
            inner = text[i + 1 : j - 1 if closed else j]
            kind = IDENT if c == "`" else STR
            toks.append(Tok(kind, inner, inner.upper(), i, j))
            i = j
        elif c.isdigit():
            j = i + 1
            while j < n and (_is_word_char(text[j]) or text[j] == "."):
                j += 1
            toks.append(Tok(NUM, text[i:j], text[i:j].upper(), i, j))
            i = j
        elif c in _WORD_START or (c.isalpha()):
            j = i + 1
            while j < n:
                ch = text[j]
                if _is_word_char(ch):
                    j += 1
                elif ch == "." and j + 1 < n and (_is_word_char(text[j + 1])):
                    j += 1
                else:
                    break
            word = text[i:j]
            toks.append(Tok(WORD, word, word.upper(), i, j))
            i = j
        else:
            toks.append(Tok(SYM, c, c, i, i + 1))
            i += 1
    return toks


def split_statements(toks: list[Tok]) -> list[list[Tok]]:
    """Split on top-level ``;`` (strings are single tokens, so quoted ones never split)."""
    out: list[list[Tok]] = []
    cur: list[Tok] = []
    for t in toks:
        if t.kind == SYM and t.text == ";":
            if cur:
                out.append(cur)
                cur = []
            if len(out) >= MAX_STATEMENTS:
                return out
        else:
            cur.append(t)
    if cur:
        out.append(cur)
    return out[:MAX_STATEMENTS]


# --- flags --------------------------------------------------------------------------------

RANSOM_WORDS = (
    "bitcoin",
    "btc",
    "ransom",
    "recover",
    "decrypt",
    "wallet",
    "monero",
    "please_read",
    "read_me",
    "readme",
    "your_data",
    "your data",
    "protonmail",
    "onionmail",
    "tutanota",
)
_WRITE_VERBS = frozenset({"CREATE", "INSERT", "REPLACE", "UPDATE", "ALTER", "RENAME"})


def _has_pair(toks: list[Tok], first: str, seconds: frozenset[str]) -> bool:
    return any(
        toks[i].kind == WORD and toks[i].upper == first and toks[i + 1].upper in seconds
        for i in range(len(toks) - 1)
    )


def _call(toks: list[Tok], name: str) -> bool:
    """Is there a call ``name(`` in the tokens?"""
    return any(
        t.kind == WORD
        and t.upper == name
        and i + 1 < len(toks)
        and toks[i + 1].kind == SYM
        and toks[i + 1].text == "("
        for i, t in enumerate(toks)
    )


def compute_flags(statements: list[list[Tok]]) -> list[str]:
    """Behaviour flags for the tagging rules in ingest. Order is stable, no duplicates."""
    flags: list[str] = []

    def add(flag: str) -> None:
        if flag not in flags:
            flags.append(flag)

    for stmt in statements:
        verb = stmt[0].upper if stmt and stmt[0].kind == WORD else ""
        if _has_pair(stmt, "INTO", frozenset({"OUTFILE", "DUMPFILE"})):
            add("into_outfile")
        if _call(stmt, "LOAD_FILE"):
            add("load_file")
        if verb == "LOAD" and any(t.upper == "INFILE" for t in stmt):
            add("load_data_infile")
        if verb == "DROP" and len(stmt) > 1 and stmt[1].upper in ("DATABASE", "SCHEMA"):
            add("drop_database")
        if verb == "CREATE" and any(t.upper == "SONAME" for t in stmt):
            add("udf")
        if any(t.kind == WORD and t.upper in ("SYS_EXEC", "SYS_EVAL") for t in stmt):
            add("udf")
        if verb in _WRITE_VERBS:
            for t in stmt:
                if t.kind in (WORD, STR, IDENT):
                    low = t.text.lower()
                    if any(word in low for word in RANSOM_WORDS):
                        add("ransom_note")
                        break
        if verb == "SET" and any(
            t.kind == WORD
            and (t.upper.endswith("GENERAL_LOG_FILE") or t.upper.endswith("SLOW_QUERY_LOG_FILE"))
            for t in stmt
        ):
            add("log_file_write")
        if _call(stmt, "SLEEP") or _call(stmt, "BENCHMARK"):
            add("sql_delay")
        if any(t.kind == WORD and t.upper in ("USER", "MYSQL.USER") for t in stmt) and any(
            t.upper in ("MYSQL.USER", "AUTHENTICATION_STRING") for t in stmt
        ):
            add("user_dump")
        if any(t.kind == WORD and t.upper.startswith("INFORMATION_SCHEMA") for t in stmt):
            add("schema_recon")
        if verb in ("GRANT", "REVOKE") or (
            verb in ("CREATE", "ALTER") and _has_pair(stmt, verb, frozenset({"USER"}))
        ):
            add("privilege_change")
        if _has_pair(stmt, "SHOW", frozenset({"DATABASES", "SCHEMAS"})):
            add("show_databases")
    return flags


# --- URLs ---------------------------------------------------------------------------------

_SCHEMES = ("http://", "https://", "ftp://", "tftp://")
_TOOLS = ("wget", "curl", "tftp", "certutil", "powershell", "bitsadmin", "fetch")


def find_urls(text: str) -> list[tuple[str, str]]:
    """``(url, tool)`` pairs found in ``text`` (only recorded, never fetched)."""
    text = text[:MAX_CHARS]
    low = text.lower()
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    for scheme in _SCHEMES:
        pos = 0
        while len(found) < MAX_URLS:
            at = low.find(scheme, pos)
            if at < 0:
                break
            end = at
            limit = min(len(text), at + MAX_URL)
            while end < limit and text[end] not in _URL_END and not text[end].isspace():
                end += 1
            url = text[at:end]
            pos = max(end, at + len(scheme))
            if len(url) > len(scheme) and url not in seen:
                seen.add(url)
                before = low[max(0, at - 160) : at]
                best = max(_TOOLS, key=before.rfind)
                tool = best if before.rfind(best) >= 0 else "sql"
                found.append((url, tool))
    return found
