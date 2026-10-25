"""Text-processing commands that work on pipes: grep, head, tail, wc, cut, awk, ..."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re

from ssh_sensor.shell.core import CmdIO, parse_flags, parse_int, parse_uint
from ssh_sensor.shell.fs import FSError
from ssh_sensor.shell.interp import Shell
from ssh_sensor.shell.util import (
    MAX_LINE_CHARS,
    MAX_TEXT_INPUT,
    make_matcher,
    read_text,
    split_lines,
    write_lines,
)

MAX_SED_REPLACEMENT = 256
MAX_TR_SET = 1024
MAX_SORT_INPUT = 256 * 1024
_NO_SPACE = str.maketrans("", "", " \t\r\n\v\f")

_ESC = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", "a": "\a", "e": "\x1b", "0": "\0"}


def _unescape(text: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt == "x":
                hx = text[i + 2 : i + 4]
                try:
                    out.append(chr(int(hx, 16)))
                    i += 2 + len(hx)
                    continue
                except ValueError:
                    pass
            if nxt in _ESC:
                out.append(_ESC[nxt])
                i += 2
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def cmd_echo(sh: Shell, io: CmdIO) -> int:
    args = list(io.args)
    newline, escapes = True, False
    while args and re.fullmatch(r"-[neE]+", args[0]):
        newline = newline and "n" not in args[0]
        if "e" in args[0]:
            escapes = True
        if "E" in args[0]:
            escapes = False
        args.pop(0)
    text = " ".join(args)
    io.write((_unescape(text) if escapes else text) + ("\n" if newline else ""))
    return 0


def cmd_printf(sh: Shell, io: CmdIO) -> int:
    if not io.args:
        io.error("printf: usage: printf [-v var] format [arguments]\n")
        return 2
    fmt, args = _unescape(io.args[0]), list(io.args[1:])

    def sub(m: re.Match[str]) -> str:
        spec = m.group(1)
        if spec == "%":
            return "%"
        value = args.pop(0) if args else ""
        if spec == "d" or spec == "i":
            number = parse_int(value)
            return str(number) if number is not None else "0"
        return value

    io.write(re.sub(r"%([sdi%])", sub, fmt))
    return 0


def _inputs(sh: Shell, io: CmdIO, cmd: str, operands: list[str]) -> list[tuple[str, str]] | None:
    """Return (name, text) pairs for file operands, or stdin when there are none."""
    if not operands:
        return [("-", (io.stdin or "")[:MAX_TEXT_INPUT])]
    result: list[tuple[str, str]] = []
    failed = False
    budget = MAX_TEXT_INPUT  # shared by all operands: `cat f f f f ...` reads at most this
    for name in operands:
        sh.tick()
        if budget <= 0:
            break
        if name == "-":
            text = (io.stdin or "")[:budget]
        else:
            try:
                text = read_text(sh, sh.abspath(name), budget)
            except FSError as exc:
                io.error(f"{cmd}: {name}: {exc}\n")
                failed = True
                continue
        budget -= len(text)
        result.append((name, text))
    return None if failed and not result else result


def cmd_grep(sh: Shell, io: CmdIO) -> int:
    flags, values, operands = parse_flags(io.args, "efmAB")
    if "e" in values:
        pattern, files = values["e"], operands
    elif operands:
        pattern, files = operands[0], operands[1:]
    else:
        io.error("Usage: grep [OPTION]... PATTERNS [FILE]...\n")
        return 2
    match = make_matcher(
        pattern, fixed="F" in flags, icase="i" in flags, extended=bool(flags & {"E", "P"})
    )
    invert, count, number = "v" in flags, "c" in flags, "n" in flags
    quiet, only_names = "q" in flags, "l" in flags
    inputs = _inputs(sh, io, "grep", files)
    if inputs is None:
        return 2
    prefix_names = len(files) > 1 and "h" not in flags
    found = False
    listing = not (quiet or only_names or count)
    for name, text in inputs:
        hits = 0
        label = f"{name[:256]}:" if prefix_names else ""
        for idx, line in enumerate(split_lines(text), 1):
            sh.tick()
            if match(line) != invert:
                hits += 1
                if listing and not io.full:
                    io.write(label + (f"{idx}:" if number else "") + line + "\n")
                elif quiet or only_names:
                    break
        if hits:
            found = True
        if quiet:
            continue
        if only_names:
            if hits:
                io.write(name + "\n")
        elif count:
            io.write(f"{label}{hits}\n")
    return 0 if found else 1


def _count_arg(flags: set[str], values: dict[str, str], operands: list[str], default: int) -> int:
    if "n" in values:
        raw = values["n"]
    else:
        raw = next((o for o in operands if _is_dash_number(o)), "")
    number = parse_uint(raw.lstrip("+-")) if raw else None
    return number if number is not None else default


def _is_dash_number(arg: str) -> bool:
    return arg.startswith("-") and parse_uint(arg[1:], 40) is not None


def cmd_head(sh: Shell, io: CmdIO) -> int:
    flags, values, operands = parse_flags(io.args, "nc")
    count = _count_arg(flags, values, operands, 10)
    files = [o for o in operands if not _is_dash_number(o)]
    inputs = _inputs(sh, io, "head", files)
    if inputs is None:
        return 1
    for name, text in inputs:
        if len(inputs) > 1:
            io.write(f"==> {name} <==\n")
        write_lines(io, split_lines(text, min(count, 5000)))
    return 0


def cmd_tail(sh: Shell, io: CmdIO) -> int:
    flags, values, operands = parse_flags(io.args, "nc")
    count = _count_arg(flags, values, operands, 10)
    files = [o for o in operands if not _is_dash_number(o)]
    inputs = _inputs(sh, io, "tail", files)
    if inputs is None:
        return 1
    for name, text in inputs:
        if len(inputs) > 1:
            io.write(f"==> {name} <==\n")
        lines = split_lines(text)
        write_lines(io, lines[-count:] if count else [])
    return 0


def cmd_wc(sh: Shell, io: CmdIO) -> int:
    flags, _, operands = parse_flags(io.args)
    inputs = _inputs(sh, io, "wc", operands)
    if inputs is None:
        return 1
    want = [f for f in "lwc" if f in flags or (f == "c" and "m" in flags)] or list("lwc")
    rows: list[tuple[list[int], str]] = []
    total = [0, 0, 0]
    for name, text in inputs:
        sh.tick()
        counts = [text.count("\n"), _count_words(text), _utf8_len(text)]
        total = [a + b for a, b in zip(total, counts, strict=True)]
        rows.append(([counts["lwc".index(k)] for k in want], "" if name == "-" else name))
    if len(inputs) > 1:
        rows.append(([total["lwc".index(k)] for k in want], "total"))
    width = 7 if not operands else max(len(str(n)) for r, _ in rows for n in r)
    for counts_, name in rows:
        cells = [str(n) if len(want) == 1 and not name else str(n).rjust(width) for n in counts_]
        io.write(" ".join(cells) + (f" {name}" if name else "") + "\n")
    return 0


_WORD_RE = re.compile(r"\S+")  # fixed pattern, never built from attacker input


def _count_words(text: str) -> int:
    """``len(text.split())`` without building the list of words."""
    return sum(1 for _ in _WORD_RE.finditer(text))


def _utf8_len(text: str) -> int:
    """``len(text.encode())`` without encoding the whole text at once."""
    if text.isascii():
        return len(text)
    step = 64 * 1024
    return sum(
        len(text[i : i + step].encode("utf-8", "replace")) for i in range(0, len(text), step)
    )


def _ranges(spec: str, limit: int = 1000) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for part in spec.split(",")[:32]:
        lo_s, _, hi_s = part.partition("-")
        lo = parse_uint(lo_s) if lo_s else 1
        hi = (parse_uint(hi_s) if hi_s else limit) if "-" in part else lo
        if lo is None or hi is None:
            continue
        out.append((lo, hi))
    return out


def cmd_cut(sh: Shell, io: CmdIO) -> int:
    flags, values, operands = parse_flags(io.args, "dfcb")
    delim = values.get("d", "\t")[:1] or "\t"
    fields = _ranges(values["f"]) if "f" in values else []
    chars = (
        _ranges(values["c"] if "c" in values else values.get("b", ""))
        if ("c" in values or "b" in values)
        else []
    )
    if not fields and not chars:
        io.error("cut: you must specify a list of bytes, characters, or fields\n")
        return 1
    inputs = _inputs(sh, io, "cut", operands)
    if inputs is None:
        return 1
    for _, text in inputs:
        for line in split_lines(text):
            sh.tick()
            if io.full:
                return 0
            if chars:
                io.write("".join(line[lo - 1 : hi] for lo, hi in chars) + "\n")
                continue
            if delim not in line:
                if "s" not in flags:
                    io.write(line + "\n")
                continue
            parts = line.split(delim)
            picked = [p for i, p in enumerate(parts, 1) if any(lo <= i <= hi for lo, hi in fields)]
            io.write(delim.join(picked) + "\n")
    return 0


def cmd_sort(sh: Shell, io: CmdIO) -> int:
    flags, _, operands = parse_flags(io.args, "kt")
    inputs = _inputs(sh, io, "sort", operands)
    if inputs is None:
        return 2
    lines = _bounded_lines(inputs, MAX_SORT_INPUT)

    def numkey(s: str) -> float:
        head = s.lstrip()[:32]
        end = 0
        while end < len(head) and (head[end] in "0123456789" or (end == 0 and head[0] == "-")):
            end += 1
        value = parse_int(head[:end], 15)
        return float(value) if value is not None else 0.0

    lines.sort(key=numkey if "n" in flags else lambda s: s.lower(), reverse="r" in flags)
    if "u" in flags:
        lines = list(dict.fromkeys(lines))
    write_lines(io, lines)
    return 0


def _bounded_lines(inputs: list[tuple[str, str]], limit: int) -> list[str]:
    """All lines of all inputs, stopping once ``limit`` characters have been collected."""
    lines: list[str] = []
    total = 0
    for _, text in inputs:
        for line in split_lines(text[: max(0, limit - total)]):
            lines.append(line)
            total += len(line) + 1
        if total >= limit:
            break
    return lines[:5000]


def cmd_uniq(sh: Shell, io: CmdIO) -> int:
    flags, _, operands = parse_flags(io.args)
    inputs = _inputs(sh, io, "uniq", operands)
    if inputs is None:
        return 1
    prev: str | None = None
    run = 0
    rows: list[tuple[int, str]] = []
    for line in _bounded_lines(inputs, MAX_SORT_INPUT):
        if line == prev:
            run += 1
        else:
            if prev is not None:
                rows.append((run, prev))
            prev, run = line, 1
    if prev is not None:
        rows.append((run, prev))
    write_lines(io, ((f"{n:>7} {line}" if "c" in flags else line) for n, line in rows))
    return 0


def _expand_set(spec: str, limit: int = MAX_TR_SET) -> str:
    """Expand ``a-z`` ranges; the result never exceeds ``limit`` characters."""
    spec = _unescape(spec[: limit * 4])
    out: list[str] = []
    i = 0
    while i < len(spec) and len(out) < limit:
        if i + 2 < len(spec) and spec[i + 1] == "-":
            lo, hi = ord(spec[i]), ord(spec[i + 2])
            hi = min(hi, lo + 512, lo + limit - len(out) - 1)
            out.extend(chr(c) for c in range(lo, hi + 1))
            i += 3
        else:
            out.append(spec[i])
            i += 1
    return "".join(out[:limit])


def cmd_tr(sh: Shell, io: CmdIO) -> int:
    flags, _, operands = parse_flags(io.args)
    # Every mode produces at most one character per input character: bound the input.
    text = (io.stdin or "")[: io.room]
    if "d" in flags and operands:
        drop = set(_expand_set(operands[0]))
        io.write("".join(c for c in text if c not in drop))
    elif len(operands) >= 2:
        src, dst = _expand_set(operands[0]), _expand_set(operands[1])
        # padding is bounded: len(src) <= MAX_TR_SET
        dst = dst + dst[-1:] * max(0, len(src) - len(dst)) if dst else dst
        io.write(text.translate({ord(a): b for a, b in zip(src, dst, strict=False)}))
    elif "s" in flags and operands:
        squeeze = set(_expand_set(operands[0]))
        out: list[str] = []
        for c in text:
            if not (out and out[-1] == c and c in squeeze):
                out.append(c)
        io.write("".join(out))
    else:
        io.error("tr: missing operand\n")
        return 1
    return 0


def _parse_awk(program: str) -> tuple[str | None, str] | None:
    """Hand parser (no regex backtracking) for ``[/re/] { print [exprs] }``."""
    text = program.strip()
    regex: str | None = None
    if text.startswith("/"):
        i = 1
        while i < len(text) and text[i] != "/":
            i += 2 if text[i] == "\\" else 1
        if i >= len(text):
            return None
        regex, text = text[1:i], text[i + 1 :].strip()
    if not (text.startswith("{") and text.endswith("}")):
        return None
    inner = text[1:-1].strip().rstrip(";").strip()
    if not inner.startswith("print"):
        return None
    rest = inner[5:]
    if rest and rest[0] not in ' \t$"(':
        return None
    return regex, rest.strip()


def cmd_awk(sh: Shell, io: CmdIO) -> int:
    flags, values, operands = parse_flags(io.args, "F")
    if not operands:
        io.error("awk: no program given\n")
        return 2
    program, files = operands[0][:512], operands[1:]
    parsed = _parse_awk(program)
    inputs = _inputs(sh, io, "awk", files)
    if inputs is None:
        return 2
    if parsed is None:
        return 0  # unsupported program: behave like a program that prints nothing
    regex, expr = parsed
    matcher = make_matcher(regex, extended=True) if regex else None
    sep = values.get("F")
    cols = [c.strip() for c in expr.split(",")[:16]] if expr else ["$0"]
    for _, text in inputs:
        for line in split_lines(text):
            sh.tick()
            if matcher is not None and not matcher(line):
                continue
            parts = line.split(sep) if sep and sep != " " else line.split()
            row: list[str] = []
            for col in cols:
                if col == "$0":
                    row.append(line)
                elif col == "$NF":
                    row.append(parts[-1] if parts else "")
                elif col.startswith("$") and parse_uint(col[1:], 4) is not None:
                    idx = parse_uint(col[1:], 4) or 0
                    row.append(parts[idx - 1] if 0 < idx <= len(parts) else "")
                elif len(col) >= 2 and col[0] == '"' and col[-1] == '"' and '"' not in col[1:-1]:
                    row.append(col[1:-1])
            io.write(" ".join(row) + "\n")
    return 0


def _parse_sed_sub(script: str) -> tuple[str, str, str] | None:
    """Hand parser for ``s<d>old<d>new<d>[flags]`` with backslash-escaped delimiters."""
    if len(script) < 4 or script[0] != "s" or script[1].isalnum() or script[1] in "\\ \n":
        return None
    delim = script[1]
    fields: list[list[str]] = [[]]
    i = 2
    while i < len(script):
        ch = script[i]
        if ch == "\\" and i + 1 < len(script):
            fields[-1].append(script[i + 1] if script[i + 1] == delim else ch + script[i + 1])
            i += 2
            continue
        if ch == delim and len(fields) < 3:
            fields.append([])
        else:
            fields[-1].append(ch)
        i += 1
    if len(fields) != 3:
        return None
    old = "".join(fields[0])
    new = "".join(fields[1])
    flags = "".join(fields[2])
    if any(f not in "gp" for f in flags):
        return None
    new = new[:MAX_SED_REPLACEMENT].replace("\\n", "\n")
    return old.replace("\\.", ".").replace("\\/", "/"), new, flags


def _bounded_replace(line: str, old: str, new: str, every: bool, cap: int) -> str:
    """``line.replace(old, new[, 1])[:cap]`` that stops as soon as ``cap`` is reached, so the
    intermediate string is never larger than ``cap + len(new)``."""
    out: list[str] = []
    size = 0
    pos = 0
    while size < cap:
        idx = line.find(old, pos)
        if idx < 0:
            break
        head = line[pos : min(idx, pos + cap - size)]
        out.append(head)
        size += len(head)
        if size >= cap:
            pos = len(line)
            break
        out.append(new)
        size += len(new)
        pos = idx + len(old)
        if not every:
            break
    if size < cap:
        out.append(line[pos : pos + cap - size])
    return "".join(out)[:cap]


def cmd_sed(sh: Shell, io: CmdIO) -> int:
    flags, values, operands = parse_flags(io.args, "e")
    script = (values.get("e") or (operands.pop(0) if operands else ""))[:512]
    inputs = _inputs(sh, io, "sed", operands)
    if inputs is None:
        return 2
    sub = _parse_sed_sub(script)
    line_no = parse_uint(script[:-1], 6) if script[-1:] in ("p", "d") else None
    for _, text in inputs:
        lines = split_lines(text)
        sh.tick()
        if sub:
            old, new, mods = sub
            if old:
                for ln in lines:
                    if io.full:
                        return 0
                    sh.tick()
                    cap = min(MAX_LINE_CHARS, io.room)
                    io.write(_bounded_replace(ln, old, new, "g" in mods, cap) + "\n")
                continue
        elif line_no is not None and script.endswith("p") and "n" in flags:
            lines = lines[line_no - 1 : line_no] if line_no else []
        elif line_no is not None and script.endswith("d"):
            lines = lines[: max(line_no - 1, 0)] + lines[line_no:] if line_no else lines
        write_lines(io, lines)
    return 0


def cmd_tee(sh: Shell, io: CmdIO) -> int:
    flags, _, operands = parse_flags(io.args)
    text = (io.stdin or "")[:MAX_TEXT_INPUT]
    status = 0
    data: bytes | None = None
    for name in operands[:64]:
        sh.tick()
        try:
            path = sh.abspath(name)
            if not sh.fs.may_write(path, sh.user.name, sh.user.home):
                raise FSError("Permission denied")
            if len(text) > sh.fs.free_bytes:  # chars <= bytes: cannot fit, do not encode
                raise FSError("No space left on device")
            if data is None:
                data = text.encode()
            sh.fs.write(path, data, append="a" in flags, owner=sh.user.name)
        except FSError as exc:
            io.error(f"tee: {name[:256]}: {exc}\n")
            status = 1
    io.write(text[: io.room])
    return status


def cmd_xargs(sh: Shell, io: CmdIO) -> int:
    _, _, operands = parse_flags(io.args, "nIdP")
    # first 256 words without splitting the whole input
    words = _WORD_RE.finditer(io.stdin or "")
    tokens = [m.group(0)[:MAX_LINE_CHARS] for _, m in zip(range(256), words, strict=False)]
    argv = (operands or ["echo"]) + tokens
    if not tokens and operands:
        return 0
    return sh.run_argv(argv, io)


def cmd_base64(sh: Shell, io: CmdIO) -> int:
    flags, _, operands = parse_flags(io.args)
    inputs = _inputs(sh, io, "base64", operands)
    if inputs is None:
        return 1
    for _, text in inputs:
        room = io.room
        if room <= 0:
            break
        if "d" in flags or "decode" in flags:
            # 4 base64 chars -> 3 bytes: decode only what the output budget can hold.
            limit = (room // 3 + 2) * 4
            src = text[: limit + limit // 76 + 8].translate(_NO_SPACE)
            if len(src) > limit:  # cut on a 4-character boundary so padding stays valid
                src = src[:limit]
            try:
                raw = base64.b64decode(src, validate=False)
            except (binascii.Error, ValueError):
                io.error("base64: invalid input\n")
                return 1
            io.write(raw[:room].decode("utf-8", "replace"))
        else:
            # 57 input bytes -> one 76-char line + newline (77 chars)
            raw = text[: (room // 77 + 1) * 57].encode()[: (room // 77 + 1) * 57]
            enc = base64.b64encode(raw).decode()
            write_lines(io, (enc[i : i + 76] for i in range(0, len(enc), 76)))
    return 0


def _hash_cmd(algo: str):  # type: ignore[no-untyped-def]
    def run(sh: Shell, io: CmdIO) -> int:
        _, _, operands = parse_flags(io.args)
        inputs = _inputs(sh, io, f"{algo}sum", operands)
        if inputs is None:
            return 1
        for name, text in inputs:
            digest = hashlib.new(algo, text.encode()).hexdigest()
            io.write(f"{digest}  {name}\n")
        return 0

    return run


def cmd_test(sh: Shell, io: CmdIO) -> int:
    args = list(io.args)
    if io.cmdline.startswith("[ ") and args and args[-1] == "]":
        args.pop()
    negate = bool(args) and args[0] == "!"
    if negate:
        args.pop(0)
    result = _eval_test(sh, args)
    return 0 if result != negate else 1


def _eval_test(sh: Shell, args: list[str]) -> bool:
    if not args:
        return False
    if len(args) == 1:
        return bool(args[0])
    if len(args) == 2:
        op, val = args
        if op == "-z":
            return not val
        if op == "-n":
            return bool(val)
        try:
            node = sh.fs.stat(sh.abspath(val))
        except FSError:
            return False
        if node is None:
            return False
        return {
            "-e": True,
            "-f": node.kind == "f",
            "-d": node.kind == "d",
            "-x": bool(node.mode & 0o111),
            "-r": True,
            "-w": True,
            "-s": bool(node.content) or node.kind == "d",
            "-L": node.kind == "l",
        }.get(op, False)
    a, op, b = args[0], args[1], args[2]
    if op in ("=", "=="):
        return a == b
    if op == "!=":
        return a != b
    x, y = parse_int(a), parse_int(b)
    if x is None or y is None:
        return False
    return {
        "-eq": x == y,
        "-ne": x != y,
        "-lt": x < y,
        "-le": x <= y,
        "-gt": x > y,
        "-ge": x >= y,
    }.get(op, False)


def cmd_true(sh: Shell, io: CmdIO) -> int:
    return 0


def cmd_false(sh: Shell, io: CmdIO) -> int:
    return 1
