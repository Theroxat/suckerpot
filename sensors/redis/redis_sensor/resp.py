"""RESP request parser and reply encoders, written by hand with strict bounds.

Requests arrive either as a RESP array of bulk strings (``*2\\r\\n$4\\r\\nPING\\r\\n...``) or as an
inline command (a text line split like ``redis-cli`` does, with quotes). RESP2 and RESP3 look
the same from the client side; only replies differ (see :class:`Reply`).

Bounds (all enforced while parsing, before anything is allocated for the data):

* at most ``MAX_ARGS`` arguments kept per command (Redis accepts up to ``MAX_COUNT``; the
  surplus is read and discarded),
* at most ``MAX_BULK`` bytes kept per argument and ``MAX_COMMAND_BYTES`` per command: a longer
  argument (up to Redis' own 512 MiB limit) is read and discarded in place, keeping only a short
  prefix, so a client sending a big payload sees what it would see on a real server,
* header lines (``*N`` / ``$N``) of at most ``MAX_HEADER_LINE`` bytes,
* inline lines of at most ``MAX_INLINE`` bytes.

A violation raises :class:`ProtocolError` whose text is the one real Redis would send
(``Protocol error: ...``); the connection is closed after it. No regular expressions are used.
"""

from __future__ import annotations

MAX_ARGS = 1024
MAX_BULK = 512 * 1024
MAX_BULK_LIMIT = 512 * 1024 * 1024  # Redis' own proto-max-bulk-len
MAX_COUNT = 1024 * 1024  # Redis' own multibulk limit
PREFIX_KEEP = 1024  # bytes kept of an argument that is discarded
MAX_COMMAND_BYTES = 1024 * 1024
MAX_INLINE = 64 * 1024
MAX_HEADER_LINE = 128
_MAX_DIGITS = 10

_SPACE = b" \t\r\n\v\f"
_HEX = b"0123456789abcdefABCDEF"


class ProtocolError(Exception):
    """A framing error. ``message`` is sent to the client as ``-ERR Protocol error: ...``."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def _parse_int(raw: bytes) -> int | None:
    body = raw[1:] if raw[:1] == b"-" else raw
    if not body or len(body) > _MAX_DIGITS or not body.isdigit():
        return None
    value = int(body)
    return -value if raw[:1] == b"-" else value


def split_inline(line: bytes) -> list[bytes] | None:
    """Split an inline command like Redis' ``sdssplitargs``; None on unbalanced quotes.

    Raises :class:`ProtocolError` for lines with more than ``MAX_ARGS`` arguments."""
    out: list[bytes] = []
    i, n = 0, len(line)
    while True:
        while i < n and line[i] in _SPACE:
            i += 1
        if i >= n:
            return out
        if len(out) >= MAX_ARGS:
            raise ProtocolError("too big inline request")
        cur = bytearray()
        in_dq = in_sq = done = False
        while not done:
            c = line[i] if i < n else 0
            if in_dq:
                if i >= n:
                    return None
                if (
                    c == 0x5C
                    and i + 3 < n
                    and line[i + 1] == 0x78
                    and (line[i + 2] in _HEX and line[i + 3] in _HEX)
                ):
                    cur.append(int(line[i + 2 : i + 4], 16))
                    i += 3
                elif c == 0x5C and i + 1 < n:
                    i += 1
                    cur.append(
                        {0x6E: 10, 0x72: 13, 0x74: 9, 0x62: 8, 0x61: 7}.get(line[i], line[i])
                    )
                elif c == 0x22:
                    if i + 1 < n and line[i + 1] not in _SPACE:
                        return None
                    done = True
                else:
                    cur.append(c)
            elif in_sq:
                if i >= n:
                    return None
                if c == 0x5C and i + 1 < n and line[i + 1] == 0x27:
                    i += 1
                    cur.append(0x27)
                elif c == 0x27:
                    if i + 1 < n and line[i + 1] not in _SPACE:
                        return None
                    done = True
                else:
                    cur.append(c)
            elif i >= n or c in _SPACE or c == 0:
                done = True
            elif c == 0x22:
                in_dq = True
            elif c == 0x27:
                in_sq = True
            else:
                cur.append(c)
            if i < n:
                i += 1
            if len(cur) > MAX_INLINE:
                raise ProtocolError("too big inline request")
        out.append(bytes(cur))


class RequestParser:
    """Incremental request parser. ``feed`` bytes, then call ``next_command`` until None."""

    def __init__(self) -> None:
        self._buf = bytearray()
        self._pos = 0
        self._expected = 0  # arguments still to read in the current multibulk
        self._bulk: int | None = None  # length of the bulk string being read
        self._args: list[bytes] = []
        self._args_bytes = 0
        self._skip: int | None = None  # bytes still to discard from an oversized bulk
        self._keep = 0
        self._prefix = bytearray()
        self.oversized = False  # set when an argument or the argument count was cut

    @property
    def held(self) -> int:
        """Bytes currently buffered (unparsed input plus arguments of the open command)."""
        return len(self._buf) - self._pos + self._args_bytes

    def feed(self, data: bytes) -> None:
        if self._pos and self._pos >= len(self._buf) // 2:
            del self._buf[: self._pos]
            self._pos = 0
        self._buf += data

    def _line(self, limit: int, what: str) -> bytes | None:
        """The next line without its terminator, or None if it is not complete yet."""
        end = self._buf.find(b"\n", self._pos)
        if end < 0:
            if len(self._buf) - self._pos > limit:
                raise ProtocolError(what)
            return None
        if end - self._pos > limit:
            raise ProtocolError(what)
        line = bytes(self._buf[self._pos : end])
        self._pos = end + 1
        return line[:-1] if line.endswith(b"\r") else line

    def next_command(self) -> list[bytes] | None:
        while True:
            if self._expected == 0:
                if self._pos >= len(self._buf):
                    return None
                if self._buf[self._pos] == 0x2A:  # '*'
                    line = self._line(MAX_HEADER_LINE, "too big mbulk count string")
                    if line is None:
                        return None
                    count = _parse_int(line[1:])
                    if count is None or count > MAX_COUNT:
                        raise ProtocolError("invalid multibulk length")
                    if count <= 0:
                        continue  # an empty array is ignored, like Redis does
                    self._expected, self._args, self._args_bytes = count, [], 0
                    continue
                inline = self._line(MAX_INLINE, "too big inline request")
                if inline is None:
                    return None
                args = split_inline(inline)
                if args is None:
                    raise ProtocolError("unbalanced quotes in request")
                if args:
                    return args
                continue
            if self._skip is not None:
                avail = len(self._buf) - self._pos
                take = min(avail, self._skip)
                want = self._keep - len(self._prefix)
                if want > 0 and take:
                    self._prefix += self._buf[self._pos : self._pos + min(take, want)]
                self._pos += take
                self._skip -= take
                if self._skip:
                    return None
                self._skip = None
                self._bulk = None
                if self._keep:
                    self._args.append(bytes(self._prefix))
                    self._args_bytes += len(self._prefix)
                self._prefix = bytearray()
                self._expected -= 1
                if self._expected == 0:
                    args = self._args
                    self._args, self._args_bytes = [], 0
                    return args
                continue
            if self._bulk is None:
                if self._pos >= len(self._buf):
                    return None
                if self._buf[self._pos] != 0x24:  # '$'
                    raise ProtocolError(f"expected '$', got '{chr(self._buf[self._pos])}'")
                line = self._line(MAX_HEADER_LINE, "too big bulk count string")
                if line is None:
                    return None
                size = _parse_int(line[1:])
                if size is None or size < 0 or size > MAX_BULK_LIMIT:
                    raise ProtocolError("invalid bulk length")
                too_many = len(self._args) >= MAX_ARGS
                if size > MAX_BULK or self._args_bytes + size > MAX_COMMAND_BYTES or too_many:
                    self.oversized = True
                    self._skip = size + 2
                    self._keep = 0 if too_many else min(size, PREFIX_KEEP)
                    self._bulk = size
                    continue
                self._bulk = size
            size = self._bulk
            if len(self._buf) - self._pos < size + 2:
                return None
            self._args.append(bytes(self._buf[self._pos : self._pos + size]))
            self._args_bytes += size
            self._pos += size + 2
            self._bulk = None
            self._expected -= 1
            if self._expected == 0:
                args = self._args
                self._args, self._args_bytes = [], 0
                return args


# --- replies -----------------------------------------------------------------------------


def simple(text: str) -> bytes:
    return b"+" + text.encode("utf-8", "replace") + b"\r\n"


def error(text: str) -> bytes:
    return b"-" + text.encode("utf-8", "replace") + b"\r\n"


def integer(value: int) -> bytes:
    return b":%d\r\n" % value


def bulk(value: bytes) -> bytes:
    return b"$%d\r\n%s\r\n" % (len(value), value)


def array(items: list[bytes]) -> bytes:
    """``items`` are already-encoded replies."""
    return b"*%d\r\n" % len(items) + b"".join(items)


class Reply:
    """Reply encoders that depend on the protocol version chosen with HELLO."""

    def __init__(self, proto: int = 2) -> None:
        self.proto = proto

    def null(self) -> bytes:
        return b"_\r\n" if self.proto == 3 else b"$-1\r\n"

    def null_array(self) -> bytes:
        return b"_\r\n" if self.proto == 3 else b"*-1\r\n"

    def mapping(self, pairs: list[tuple[bytes, bytes]]) -> bytes:
        """``pairs`` are already-encoded (key, value) replies."""
        if self.proto == 3:
            return b"%%%d\r\n" % len(pairs) + b"".join(k + v for k, v in pairs)
        return array([part for pair in pairs for part in pair])
