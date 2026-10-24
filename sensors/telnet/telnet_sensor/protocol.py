"""Telnet wire protocol: IAC parser, option negotiation and a tiny line editor.

Everything here is pure (no I/O) and bounded:

* the parser keeps at most ``MAX_SB`` bytes of a subnegotiation (the rest is dropped);
* the negotiator tracks one small state per option number (256 at most) and never answers a
  command that would not change a state, so two peers cannot loop;
* the line editor never holds more than ``max_line`` bytes of a line.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

IAC = 255
DONT = 254
DO = 253
WONT = 252
WILL = 251
SB = 250
SE = 240
NOP = 241
_COMMANDS = {WILL: "WILL", WONT: "WONT", DO: "DO", DONT: "DONT"}

OPT_ECHO = 1
OPT_SGA = 3
OPT_TTYPE = 24
OPT_NAWS = 31
OPT_LINEMODE = 34

OPTION_NAMES = {
    0: "BINARY",
    1: "ECHO",
    3: "SGA",
    5: "STATUS",
    24: "TTYPE",
    31: "NAWS",
    32: "TSPEED",
    33: "LFLOW",
    34: "LINEMODE",
    35: "XDISPLOC",
    36: "ENVIRON",
    39: "NEW-ENVIRON",
}

MAX_SB = 64
TTYPE_IS = 0
TTYPE_SEND = 1


def option_name(opt: int) -> str:
    return OPTION_NAMES.get(opt, str(opt))


@dataclass(frozen=True, slots=True)
class Negotiation:
    """One IAC WILL/WONT/DO/DONT received from the client."""

    verb: int
    option: int

    @property
    def text(self) -> str:
        return f"{_COMMANDS[self.verb]} {option_name(self.option)}"


@dataclass(frozen=True, slots=True)
class Subnegotiation:
    option: int
    payload: bytes


class TelnetParser:
    """Incremental IAC parser. ``feed`` returns the data bytes and the commands found."""

    _DATA, _IAC, _OPT, _SB_OPT, _SB, _SB_IAC = range(6)

    def __init__(self) -> None:
        self._state = self._DATA
        self._verb = 0
        self._sb_opt = 0
        self._sb = bytearray()
        self._sb_over = False

    def feed(self, chunk: bytes) -> tuple[bytes, list[Negotiation | Subnegotiation]]:
        data = bytearray()
        events: list[Negotiation | Subnegotiation] = []
        state = self._state
        for byte in chunk:
            if state == self._DATA:
                if byte == IAC:
                    state = self._IAC
                else:
                    data.append(byte)
            elif state == self._IAC:
                if byte == IAC:
                    data.append(IAC)
                    state = self._DATA
                elif byte in _COMMANDS:
                    self._verb = byte
                    state = self._OPT
                elif byte == SB:
                    state = self._SB_OPT
                else:  # NOP, DM, BRK, IP, AO, AYT, EC, EL, GA, SE out of place...
                    state = self._DATA
            elif state == self._OPT:
                events.append(Negotiation(self._verb, byte))
                state = self._DATA
            elif state == self._SB_OPT:
                self._sb_opt = byte
                self._sb = bytearray()
                self._sb_over = False
                state = self._SB
            elif state == self._SB:
                if byte == IAC:
                    state = self._SB_IAC
                elif len(self._sb) < MAX_SB:
                    self._sb.append(byte)
                else:
                    self._sb_over = True
            else:  # _SB_IAC
                if byte == SE:
                    if not self._sb_over:
                        events.append(Subnegotiation(self._sb_opt, bytes(self._sb)))
                    state = self._DATA
                elif byte == IAC:
                    if len(self._sb) < MAX_SB:
                        self._sb.append(IAC)
                    else:
                        self._sb_over = True
                    state = self._SB
                else:  # malformed: IAC <x> inside SB aborts it, like most implementations
                    state = self._DATA
        self._state = state
        return bytes(data), events


def cmd(verb: int, option: int) -> bytes:
    return bytes((IAC, verb, option))


@dataclass
class Negotiator:
    """Like BusyBox telnetd: send the opening four commands, then never answer.

    WILL/WONT/DO/DONT from the client are only recorded (they fingerprint the client), and
    NAWS and a volunteered TTYPE IS subnegotiation are parsed. Not answering means two peers can
    never loop, and the server never asks for anything else (no TTYPE SEND, no LINEMODE)."""

    window: tuple[int, int] = (80, 24)
    terminal: str = ""
    seen: list[str] = field(default_factory=list)

    def initial(self) -> bytes:
        """What busybox telnetd sends first: DO ECHO, DO NAWS, WILL ECHO, WILL SGA."""
        return cmd(DO, OPT_ECHO) + cmd(DO, OPT_NAWS) + cmd(WILL, OPT_ECHO) + cmd(WILL, OPT_SGA)

    def handle(self, items: Sequence[Negotiation | Subnegotiation]) -> bytes:
        for item in items:
            if isinstance(item, Subnegotiation):
                self._subneg(item)
            elif len(self.seen) < 16 and item.text not in self.seen:
                self.seen.append(item.text)
        return b""

    def _subneg(self, sub: Subnegotiation) -> None:
        if sub.option == OPT_NAWS and len(sub.payload) == 4:
            width = sub.payload[0] * 256 + sub.payload[1]
            height = sub.payload[2] * 256 + sub.payload[3]
            if 0 < width <= 1000 and 0 < height <= 1000:
                self.window = (width, height)
        elif sub.option == OPT_TTYPE and sub.payload[:1] == bytes((TTYPE_IS,)):
            text = sub.payload[1:33].decode("ascii", "replace")
            self.terminal = "".join(c for c in text if c.isalnum() or c in "-_.")[:32]


class LineEditor:
    """Turns the data bytes of the client into lines, with a minimal tty-like editing.

    Feed bytes with :meth:`push` and pull lines with :meth:`next_line`. The editor stops at the
    first complete line, so the caller can change the echo mode (password prompt) between two
    lines even when the client sent both in one packet."""

    EOF = object()

    def __init__(self, max_line: int = 4096) -> None:
        self._max = max_line
        self._buf = bytearray()
        self._pending = bytearray()
        self._after_cr = False
        self._esc = 0  # 0 none, 1 saw ESC, 2.. inside a CSI/SS3 sequence (counts bytes)
        self.truncated = False

    @property
    def idle(self) -> bool:
        return not self._pending

    def push(self, data: bytes) -> None:
        self._pending += data

    def next_line(self, echo: bool) -> tuple[str | object | None, bytes]:
        """Return ``(line, echo_bytes)``; ``line`` is None when more input is needed,
        ``LineEditor.EOF`` for Ctrl-D on an empty line, and ``""`` after Ctrl-C."""
        out = bytearray()
        pending = self._pending
        consumed = 0
        result: str | object | None = None
        for byte in pending:
            consumed += 1
            if self._esc:
                if self._esc == 1:
                    self._esc = 2 if byte in (0x5B, 0x4F) else 0  # '[' or 'O'
                else:
                    self._esc = 0 if 0x40 <= byte <= 0x7E or self._esc > 16 else self._esc + 1
                continue
            if self._after_cr:
                self._after_cr = False
                if byte in (0x0A, 0x00):
                    continue
            if byte in (0x0D, 0x0A):
                self._after_cr = byte == 0x0D
                line = self._buf.decode("utf-8", "replace")
                self._buf = bytearray()
                self.truncated = False
                if echo:
                    out += b"\r\n"
                result = line
                break
            if byte == 0x03:  # Ctrl-C
                self._buf = bytearray()
                if echo:
                    out += b"^C\r\n"
                result = ""
                break
            if byte == 0x04:  # Ctrl-D
                if not self._buf:
                    result = self.EOF
                    break
                continue
            if byte in (0x7F, 0x08):
                if self._buf:
                    self._buf.pop()
                    if echo:
                        out += b"\x08 \x08"
                continue
            if byte == 0x1B:
                self._esc = 1
                continue
            if byte < 0x20 and byte != 0x09:
                continue
            if len(self._buf) < self._max:
                self._buf.append(byte)
                if echo:
                    out += b"\xff\xff" if byte == IAC else bytes((byte,))
            else:
                self.truncated = True
        del pending[:consumed]
        return result, bytes(out)
