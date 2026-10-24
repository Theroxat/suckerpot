from __future__ import annotations

import random
import time

from telnet_sensor.config import Config, parse_credentials
from telnet_sensor.protocol import (
    DO,
    DONT,
    IAC,
    SB,
    SE,
    WILL,
    WONT,
    LineEditor,
    Negotiation,
    Negotiator,
    Subnegotiation,
    TelnetParser,
)
from telnet_sensor.secret import load_or_create_secret
from telnet_sensor.server import to_wire


def test_parser_splits_commands_across_chunks() -> None:
    p = TelnetParser()
    data, items = p.feed(b"ab" + bytes([IAC]))
    assert data == b"ab" and items == []
    data, items = p.feed(bytes([WILL, 24]) + b"c" + bytes([IAC, IAC]) + b"d")
    assert data == b"c\xffd" and items == [Negotiation(WILL, 24)]
    data, items = p.feed(bytes([IAC, SB, 31, 0, 80]))
    assert items == []
    data, items = p.feed(bytes([0, 24, IAC, SE]) + b"x")
    assert data == b"x" and items == [Subnegotiation(31, bytes([0, 80, 0, 24]))]


def test_parser_bounds_subnegotiation() -> None:
    p = TelnetParser()
    big = bytes([IAC, SB, 24]) + b"A" * 100_000 + bytes([IAC, SE]) + b"ok"
    data, items = p.feed(big)
    assert data == b"ok" and items == []  # too long: dropped, not buffered
    assert len(p._sb) <= 64


def test_parser_survives_garbage() -> None:
    rng = random.Random(7)
    p = TelnetParser()
    start = time.perf_counter()
    for _ in range(300):
        p.feed(bytes(rng.choice((IAC, SB, SE, WILL, DO, 0, 1, 24, 31, 65)) for _ in range(1000)))
    assert time.perf_counter() - start < 2.0
    assert len(p._sb) <= 64


def test_negotiator_is_silent_like_busybox() -> None:
    n = Negotiator()
    assert n.initial() == bytes([IAC, DO, 1, IAC, DO, 31, IAC, WILL, 1, IAC, WILL, 3])
    items: list[Negotiation | Subnegotiation] = [Negotiation(WILL, 24), Negotiation(DO, 39)] * 50
    items += [
        Negotiation(WONT, 77),
        Negotiation(DONT, 77),
        Negotiation(DO, 1),
        Negotiation(WILL, 31),
    ]
    assert n.handle(items) == b""  # nothing is ever answered, so nothing can loop
    assert n.seen[:2] == ["WILL TTYPE", "DO NEW-ENVIRON"] and len(n.seen) <= 16


def test_negotiator_naws_and_ttype_values() -> None:
    n = Negotiator()
    n.handle([Subnegotiation(31, bytes([0, 200, 0, 50]))])
    assert n.window == (200, 50)
    n.handle([Subnegotiation(31, bytes([255, 255, 255, 255]))])  # absurd: ignored
    assert n.window == (200, 50)
    n.handle([Subnegotiation(24, b"\x00xterm\x1b[31m" + b"x" * 100)])
    assert n.terminal.startswith("xterm31mxxxx") and len(n.terminal) <= 32


def test_line_editor() -> None:
    e = LineEditor(max_line=8)
    e.push(b"ab\x7fc\r\x00de\r\nfg\x03\x04")
    assert e.next_line(True) == ("ac", b"ab\x08 \x08c\r\n")
    assert e.next_line(True) == ("de", b"de\r\n")
    assert e.next_line(True) == ("", b"fg^C\r\n")
    assert e.next_line(True)[0] is LineEditor.EOF
    # password mode: no echo at all
    e.push(b"secret\n")
    assert e.next_line(False) == ("secret", b"")
    # over-long lines are cut at max_line
    e.push(b"x" * 100 + b"\n")
    line, _ = e.next_line(False)
    assert line == "x" * 8


def test_line_editor_bounded_and_fast() -> None:
    e = LineEditor(max_line=4096)
    e.push(b"\x1b[" * 5000 + b"A" * 100_000)
    start = time.perf_counter()
    line, _ = e.next_line(True)
    assert line is None and len(e._buf) <= 4096
    assert time.perf_counter() - start < 1.0


def test_to_wire() -> None:
    assert to_wire("a\nb\r\nc") == b"a\r\nb\r\nc"
    assert to_wire("\xff") == b"\xc3\xbf"
    e = LineEditor()
    e.push(b"a\xffb\n")
    assert e.next_line(True) == ("a\ufffdb", b"a\xff\xffb\r\n")  # a literal 0xFF is doubled


def test_config_and_credentials() -> None:
    cfg = Config.from_env({})
    assert ("root", "xc3511") in cfg.accept_credentials and len(cfg.accept_credentials) <= 12
    assert parse_credentials("a:b:c,,x") == frozenset({("a", "b:c")})
    cfg = Config.from_env(
        {"TELNET_LOGIN_PROMPT": "\\r\\nrouter login: ", "TELNET_PUBLIC_PORT": "2323"}
    )
    assert cfg.login_prompt == "\r\nrouter login: " and cfg.public_port == 2323
    for bad in (
        {"TELNET_HOSTNAME": "bad host"},
        {"TELNET_PERSONALITY": "toaster"},
        {"TELNET_MOTD": "welcome to the honeypot"},
        {"TELNET_ACCEPT_RANDOM_PROB": "2"},
    ):
        try:
            Config.from_env(bad)
        except ValueError:
            continue
        raise AssertionError(bad)


def test_secret_is_created_once_with_private_mode(tmp_path) -> None:  # type: ignore[no-untyped-def]
    first = load_or_create_secret(str(tmp_path / "d"))
    assert first == load_or_create_secret(str(tmp_path / "d")) and len(first) == 64
    assert ((tmp_path / "d" / "profile_secret").stat().st_mode & 0o777) == 0o600
