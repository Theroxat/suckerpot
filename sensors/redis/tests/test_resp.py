"""The request parser: framing, bounds, inline commands, hostile input."""

from __future__ import annotations

import os
import random
import re
import time

import pytest
from conftest import cmd

from redis_sensor import resp
from redis_sensor.resp import ProtocolError, RequestParser, split_inline


def parse_all(data: bytes) -> list[list[bytes]]:
    p = RequestParser()
    p.feed(data)
    out = []
    while (c := p.next_command()) is not None:
        out.append(c)
    return out


def test_multibulk_and_pipeline() -> None:
    data = cmd("SET", "k", "v") + cmd("GET", "k") + cmd("PING")
    assert parse_all(data) == [[b"SET", b"k", b"v"], [b"GET", b"k"], [b"PING"]]


def test_binary_safe_bulk() -> None:
    blob = bytes(range(256)) + b"\r\n$3\r\n"
    assert parse_all(cmd("SET", "k", blob)) == [[b"SET", b"k", blob]]


def test_byte_by_byte_feed() -> None:
    data = cmd("CONFIG", "SET", "dir", "/var/spool/cron/") + b"PING\r\n"
    p = RequestParser()
    got = []
    for i in range(len(data)):
        p.feed(data[i : i + 1])
        while (c := p.next_command()) is not None:
            got.append(c)
    assert got == [[b"CONFIG", b"SET", b"dir", b"/var/spool/cron/"], [b"PING"]]
    assert p.held == 0


def test_inline_commands() -> None:
    assert parse_all(b"PING\r\n") == [[b"PING"]]
    assert parse_all(b"set a b\n") == [[b"set", b"a", b"b"]]
    assert parse_all(b'SET "a b" \'c d\' "\\x41\\n"\r\n') == [[b"SET", b"a b", b"c d", b"A\n"]]
    assert parse_all(b"\r\n\r\nPING\r\n") == [[b"PING"]]
    assert parse_all(b"*0\r\n*-1\r\nPING\r\n") == [[b"PING"]]


def test_unbalanced_quotes() -> None:
    p = RequestParser()
    p.feed(b'SET "abc\r\n')
    with pytest.raises(ProtocolError, match="unbalanced quotes"):
        p.next_command()
    assert split_inline(b'a "b"c') is None


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"*abc\r\n", "invalid multibulk length"),
        (b"*2000000\r\n", "invalid multibulk length"),
        (b"*99999999999\r\n", "invalid multibulk length"),
        (b"*1\r\nfoo\r\n", "expected '$', got 'f'"),
        (b"*1\r\n$-5\r\n", "invalid bulk length"),
        (b"*1\r\n$536870913\r\n", "invalid bulk length"),
        (b"*1\r\n$x\r\n", "invalid bulk length"),
        (b"*" + b"1" * 200, "too big mbulk count string"),
        (b"*1\r\n$" + b"1" * 200, "too big bulk count string"),
        (b"A" * (resp.MAX_INLINE + 10), "too big inline request"),
    ],
)
def test_protocol_errors(data: bytes, message: str) -> None:
    p = RequestParser()
    p.feed(data)
    with pytest.raises(ProtocolError, match=re.escape(message)):
        p.next_command()


def test_oversized_argument_is_discarded_not_an_error() -> None:
    p = RequestParser()
    p.feed(b"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$%d\r\n" % (resp.MAX_BULK + 1000))
    for _ in range(10):  # arrives in pieces; nothing is kept beyond the short prefix
        p.feed(b"A" * 30_000)
        assert p.next_command() is None
        assert p.held < 40_000
    p.feed(b"B" * (resp.MAX_BULK + 1000 - 300_000) + b"\r\nPING\r\n")
    cmd_ = p.next_command()
    assert cmd_ is not None and cmd_[:2] == [b"SET", b"k"]
    assert cmd_[2] == b"A" * resp.PREFIX_KEEP and p.oversized
    assert p.next_command() == [b"PING"]


def test_total_command_bytes_cap_discards_the_surplus() -> None:
    p = RequestParser()
    p.feed(b"*5\r\n")
    for _ in range(4):
        p.feed(b"$%d\r\n" % resp.MAX_BULK + b"x" * resp.MAX_BULK + b"\r\n")
    got = None
    for _ in range(3):
        got = p.next_command() or got
    assert p.oversized or got is None


def test_more_arguments_than_kept_are_read_and_dropped() -> None:
    p = RequestParser()
    n = resp.MAX_ARGS + 50
    p.feed(b"*%d\r\n" % n + b"$1\r\na\r\n" * n + b"PING\r\n")
    got = p.next_command()
    assert got is not None and len(got) == resp.MAX_ARGS and p.oversized
    assert p.next_command() == [b"PING"]


def test_held_is_bounded_by_caps() -> None:
    p = RequestParser()
    p.feed(b"*2\r\n$524288\r\n" + b"x" * 100_000)
    assert p.next_command() is None
    assert p.held >= 100_000
    assert p.held < resp.MAX_BULK


def test_too_many_inline_args() -> None:
    with pytest.raises(ProtocolError):
        split_inline(b"a " * (resp.MAX_ARGS + 1))


def test_fuzz_never_raises_anything_else() -> None:
    rng = random.Random(7)
    alphabet = b"*$\r\n0123456789 \"'\\xaPING-"
    for _ in range(3000):
        n = rng.randint(1, 80)
        blob = (
            bytes(rng.choice(alphabet) for _ in range(n)) if rng.random() < 0.7 else os.urandom(n)
        )
        p = RequestParser()
        p.feed(blob)
        try:
            for _ in range(200):
                if p.next_command() is None:
                    break
        except ProtocolError:
            pass


@pytest.mark.parametrize(
    "payload",
    [
        b'"' * 60_000,
        b"\\" * 60_000,
        b"'" + b"\\'" * 30_000,
        b"a" * 60_000 + b"\n",
        b"*1\r\n$" + b"9" * 120 + b"\r\n",
        b"*1\r\n" * 10_000,
        (b"*1\r\n$1\r\na\r\n") * 5_000,
        b"\n" * 60_000,
        b"a " * 1000,
    ],
)
def test_pathological_inputs_are_fast(payload: bytes) -> None:
    start = time.perf_counter()
    p = RequestParser()
    p.feed(payload)
    try:
        for _ in range(20_000):
            if p.next_command() is None:
                break
    except ProtocolError:
        pass
    assert time.perf_counter() - start < 1.0


def test_reply_encoders() -> None:
    assert resp.simple("OK") == b"+OK\r\n"
    assert resp.error("ERR x") == b"-ERR x\r\n"
    assert resp.integer(-2) == b":-2\r\n"
    assert resp.bulk(b"hi") == b"$2\r\nhi\r\n"
    assert resp.array([resp.integer(1)]) == b"*1\r\n:1\r\n"
    assert resp.Reply(2).null() == b"$-1\r\n"
    assert resp.Reply(3).null() == b"_\r\n"
    pairs = [(resp.bulk(b"a"), resp.bulk(b"b"))]
    assert resp.Reply(2).mapping(pairs) == b"*2\r\n$1\r\na\r\n$1\r\nb\r\n"
    assert resp.Reply(3).mapping(pairs) == b"%1\r\n$1\r\na\r\n$1\r\nb\r\n"
