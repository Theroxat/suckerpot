"""Property-style tests: the parser either returns a well-formed Head or raises BadRequest."""

from __future__ import annotations

import random

import pytest

from hubproxy.httpwire import (
    HEAD_LIMIT,
    MAX_HEADER_COUNT,
    MAX_HEADERS_BYTES,
    MAX_LINE,
    BadRequest,
    parse_head,
)

GOOD = b"CONNECT suckerpot-hub.selfhostr.io:443 HTTP/1.1\r\nHost: suckerpot-hub.selfhostr.io:443\r\n\r\n"


def test_good_head_parses() -> None:
    head = parse_head(GOOD + b"")
    assert (head.method, head.target, head.version) == (
        "CONNECT",
        "suckerpot-hub.selfhostr.io:443",
        "HTTP/1.1",
    )
    assert head.headers == {"host": "suckerpot-hub.selfhostr.io:443"}


def test_header_names_are_case_insensitive_and_values_trimmed() -> None:
    head = parse_head(
        b"CONNECT a.example.org:443 HTTP/1.0\r\nPROXY-authorization:   Basic abc \t\r\n\r\n"
    )
    assert head.headers["proxy-authorization"] == "Basic abc"


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\r\n\r\n",
        b"CONNECT a.example.org:443 HTTP/1.1\r\n",  # no blank line
        b"CONNECT a.example.org:443 HTTP/1.1\n\n",
        b"CONNECT a.example.org:443 HTTP/1.1\r\nHost: x\n\r\n",  # bare LF
        b"CONNECT a.example.org:443 HTTP/1.1\r\nHost: x\rY: z\r\n\r\n",  # bare CR
        b"CONNECT a.example.org:443 HTTP/1.1\r\n Folded: x\r\n\r\n",  # obs-fold
        b"CONNECT a.example.org:443 HTTP/1.1\r\nHost: x\r\n\tcontinued\r\n\r\n",
        b"CONNECT a.example.org:443 HTTP/1.1\r\nBad Name: x\r\n\r\n",
        b"CONNECT a.example.org:443 HTTP/1.1\r\nNoColon\r\n\r\n",
        b"CONNECT a.example.org:443 HTTP/1.1\r\nHost: x\r\nHost: y\r\n\r\n",  # duplicate
        b"CONNECT a.example.org:443 HTTP/1.1\r\nX: a\x00b\r\n\r\n",
        b"CONNECT a.example.org:443 HTTP/1.1\r\nX: caf\xc3\xa9\r\n\r\n",
        b"CONNECT a.example.org:443 HTTP/1.1\r\nX: a\x7fb\r\n\r\n",
        b"CONNECT a.example.org:443 HTTP/1.1\r\n: empty\r\n\r\n",
        b"CONNECT a.example.org:443 HTTP/1.1 extra\r\n\r\n",
        b"CONNECT a.example.org:443\r\n\r\n",
        b"CONNECT a.example.org:443 HTTP/1.1 \r\n\r\n",
        b"CONNECT a.example.org:443 HTTP/2.0\r\n\r\n",
        b"CONNECT a.example.org:443 http/1.1\r\n\r\n",
        b"CONN ECT a.example.org:443 HTTP/1.1\r\n\r\n",
        b"C\xc3\x93NNECT a.example.org:443 HTTP/1.1\r\n\r\n",
        b"CONNECT a.example.org:443\t HTTP/1.1\r\n\r\n",
    ],
)
def test_malformed_heads_raise(data: bytes) -> None:
    with pytest.raises(BadRequest):
        parse_head(data)


def test_size_bounds() -> None:
    line = b"CONNECT " + b"a" * (MAX_LINE - len(b"CONNECT  HTTP/1.1")) + b" HTTP/1.1"
    assert len(line) == MAX_LINE
    parse_head(line + b"\r\n\r\n")
    with pytest.raises(BadRequest):
        parse_head(line + b"a\r\n\r\n")

    many = b"".join(b"H%d: v\r\n" % i for i in range(MAX_HEADER_COUNT))
    parse_head(b"CONNECT a.example.org:443 HTTP/1.1\r\n" + many + b"\r\n")
    with pytest.raises(BadRequest):
        parse_head(b"CONNECT a.example.org:443 HTTP/1.1\r\n" + many + b"Extra: v\r\n\r\n")

    big = b"X: " + b"v" * (MAX_HEADERS_BYTES) + b"\r\n"
    with pytest.raises(BadRequest):
        parse_head(b"CONNECT a.example.org:443 HTTP/1.1\r\n" + big + b"\r\n")
    with pytest.raises(BadRequest):
        parse_head(b"A" * (HEAD_LIMIT + 1) + b"\r\n\r\n")


def test_trailing_bytes_after_the_blank_line_are_refused() -> None:
    # The reader splits at the first blank line; a second head inside one buffer is smuggling.
    with pytest.raises(BadRequest):
        parse_head(GOOD + GOOD)


def test_random_input_never_crashes_the_parser() -> None:
    rng = random.Random(0xC0FFEE)
    alphabet = [
        b"CONNECT",
        b" ",
        b"\r\n",
        b"\r",
        b"\n",
        b":",
        b"HTTP/1.1",
        b"a.example.org",
        b"443",
        b"\x00",
        b"\xff",
        b"Proxy-Authorization",
        b"Basic ",
        b"\t",
        b"[",
        b"]",
        b"%",
        b"@",
    ]
    for _ in range(5000):
        data = b"".join(rng.choice(alphabet) for _ in range(rng.randint(0, 40)))
        if rng.random() < 0.5:
            data += b"\r\n\r\n"
        try:
            head = parse_head(data)
        except BadRequest:
            continue
        assert (
            head.method.isascii() and " " not in head.target and head.version.startswith("HTTP/1.")
        )
        assert all(h == h.lower() for h in head.headers)


def test_random_bytes_never_crash_the_parser() -> None:
    rng = random.Random(1234)
    for _ in range(3000):
        data = rng.randbytes(rng.randint(0, 300))
        if rng.random() < 0.5:
            data += b"\r\n\r\n"
        try:
            parse_head(data)
        except BadRequest:
            pass


def test_mutations_of_a_valid_head() -> None:
    rng = random.Random(99)
    for _ in range(3000):
        buf = bytearray(GOOD)
        for _ in range(rng.randint(1, 4)):
            op = rng.random()
            pos = rng.randrange(len(buf))
            if op < 0.4:
                buf[pos] = rng.randrange(256)
            elif op < 0.7:
                del buf[pos]
            else:
                buf.insert(pos, rng.randrange(256))
        try:
            parse_head(bytes(buf))
        except BadRequest:
            pass
