from __future__ import annotations

import hashlib
import importlib

import pytest

from suckerpot_analysis import digests, printable_strings


def test_ascii_and_utf16() -> None:
    data = b"\x00\x01hello-world\x00\x01" + "wide text".encode("utf-16-le") + b"\x00\x00ab\x00"
    out = printable_strings(data)
    assert "hello-world" in out
    assert "wide text" in out
    assert "ab" not in out


def test_unique_and_capped() -> None:
    data = b"\x00".join(b"string%04d" % i for i in range(1000)) + b"\x00string0001"
    out = printable_strings(data, max_count=500)
    assert len(out) == 500
    assert len(set(out)) == 500


def test_length_cap_and_huge_run() -> None:
    out = printable_strings(b"A" * 5_000_000)
    assert out
    assert all(len(s) <= 120 for s in out)


def test_digests() -> None:
    d = digests(b"abc")
    assert d.sha256 == hashlib.sha256(b"abc").hexdigest()
    assert d.md5 == "900150983cd24fb0d6963f7d28e17f72"
    assert d.sha1 == "a9993e364706816aba3e25717850c26c9cd0d89d"
    assert d.tlsh is None or isinstance(d.tlsh, str)  # optional dependency


def test_tlsh_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    mod = importlib.import_module("suckerpot_analysis.digests")
    monkeypatch.setattr(mod, "_tlsh", None)
    assert mod.digests(bytes(range(256)) * 8).tlsh is None
