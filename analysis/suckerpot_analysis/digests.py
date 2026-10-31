"""Hashes. TLSH is optional: py-tlsh has no cp313 wheel, the collector image builds it."""

from __future__ import annotations

import hashlib

from .models import Digests

try:  # pragma: no cover - depends on the build
    import tlsh as _tlsh  # type: ignore[import-not-found,unused-ignore]
except ImportError:  # pragma: no cover
    _tlsh = None


def _tlsh_hash(data: bytes) -> str | None:
    if _tlsh is None or len(data) < 50:
        return None
    try:
        value = _tlsh.hash(data)
    except Exception:  # a hash failure must never break analysis
        return None
    if not isinstance(value, str) or not value or value == "TNULL":
        return None
    return value


def digests(data: bytes) -> Digests:
    return Digests(
        sha256=hashlib.sha256(data).hexdigest(),
        sha1=hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        md5=hashlib.md5(data, usedforsecurity=False).hexdigest(),
        tlsh=_tlsh_hash(data),
    )
