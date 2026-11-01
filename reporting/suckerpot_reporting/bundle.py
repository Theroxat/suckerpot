"""Encrypted zip for public malware repositories (design M22, section 8.4).

``build_encrypted_zip`` is the one place that writes an AES-256 zip with neutral metadata. The
samples are only ever bytes here: nothing is opened, parsed or executed.
"""

from __future__ import annotations

import csv
import hashlib
import io
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

import pyzipper

from .errors import BundleLimitError, GuardFailed
from .evidence import SampleRef
from .guard import GuardContext, guard, scan_binary
from .normalize import to_ascii
from .terms import SelfTerms

ARCHIVE_PASSWORD: Final = b"infected"
MAX_SAMPLES: Final = 10
MAX_TOTAL_BYTES: Final = 64 * 1024 * 1024
NEUTRAL_TIME: Final = (1980, 1, 1, 0, 0, 0)

HASH_COLUMNS: Final = (
    "sha256",
    "sha1",
    "md5",
    "tlsh",
    "size",
    "kind",
    "arch",
    "family",
    "first_seen_utc",
)


def build_encrypted_zip(
    members: Sequence[tuple[str, bytes]], password: bytes = ARCHIVE_PASSWORD
) -> bytes:
    """AES-256 zip: every entry dated 1980-01-01, no comment, no extra data, order as given.

    The only extra field is the AES header the format itself requires.
    """
    buf = io.BytesIO()
    with pyzipper.AESZipFile(
        buf, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
    ) as zf:
        zf.setpassword(password)
        zf.setencryption(pyzipper.WZ_AES, nbits=256)
        zf.comment = b""
        for name, data in members:
            info = zf.zipinfo_cls(filename=name, date_time=NEUTRAL_TIME)
            info.compress_type = pyzipper.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o600 << 16
            info.comment = b""
            info.extra = b""
            zf.writestr(info, data)
    return buf.getvalue()


@dataclass(frozen=True)
class BundleSample:
    ref: SampleRef
    data: bytes


@dataclass(frozen=True)
class BundleResult:
    data: bytes | None
    included: tuple[str, ...]
    excluded: tuple[tuple[str, tuple[str, ...]], ...]  # (sha256, reason codes)


def _cell(value: object) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@") else text


def hashes_csv(refs: Sequence[SampleRef]) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(HASH_COLUMNS)
    for r in refs:
        first = r.first_seen.strftime("%Y-%m-%dT%H:%M:%SZ") if r.first_seen else ""
        writer.writerow(
            [
                _cell(c)
                for c in (r.sha256, r.sha1, r.md5, r.tlsh, r.size, r.kind, r.arch, r.family, first)
            ]
        )
    return to_ascii(out.getvalue())


def build_sample_bundle(
    samples: Sequence[BundleSample],
    terms: SelfTerms | None,
    *,
    ctx: GuardContext | None = None,
    password: bytes = ARCHIVE_PASSWORD,
) -> BundleResult:
    """Zip the samples that pass the byte scan; list the rest with reason codes.

    Raises ``BundleLimitError`` for too many or too large inputs and ``GuardFailed`` when the
    deny set is unavailable or ``hashes.csv`` itself would leak.
    """
    if terms is None:
        raise GuardFailed(("self_terms_unavailable",))
    if not terms.has_self_address:
        raise GuardFailed(("no_self_address",))
    if not samples:
        raise BundleLimitError("no_samples")
    if len(samples) > MAX_SAMPLES:
        raise BundleLimitError("too_many_samples")
    if sum(len(s.data) for s in samples) > MAX_TOTAL_BYTES:
        raise BundleLimitError("bundle_too_large")
    included: list[BundleSample] = []
    excluded: list[tuple[str, tuple[str, ...]]] = []
    for s in sorted(samples, key=lambda x: x.ref.sha256):
        if hashlib.sha256(s.data).hexdigest() != s.ref.sha256:
            raise BundleLimitError("sample_hash_mismatch")
        codes = scan_binary(s.data, terms)
        if codes:
            excluded.append((s.ref.sha256, codes))
        else:
            included.append(s)
    if not included:
        return BundleResult(None, (), tuple(excluded))
    manifest = hashes_csv([s.ref for s in included])
    verdict = guard(manifest, terms, fmt="csv", ctx=ctx)
    if not verdict.ok:
        raise GuardFailed(verdict.codes)
    members: list[tuple[str, bytes]] = [("hashes.csv", manifest.encode("ascii"))]
    members += [(f"{s.ref.sha256}.bin", s.data) for s in included]
    return BundleResult(
        build_encrypted_zip(members, password),
        tuple(s.ref.sha256 for s in included),
        tuple(excluded),
    )
