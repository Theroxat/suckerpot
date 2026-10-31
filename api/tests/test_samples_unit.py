"""Archive helpers without a database."""

import hashlib
import io
import os
from pathlib import Path

import pytest
import pyzipper  # type: ignore[import-untyped]

import api.samples as samples


def put(root: Path, data: bytes) -> str:
    sha = hashlib.sha256(data).hexdigest()
    d = root / sha[:2] / sha[2:4]
    d.mkdir(parents=True)
    (d / sha).write_bytes(data)
    return sha


@pytest.fixture(autouse=True)
def quarantine(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setenv(samples.QUARANTINE_ENV, str(tmp_path))
    return tmp_path


def test_path_only_from_a_valid_hash(quarantine: Path) -> None:
    sha = "ab" + "cd" + "0" * 60
    assert samples.quarantine_path(sha) == str(quarantine / "ab" / "cd" / sha)
    for bad in ("../" * 20, "AB" * 32, "ab" * 31, "ab" * 33, "ab" * 31 + "/.", ""):
        with pytest.raises(ValueError):
            samples.quarantine_path(bad)


def test_read_checks_hash_size_and_type(quarantine: Path) -> None:
    sha = put(quarantine, b"payload")
    assert samples.read_quarantined(sha) == b"payload"
    with pytest.raises(samples.ArchiveError) as missing:
        samples.read_quarantined("1" * 64)
    assert missing.value.status == 404
    path = Path(samples.quarantine_path(sha))
    path.write_bytes(b"other")
    with pytest.raises(samples.ArchiveError) as bad:
        samples.read_quarantined(sha)
    assert bad.value.status == 500
    path.unlink()
    os.symlink("/etc/hostname", path)  # a link is never followed
    with pytest.raises(samples.ArchiveError):
        samples.read_quarantined(sha)


def test_too_large_is_refused(quarantine: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sha = put(quarantine, b"x" * 100)
    monkeypatch.setattr(samples, "MAX_ARCHIVE_INPUT", 50)
    with pytest.raises(samples.ArchiveError) as big:
        samples.read_quarantined(sha)
    assert big.value.status == 413


def test_archive_opens_with_the_conventional_password() -> None:
    sha = hashlib.sha256(b"abc").hexdigest()
    blob = samples.build_archive(sha, b"abc")
    with pyzipper.AESZipFile(io.BytesIO(blob)) as zf:
        assert zf.namelist() == [f"{sha}.bin"]
        assert zf.read(f"{sha}.bin", pwd=b"infected") == b"abc"
        assert zf.infolist()[0].compress_type in (pyzipper.ZIP_STORED, pyzipper.ZIP_DEFLATED)


def test_hourly_limit() -> None:
    samples._downloads.clear()
    for _ in range(samples.ARCHIVE_PER_HOUR):
        assert samples._rate_limited("u") is None
        samples._note_download("u")
    assert samples._rate_limited("u") is not None
    assert samples._rate_limited("other") is None
