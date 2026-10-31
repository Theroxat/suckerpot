import hashlib
import os
import stat
from pathlib import Path

import pytest

from collector.store import Quarantine, TooLarge


@pytest.fixture
def q(tmp_path: Path) -> Quarantine:
    store = Quarantine(tmp_path / "quarantine")
    store.prepare()
    return store


def put(q: Quarantine, data: bytes, limit: int = 1 << 20):  # type: ignore[no-untyped-def]
    with q.open_temp(limit) as temp:
        for i in range(0, len(data), 1000):
            temp.write(data[i : i + 1000])
        return q.commit(temp)


def test_file_is_sha_named_read_only_and_not_executable(q: Quarantine) -> None:
    data = b"#!/bin/sh\necho synthetic\n" * 50
    stored = put(q, data)
    sha = hashlib.sha256(data).hexdigest()
    assert stored.sha256 == sha
    assert stored.sha1 == hashlib.sha1(data, usedforsecurity=False).hexdigest()
    assert stored.md5 == hashlib.md5(data, usedforsecurity=False).hexdigest()
    assert stored.path == q.root / sha[:2] / sha[2:4] / sha
    assert stored.path.read_bytes() == data
    mode = stat.S_IMODE(stored.path.stat().st_mode)
    assert mode == 0o400
    assert not mode & 0o111
    assert stat.S_IMODE(stored.path.parent.stat().st_mode) == 0o700
    assert stored.path.suffix == ""


def test_dedupe_keeps_one_file_and_cleans_the_temp(q: Quarantine) -> None:
    first = put(q, b"same bytes")
    second = put(q, b"same bytes")
    assert first.new and not second.new
    assert first.path == second.path
    assert list(q.incoming.iterdir()) == []
    files = [p for p in q.root.rglob("*") if p.is_file()]
    assert files == [first.path]


def test_size_cap_aborts_and_unlinks(q: Quarantine) -> None:
    with pytest.raises(TooLarge), q.open_temp(2500) as temp:
        for _ in range(10):
            temp.write(b"x" * 1000)
    assert list(q.incoming.iterdir()) == []
    assert [p for p in q.root.rglob("*") if p.is_file()] == []


def test_exact_cap_is_allowed(q: Quarantine) -> None:
    assert put(q, b"y" * 1000, limit=1000).size == 1000


def test_abort_without_commit_leaves_nothing(q: Quarantine) -> None:
    with q.open_temp(100) as temp:
        temp.write(b"partial")
    assert list(q.incoming.iterdir()) == []


def test_prepare_wipes_leftovers_from_a_crash(tmp_path: Path) -> None:
    store = Quarantine(tmp_path / "qq")
    store.prepare()
    (store.incoming / "stale").write_bytes(b"left by a crash")
    store.prepare()
    assert list(store.incoming.iterdir()) == []


def test_temp_file_refuses_a_symlink(q: Quarantine, tmp_path: Path) -> None:
    from collector.store import TempFile

    target = tmp_path / "victim"
    link = q.incoming / "link"
    link.symlink_to(target)
    with pytest.raises(OSError):  # O_EXCL | O_NOFOLLOW
        TempFile(link, 10)
    assert not target.exists()


def test_path_for_rejects_anything_but_a_sha256(q: Quarantine) -> None:
    for bad in ("../../etc/passwd", "ab" * 31, "A" * 64, ""):
        with pytest.raises(ValueError):
            q.path_for(bad)


def test_read_and_remove(q: Quarantine) -> None:
    stored = put(q, b"abc")
    assert q.read(stored.sha256, 100) == b"abc"
    with pytest.raises(TooLarge):
        q.read(stored.sha256, 2)
    assert q.remove(stored.sha256) is True
    assert q.remove(stored.sha256) is False
    with pytest.raises(FileNotFoundError):
        q.read(stored.sha256, 100)


def test_no_execute_bit_whatever_the_umask(q: Quarantine) -> None:
    old = os.umask(0)
    try:
        stored = put(q, b"data")
    finally:
        os.umask(old)
    assert not stat.S_IMODE(stored.path.stat().st_mode) & 0o177
