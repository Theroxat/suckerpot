"""Profile, TLS material, login tracker and event sink."""

from __future__ import annotations

import json
import os
from pathlib import Path

from synology_sensor.api import LoginTracker
from synology_sensor.profile import build_profile, load_or_create_profile
from synology_sensor.tls import ensure_certificate


def test_profile_is_persisted_with_mode_0600(tmp_path: Path) -> None:
    first = load_or_create_profile(str(tmp_path))
    second = load_or_create_profile(str(tmp_path))
    assert first == second
    assert oct(os.stat(tmp_path / "profile.json").st_mode & 0o777) == "0o600"
    assert json.loads((tmp_path / "profile.json").read_text()).keys() == {"secret", "created"}


def test_profile_names_look_real() -> None:
    names = {build_profile(bytes([i]) * 32, 1_790_000_000.0).hostname for i in range(60)}
    assert len(names) > 3
    for n in names:
        assert n.isalnum() and n.lower() not in ("honeypot", "suckerpot")


def test_profile_falls_back_when_data_dir_is_not_writable() -> None:
    assert load_or_create_profile("/proc/nonexistent/x").hostname


def test_certificate_is_created_once(tmp_path: Path) -> None:
    profile = build_profile(b"y" * 32, 1_790_000_000.0)
    a = ensure_certificate(str(tmp_path), profile)
    mtime = a[0].stat().st_mtime_ns
    b = ensure_certificate(str(tmp_path), profile)
    assert a == b and b[0].stat().st_mtime_ns == mtime
    assert oct(a[1].stat().st_mode & 0o777) == "0o600"


def test_login_tracker_is_bounded_and_expires() -> None:
    t = LoginTracker(limit=2, window=0.05, max_ips=10)
    for n in range(100):
        t.fail(f"198.51.100.{n}")
    assert len(t._items) == 10
    t.fail("192.0.2.1")
    t.fail("192.0.2.1")
    assert t.blocked("192.0.2.1")
    import time

    time.sleep(0.06)
    assert not t.blocked("192.0.2.1")
