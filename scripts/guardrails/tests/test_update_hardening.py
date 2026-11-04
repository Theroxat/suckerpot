"""Hardening of the automatic update: the age floor and the choice of the candidate release."""

import time

from conftest import Sandbox
from test_auto_update import (
    ENV,
    names,
    publish,
    result,
    run_auto,
    stage_auto,
    stage_release,
    verify,
)


def test_a_manifest_cannot_lower_the_minimum_age_below_48_hours(sandbox: Sandbox) -> None:
    stage_release(sandbox)
    publish(sandbox, auto_min_age_h=0, released_at=int(time.time()) - 3600)
    proc = verify(sandbox, "--auto", "v0.9.0")
    assert proc.returncode == 4
    assert "waits for 48 h" in proc.stderr
    # A manual update does not check the age.
    assert verify(sandbox, "v0.9.0").returncode == 0


def test_the_local_setting_can_raise_the_minimum_age_never_lower_it(sandbox: Sandbox) -> None:
    stage_release(sandbox)
    publish(sandbox, released_at=int(time.time()) - 72 * 3600)
    sandbox.write_env(ENV + "AUTO_UPDATE_MIN_AGE_H=96\n")
    proc = verify(sandbox, "--auto", "v0.9.0")
    assert proc.returncode == 4 and "waits for 96 h" in proc.stderr
    sandbox.write_env(ENV + "AUTO_UPDATE_MIN_AGE_H=1\n")
    assert verify(sandbox, "--auto", "v0.9.0").returncode == 0
    publish(sandbox, released_at=int(time.time()) - 3600)
    assert verify(sandbox, "--auto", "v0.9.0").returncode == 4
    sandbox.write_env(ENV + "AUTO_UPDATE_MIN_AGE_H=banana\n")
    proc = verify(sandbox, "--auto", "v0.9.0")
    assert proc.returncode == 4 and "ignoring AUTO_UPDATE_MIN_AGE_H" in proc.stderr


def test_the_manifest_can_still_raise_the_minimum_age(sandbox: Sandbox) -> None:
    stage_release(sandbox)
    publish(sandbox, auto_min_age_h=200, released_at=int(time.time()) - 72 * 3600)
    assert verify(sandbox, "--auto", "v0.9.0").returncode == 4


def test_a_download_problem_is_not_a_verdict(sandbox: Sandbox) -> None:
    stage_auto(sandbox)
    sandbox.env["SHIM_RELEASE_RC"] = "9"
    assert run_auto(sandbox).returncode == 1
    assert result(sandbox)["error_code"] == "download_failed"
    assert not (sandbox.root / ".suckerpot-state" / "bad-versions").exists()


def test_a_release_that_fails_verification_is_marked_bad_and_the_next_one_is_tried(
    sandbox: Sandbox,
) -> None:
    stage_auto(sandbox)
    sandbox.git_set("tags", "v0.7.0\nv0.8.0\nv0.9.0\nv0.9.1\n")
    # The newest tag fails; the one before it passes.
    stub = sandbox.root / "scripts" / "verify-release.sh"
    text = stub.read_text().replace(
        'exit "${SHIM_RELEASE_RC:-0}"', '[ "$2" = v0.9.1 ] && exit 6\nexit 0'
    )
    stub.write_text(text)
    assert run_auto(sandbox).returncode == 0
    calls = sandbox.calls()
    assert "verify-release --auto v0.9.1" in calls and "verify-release --auto v0.9.0" in calls
    assert "update --yes --auto v0.9.0 lock_held=1" in calls
    state = sandbox.root / ".suckerpot-state"
    assert (state / "bad-versions").read_text() == "v0.9.1\n"
    assert "v0.9.1 signature_invalid" in (state / "bad-versions.log").read_text()
    assert result(sandbox)["last_result"] == "updated"


def test_at_most_three_candidates_are_tried_and_none_is_older_than_the_installed(
    sandbox: Sandbox,
) -> None:
    stage_auto(sandbox)
    sandbox.git_set("tags", "v0.7.0\nv0.8.0\nv0.8.1\nv0.8.2\nv0.8.3\nv0.8.4\nv0.8.5\n")
    sandbox.env["SHIM_RELEASE_RC"] = "5"
    assert run_auto(sandbox).returncode == 0
    tried = [c for c in sandbox.calls() if c.startswith("verify-release")]
    assert tried == [f"verify-release --auto v0.8.{n}" for n in (5, 4, 3)]
    assert result(sandbox)["error_code"] == "commit_mismatch"
    assert names(sandbox) == []
    bad = (sandbox.root / ".suckerpot-state" / "bad-versions").read_text().split()
    assert bad == ["v0.8.5", "v0.8.4", "v0.8.3"]


def test_a_young_newest_release_stops_the_run_without_marking_it_bad(sandbox: Sandbox) -> None:
    stage_auto(sandbox)
    sandbox.git_set("tags", "v0.8.0\nv0.9.0\nv0.9.1\n")
    sandbox.env["SHIM_RELEASE_RC"] = "4"
    assert run_auto(sandbox).returncode == 0
    assert result(sandbox)["error_code"] == "too_young"
    assert len([c for c in sandbox.calls() if c.startswith("verify-release")]) == 1
    assert not (sandbox.root / ".suckerpot-state" / "bad-versions").exists()
