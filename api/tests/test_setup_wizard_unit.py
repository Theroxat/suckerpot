"""Pure parts of the M28 setup routes: request validation, progress state, ports, version."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from api.sensors import SENSORS
from api.setup_wizard import (
    PORTS,
    STEP_IDS,
    ProgressUpdate,
    build_ports,
    dashboard_port,
    progress_of,
    sensor_enabled,
)
from api.version import DEFAULT_UPDATE_REPO, build_info, parse_release

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


def row(**kw: Any) -> Any:
    base: dict[str, Any] = {"finished_at": None, "skipped_at": None, "steps": {}}
    return SimpleNamespace(**{**base, **kw})


# ---- progress ---------------------------------------------------------------------------------


def test_no_row_is_new_and_shown() -> None:
    got = progress_of(None)
    assert (got.state, got.steps, got.show) == ("new", {}, True)


def test_state_machine_reads() -> None:
    assert progress_of(row()).state == "in_progress"
    assert progress_of(row()).show is True
    done = progress_of(row(finished_at=NOW))
    assert (done.state, done.show) == ("finished", False)
    skipped = progress_of(row(skipped_at=NOW))
    assert (skipped.state, skipped.show) == ("skipped", False)


def test_unknown_or_odd_stored_steps_are_not_echoed() -> None:
    got = progress_of(row(steps={"welcome": "done", "ports": "skipped", "x": "done", "vpn": 3}))
    assert got.steps == {"welcome": "done", "ports": "skipped"}


@pytest.mark.parametrize(
    "payload",
    [
        {"step": "welcome", "status": "done"},
        {"step": "network", "status": "skipped"},
        {"finish": True},
        {"skip": True},
        {"reopen": True},
    ],
)
def test_valid_updates(payload: dict[str, Any]) -> None:
    ProgressUpdate.model_validate(payload)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"step": "nope", "status": "done"},
        {"step": "welcome"},
        {"status": "done"},
        {"step": "welcome", "status": "maybe"},
        {"finish": True, "skip": True},
        {"finish": False},
        {"step": "welcome", "status": "done", "finish": True},
        {"finish": True, "extra": 1},
    ],
)
def test_invalid_updates(payload: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        ProgressUpdate.model_validate(payload)


def test_step_ids_are_the_documented_ones() -> None:
    assert STEP_IDS == (
        "welcome", "sensors", "ports", "vpn", "self", "reporting", "alerts", "network", "done"
    )  # fmt: skip


# ---- ports ------------------------------------------------------------------------------------


def test_every_sensor_has_a_port_row() -> None:
    assert {p.sensor for p in PORTS} == set(SENSORS)
    assert len({p.env_var for p in PORTS}) == len(PORTS)


def test_sensor_enabled_defaults_on() -> None:
    assert sensor_enabled("ssh", {})
    assert sensor_enabled("ssh", {"SENSOR_SSH": "1"})
    assert not sensor_enabled("ssh", {"SENSOR_SSH": "0"})
    assert not sensor_enabled("sip", {"SENSOR_SIP": " 0 "})


def test_port_states() -> None:
    env = {"SENSOR_TELNET": "0", "SSH_HOST_PORT": "2222", "HTTP_HOST_PORT": "junk"}
    last = {"ssh": NOW - timedelta(hours=1), "telnet": NOW, "web": NOW - timedelta(hours=30)}
    got = {i.env_var: i for i in build_ports(last, NOW, env)}
    assert (got["SSH_HOST_PORT"].state, got["SSH_HOST_PORT"].host_port) == ("receiving", 2222)
    assert got["SSH_HOST_PORT"].external_port == 22
    assert got["TELNET_HOST_PORT"].state == "off"
    assert got["TELNET_HOST_PORT"].last_event_at is None  # a disabled sensor shows nothing
    assert (got["HTTP_HOST_PORT"].state, got["HTTP_HOST_PORT"].host_port) == ("waiting", 80)
    assert got["RDP_HOST_PORT"].state == "waiting" and got["RDP_HOST_PORT"].last_event_at is None
    assert got["SIP_HOST_PORT"].protocols == ["udp", "tcp"]
    assert got["SSH_HOST_PORT"].protocols == ["tcp"]


def test_dashboard_port() -> None:
    assert dashboard_port({}) == 8443
    assert dashboard_port({"DASHBOARD_PORT": "9443"}) == 9443
    assert dashboard_port({"DASHBOARD_PORT": "0"}) == 8443


# ---- version ----------------------------------------------------------------------------------


def info(detail: dict[str, Any] | None, running: str = "v0.8.0", enabled: bool = True) -> Any:
    return build_info(
        detail, running=running, kind="image", commit="abc1234", enabled=enabled,
        repo=DEFAULT_UPDATE_REPO,
    )  # fmt: skip


CHECKED = {"latest": "v0.9.0", "state": "ok", "checked_at": NOW.isoformat()}


def test_parse_release() -> None:
    assert parse_release("v1.2.3") == (1, 2, 3)
    for bad in ("dev", "v1.2", "v1.2.3-4-gabc", "v1.2.3-dirty", "1.2.3", None, 3):
        assert parse_release(bad) is None


def test_newer_release_is_an_update() -> None:
    got = info(CHECKED)
    assert got.update_available and got.latest == "v0.9.0" and got.check == "ok"
    assert got.build == "image" and got.checked_at == NOW
    assert got.release_url == f"https://github.com/{DEFAULT_UPDATE_REPO}/releases/tag/v0.9.0"


def test_equal_or_older_is_not_an_update() -> None:
    assert not info(CHECKED, running="v0.9.0").update_available
    assert not info(CHECKED, running="v1.0.0").update_available
    assert info({**CHECKED, "latest": "v0.10.0"}).update_available  # numeric, not textual


def test_dev_builds_never_claim_an_update() -> None:
    for running in ("dev", "v0.8.0-3-gabc1234", "v0.8.0-dirty"):
        got = info(CHECKED, running=running)
        assert not got.update_available and got.version == running


def test_check_states() -> None:
    assert info(None).check == "pending"
    assert info({"state": "no_egress"}).check == "no_egress"
    assert info({"state": "error"}).check == "error"
    assert info({"state": "weird"}).check == "pending"
    off = info(CHECKED, enabled=False)
    assert (off.check, off.latest, off.update_available, off.checked_at) == (
        "off", None, False, None,
    )  # fmt: skip


def test_a_stored_latest_in_a_bad_format_is_ignored() -> None:
    got = info({"latest": "v9.9.9; rm -rf /", "state": "ok"})
    assert got.latest is None and not got.update_available
    assert got.release_url == f"https://github.com/{DEFAULT_UPDATE_REPO}/releases"
