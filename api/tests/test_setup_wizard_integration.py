"""Setup progress, ports and version against a real TimescaleDB, as the API role (M28)."""

import os
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from analytics_seed import owner_engine
from sqlalchemy import text
from test_vpn_settings_integration import (  # noqa: F401
    admin,
    app,
    put_status,
    rows,
    viewer,
    vpn_dir,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

PROGRESS = "/api/v1/setup/progress"


@pytest.fixture(autouse=True)
async def clean(app: Any, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    for name in ("UPDATE_CHECK_ENABLED", "SENSOR_TELNET", "SUCKERPOT_RUNNING_VERSION"):
        monkeypatch.delenv(name, raising=False)
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(text("DELETE FROM setup_progress"))
        await conn.execute(text("DELETE FROM events"))


async def test_progress_state_machine(admin: httpx.AsyncClient) -> None:  # noqa: F811
    r = await admin.get(PROGRESS)
    assert r.json() == {"state": "new", "steps": {}, "show": True}
    assert await rows("SELECT 1 FROM setup_progress") == []  # a GET never writes

    r = await admin.put(PROGRESS, json={"step": "welcome", "status": "done"})
    assert r.status_code == 200, r.text
    assert r.json() == {"state": "in_progress", "steps": {"welcome": "done"}, "show": True}
    r = await admin.put(PROGRESS, json={"step": "vpn", "status": "skipped"})
    assert r.json()["steps"] == {"welcome": "done", "vpn": "skipped"}

    r = await admin.put(PROGRESS, json={"finish": True})
    assert r.json() == {
        "state": "finished",
        "steps": {"welcome": "done", "vpn": "skipped"},
        "show": False,
    }
    assert (await rows("SELECT finished_by FROM setup_progress"))[0][0] == "admin"

    r = await admin.put(PROGRESS, json={"reopen": True})
    assert r.json()["state"] == "in_progress" and r.json()["show"] is True
    r = await admin.put(PROGRESS, json={"skip": True})
    assert r.json()["state"] == "skipped" and r.json()["show"] is False
    r = await admin.put(PROGRESS, json={"reopen": True})
    assert r.json()["state"] == "in_progress"

    actions = [a.action for a in await rows("SELECT action FROM audit_log ORDER BY id")]
    assert [a for a in actions if a.startswith("setup.")] == [
        "setup.finish",
        "setup.reopen",
        "setup.skip",
        "setup.reopen",
    ]


async def test_bad_updates_are_refused(admin: httpx.AsyncClient) -> None:  # noqa: F811
    for payload in (
        {},
        {"step": "nope", "status": "done"},
        {"finish": True, "skip": True},
        {"step": "welcome"},
    ):
        assert (await admin.put(PROGRESS, json=payload)).status_code == 422
    assert await rows("SELECT 1 FROM setup_progress") == []


async def test_admin_only_and_csrf(
    admin: httpx.AsyncClient,  # noqa: F811
    viewer: httpx.AsyncClient,  # noqa: F811
    app: Any,  # noqa: F811
) -> None:
    for path in (PROGRESS, "/api/v1/setup/ports"):
        assert (await viewer.get(path)).status_code == 403
    assert (await viewer.put(PROGRESS, json={"finish": True})).status_code == 403
    assert (await viewer.get("/api/v1/version")).status_code == 200  # any signed-in user
    del admin.headers["X-CSRF-Token"]
    assert (await admin.put(PROGRESS, json={"finish": True})).status_code == 403
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://testserver"
    ) as anon:
        assert (await anon.get(PROGRESS)).status_code == 401
        assert (await anon.get("/api/v1/version")).status_code == 401
    assert await rows("SELECT 1 FROM setup_progress WHERE finished_at IS NOT NULL") == []


async def test_ports_states(
    admin: httpx.AsyncClient,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SENSOR_TELNET", "0")
    monkeypatch.setenv("SSH_HOST_PORT", "2222")
    monkeypatch.setenv("DASHBOARD_PORT", "9443")
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO events (ts, sensor, session_id, type, src_ip, src_port, dst_port, "
                "data) VALUES (:ts, 'ssh', 's1', 'connect', '192.0.2.10', 40000, 22, '{}'::jsonb)"
            ),
            {"ts": datetime.now(UTC) - timedelta(minutes=5)},
        )
    r = await admin.get("/api/v1/setup/ports")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["dashboard_port"] == 9443
    by_var = {i["env_var"]: i for i in body["items"]}
    ssh = by_var["SSH_HOST_PORT"]
    assert (ssh["state"], ssh["external_port"], ssh["host_port"]) == ("receiving", 22, 2222)
    assert ssh["last_event_at"] is not None and ssh["protocols"] == ["tcp"]
    assert by_var["TELNET_HOST_PORT"]["state"] == "off"
    assert not by_var["TELNET_HOST_PORT"]["enabled"]
    assert by_var["RDP_HOST_PORT"]["state"] == "waiting"
    assert set(ssh) == {
        "sensor", "label", "enabled", "protocols", "external_port", "host_port", "env_var",
        "state", "last_event_at",
    }  # fmt: skip


async def test_version(
    admin: httpx.AsyncClient,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SUCKERPOT_RUNNING_VERSION", "v0.8.0")
    r = await admin.get("/api/v1/version")
    assert r.status_code == 200, r.text
    assert r.json()["check"] == "pending" and r.json()["update_available"] is False
    await put_status(
        "update_check", latest="v0.9.0", state="ok", checked_at=datetime.now(UTC).isoformat()
    )
    got = (await admin.get("/api/v1/version")).json()
    assert got["update_available"] is True and got["latest"] == "v0.9.0" and got["check"] == "ok"
    assert set(got) == {
        "version", "build", "commit", "latest", "update_available", "checked_at", "check",
        "release_url",
    }  # fmt: skip
    monkeypatch.setenv("UPDATE_CHECK_ENABLED", "false")
    got = (await admin.get("/api/v1/version")).json()
    assert got["check"] == "off" and got["update_available"] is False


async def test_setup_checklist_items(
    admin: httpx.AsyncClient,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SUCKERPOT_RUNNING_VERSION", "v0.8.0")
    await put_status("update_check", latest="v0.9.0", state="ok")
    got = {i["id"]: i for i in (await admin.get("/api/v1/setup/status")).json()["items"]}
    assert got["updates"]["state"] == "warning" and "v0.9.0" in got["updates"]["detail"]
    assert got["ports"]["state"] in ("ok", "todo")
    monkeypatch.setenv("UPDATE_CHECK_ENABLED", "false")
    got = {i["id"]: i for i in (await admin.get("/api/v1/setup/status")).json()["items"]}
    assert got["updates"]["state"] == "off"
