"""abuse.ch submission settings and queue (M27) against a real TimescaleDB: re-authentication,
the write-only key, the server switch, approval and cancellation by the API role."""

# ruff: noqa: F811  (the imported `client` fixture is requested by name)
import base64
import os
from typing import Any

import httpx
import pytest
from analytics_seed import owner_engine
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_abuse_integration import PASSWORD, client  # noqa: F401  (the seeded, signed-in admin)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]
KEY = "abusech-secret-key-" + "q" * 20
URL = "/api/v1/abusech/submission"
BODY: dict[str, Any] = {
    "mode": "review", "threatfox_enabled": False, "anonymous": True,
    "auto_hold_minutes": 60, "daily_cap": 20, "key": KEY, "current_password": PASSWORD,
}  # fmt: skip


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SETTINGS_ENCRYPTION_KEY", base64.b64encode(bytes(range(32, 72))).decode())
    monkeypatch.setenv("ABUSECH_SUBMIT_ENABLED", "true")


@pytest.fixture
async def world(client: httpx.AsyncClient) -> httpx.AsyncClient:
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text("TRUNCATE takedown_target_links, abusech_submissions, abusech_submission CASCADE")
        )
    return client


async def row(sql: str, **params: Any) -> Any:
    async with owner_engine() as owner, owner.connect() as conn:
        return (await conn.execute(text(sql), params)).first()


async def seed(value: str, *, status: str = "candidate", lookup: str = "unknown",
               demo: bool = False, platform: str = "urlhaus",
               reference: str | None = None) -> int:  # fmt: skip
    ioc = "url" if platform == "urlhaus" else "ip:port"
    threat = "malware_download" if platform == "urlhaus" else "botnet_cc"
    async with owner_engine() as owner, owner.begin() as conn:
        sid = int(
            await conn.scalar(
                text(
                    "INSERT INTO abusech_submissions (platform, ioc_type, value, threat, lookup, "
                    "demo, reference) VALUES (:p, :i, :v, :t, :l, :d, :r) RETURNING id"
                ),
                {
                    "p": platform,
                    "i": ioc,
                    "v": value,
                    "t": threat,
                    "l": lookup,
                    "d": demo,
                    "r": reference,
                },
            )
            or 0
        )
        if status == "pending":
            await conn.execute(
                text("UPDATE abusech_submissions SET status = 'pending', auto = true, "
                     "scheduled_at = now() WHERE id = :i"),
                {"i": sid},
            )  # fmt: skip
    return sid


async def test_defaults_and_the_server_flag(world: httpx.AsyncClient) -> None:
    got = (await world.get(URL)).json()
    assert got["mode"] == "off" and got["key_set"] is False and got["server_enabled"] is True
    assert got["anonymous"] is True and got["daily_cap"] == 20 and got["submitted_today"] == 0
    assert "key" not in got and "key_ciphertext" not in got


async def test_putting_a_mode_needs_the_server_flag(
    world: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ABUSECH_SUBMIT_ENABLED", "false")
    assert (await world.get(URL)).json()["server_enabled"] is False
    r = await world.put(URL, json=BODY)
    assert r.status_code == 422 and r.json()["code"] == "server_disabled"
    off = await world.put(URL, json=BODY | {"mode": "off", "key": None})
    assert off.status_code == 200  # switching off is always allowed


async def test_auto_needs_a_key(world: httpx.AsyncClient) -> None:
    r = await world.put(URL, json=BODY | {"mode": "auto", "key": None})
    assert r.status_code == 422 and r.json()["code"] == "key_required"
    ok = await world.put(URL, json=BODY | {"mode": "auto"})
    assert ok.status_code == 200 and ok.json()["mode"] == "auto"


async def test_saving_needs_the_password_and_never_returns_the_key(
    world: httpx.AsyncClient,
) -> None:
    wrong = await world.put(URL, json=BODY | {"current_password": "not the password"})
    assert wrong.status_code in (401, 403)
    assert (await row("SELECT 1 FROM abusech_submission")) is None
    ok = await world.put(URL, json=BODY)
    assert ok.status_code == 200
    got = ok.json()
    assert got["key_set"] is True and got["key_last4"] == KEY[-4:] and got["mode"] == "review"
    assert KEY not in ok.text and KEY not in (await world.get(URL)).text
    stored = await row("SELECT key_ciphertext, key_nonce FROM abusech_submission")
    assert stored.key_ciphertext and KEY.encode() not in bytes(stored.key_ciphertext)
    again = await world.put(URL, json=BODY | {"key": None, "anonymous": False})
    assert again.json()["key_set"] is True and again.json()["anonymous"] is False  # key kept
    audit = await row(
        "SELECT details::text AS d FROM audit_log "
        "WHERE action = 'abusech.settings.update' ORDER BY id DESC LIMIT 1"
    )
    assert KEY not in audit.d and "anonymous" in audit.d


async def test_an_invalid_key_is_refused(world: httpx.AsyncClient) -> None:
    for bad in ("short", "has space in it" + "x" * 20, "é" * 30):
        r = await world.put(URL, json=BODY | {"key": bad})
        assert r.status_code == 422 and r.json()["code"] == "invalid_key"


async def test_the_api_role_cannot_read_the_key_column(world: httpx.AsyncClient) -> None:
    await world.put(URL, json=BODY)
    from analytics_seed import api_engine

    engine = api_engine()
    try:
        async with engine.connect() as conn:
            with pytest.raises(DBAPIError):
                await conn.execute(text("SELECT key_ciphertext FROM abusech_submission"))
    finally:
        await engine.dispose()


async def test_delete_removes_the_key_and_switches_off(world: httpx.AsyncClient) -> None:
    await world.put(URL, json=BODY | {"mode": "auto"})
    r = await world.request("DELETE", URL, json={"current_password": "nope"})
    assert r.status_code in (401, 403)
    gone = await world.request("DELETE", URL, json={"current_password": PASSWORD})
    assert gone.status_code == 204
    got = (await world.get(URL)).json()
    assert got["mode"] == "off" and got["key_set"] is False and got["key_last4"] is None
    actions = await row(
        "SELECT count(*) AS n FROM audit_log WHERE action = 'abusech.settings.delete'"
    )
    assert actions.n == 1


async def test_the_list_paginates_filters_and_counts(world: httpx.AsyncClient) -> None:
    ids = [await seed(f"http://files.example.net/{i}") for i in range(5)]
    await seed("http://files.example.net/p", status="pending")
    await seed("203.0.113.9:4444", platform="threatfox", lookup="pending")
    await seed("http://files.example.net/ref", reference="https://urlhaus.abuse.ch/url/9/")
    await seed("http://files.example.net/evil", reference="https://evil.example.net/")
    page = (await world.get("/api/v1/abusech/submissions?limit=4")).json()
    assert len(page["items"]) == 4 and page["next_cursor"]
    assert page["counts"]["candidate"] == 8 and page["counts"]["pending"] == 1
    rest = (
        await world.get(f"/api/v1/abusech/submissions?limit=50&cursor={page['next_cursor']}")
    ).json()
    assert len(page["items"]) + len(rest["items"]) == 9
    tf = (await world.get("/api/v1/abusech/submissions?platform=threatfox")).json()
    assert [i["value"] for i in tf["items"]] == ["203.0.113.9:4444"]
    pend = (
        await world.get("/api/v1/abusech/submissions?status=pending,candidate&limit=100")
    ).json()
    assert len(pend["items"]) == 9
    refs = {
        i["value"]: i["reference"]
        for i in (await world.get("/api/v1/abusech/submissions?limit=100")).json()["items"]
    }
    assert refs["http://files.example.net/ref"] == "https://urlhaus.abuse.ch/url/9/"
    assert refs["http://files.example.net/evil"] is None
    assert (await world.get("/api/v1/abusech/submissions?status=bogus")).status_code == 422
    assert ids


async def test_submit_approves_candidates_only_in_the_right_state(world: httpx.AsyncClient) -> None:
    ready = await seed("http://files.example.net/ready")
    waiting = await seed("http://files.example.net/waiting", lookup="pending")
    demo = await seed("http://demo.example.net/x", demo=True)
    off = await world.post("/api/v1/abusech/submissions/submit", json={"ids": [ready]})
    assert off.status_code == 409 and off.json()["code"] == "mode_off"
    await world.put(URL, json=BODY)
    lookup = await world.post("/api/v1/abusech/submissions/submit", json={"ids": [ready, waiting]})
    assert lookup.status_code == 409 and lookup.json()["code"] == "lookup_not_ready"
    assert (
        await row("SELECT status FROM abusech_submissions WHERE id = :i", i=ready)
    ).status == "candidate"
    assert (
        await world.post("/api/v1/abusech/submissions/submit", json={"ids": [demo]})
    ).status_code == 409
    assert (
        await world.post("/api/v1/abusech/submissions/submit", json={"ids": [999999]})
    ).status_code == 404
    assert (
        await world.post("/api/v1/abusech/submissions/submit", json={"ids": list(range(21))})
    ).status_code == 422
    ok = await world.post("/api/v1/abusech/submissions/submit", json={"ids": [ready]})
    assert ok.status_code == 200 and ok.json() == {"approved": [ready]}
    done = await row(
        "SELECT status, approved_by, approved_at FROM abusech_submissions WHERE id = :i", i=ready
    )
    assert done.status == "pending" and done.approved_by and done.approved_at is not None
    again = await world.post("/api/v1/abusech/submissions/submit", json={"ids": [ready]})
    assert again.status_code == 409 and again.json()["code"] == "not_a_candidate"
    audit = await row("SELECT details::text AS d FROM audit_log WHERE action = 'abusech.submit'")
    assert str(ready) in audit.d


async def test_submit_needs_a_key_and_the_server_flag(
    world: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    sid = await seed("http://files.example.net/k")
    await world.put(URL, json=BODY | {"key": None})
    r = await world.post("/api/v1/abusech/submissions/submit", json={"ids": [sid]})
    assert r.status_code == 409 and r.json()["code"] == "key_required"
    await world.put(URL, json=BODY)
    monkeypatch.setenv("ABUSECH_SUBMIT_ENABLED", "false")
    r = await world.post("/api/v1/abusech/submissions/submit", json={"ids": [sid]})
    assert r.status_code == 409 and r.json()["code"] == "server_disabled"


async def test_cancel_only_a_pending_row_and_audits_it(world: httpx.AsyncClient) -> None:
    pending = await seed("http://files.example.net/c", status="pending")
    candidate = await seed("http://files.example.net/d")
    r = await world.post(f"/api/v1/abusech/submissions/{candidate}/cancel")
    assert r.status_code == 409 and r.json()["code"] == "not_pending"
    ok = await world.post(f"/api/v1/abusech/submissions/{pending}/cancel")
    assert ok.status_code == 200 and ok.json()["status"] == "cancelled"
    done = await row("SELECT status, done_at FROM abusech_submissions WHERE id = :i", i=pending)
    assert done.status == "cancelled" and done.done_at is not None
    assert (await world.post(f"/api/v1/abusech/submissions/{pending}/cancel")).status_code == 409
    assert (await world.post("/api/v1/abusech/submissions/999999/cancel")).status_code == 404
    n = await row("SELECT count(*) AS n FROM audit_log WHERE action = 'abusech.submit.cancel'")
    assert n.n == 1


async def test_the_api_role_cannot_mark_a_row_submitted(world: httpx.AsyncClient) -> None:
    """Defence in depth: even a buggy route could not skip the workflow (grants and trigger)."""
    sid = await seed("http://files.example.net/z")
    from analytics_seed import api_engine

    engine = api_engine()
    try:
        for sql in (
            "UPDATE abusech_submissions SET status = 'submitted' WHERE id = :i",
            "UPDATE abusech_submissions SET result_code = 'inserted' WHERE id = :i",
            "UPDATE abusech_submissions SET status = 'pending' WHERE id = :i",  # mode is off
        ):
            async with engine.connect() as conn:
                with pytest.raises(DBAPIError):
                    await conn.execute(text(sql), {"i": sid})
    finally:
        await engine.dispose()
