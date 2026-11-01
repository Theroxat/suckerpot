"""SMTP profile, send queue, send and cancel (M25) against a real TimescaleDB.

The API never talks SMTP: these tests only check what it stores and queues. Ingest's side is in
``ingest/tests/test_report_mail_integration.py``.
"""

# ruff: noqa: F811  (the imported `client` fixture is requested by name)
import base64
import json
import os
import uuid
from typing import Any

import httpx
import pytest
from analytics_seed import api_engine, owner_engine
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from suckerpot_db.secretbox import box_from_env
from suckerpot_reporting import GuardContext
from test_abuse_integration import (
    DEMO_ID,
    NOW,
    PASSWORD,
    SELF,
    SENT_ID,
    WORDING,
    client,  # noqa: F401  (the seeded, signed-in client of the M22 tests)
    evidence,
    settings_body,
)

import api.abuse_core as core

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

SMTP_PASSWORD = "S3cret-smtp-token-xyz"
READY = uuid.UUID("44444444-4444-4444-8444-444444444444")
LEAKY = uuid.UUID("55555555-5555-4555-8555-555555555555")
WORDING_ALL = {
    **WORDING,
    "reply_contact": "reports@example.org",
    "signature": "Regards",
    "xarf_user_agent": "reporter/1.0",
}
PROFILE: dict[str, Any] = {
    "host": "smtp.example.org",
    "port": 587,
    "security": "starttls",
    "username": "reporter",
    "from_address": "sender@mail.example.org",
    "from_name": "Network Volunteer",
    "password": SMTP_PASSWORD,
    "mode": "click",
    "auto_hold_minutes": 60,
    "daily_cap": 20,
    "current_password": PASSWORD,
}


# The app reads the encryption key when it is built: the key goes into the environment before
# the seeded client is requested (fixtures are created in the order they are named).
@pytest.fixture
def key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SETTINGS_ENCRYPTION_KEY", base64.b64encode(bytes(range(32, 72))).decode())


@pytest.fixture
def documentation_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    """The fixtures use documentation addresses, which the guard refuses outside demo reports."""
    real = core.guard_context

    async def lenient(db: Any, row: Any, ev: Any) -> GuardContext:
        ctx = await real(db, row, ev)
        return GuardContext(internal_ids=ctx.internal_ids, allow_documentation=True)

    monkeypatch.setattr("api.abuse_smtp.guard_context", lenient)


@pytest.fixture
async def api(key: None, documentation_ok: None, client: httpx.AsyncClient) -> httpx.AsyncClient:
    r = await client.put("/api/v1/abuse/settings", json=settings_body(0, **WORDING_ALL))
    assert r.status_code == 200, r.text
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(text("DELETE FROM report_smtp"))
        await conn.execute(
            text(
                "INSERT INTO abuse_recipients (mailbox, source) VALUES ('abuse2@example.net', "
                "'rdap')"
            )
        )
        for pid, cmd, kind in (
            (READY, "id", "payload_host"),
            (LEAKY, f"curl http://{SELF}/x", "attack_source"),
        ):
            await conn.execute(
                text(
                    "INSERT INTO abuse_reports (public_id, id_seed, recipient_id, kind, status, "
                    "demo, window_start, window_end, subject_count, evidence, content_sha256, "
                    "guard_ok) VALUES (:p, gen_random_uuid(), :r, :k, 'draft', false, :t, :t, 1, "
                    "CAST(:e AS jsonb), 'x', true)"
                ),
                {
                    "p": pid,
                    "r": 3,  # recipient 1 already has open reports of these kinds
                    "k": kind,
                    "t": NOW,
                    "e": json.dumps(evidence(cmd) | {"recipient": "abuse@example.net"}),
                },
            )
    return client


async def count(sql: str, **params: Any) -> Any:
    async with owner_engine() as owner, owner.connect() as conn:
        return await conn.scalar(text(sql), params)


async def put_profile(c: httpx.AsyncClient, **over: Any) -> httpx.Response:
    return await c.put("/api/v1/abuse/smtp", json=PROFILE | over)


# ---- the profile -----------------------------------------------------------------------------


async def test_an_unconfigured_profile(api: httpx.AsyncClient) -> None:
    got = (await api.get("/api/v1/abuse/smtp")).json()
    assert got["configured"] is False and got["password_set"] is False
    assert got["mode"] == "off" and got["port"] == 587 and got["security"] == "starttls"
    assert got["sent_today"] == 0 and got["last_test"] is None and got["host"] == ""


@pytest.mark.parametrize(
    "host",
    ["192.0.2.10", "2130706433", "0x7f.1", "localhost", "mail", "smtp.local", "smtp.internal",
     "smtp.lan", "-bad.example.org", "bad_.example.org", "a" * 64 + ".example.org", "[::1]",
     "smtp.example.org.", "smtp.home.arpa", "1.2.3.4"],
)  # fmt: skip
async def test_the_host_must_be_a_public_dns_name(api: httpx.AsyncClient, host: str) -> None:
    r = await put_profile(api, host=host)
    assert r.status_code == 422 and r.json()["code"] == "invalid_host", host
    assert await count("SELECT count(*) FROM report_smtp") == 0


@pytest.mark.parametrize(
    ("over", "status", "code"),
    [
        ({"security": "plain"}, 422, None),
        ({"port": 0}, 422, None),
        ({"port": 70000}, 422, None),
        ({"auto_hold_minutes": 9}, 422, None),
        ({"auto_hold_minutes": 1441}, 422, None),
        ({"daily_cap": 0}, 422, None),
        ({"daily_cap": 201}, 422, None),
        ({"mode": "always"}, 422, None),
        ({"from_address": "not-an-address"}, 422, "invalid_from_address"),
        ({"from_address": "user@localhost"}, 422, "invalid_from_address"),
        ({"from_address": "user@mail.internal"}, 422, "invalid_from_address"),
        ({"from_name": "Evil <x@example.org>"}, 422, "invalid_from_name"),
        ({"from_name": "Line\nBreak"}, 422, "invalid_from_name"),
        ({"password": ""}, 422, "password_required"),  # no SMTP password
        ({"password": None}, 422, "password_required"),  # first save without one
        ({"username": "u\r\nBcc: x@example.org"}, 422, "invalid_credentials"),
    ],
)  # fmt: skip
async def test_profile_validation(
    api: httpx.AsyncClient, over: dict[str, Any], status: int, code: str | None
) -> None:
    r = await put_profile(api, **over)
    assert r.status_code == status, r.text
    if code:
        assert r.json()["code"] == code
    assert SMTP_PASSWORD not in r.text
    assert await count("SELECT count(*) FROM report_smtp") == 0


async def test_the_identity_guard_refuses_a_profile_that_names_the_owner(
    api: httpx.AsyncClient,
) -> None:
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text("UPDATE report_self_terms SET confirmed = true WHERE kind = 'name'")
        )
    from api.abuse_core import invalidate_terms

    invalidate_terms()
    for over in ({"from_name": f"Host {SELF}"}, {"from_address": "ops@learned.example.net"}):
        r = await put_profile(api, **over)
        assert r.status_code == 422 and r.json()["code"] == "identity_guard_failed", over
        assert r.json()["reasons"]
        assert SELF not in r.text and "learned.example.net" not in r.text
    assert await count("SELECT count(*) FROM report_smtp") == 0


async def test_writes_need_the_account_password(api: httpx.AsyncClient) -> None:
    r = await put_profile(api, current_password="wrong password")
    assert r.status_code in (401, 403) and await count("SELECT count(*) FROM report_smtp") == 0
    ok = await put_profile(api)
    assert ok.status_code == 200
    bad = await api.request(
        "DELETE", "/api/v1/abuse/smtp", json={"current_password": "wrong password"}
    )
    assert bad.status_code in (401, 403) and await count("SELECT count(*) FROM report_smtp") == 1
    bad_test = await api.post(
        "/api/v1/abuse/smtp/test", json={"current_password": "wrong password"}
    )
    assert bad_test.status_code in (401, 403)
    assert await count("SELECT count(*) FROM abuse_send_requests") == 0


async def test_the_password_is_stored_encrypted_and_never_returned(
    api: httpx.AsyncClient,
) -> None:
    r = await put_profile(api)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["configured"] and body["password_set"] and body["mode"] == "click"
    assert body["host"] == "smtp.example.org" and body["from_name"] == "Network Volunteer"
    again = await api.get("/api/v1/abuse/smtp")
    assert SMTP_PASSWORD not in again.text and SMTP_PASSWORD not in r.text
    assert "password_ciphertext" not in again.text
    async with owner_engine() as owner, owner.connect() as conn:
        row = (await conn.execute(text("SELECT * FROM report_smtp"))).one()
        audit = (await conn.execute(text("SELECT action, details FROM audit_log"))).all()
    assert bytes(row.password_ciphertext) != SMTP_PASSWORD.encode()
    assert SMTP_PASSWORD.encode() not in bytes(row.password_ciphertext)
    box = box_from_env()
    assert box is not None
    assert (
        box.decrypt("report_smtp", bytes(row.password_ciphertext), bytes(row.password_nonce)).key
        == SMTP_PASSWORD
    )
    actions = {a.action: a.details for a in audit}
    assert "abuse.smtp.update" in actions
    assert SMTP_PASSWORD not in json.dumps(actions, default=str)
    assert "password" in actions["abuse.smtp.update"]["changed"]  # the name, not the value
    # The API's own role cannot read the ciphertext back, even by mistake.
    engine = api_engine()
    try:
        async with engine.connect() as conn:
            assert await conn.scalar(text("SELECT password_set FROM report_smtp")) is True
            with pytest.raises(DBAPIError):
                await conn.execute(text("SELECT password_ciphertext FROM report_smtp"))
    finally:
        await engine.dispose()


async def test_updating_without_a_password_keeps_it_and_empty_removes_it(
    api: httpx.AsyncClient,
) -> None:
    await put_profile(api)
    kept = await put_profile(api, password=None, mode="auto", auto_hold_minutes=30)
    body = kept.json()
    assert kept.status_code == 200 and body["password_set"] and body["mode"] == "auto"
    assert body["auto_hold_minutes"] == 30
    assert (await put_profile(api, password="")).json()["code"] == "password_required"
    changed = await put_profile(api, password="Another-token-0123456789")
    assert changed.status_code == 200 and changed.json()["password_set"]


async def test_delete_removes_the_profile_and_cancels_what_waits(api: httpx.AsyncClient) -> None:
    await put_profile(api)
    assert (await api.post(f"/api/v1/abuse/reports/{SENT_ID}/send")).status_code == 202
    gone = await api.request("DELETE", "/api/v1/abuse/smtp", json={"current_password": PASSWORD})
    assert gone.status_code == 204
    assert await count("SELECT count(*) FROM report_smtp") == 0
    assert await count("SELECT count(*) FROM abuse_send_requests WHERE status = 'pending'") == 0
    assert await count("SELECT count(*) FROM audit_log WHERE action = 'abuse.smtp.delete'") == 1
    assert (await api.get("/api/v1/abuse/smtp")).json()["configured"] is False


# ---- test mail -------------------------------------------------------------------------------


async def test_a_test_is_queued_once(api: httpx.AsyncClient) -> None:
    body = {"current_password": PASSWORD}
    assert (await api.post("/api/v1/abuse/smtp/test", json=body)).json()["code"] == (
        "smtp_not_configured"
    )
    await put_profile(api, mode="off")
    queued = await api.post("/api/v1/abuse/smtp/test", json=body)
    assert queued.status_code == 202 and queued.json()["status"] == "pending"
    again = await api.post("/api/v1/abuse/smtp/test", json=body)
    assert again.status_code == 409 and again.json()["code"] == "already_queued"
    last = (await api.get("/api/v1/abuse/smtp")).json()["last_test"]
    assert last["status"] == "pending" and last["error_code"] is None
    assert await count("SELECT count(*) FROM audit_log WHERE action = 'abuse.smtp.test'") == 1
    # Ingest answers; the dashboard shows the outcome.
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text(
                "UPDATE abuse_send_requests SET status = 'failed', error_code = 'auth_failed', "
                "done_at = now()"
            )
        )
    last = (await api.get("/api/v1/abuse/smtp")).json()["last_test"]
    assert last["status"] == "failed" and last["error_code"] == "auth_failed" and last["done_at"]


# ---- send and cancel ------------------------------------------------------------------------


async def test_send_needs_a_profile_and_a_mode(api: httpx.AsyncClient) -> None:
    url = f"/api/v1/abuse/reports/{SENT_ID}/send"
    assert (await api.post(url)).json()["code"] == "smtp_not_configured"
    await put_profile(api, mode="off")
    off = await api.post(url)
    assert off.status_code == 409 and off.json()["code"] == "smtp_off"
    assert await count("SELECT count(*) FROM abuse_send_requests") == 0


async def test_send_queues_one_request_and_audits_without_the_body(api: httpx.AsyncClient) -> None:
    await put_profile(api)
    url = f"/api/v1/abuse/reports/{SENT_ID}/send"
    r = await api.post(url)
    assert r.status_code == 202 and r.json()["status"] == "pending" and r.json()["id"] > 0
    again = await api.post(url)
    assert again.status_code == 409 and again.json()["code"] == "already_queued"
    row = await count("SELECT requested_by FROM abuse_send_requests")
    assert row == "admin"
    async with owner_engine() as owner, owner.connect() as conn:
        audit = (
            await conn.execute(
                text("SELECT target, details FROM audit_log WHERE action = 'abuse.send'")
            )
        ).one()
    assert audit.target == str(SENT_ID) and audit.details["mode"] == "click"
    assert "Own intro" not in json.dumps(audit.details)


async def test_send_refuses_what_cannot_be_sent(api: httpx.AsyncClient) -> None:
    await put_profile(api)
    demo = await api.post(f"/api/v1/abuse/reports/{DEMO_ID}/send")
    assert demo.status_code == 409 and demo.json()["code"] == "demo_report"
    leaky = await api.post(f"/api/v1/abuse/reports/{LEAKY}/send")
    assert leaky.status_code == 409 and leaky.json()["code"] == "identity_guard_failed"
    assert leaky.json()["reasons"] and SELF not in leaky.text
    missing = await api.post(f"/api/v1/abuse/reports/{uuid.uuid4()}/send")
    assert missing.status_code == 404
    stale = await api.post(f"/api/v1/abuse/reports/{SENT_ID}/send", json={"revision": 99})
    assert stale.status_code == 409 and stale.json()["code"] == "revision_mismatch"
    assert await count("SELECT count(*) FROM abuse_send_requests") == 0
    # A report that is no longer open is not ready.
    s = await api.post(
        f"/api/v1/abuse/reports/{READY}/status", json={"to": "discarded", "revision": 1}
    )
    assert s.status_code == 200, s.text
    gone = await api.post(f"/api/v1/abuse/reports/{READY}/send")
    assert gone.status_code == 409 and gone.json()["code"] == "report_not_ready"


async def test_send_without_the_owners_wording_is_refused(
    key: None, documentation_ok: None, client: httpx.AsyncClient
) -> None:
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(text("DELETE FROM report_smtp"))
    c = client
    assert (await put_profile(c)).status_code == 200
    r = await c.post(f"/api/v1/abuse/reports/{SENT_ID}/send")
    assert r.status_code == 409 and r.json()["code"] == "settings_incomplete"


async def test_cancel(api: httpx.AsyncClient) -> None:
    await put_profile(api)
    send, cancel = (f"/api/v1/abuse/reports/{SENT_ID}/{p}" for p in ("send", "send/cancel"))
    nothing = await api.post(cancel)
    assert nothing.status_code == 409 and nothing.json()["code"] == "nothing_to_cancel"
    assert (await api.post(send)).status_code == 202
    done = await api.post(cancel)
    assert done.status_code == 200 and done.json() == {"cancelled": 1}
    async with owner_engine() as owner, owner.connect() as conn:
        row = (await conn.execute(text("SELECT status, done_at FROM abuse_send_requests"))).one()
    assert row.status == "cancelled" and row.done_at is not None
    assert await count("SELECT count(*) FROM audit_log WHERE action = 'abuse.send.cancel'") == 1
    assert (await api.post(cancel)).status_code == 409
    assert (await api.post(send)).status_code == 202  # a new request is possible
    assert (await api.post(f"/api/v1/abuse/reports/{uuid.uuid4()}/send/cancel")).status_code == 404


async def test_a_request_being_sent_cannot_be_cancelled(api: httpx.AsyncClient) -> None:
    """Ingest keeps the request row locked while it sends: the cancel says so, it does not hang."""
    await put_profile(api)
    assert (await api.post(f"/api/v1/abuse/reports/{SENT_ID}/send")).status_code == 202
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(text("SELECT id FROM abuse_send_requests FOR UPDATE"))
        r = await api.post(f"/api/v1/abuse/reports/{SENT_ID}/send/cancel")
    assert r.status_code == 409 and r.json()["code"] == "already_sending"
    assert await count("SELECT status FROM abuse_send_requests") == "pending"


async def test_marking_sent_by_hand_withdraws_a_waiting_request(api: httpx.AsyncClient) -> None:
    await put_profile(api)
    assert (await api.post(f"/api/v1/abuse/reports/{SENT_ID}/send")).status_code == 202
    rev = (await api.get(f"/api/v1/abuse/reports/{SENT_ID}")).json()["revision"]
    r = await api.post(
        f"/api/v1/abuse/reports/{SENT_ID}/status", json={"to": "sent", "revision": rev}
    )
    assert r.status_code == 200, r.text
    assert await count("SELECT status FROM abuse_send_requests") == "cancelled"
    assert await count("SELECT sent_via FROM abuse_reports WHERE status = 'sent'") == "manual"


# ---- the queue ------------------------------------------------------------------------------


async def test_the_queue_lists_ready_reports_with_their_guarded_text(
    api: httpx.AsyncClient,
) -> None:
    await put_profile(api)
    page = (await api.get("/api/v1/abuse/send-queue")).json()
    ids = [i["id"] for i in page["items"]]
    assert ids == [str(SENT_ID), str(READY)]  # oldest first; not the demo, not the leaky one
    first = page["items"][0]
    assert set(first) == {"id", "recipient", "subject", "body_text", "scheduled_at", "last_request"}
    assert first["recipient"] == "abuse@example.net" and "Own intro." in first["body_text"]
    assert first["scheduled_at"] is None and first["last_request"] is None
    assert SELF not in json.dumps(page) and page["mode"] == "click" and page["next_cursor"] is None


async def test_the_queue_is_paginated_and_shows_the_last_request(api: httpx.AsyncClient) -> None:
    await put_profile(api)
    one = (await api.get("/api/v1/abuse/send-queue", params={"limit": 1})).json()
    assert len(one["items"]) == 1 and one["next_cursor"]
    rest = (
        await api.get("/api/v1/abuse/send-queue", params={"limit": 1, "cursor": one["next_cursor"]})
    ).json()
    assert [i["id"] for i in rest["items"]] == [str(READY)]
    # The next candidate fails the live guard: its page is empty, the list ends there.
    last = (
        await api.get(
            "/api/v1/abuse/send-queue", params={"limit": 1, "cursor": rest["next_cursor"]}
        )
    ).json()
    assert last["items"] == [] and last["next_cursor"] is None
    assert (await api.get("/api/v1/abuse/send-queue", params={"cursor": "zz"})).status_code == 400
    assert (await api.get("/api/v1/abuse/send-queue", params={"limit": 500})).status_code == 422
    assert (await api.post(f"/api/v1/abuse/reports/{SENT_ID}/send")).status_code == 202
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text(
                "UPDATE abuse_send_requests SET status = 'failed', error_code = 'refused', "
                "done_at = now()"
            )
        )
    item = (await api.get("/api/v1/abuse/send-queue")).json()["items"][0]
    assert item["last_request"]["status"] == "failed"
    assert item["last_request"]["error_code"] == "refused" and item["last_request"]["done_at"]
    # A failed request leaves the report in the queue, and the report page carries the state.
    detail = (await api.get(f"/api/v1/abuse/reports/{SENT_ID}")).json()["send_state"]
    assert detail["scheduled_at"] is None and detail["last_request"]["status"] == "failed"
    fresh = (await api.get(f"/api/v1/abuse/reports/{READY}")).json()["send_state"]
    assert fresh == {"scheduled_at": None, "last_request": None}


async def test_the_queue_shows_the_scheduled_time_of_an_automatic_send(
    api: httpx.AsyncClient,
) -> None:
    await put_profile(api, mode="auto")
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO abuse_send_requests (report_id, kind, auto, requested_by, "
                "scheduled_at) SELECT id, 'send', true, 'auto', now() + interval '1 hour' "
                "FROM abuse_reports WHERE public_id = :p"
            ),
            {"p": SENT_ID},
        )
    item = (await api.get("/api/v1/abuse/send-queue")).json()["items"][0]
    assert item["scheduled_at"] and item["last_request"]["status"] == "pending"
    cancelled = await api.post(f"/api/v1/abuse/reports/{SENT_ID}/send/cancel")
    assert cancelled.status_code == 200
    item = (await api.get("/api/v1/abuse/send-queue")).json()["items"][0]
    assert item["scheduled_at"] is None and item["last_request"]["status"] == "cancelled"


async def test_the_queue_needs_the_wording_first(
    key: None, documentation_ok: None, client: httpx.AsyncClient
) -> None:
    page = (await client.get("/api/v1/abuse/send-queue")).json()
    assert page["items"] == [] and page["missing"]
