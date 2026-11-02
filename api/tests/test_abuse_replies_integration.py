"""Replies, outcomes and the replies mailbox (M26) against a real TimescaleDB.

The API never reads mail: these tests check what it stores, queues and shows. Ingest's side is in
``ingest/tests/replies``.
"""

# ruff: noqa: F811, E501  (the imported `client` fixture is requested by name; long SQL literals)
import base64
import json
import os
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from analytics_seed import owner_engine
from sqlalchemy import text
from test_abuse_integration import (
    DEMO_ID,
    PASSWORD,
    SENT_ID,
    WORDING,
    client,  # noqa: F401  (the seeded, signed-in client of the M22 tests)
    settings_body,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

IMAP_PASSWORD = "Imap-secret-token-4711"  # gitleaks:allow (a test value)
PROFILE: dict[str, Any] = {
    "enabled": True,
    "host": "imap.example.org",
    "port": 993,
    "security": "ssl",
    "username": "reports@example.org",
    "password": IMAP_PASSWORD,
    "folder": "INBOX",
    "processed_action": "mark_read",
    "move_folder": None,
    "poll_minutes": 15,
    "current_password": PASSWORD,
}
TOKEN = "3f9a1c7b2e4d"  # gitleaks:allow (a sample token)


@pytest.fixture
def key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SETTINGS_ENCRYPTION_KEY", base64.b64encode(bytes(range(32, 72))).decode())
    monkeypatch.setenv("ABUSE_REPLIES_ENABLED", "true")


@pytest.fixture
async def api(key: None, client: httpx.AsyncClient) -> httpx.AsyncClient:
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text(
                "TRUNCATE report_imap, report_imap_state, report_imap_requests, abuse_replies, "
                "abuse_reply_imports, abuse_report_outcomes RESTART IDENTITY CASCADE"
            )
        )
    return client


async def sql(statement: str, **params: Any) -> Any:
    async with owner_engine() as owner, owner.begin() as conn:
        result = await conn.execute(text(statement), params)
        return result.fetchall() if result.returns_rows else result.rowcount


async def send_report() -> int:
    """Mark the seeded report as sent three days ago (by hand), and return its id."""
    await sql(
        "UPDATE abuse_reports SET status = 'sent', sent_at = now() - interval '3 days', "
        "sent_via = 'manual', sent_by = 'x' WHERE public_id = :p",
        p=SENT_ID,
    )
    rows = await sql("SELECT id FROM abuse_reports WHERE public_id = :p", p=SENT_ID)
    return int(rows[0][0])


async def add_reply(report_id: int | None, **over: Any) -> int:
    values: dict[str, Any] = {
        "r": report_id,
        "received": datetime.now(UTC) - timedelta(hours=1),
        "domain": "example.net",
        "address": "desk@example.net",
        "cls": "human_reply",
        "verified": True,
        "method": "token" if report_id else "none",
        "excerpt": "We looked into it. Thanks.",
    } | over
    rows = await sql(
        "INSERT INTO abuse_replies (source, received_at, from_address, from_domain, subject, "
        "report_id, match_method, verified, classification, size_bytes, excerpt) "
        "VALUES ('imap', :received, :address, :domain, 'Re: report', :r, :method, :verified, "
        ":cls, 120, :excerpt) RETURNING id",
        **values,
    )
    return int(rows[0][0])


# ---- the profile -----------------------------------------------------------------------------


async def test_an_unconfigured_profile(api: httpx.AsyncClient) -> None:
    got = (await api.get("/api/v1/abuse/imap")).json()
    assert got["configured"] is False and got["password_set"] is False and got["enabled"] is False
    assert got["host"] == "" and got["port"] == 993 and got["security"] == "ssl"
    assert got["folder"] == "INBOX" and got["worker_enabled"] is True
    assert got["state"]["last_error"] is None and got["last_test"] is None


async def test_the_password_is_write_only(api: httpx.AsyncClient) -> None:
    saved = await api.put("/api/v1/abuse/imap", json=PROFILE)
    assert saved.status_code == 200, saved.text
    for body in (saved.text, (await api.get("/api/v1/abuse/imap")).text):
        assert IMAP_PASSWORD not in body and "password_ciphertext" not in body
    got = saved.json()
    assert got["configured"] and got["password_set"] and got["enabled"]
    assert got["since"] == datetime.now(UTC).date().isoformat()
    # The ciphertext is in the table; the plain text is nowhere.
    cipher = (await sql("SELECT password_ciphertext FROM report_imap"))[0][0]
    assert cipher and IMAP_PASSWORD.encode() not in bytes(cipher)
    audit = await sql("SELECT details::text FROM audit_log WHERE action = 'abuse.imap.update'")
    assert audit and IMAP_PASSWORD not in audit[0][0]
    assert "password" in json.loads(audit[0][0])["changed"]
    # Omitting the password keeps the stored one.
    again = await api.put(
        "/api/v1/abuse/imap",
        json={k: v for k, v in PROFILE.items() if k != "password"} | {"poll_minutes": 30},
    )
    assert again.status_code == 200 and again.json()["poll_minutes"] == 30


async def test_the_trusted_authserv_id_is_saved_and_validated(api: httpx.AsyncClient) -> None:
    saved = await api.put(
        "/api/v1/abuse/imap", json=PROFILE | {"trusted_authserv_id": " MX.Example.ORG "}
    )
    assert saved.status_code == 200, saved.text
    assert saved.json()["trusted_authserv_id"] == "mx.example.org"
    assert (await sql("SELECT trusted_authserv_id FROM report_imap"))[0][0] == "mx.example.org"
    for bad in ("bad id", "a;b", "x" * 300, "in\nvalid"):
        r = await api.put("/api/v1/abuse/imap", json=PROFILE | {"trusted_authserv_id": bad})
        assert r.status_code == 422, (bad, r.text)
    cleared = await api.put("/api/v1/abuse/imap", json=PROFILE | {"trusted_authserv_id": ""})
    assert cleared.json()["trusted_authserv_id"] is None


async def test_a_free_mail_mailbox_is_flagged_for_the_ui(api: httpx.AsyncClient) -> None:
    ok = await api.put("/api/v1/abuse/imap", json=PROFILE)
    assert ok.json()["shared_mailbox"] is False
    free = await api.put(
        "/api/v1/abuse/imap", json=PROFILE | {"host": "imap.gmail.com", "username": "me@gmail.com"}
    )
    assert free.status_code == 200, free.text
    assert free.json()["shared_mailbox"] is True


async def test_pointing_the_profile_elsewhere_needs_the_password_again(
    api: httpx.AsyncClient,
) -> None:
    assert (await api.put("/api/v1/abuse/imap", json=PROFILE)).status_code == 200
    no_pw = {k: v for k, v in PROFILE.items() if k != "password"}
    for over in (
        {"host": "imap2.example.org"},
        {"port": 143, "security": "starttls"},
        {"security": "starttls"},
        {"username": "other@example.org"},
    ):
        r = await api.put("/api/v1/abuse/imap", json=no_pw | over)
        assert r.status_code == 422 and r.json()["code"] == "password_required", (over, r.text)
    # The stored password is untouched by the refused attempts and still kept for harmless edits.
    kept = await api.put("/api/v1/abuse/imap", json=no_pw | {"poll_minutes": 60, "folder": "Abuse"})
    assert kept.status_code == 200 and kept.json()["password_set"]
    moved = await api.put(
        "/api/v1/abuse/imap",
        json=PROFILE | {"host": "imap2.example.org", "password": "another-one"},
    )
    assert moved.status_code == 200 and moved.json()["host"] == "imap2.example.org"


@pytest.mark.parametrize(
    ("over", "code"),
    [
        ({"host": "192.0.2.10"}, "invalid_host"),
        ({"host": "mail"}, "invalid_host"),
        ({"host": "imap.local"}, "invalid_host"),
        ({"folder": 'IN"BOX'}, "invalid_folder"),
        ({"folder": "a*"}, "invalid_folder"),
        ({"processed_action": "move"}, "invalid_move_folder"),
        ({"processed_action": "move", "move_folder": "INBOX"}, "same_folder"),
        ({"processed_action": "move", "move_folder": "a%"}, "invalid_move_folder"),
        ({"username": "us\ner"}, "invalid_credentials"),
    ],
)
async def test_invalid_profiles(api: httpx.AsyncClient, over: dict[str, Any], code: str) -> None:
    r = await api.put("/api/v1/abuse/imap", json=PROFILE | over)
    assert r.status_code == 422 and r.json()["code"] == code, r.text


async def test_a_new_profile_needs_a_password_and_the_account_password(
    api: httpx.AsyncClient,
) -> None:
    no_pw = {k: v for k, v in PROFILE.items() if k != "password"}
    assert (await api.put("/api/v1/abuse/imap", json=no_pw)).json()["code"] == "password_required"
    wrong = await api.put("/api/v1/abuse/imap", json=PROFILE | {"current_password": "nope"})
    assert wrong.status_code in (401, 403)
    assert await sql("SELECT count(*) FROM report_imap") == [(0,)]


async def test_delete_asks_for_the_password_and_keeps_replies(api: httpx.AsyncClient) -> None:
    await api.put("/api/v1/abuse/imap", json=PROFILE)
    rid = await send_report()
    await add_reply(rid)
    assert (
        await api.request("DELETE", "/api/v1/abuse/imap", json={"current_password": "no"})
    ).status_code in (401, 403)
    gone = await api.request("DELETE", "/api/v1/abuse/imap", json={"current_password": PASSWORD})
    assert gone.status_code == 204
    assert (await api.get("/api/v1/abuse/imap")).json()["configured"] is False
    assert await sql("SELECT count(*) FROM abuse_replies") == [(1,)]


# ---- test and check-now requests -------------------------------------------------------------


async def test_test_and_poll_requests(api: httpx.AsyncClient) -> None:
    assert (await api.post("/api/v1/abuse/imap/test")).json()["code"] == "imap_not_configured"
    await api.put("/api/v1/abuse/imap", json=PROFILE)
    first = await api.post("/api/v1/abuse/imap/test")
    assert first.status_code == 202 and first.json()["status"] == "pending"
    assert (await api.post("/api/v1/abuse/imap/test")).json()["code"] == "already_queued"
    state = (await api.get(f"/api/v1/abuse/imap/requests/{first.json()['id']}")).json()
    assert state["status"] == "pending" and state["kind"] == "test" and state["done_at"] is None
    await sql(
        'UPDATE report_imap_requests SET status = \'done\', done_at = now(), result = \'{"ok": true, "folders": ["INBOX"]}\''
    )
    state = (await api.get(f"/api/v1/abuse/imap/requests/{first.json()['id']}")).json()
    assert state["status"] == "done" and state["result"]["folders"] == ["INBOX"]
    assert (await api.get("/api/v1/abuse/imap")).json()["last_test"]["status"] == "done"
    poll = await api.post("/api/v1/abuse/imap/poll")
    assert poll.status_code == 202
    await sql(
        "UPDATE report_imap_requests SET status = 'done', done_at = now() WHERE kind = 'poll'"
    )
    assert (await api.post("/api/v1/abuse/imap/poll")).status_code == 429  # one a minute
    assert (await api.get("/api/v1/abuse/imap/requests/999999")).status_code == 404


async def test_six_tests_an_hour(api: httpx.AsyncClient) -> None:
    await api.put("/api/v1/abuse/imap", json=PROFILE)
    for _ in range(6):
        assert (await api.post("/api/v1/abuse/imap/test")).status_code == 202
        await sql(
            "UPDATE report_imap_requests SET status = 'done', done_at = now() WHERE status = 'pending'"
        )
    assert (await api.post("/api/v1/abuse/imap/test")).status_code == 429


async def test_requests_are_refused_while_the_server_switch_is_off(
    api: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    await api.put("/api/v1/abuse/imap", json=PROFILE)
    monkeypatch.setenv("ABUSE_REPLIES_ENABLED", "false")
    assert (await api.post("/api/v1/abuse/imap/test")).json()["code"] == "replies_disabled"
    assert (await api.post("/api/v1/abuse/replies/import", json={"raw": "x"})).json()[
        "code"
    ] == "replies_disabled"


# ---- replies ---------------------------------------------------------------------------------


async def test_the_replies_list(api: httpx.AsyncClient) -> None:
    rid = await send_report()
    first = await add_reply(rid)
    second = await add_reply(None, cls="unknown", verified=False)
    page = (await api.get("/api/v1/abuse/replies", params={"limit": 1})).json()
    assert len(page["items"]) == 1 and page["next_cursor"]
    nxt = (
        await api.get("/api/v1/abuse/replies", params={"limit": 5, "cursor": page["next_cursor"]})
    ).json()
    assert {page["items"][0]["id"], *(i["id"] for i in nxt["items"])} == {first, second}
    full = (await api.get("/api/v1/abuse/replies")).json()["items"]
    mine = next(i for i in full if i["id"] == first)
    assert mine["report"] == str(SENT_ID) and mine["from_address"] == "desk@example.net"
    assert mine["excerpt"].startswith("We looked") and mine["needs_review"] is False
    assert mine["attachments"] == {"count": 0, "types": [], "bytes": 0}
    other = next(i for i in full if i["id"] == second)
    assert other["report"] is None and other["needs_review"] is True
    for params, expected in (
        ({"matched": "true"}, {first}),
        ({"matched": "false"}, {second}),
        ({"needs_review": "true"}, {second}),
        ({"classification": "unknown"}, {second}),
        ({"report": str(SENT_ID)}, {first}),
        ({"since": (datetime.now(UTC) + timedelta(days=1)).isoformat()}, set()),
    ):
        got = (await api.get("/api/v1/abuse/replies", params=params)).json()["items"]
        assert {i["id"] for i in got} == expected, params
    assert (await api.get("/api/v1/abuse/replies", params={"cursor": "garbage"})).status_code == 400
    assert (await api.get("/api/v1/abuse/replies", params={"limit": 101})).status_code == 422
    one = await api.get(f"/api/v1/abuse/replies/{first}")
    assert one.status_code == 200 and one.json()["id"] == first
    assert (await api.get("/api/v1/abuse/replies/999999")).status_code == 404


async def test_patch_links_confirms_and_trusts(api: httpx.AsyncClient) -> None:
    rid = await send_report()
    stray = await add_reply(None, cls="unknown", verified=False, domain="tickets.example.org")
    assert (await api.patch(f"/api/v1/abuse/replies/{stray}", json={})).json()["code"] == "empty"
    assert (await api.patch(f"/api/v1/abuse/replies/{stray}", json={"trust_domain": True})).json()[
        "code"
    ] == "no_report"
    assert (
        await api.patch(f"/api/v1/abuse/replies/{stray}", json={"report": str(DEMO_ID)})
    ).status_code == 409
    r = await api.patch(
        f"/api/v1/abuse/replies/{stray}",
        json={
            "report": str(SENT_ID),
            "classification": "resolved",
            "ticket_id": "TK-4411",
            "trust_domain": True,
        },
    )
    assert r.status_code == 200, r.text
    got = r.json()
    assert got["report"] == str(SENT_ID) and got["match_method"] == "manual" and got["verified"]
    assert got["classification"] == "resolved" and got["classification_source"] == "manual"
    assert (
        got["ticket_id"] == "TK-4411"
        and got["reviewed_by"] == "admin"
        and got["needs_review"] is False
    )
    domains = await sql("SELECT reply_domains FROM abuse_recipients WHERE id = 1")
    assert domains[0][0] == ["tickets.example.org"]
    audit = await sql("SELECT details::text FROM audit_log WHERE action = 'abuse.reply.update'")
    assert audit and "example" not in audit[0][0]  # field names only
    # Unlinking.
    back = await api.patch(f"/api/v1/abuse/replies/{stray}", json={"report": None})
    assert back.json()["report"] is None and back.json()["verified"] is False
    assert rid


async def test_at_most_five_reply_domains(api: httpx.AsyncClient) -> None:
    await send_report()
    await sql(
        "UPDATE abuse_recipients SET reply_domains = ARRAY['a.example.org','b.example.org','c.example.org','d.example.org','e.example.org'] WHERE id = 1"
    )
    reply = await add_reply(None, domain="f.example.org")
    r = await api.patch(
        f"/api/v1/abuse/replies/{reply}", json={"report": str(SENT_ID), "trust_domain": True}
    )
    assert r.status_code == 409 and r.json()["code"] == "too_many"
    assert (await api.get(f"/api/v1/abuse/replies/{reply}")).json()["report"] is None  # rolled back


# ---- pasted replies --------------------------------------------------------------------------

EML = b"From: Desk <desk@example.net>\r\nSubject: Re: report\r\n\r\nWe suspended the account.\r\n"


async def test_pasting_a_reply(api: httpx.AsyncClient) -> None:
    await send_report()
    r = await api.post(
        "/api/v1/abuse/replies/import", json={"raw": EML.decode(), "report": str(SENT_ID)}
    )
    assert r.status_code == 202 and r.json()["status"] == "pending"
    row = (await sql("SELECT raw, report_id, requested_by FROM abuse_reply_imports"))[0]
    assert bytes(row[0]) == EML and row[1] is not None and row[2] == "admin"
    state = (await api.get(f"/api/v1/abuse/replies/imports/{r.json()['id']}")).json()
    assert state["status"] == "pending" and "raw" not in state
    audit = await sql("SELECT details::text FROM audit_log WHERE action = 'abuse.reply.import'")
    assert audit and "suspended" not in audit[0][0]


async def test_uploading_an_eml_file(api: httpx.AsyncClient) -> None:
    files = {"file": ("reply.eml", EML, "message/rfc822")}
    r = await api.post("/api/v1/abuse/replies/import", files=files, data={"report": str(SENT_ID)})
    assert r.status_code == 409  # not sent yet
    await send_report()
    r = await api.post("/api/v1/abuse/replies/import", files=files)
    assert r.status_code == 202, r.text
    assert bytes((await sql("SELECT raw FROM abuse_reply_imports"))[0][0]) == EML


async def test_bad_and_oversize_imports(api: httpx.AsyncClient) -> None:
    assert (await api.post("/api/v1/abuse/replies/import", json={"nope": 1})).json()[
        "code"
    ] == "bad_body"
    assert (await api.post("/api/v1/abuse/replies/import", json={"raw": "  "})).status_code in (
        422,
    )
    big = await api.post(
        "/api/v1/abuse/replies/import",
        content=b"x" * 400_000,
        headers={"Content-Type": "application/json"},
    )
    assert big.status_code == 413
    bad = await api.post("/api/v1/abuse/replies/import", json={"raw": "x", "report": "not-a-uuid"})
    assert bad.status_code == 422
    assert await sql("SELECT count(*) FROM abuse_reply_imports") == [(0,)]


async def test_twenty_imports_an_hour(api: httpx.AsyncClient) -> None:
    for _ in range(20):
        assert (
            await api.post("/api/v1/abuse/replies/import", json={"raw": "Subject: x\n\nhello"})
        ).status_code == 202
    assert (
        await api.post("/api/v1/abuse/replies/import", json={"raw": "Subject: x\n\nhello"})
    ).status_code == 429


# ---- outcomes --------------------------------------------------------------------------------


async def test_the_owner_sets_and_clears_an_outcome(api: httpx.AsyncClient) -> None:
    url = f"/api/v1/abuse/reports/{SENT_ID}/outcome"
    assert (await api.put(url, json={"outcome": "resolved"})).json()[
        "code"
    ] == "not_sent"  # still reviewed
    assert (
        await api.put(f"/api/v1/abuse/reports/{DEMO_ID}/outcome", json={"outcome": "resolved"})
    ).status_code == 409
    await send_report()
    assert (
        await api.put(
            url,
            json={
                "outcome": "resolved",
                "at": (datetime.now(UTC) - timedelta(days=30)).isoformat(),
            },
        )
    ).json()["code"] == "before_sent"
    assert (
        await api.put(
            url,
            json={"outcome": "resolved", "at": (datetime.now(UTC) + timedelta(days=2)).isoformat()},
        )
    ).json()["code"] == "in_future"
    assert (await api.put(url, json={"outcome": "bogus"})).status_code == 422
    r = await api.put(url, json={"outcome": "ticket_opened", "note": "They phoned me."})
    assert r.status_code == 200, r.text
    out = r.json()
    assert (
        out["effective"] == "ticket_opened"
        and out["manual"] == "ticket_opened"
        and out["auto"] == "none"
    )
    assert out["manual_by"] == "admin" and out["note"] == "They phoned me."
    detail = (await api.get(f"/api/v1/abuse/reports/{SENT_ID}")).json()
    assert detail["outcome"]["effective"] == "ticket_opened"
    listing = (await api.get("/api/v1/abuse/reports", params={"status": "sent"})).json()["items"]
    assert listing and listing[0]["outcome"]["effective"] == "ticket_opened"
    cleared = await api.delete(url)
    assert (
        cleared.status_code == 200
        and cleared.json()["effective"] == "none"
        and cleared.json()["manual"] is None
    )
    audit = await sql(
        "SELECT action FROM audit_log WHERE action LIKE 'abuse.outcome.%' ORDER BY id"
    )
    assert [a[0] for a in audit] == ["abuse.outcome.set", "abuse.outcome.clear"]


async def test_no_answer_after_the_waiting_period(api: httpx.AsyncClient) -> None:
    await send_report()
    detail = (await api.get(f"/api/v1/abuse/reports/{SENT_ID}")).json()
    assert detail["outcome"]["effective"] == "none" and detail["outcome"]["no_answer"] is False
    await sql(
        "UPDATE abuse_reports SET sent_at = now() - interval '20 days' WHERE public_id = :p",
        p=SENT_ID,
    )
    detail = (await api.get(f"/api/v1/abuse/reports/{SENT_ID}")).json()
    assert detail["outcome"]["no_answer"] is True


async def test_automatic_columns_show_through(api: httpx.AsyncClient) -> None:
    rid = await send_report()
    await sql(
        "INSERT INTO abuse_report_outcomes (report_id, auto_outcome, reply_count, first_reply_at, resolved_at, ticket_id, needs_review) "
        "VALUES (:r, 'resolved', 2, now() - interval '2 days 22 hours', now() - interval '1 day', 'TK-9', true)",
        r=rid,
    )
    out = (await api.get(f"/api/v1/abuse/reports/{SENT_ID}")).json()["outcome"]
    assert out["effective"] == "resolved" and out["auto"] == "resolved" and out["manual"] is None
    assert out["reply_count"] == 2 and out["ticket_id"] == "TK-9" and out["needs_review"] is True
    assert 0 < out["first_reply_after_s"] < 3 * 86400


async def test_the_report_detail_carries_replies_and_the_token(api: httpx.AsyncClient) -> None:
    rid = await send_report()
    await add_reply(rid)
    detail = (await api.get(f"/api/v1/abuse/reports/{SENT_ID}")).json()
    assert len(detail["replies"]) == 1 and detail["replies"][0]["report"] == str(SENT_ID)
    token = detail["reply_token"]
    assert len(token) == 12 and set(token) <= set("0123456789abcdef")
    assert detail["reply_token"] != str(SENT_ID).replace("-", "")[:12]


async def test_the_subject_of_a_render_carries_the_token(api: httpx.AsyncClient) -> None:
    r = await api.put("/api/v1/abuse/settings", json=settings_body(0, **WORDING))
    assert r.status_code == 200 and r.json()["reference_style"] == "subject"
    detail = (await api.get(f"/api/v1/abuse/reports/{DEMO_ID}")).json()
    rendered = (
        await api.get(f"/api/v1/abuse/reports/{DEMO_ID}/render", params={"format": "text"})
    ).json()
    assert detail["reply_token"] and f"(ref {detail['reply_token']})" in rendered["subject"]
    assert detail["reply_token"] not in rendered["body"]
    csv = next(a for a in rendered["attachments"] if a["name"] == "evidence.csv")
    assert detail["reply_token"] not in csv["content"]
    # The style can be changed; "off" prints nothing; the template may place it.
    revision = r.json()["revision"]
    r = await api.put(
        "/api/v1/abuse/settings", json=settings_body(revision, **WORDING, reference_style="off")
    )
    assert r.json()["reference_style"] == "off"
    off = (
        await api.get(f"/api/v1/abuse/reports/{DEMO_ID}/render", params={"format": "text"})
    ).json()
    assert detail["reply_token"] not in off["subject"]
    revision = r.json()["revision"]
    placed = await api.put(
        "/api/v1/abuse/settings",
        json=settings_body(
            revision,
            **(WORDING | {"subject_template": "Abuse from {value} [{ref}]"}),
            reference_style="subject_and_body",
        ),
    )
    assert placed.status_code == 200, placed.text
    both = (
        await api.get(f"/api/v1/abuse/reports/{DEMO_ID}/render", params={"format": "text"})
    ).json()
    assert f"[ref {detail['reply_token']}]" in both["subject"]
    assert both["body"].rstrip().endswith(f"Ref: {detail['reply_token']}")


# ---- the status card, the summary and the timeline -------------------------------------------


async def test_status_counts_and_setup_item(api: httpx.AsyncClient) -> None:
    rid = await send_report()
    await add_reply(None, cls="unknown", verified=False)
    await add_reply(rid, verified=False)
    status = (await api.get("/api/v1/abuse/status")).json()["replies"]
    assert status == {
        "enabled": False,
        "configured": False,
        "last_poll_at": None,
        "last_error": None,
        "unmatched": 1,
        "needs_review": 1,
    }
    await api.put("/api/v1/abuse/imap", json=PROFILE)
    assert (await api.get("/api/v1/abuse/status")).json()["replies"]["enabled"] is True
    items = {i["id"]: i for i in (await api.get("/api/v1/setup/status")).json()["items"]}
    assert items["replies"]["state"] in ("ok", "off", "warning")


async def seed_outcomes() -> None:
    """Three sent reports with known outcomes, each to its own provider."""
    # Reports of one recipient are limited to one open report per kind, so use fresh recipients.
    for n, (kind, eff, days, first_h) in enumerate(
        (
            ("attack_source", "resolved", 10, 3.0),
            ("c2", "none", 20, None),
            ("payload_host", "rejected", 8, 30.0),
        ),
        start=10,
    ):
        await sql(
            "INSERT INTO abuse_recipients (mailbox, name, source) VALUES (:m, :n, 'rdap')",
            m=f"abuse{n}@example.net",
            n=f"Provider {n}",
        )
        created = await sql(
            "INSERT INTO abuse_reports (public_id, id_seed, recipient_id, kind, status, demo, window_start, window_end, subject_count, evidence, content_sha256, guard_ok) "
            "VALUES (gen_random_uuid(), gen_random_uuid(), (SELECT max(id) FROM abuse_recipients), :k, 'reviewed', false, now(), now(), 1, '{}', 'x', true) RETURNING id",
            k=kind,
        )
        rid = int(created[0][0])
        await sql(
            "UPDATE abuse_reports SET status = 'sent', sent_at = now() - make_interval(days => :d), sent_by = 'x', sent_via = 'manual' WHERE id = :r",
            d=days,
            r=rid,
        )
        await sql(
            "INSERT INTO abuse_report_outcomes (report_id, auto_outcome, first_reply_at, resolved_at) "
            "VALUES (:r, CAST(:e AS text), CASE WHEN CAST(:h AS double precision) IS NULL THEN NULL "
            "ELSE now() - make_interval(days => :d) + make_interval(secs => CAST(:h AS double precision) * 3600) END, "
            "CASE WHEN CAST(:e AS text) = 'resolved' THEN now() - make_interval(days => :d) + interval '5 hours' END)",
            r=rid,
            e=eff,
            h=first_h,
            d=days,
        )


async def test_the_summary(api: httpx.AsyncClient) -> None:
    await seed_outcomes()
    got = (await api.get("/api/v1/abuse/outcomes")).json()
    totals = got["totals"]
    assert totals["sent"] == 3 and totals["eligible"] == 3 and totals["answered"] == 2
    assert totals["no_answer"] == 1  # only the report sent 20 days ago is past the 14-day wait
    assert (
        totals["by_outcome"]["resolved"] == 1
        and totals["by_outcome"]["rejected"] == 1
        and totals["by_outcome"]["none"] == 1
    )
    assert (
        totals["first_reply_p50_s"] is not None
        and totals["first_reply_p90_s"] >= totals["first_reply_p50_s"]
    )
    assert totals["resolved_p50_s"] == 5 * 3600
    kinds = {g["key"]: g for g in got["groups"]}
    assert (
        set(kinds) == {"attack_source", "c2", "payload_host"}
        and kinds["attack_source"]["answered"] == 1
    )
    for group in ("asn", "country", "recipient"):
        other = (await api.get("/api/v1/abuse/outcomes", params={"group": group})).json()
        assert other["group"] == group and len(other["groups"]) <= 200
    by_recipient = (await api.get("/api/v1/abuse/outcomes", params={"group": "recipient"})).json()[
        "groups"
    ]
    assert {g["label"] for g in by_recipient} >= {"Provider 10", "Provider 11"}
    assert (await api.get("/api/v1/abuse/outcomes", params={"group": "bogus"})).status_code == 422
    too_long = {"since": (datetime.now(UTC) - timedelta(days=800)).isoformat()}
    assert (await api.get("/api/v1/abuse/outcomes", params=too_long)).json()["code"] == "bad_range"


async def test_demo_reports_are_never_counted(api: httpx.AsyncClient) -> None:
    got = (await api.get("/api/v1/abuse/outcomes")).json()["totals"]
    assert got["sent"] == 0 and got["answered"] == 0 and got["first_reply_p50_s"] is None


async def test_the_timeline(api: httpx.AsyncClient) -> None:
    await seed_outcomes()
    got = (await api.get("/api/v1/abuse/outcomes/timeline", params={"bucket": "week"})).json()
    assert got["bucket"] == "week" and len(got["points"]) >= 20
    assert sum(p["sent_total"] for p in got["points"]) == 3
    assert (
        sum(p["answered"] for p in got["points"]) == 2
        and sum(p["resolved"] for p in got["points"]) == 1
    )
    assert {"attack_source", "payload_host", "c2"} == set(got["points"][0]["sent"])
    month = (await api.get("/api/v1/abuse/outcomes/timeline", params={"bucket": "month"})).json()
    assert sum(p["sent_total"] for p in month["points"]) == 3
    assert all(p["start"].endswith("+00:00") or p["start"].endswith("Z") for p in month["points"])
    assert (
        await api.get("/api/v1/abuse/outcomes/timeline", params={"bucket": "day"})
    ).status_code == 422


async def test_trusting_a_free_mail_sender_stores_the_exact_address(
    api: httpx.AsyncClient,
) -> None:
    await send_report()
    reply = await add_reply(
        None, domain="gmail.com", address="Desk.Person@gmail.com", verified=False
    )
    r = await api.patch(
        f"/api/v1/abuse/replies/{reply}", json={"report": str(SENT_ID), "trust_domain": True}
    )
    assert r.status_code == 200, r.text
    assert (await sql("SELECT reply_domains FROM abuse_recipients WHERE id = 1"))[0][0] == [
        "desk.person@gmail.com"
    ]


async def test_the_recipient_list_flags_a_free_mail_contact(api: httpx.AsyncClient) -> None:
    await sql("UPDATE abuse_recipients SET mailbox = 'abuse-desk@gmail.com' WHERE id = 1")
    page = (await api.get("/api/v1/abuse/recipients")).json()
    row = next(i for i in page["items"] if i["id"] == 1)
    assert row["shared_mailbox"] is True
    await sql("UPDATE abuse_recipients SET mailbox = 'abuse@example.net' WHERE id = 1")
    page = (await api.get("/api/v1/abuse/recipients")).json()
    assert next(i for i in page["items"] if i["id"] == 1)["shared_mailbox"] is False
