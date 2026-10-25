"""Users, roles, sessions, lockout and the audit log against a real TimescaleDB.

The API runs as its least-privileged database role, like in production.
"""

import json
import os
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx
import pytest
from analytics_seed import api_engine, owner_engine
from argon2 import PasswordHasher
from fastapi import FastAPI
from sqlalchemy import text
from suckerpot_db import create_session_factory

import api.auth as auth_mod
from api.auth import AuthSettings
from api.main import create_app
from api.passwords import common_passwords

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

OWNER = "admin"
PASSWORD = "correct horse battery staple"
FAST = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
HASH = FAST.hash(PASSWORD)
ORIGIN = "https://testserver"
CSRF = "__Host-sp_csrf"
GOOD = "a long passphrase for tests 2026"
# Taken from the bundled list at run time, so no password-looking literal sits in the source.
COMMON = sorted(common_passwords())[0]
WaitFor = Callable[[], Awaitable[Any]]


@dataclass
class Stack:
    app: FastAPI

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url=ORIGIN, headers={"Origin": ORIGIN}
        )


@pytest.fixture
async def stack(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[Stack]:
    monkeypatch.setattr(auth_mod, "FAILURE_DELAY_S", 0.0)
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(text("TRUNCATE users, audit_log RESTART IDENTITY"))
    engine = api_engine()
    settings = AuthSettings(
        password_hash=HASH,
        secret=b"k" * 40,
        rate_per_ip=10_000,
        rate_global=10_000,
        rate_per_user=10_000,
    )
    app = create_app(create_session_factory(engine), enable_live=False, auth_settings=settings)
    app.state.auth._hasher = FAST  # same code path, cheap parameters
    async with app.router.lifespan_context(app):
        yield Stack(app)
    await engine.dispose()


def hdr(c: httpx.AsyncClient) -> dict[str, str]:
    return {"X-CSRF-Token": c.cookies[CSRF], "Origin": ORIGIN}


async def sign_in(c: httpx.AsyncClient, username: str, password: str) -> httpx.Response:
    return await c.post("/api/v1/auth/login", json={"username": username, "password": password})


async def signed_in(stack: Stack, username: str, password: str) -> httpx.AsyncClient:
    c = stack.client()
    r = await sign_in(c, username, password)
    assert r.status_code == 204, r.text
    return c


async def call(
    c: httpx.AsyncClient, method: str, path: str, body: dict[str, Any] | None = None
) -> httpx.Response:
    return await c.request(method, f"/api/v1{path}", json=body, headers=hdr(c))


async def make_user(
    admin: httpx.AsyncClient,
    username: str = "colleague",
    role: str = "viewer",
    password: str = PASSWORD,
) -> dict[str, Any]:
    r = await call(
        admin,
        "POST",
        "/users",
        {
            "username": username,
            "display_name": username.title(),
            "role": role,
            "password": password,
        },
    )
    assert r.status_code == 201, r.text
    return dict(r.json())


async def ready_user(
    stack: Stack, admin: httpx.AsyncClient, username: str = "colleague", role: str = "viewer"
) -> tuple[dict[str, Any], httpx.AsyncClient]:
    """A user who already chose their own password, signed in."""
    created = await make_user(admin, username, role)
    c = await signed_in(stack, username, created["temporary_password"])
    r = await call(
        c,
        "POST",
        "/auth/password",
        {"current_password": created["temporary_password"], "new_password": GOOD},
    )
    assert r.status_code == 204, r.text
    return created["user"], c


async def query(sql: str, **params: Any) -> list[Any]:
    async with owner_engine() as owner, owner.begin() as conn:
        return list((await conn.execute(text(sql), params)).all())


# ---- onboarding --------------------------------------------------------------------------------


async def test_a_new_user_gets_a_one_time_password_and_must_change_it(stack: Stack) -> None:
    admin = await signed_in(stack, OWNER, PASSWORD)
    r = await call(
        admin,
        "POST",
        "/users",
        {
            "username": "Colleague",
            "display_name": "A Colleague",
            "role": "viewer",
            "password": PASSWORD,
        },
    )
    assert r.status_code == 201
    assert r.headers["cache-control"] == "no-store"
    body = r.json()
    temp = body["temporary_password"]
    assert len(temp) >= 20 and body["user"]["must_change_password"] is True
    assert body["user"]["role"] == "viewer" and body["user"]["created_by"] == OWNER
    # Only a hash is stored.
    (row,) = await query("SELECT password_hash, must_change_password FROM users")
    assert row.password_hash.startswith("$argon2id$") and temp not in row.password_hash
    assert row.must_change_password is True
    # The password is not shown again anywhere.
    listing = await call(admin, "GET", "/users")
    assert temp not in listing.text and "temporary_password" not in listing.text
    assert (await call(admin, "GET", "/audit")).text.count(temp) == 0


async def test_first_login_allows_nothing_but_choosing_a_password(stack: Stack) -> None:
    admin = await signed_in(stack, OWNER, PASSWORD)
    created = await make_user(admin)
    temp = created["temporary_password"]
    c = await signed_in(stack, "colleague", temp)

    me = (await c.get("/api/v1/auth/me")).json()
    assert me["must_change_password"] is True and me["role"] == "viewer" and me["read_only"]
    blocked = await c.get("/api/v1/sessions")
    assert blocked.status_code == 403 and blocked.json()["code"] == "password_change_required"
    assert (await c.get("/api/v1/settings/system")).status_code == 403

    cases = [
        ("wrong current", {"current_password": "not it at all", "new_password": GOOD}, 403),
        ("too short", {"current_password": temp, "new_password": "tiny-pw"}, 422),
        ("common", {"current_password": temp, "new_password": COMMON}, 422),
        (
            "has the username",
            {"current_password": temp, "new_password": "colleague-and-more!"},
            422,
        ),
        ("same password", {"current_password": temp, "new_password": temp}, 422),
    ]
    for label, payload, status in cases:
        r = await call(c, "POST", "/auth/password", payload)
        assert r.status_code == status, label
        assert payload["new_password"] not in r.text
    r = await call(c, "POST", "/auth/password", {"current_password": temp, "new_password": GOOD})
    assert r.status_code == 204

    assert (await c.get("/api/v1/sessions")).status_code == 200  # the same browser stays in
    me = (await c.get("/api/v1/auth/me")).json()
    assert me["must_change_password"] is False
    assert (await sign_in(stack.client(), "colleague", temp)).status_code == 401
    assert (await sign_in(stack.client(), "colleague", GOOD)).status_code == 204


async def test_changing_your_password_ends_your_other_sessions(stack: Stack) -> None:
    admin = await signed_in(stack, OWNER, PASSWORD)
    _, here = await ready_user(stack, admin)
    other = await signed_in(stack, "colleague", GOOD)
    assert (await other.get("/api/v1/sessions")).status_code == 200
    new = "another long passphrase 2027"
    r = await call(here, "POST", "/auth/password", {"current_password": GOOD, "new_password": new})
    assert r.status_code == 204
    assert (await other.get("/api/v1/sessions")).status_code == 401
    assert (await here.get("/api/v1/sessions")).status_code == 200


async def test_the_owner_password_is_changed_in_env_only(stack: Stack) -> None:
    admin = await signed_in(stack, OWNER, PASSWORD)
    r = await call(
        admin, "POST", "/auth/password", {"current_password": PASSWORD, "new_password": GOOD}
    )
    assert r.status_code == 403 and r.json()["code"] == "owner_password_in_env"
    listing = (await call(admin, "GET", "/users")).json()
    assert listing["owner"]["is_owner"] is True and listing["owner"]["username"] == OWNER
    assert listing["items"] == []
    assert (await query("SELECT count(*) AS n FROM users"))[0].n == 0


async def test_username_rules(stack: Stack) -> None:
    admin = await signed_in(stack, OWNER, PASSWORD)
    await make_user(admin, "Colleague")
    base = {"display_name": "X", "role": "viewer", "password": PASSWORD}
    same = await call(admin, "POST", "/users", {**base, "username": "COLLEAGUE"})
    assert same.status_code == 409 and same.json()["code"] == "username_taken"
    owner = await call(admin, "POST", "/users", {**base, "username": "ADMIN"})
    assert owner.status_code == 409
    for bad in ("ab", "has space", "-leading", "x" * 33, "semi;colon"):
        r = await call(admin, "POST", "/users", {**base, "username": bad})
        assert r.status_code == 422, bad
    r = await call(admin, "POST", "/users", {**base, "username": "okay.name", "role": "root"})
    assert r.status_code == 422
    # A user may sign in with any letter case.
    created = await make_user(admin, "MixedCase")
    assert (
        await sign_in(stack.client(), "mixedcase", created["temporary_password"])
    ).status_code == 204


# ---- roles -------------------------------------------------------------------------------------


async def test_a_viewer_reads_but_cannot_write(stack: Stack) -> None:
    admin = await signed_in(stack, OWNER, PASSWORD)
    _, viewer = await ready_user(stack, admin)
    for path in ("/sessions", "/settings/system", "/settings/enrichment", "/stats/summary"):
        assert (await viewer.get(f"/api/v1{path}")).status_code == 200, path
    writes = [
        ("PUT", "/settings/providers/abuseipdb", {"key": "x" * 20, "password": GOOD}),
        ("DELETE", "/settings/providers/abuseipdb", {"password": GOOD}),
        ("POST", "/settings/providers/abuseipdb/test", None),
        (
            "POST",
            "/users",
            {"username": "evil", "display_name": "E", "role": "admin", "password": GOOD},
        ),
        ("PATCH", "/users/1", {"role": "admin", "password": GOOD}),
        ("DELETE", "/users/1", {"password": GOOD}),
    ]
    for method, path, body in writes:
        r = await call(viewer, method, path, body)
        assert r.status_code == 403 and r.json()["code"] == "admin_required", (method, path)
    for path in ("/users", "/audit"):
        r = await viewer.get(f"/api/v1{path}")
        assert r.status_code == 403 and r.json()["code"] == "admin_required", path
    assert (await query("SELECT count(*) AS n FROM users"))[0].n == 1
    me = (await viewer.get("/api/v1/auth/me")).json()
    assert me["read_only"] is True and me["is_owner"] is False


async def test_an_admin_user_can_manage_users_with_their_own_password(stack: Stack) -> None:
    owner = await signed_in(stack, OWNER, PASSWORD)
    _, boss = await ready_user(stack, owner, "boss", "admin")
    assert (await boss.get("/api/v1/users")).status_code == 200
    # Re-authentication uses the signed-in admin's password, not the owner's.
    wrong = await call(
        boss,
        "POST",
        "/users",
        {"username": "newbie", "display_name": "N", "role": "viewer", "password": PASSWORD},
    )
    assert wrong.status_code == 403 and wrong.json()["code"] == "reauth_failed"
    ok = await call(
        boss,
        "POST",
        "/users",
        {"username": "newbie", "display_name": "N", "role": "viewer", "password": GOOD},
    )
    assert ok.status_code == 201 and ok.json()["user"]["created_by"] == "boss"


async def test_admins_cannot_lock_themselves_out(stack: Stack) -> None:
    owner = await signed_in(stack, OWNER, PASSWORD)
    me, boss = await ready_user(stack, owner, "boss", "admin")
    uid = me["id"]
    for method, path, body in (
        ("PATCH", f"/users/{uid}", {"role": "viewer", "password": GOOD}),
        ("PATCH", f"/users/{uid}", {"disabled": True, "password": GOOD}),
        ("POST", f"/users/{uid}/reset-password", {"password": GOOD}),
        ("DELETE", f"/users/{uid}", {"password": GOOD}),
    ):
        r = await call(boss, method, path, body)
        assert r.status_code == 409 and r.json()["code"] == "self_action", path
    assert (await boss.get("/api/v1/users")).status_code == 200


# ---- sessions die at once -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "action",
    ["disable", "role", "reset", "revoke", "delete", "own-password"],
)
async def test_existing_sessions_die_immediately(stack: Stack, action: str) -> None:
    admin = await signed_in(stack, OWNER, PASSWORD)
    user, c = await ready_user(stack, admin)
    uid = user["id"]
    assert (await c.get("/api/v1/sessions")).status_code == 200
    requests: dict[str, tuple[str, str, dict[str, Any]]] = {
        "disable": ("PATCH", f"/users/{uid}", {"disabled": True, "password": PASSWORD}),
        "role": ("PATCH", f"/users/{uid}", {"role": "admin", "password": PASSWORD}),
        "reset": ("POST", f"/users/{uid}/reset-password", {"password": PASSWORD}),
        "revoke": ("POST", f"/users/{uid}/revoke-sessions", {"password": PASSWORD}),
        "delete": ("DELETE", f"/users/{uid}", {"password": PASSWORD}),
    }
    if action == "own-password":
        other = await signed_in(stack, "colleague", GOOD)
        r = await call(
            c, "POST", "/auth/password", {"current_password": GOOD, "new_password": GOOD + "!"}
        )
        assert r.status_code == 204
        c = other
    else:
        method, path, body = requests[action]
        assert (await call(admin, method, path, body)).status_code in (200, 204)
    gone = await c.get("/api/v1/sessions")
    assert gone.status_code == 401
    assert (await c.get("/api/v1/auth/me")).status_code == 401


async def test_a_disabled_user_cannot_sign_in_until_enabled(stack: Stack) -> None:
    admin = await signed_in(stack, OWNER, PASSWORD)
    user, c = await ready_user(stack, admin)

    async def patch(**changes: Any) -> httpx.Response:
        return await call(admin, "PATCH", f"/users/{user['id']}", {**changes, "password": PASSWORD})

    assert (await patch(disabled=True)).json()["disabled"] is True
    refused = await sign_in(stack.client(), "colleague", GOOD)
    assert refused.status_code == 401 and refused.json() == {"detail": "Invalid credentials"}
    assert (await patch(disabled=False)).json()["disabled"] is False
    assert (await c.get("/api/v1/sessions")).status_code == 401  # the old cookie stays dead
    assert (await sign_in(stack.client(), "colleague", GOOD)).status_code == 204


async def test_a_role_change_applies_after_signing_in_again(stack: Stack) -> None:
    admin = await signed_in(stack, OWNER, PASSWORD)
    user, _ = await ready_user(stack, admin)
    await call(admin, "PATCH", f"/users/{user['id']}", {"role": "admin", "password": PASSWORD})
    again = await signed_in(stack, "colleague", GOOD)
    assert (await again.get("/api/v1/users")).status_code == 200
    assert (await again.get("/api/v1/auth/me")).json()["read_only"] is False
    await call(admin, "PATCH", f"/users/{user['id']}", {"role": "viewer", "password": PASSWORD})
    assert (await again.get("/api/v1/users")).status_code == 401


async def test_reset_password_gives_a_new_one_time_password(stack: Stack) -> None:
    admin = await signed_in(stack, OWNER, PASSWORD)
    user, _ = await ready_user(stack, admin)
    r = await call(admin, "POST", f"/users/{user['id']}/reset-password", {"password": PASSWORD})
    temp = r.json()["temporary_password"]
    assert r.headers["cache-control"] == "no-store"
    assert (await sign_in(stack.client(), "colleague", GOOD)).status_code == 401
    c = await signed_in(stack, "colleague", temp)
    assert (await c.get("/api/v1/sessions")).status_code == 403  # must choose a password again
    (row,) = await query("SELECT must_change_password, password_hash FROM users")
    assert row.must_change_password and temp not in row.password_hash


# ---- login hardening ----------------------------------------------------------------------------


async def test_unknown_and_known_users_fail_the_same_way(stack: Stack) -> None:
    admin = await signed_in(stack, OWNER, PASSWORD)
    await ready_user(stack, admin)
    a = await sign_in(stack.client(), "colleague", "wrong password here")
    b = await sign_in(stack.client(), "nobody-here", "wrong password here")
    c = await sign_in(stack.client(), OWNER, "wrong password here")
    assert a.status_code == b.status_code == c.status_code == 401
    assert a.json() == b.json() == c.json() == {"detail": "Invalid credentials"}
    assert "set-cookie" not in a.headers and "set-cookie" not in b.headers


async def test_ten_failures_lock_the_account_for_fifteen_minutes(stack: Stack) -> None:
    admin = await signed_in(stack, OWNER, PASSWORD)
    user, _ = await ready_user(stack, admin)
    client = stack.client()
    for _ in range(9):
        assert (await sign_in(client, "colleague", "wrong password here")).status_code == 401
    (row,) = await query("SELECT failed_logins, locked_until FROM users")
    assert row.failed_logins == 9 and row.locked_until is None
    assert (
        await sign_in(client, "colleague", "wrong password here")
    ).status_code == 401  # the 10th
    (row,) = await query("SELECT locked_until, locked_until - now() AS left FROM users")
    assert row.locked_until is not None
    assert 14 * 60 < row.left.total_seconds() <= 15 * 60
    # The right password does not help while locked, and says the same thing.
    refused = await sign_in(client, "colleague", GOOD)
    assert refused.status_code == 401 and refused.json() == {"detail": "Invalid credentials"}
    # The admin sees the lock and removes it.
    listing = (await call(admin, "GET", "/users")).json()["items"]
    assert listing[0]["locked_until"] is not None
    r = await call(admin, "POST", f"/users/{user['id']}/unlock", {"password": PASSWORD})
    assert r.status_code == 200 and r.json()["locked_until"] is None
    assert (await sign_in(client, "colleague", GOOD)).status_code == 204


async def test_the_lock_expires_by_itself_and_failures_restart_from_zero(stack: Stack) -> None:
    admin = await signed_in(stack, OWNER, PASSWORD)
    await ready_user(stack, admin)
    client = stack.client()
    for _ in range(10):
        await sign_in(client, "colleague", "wrong password here")
    assert (await sign_in(client, "colleague", GOOD)).status_code == 401
    await query("SELECT 1")
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(text("UPDATE users SET locked_until = now() - interval '1 second'"))
    assert (await sign_in(client, "colleague", GOOD)).status_code == 204
    (row,) = await query("SELECT failed_logins, locked_until FROM users")
    assert row.failed_logins == 0 and row.locked_until is None


async def test_a_good_login_resets_the_failure_count(stack: Stack) -> None:
    admin = await signed_in(stack, OWNER, PASSWORD)
    await ready_user(stack, admin)
    client = stack.client()
    for _ in range(9):
        await sign_in(client, "colleague", "wrong password here")
    assert (await sign_in(client, "colleague", GOOD)).status_code == 204
    for _ in range(9):
        await sign_in(client, "colleague", "wrong password here")
    assert (await sign_in(client, "colleague", GOOD)).status_code == 204  # never reached ten


async def test_the_owner_is_never_locked_out_by_failures(stack: Stack) -> None:
    client = stack.client()
    for _ in range(12):
        await sign_in(client, OWNER, "wrong password here")
    assert (await sign_in(client, OWNER, PASSWORD)).status_code == 204


async def test_last_login_is_the_previous_one(stack: Stack) -> None:
    admin = await signed_in(stack, OWNER, PASSWORD)
    await ready_user(stack, admin)
    first = (await (await signed_in(stack, "colleague", GOOD)).get("/api/v1/auth/me")).json()
    second = (await (await signed_in(stack, "colleague", GOOD)).get("/api/v1/auth/me")).json()
    assert second["last_login_at"] is not None
    assert first["last_login_at"] is not None  # the sign-in that chose the password
    assert second["last_login_at"] >= first["last_login_at"]


# ---- re-authentication -------------------------------------------------------------------------


async def test_a_wrong_admin_password_changes_nothing(stack: Stack) -> None:
    admin = await signed_in(stack, OWNER, PASSWORD)
    user, _ = await ready_user(stack, admin)
    before = await query("SELECT count(*) AS n FROM audit_log")
    r = await call(admin, "PATCH", f"/users/{user['id']}", {"disabled": True, "password": "nope"})
    assert r.status_code == 403 and r.json()["code"] == "reauth_failed"
    (row,) = await query("SELECT disabled FROM users")
    assert row.disabled is False
    assert (await query("SELECT count(*) AS n FROM audit_log"))[0].n == before[0].n


async def test_five_wrong_passwords_end_the_admin_session(stack: Stack) -> None:
    admin = await signed_in(stack, OWNER, PASSWORD)
    user, _ = await ready_user(stack, admin)
    last = None
    for _ in range(5):
        last = await call(admin, "DELETE", f"/users/{user['id']}", {"password": "nope"})
    assert last is not None and last.status_code == 401 and last.json()["code"] == "session_revoked"
    assert (await admin.get("/api/v1/auth/me")).status_code == 401


# ---- audit log ---------------------------------------------------------------------------------


async def test_every_admin_action_is_audited_without_secrets(stack: Stack) -> None:
    admin = await signed_in(stack, OWNER, PASSWORD)
    created = await make_user(admin)
    uid = created["user"]["id"]
    temp = created["temporary_password"]
    c = await signed_in(stack, "colleague", temp)
    await call(c, "POST", "/auth/password", {"current_password": temp, "new_password": GOOD})
    await call(admin, "PATCH", f"/users/{uid}", {"role": "admin", "password": PASSWORD})
    await call(admin, "PATCH", f"/users/{uid}", {"disabled": True, "password": PASSWORD})
    await call(admin, "PATCH", f"/users/{uid}", {"disabled": False, "password": PASSWORD})
    await call(admin, "PATCH", f"/users/{uid}", {"display_name": "Renamed", "password": PASSWORD})
    reset = await call(admin, "POST", f"/users/{uid}/reset-password", {"password": PASSWORD})
    await call(admin, "POST", f"/users/{uid}/unlock", {"password": PASSWORD})
    await call(admin, "POST", f"/users/{uid}/revoke-sessions", {"password": PASSWORD})
    await call(admin, "DELETE", f"/users/{uid}", {"password": PASSWORD})

    page = (await call(admin, "GET", "/audit?limit=200")).json()
    actions = [e["action"] for e in page["items"]]
    for expected in (
        "auth.login",
        "user.create",
        "password.change",
        "user.role",
        "user.disable",
        "user.enable",
        "user.rename",
        "user.reset_password",
        "user.unlock",
        "user.revoke_sessions",
        "user.delete",
    ):
        assert expected in actions, expected
    created_entry = next(e for e in page["items"] if e["action"] == "user.create")
    assert created_entry["actor"] == OWNER and created_entry["target"] == "colleague"
    assert created_entry["details"] == {"role": "viewer"}
    role_entry = next(e for e in page["items"] if e["action"] == "user.role")
    assert role_entry["details"] == {"from": "viewer", "to": "admin"}
    # Newest first, and nothing sensitive anywhere in the table.
    ids = [e["id"] for e in page["items"]]
    assert ids == sorted(ids, reverse=True)
    rows = await query("SELECT actor, action, target, ip, details::text FROM audit_log")
    dump = json.dumps([list(r) for r in rows])
    for secret in (temp, reset.json()["temporary_password"], PASSWORD, GOOD, "$argon2"):
        assert secret not in dump, secret


async def test_provider_key_changes_are_audited(
    stack: Stack, monkeypatch: pytest.MonkeyPatch
) -> None:
    import base64

    from suckerpot_db.secretbox import ENV_VAR

    monkeypatch.setenv(ENV_VAR, base64.b64encode(bytes(range(32))).decode())
    from api.provider_keys import install

    install(stack.app)
    admin = await signed_in(stack, OWNER, PASSWORD)
    key = "placeholder-secret-" + "for-tests-0007777"
    r = await call(
        admin, "PUT", "/settings/providers/abuseipdb", {"key": key, "password": PASSWORD}
    )
    assert r.status_code == 200
    r = await call(admin, "DELETE", "/settings/providers/abuseipdb", {"password": PASSWORD})
    assert r.status_code == 204
    rows = await query(
        "SELECT action, target, details::text AS d FROM audit_log "
        "WHERE action LIKE 'provider_key.%'"
    )
    assert {(r.action, r.target) for r in rows} == {
        ("provider_key.set", "abuseipdb"),
        ("provider_key.remove", "abuseipdb"),
    }
    assert key not in json.dumps([tuple(r) for r in rows])


async def test_audit_filters_and_pagination(stack: Stack) -> None:
    admin = await signed_in(stack, OWNER, PASSWORD)
    for name in ("alpha", "bravo", "charlie"):
        await make_user(admin, name)
    everything = (await call(admin, "GET", "/audit?limit=200")).json()["items"]
    assert len(everything) >= 4  # one sign-in and three creations

    first = (await call(admin, "GET", "/audit?limit=2")).json()
    assert len(first["items"]) == 2 and first["next_cursor"]
    second = (await call(admin, "GET", f"/audit?limit=2&cursor={first['next_cursor']}")).json()
    assert {e["id"] for e in first["items"]}.isdisjoint(e["id"] for e in second["items"])
    assert second["items"][0]["id"] < first["items"][-1]["id"]

    creates = (await call(admin, "GET", "/audit?action=user.create")).json()["items"]
    assert len(creates) == 3 and {e["action"] for e in creates} == {"user.create"}
    by_prefix = (await call(admin, "GET", "/audit?action=user.")).json()["items"]
    assert len(by_prefix) == 3
    by_actor = (await call(admin, "GET", f"/audit?actor={OWNER.upper()}")).json()["items"]
    assert len(by_actor) == len(everything)
    assert (await call(admin, "GET", "/audit?actor=nobody")).json()["items"] == []
    assert (await call(admin, "GET", "/audit?action=%25")).json()["items"] == []  # no wildcard
    assert (await call(admin, "GET", "/audit?cursor=not-a-cursor")).status_code == 400
    assert (await call(admin, "GET", "/audit?limit=1000")).status_code == 422


async def test_user_list_is_paginated(stack: Stack) -> None:
    admin = await signed_in(stack, OWNER, PASSWORD)
    for name in ("alpha", "bravo", "charlie"):
        await make_user(admin, name)
    first = (await call(admin, "GET", "/users?limit=2")).json()
    assert [u["username"] for u in first["items"]] == ["alpha", "bravo"] and first["next_cursor"]
    second = (await call(admin, "GET", f"/users?limit=2&cursor={first['next_cursor']}")).json()
    assert [u["username"] for u in second["items"]] == ["charlie"] and second["next_cursor"] is None
    assert "password_hash" not in json.dumps(first)


async def test_missing_users_are_404(stack: Stack) -> None:
    admin = await signed_in(stack, OWNER, PASSWORD)
    r = await call(admin, "DELETE", "/users/999", {"password": PASSWORD})
    assert r.status_code == 404 and r.json()["code"] == "not_found"
    assert (
        await call(admin, "PATCH", "/users/999", {"disabled": True, "password": PASSWORD})
    ).status_code == 404
    assert (await call(admin, "PATCH", "/users/1", {"password": PASSWORD})).status_code == 422


# ---- grants and retention ----------------------------------------------------------------------


async def test_database_grants() -> None:
    api_role = os.environ.get("POSTGRES_API_USER", "suckerpot_api")
    ingest_role = os.environ.get("POSTGRES_INGEST_USER", "suckerpot_ingest")

    async def can(role: str, table: str, privilege: str) -> bool:
        rows = await query(
            "SELECT has_table_privilege(:r, :t, :p) AS ok", r=role, t=table, p=privilege
        )
        return bool(rows[0].ok)

    for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE"):
        assert await can(api_role, "users", privilege), privilege
    assert await can(api_role, "audit_log", "SELECT")
    assert await can(api_role, "audit_log", "INSERT")
    assert not await can(api_role, "audit_log", "UPDATE")
    assert not await can(api_role, "audit_log", "DELETE")
    assert not await can(api_role, "audit_log", "TRUNCATE")
    for table in ("users", "audit_log"):
        for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE"):
            assert not await can(ingest_role, table, privilege), (table, privilege)


async def test_audit_log_is_pruned_after_a_year() -> None:
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(text("TRUNCATE audit_log"))
        await conn.execute(
            text(
                "INSERT INTO audit_log (ts, actor, action) VALUES "
                "(now() - interval '400 days', 'old', 'x'), "
                "(now() - interval '364 days', 'recent', 'x')"
            )
        )
        await conn.execute(text("CALL suckerpot_audit_prune(0, '{}'::jsonb)"))
    assert [r.actor for r in await query("SELECT actor FROM audit_log")] == ["recent"]


async def test_audit_details_are_bounded_by_the_database() -> None:
    from sqlalchemy.exc import DBAPIError

    async with owner_engine() as owner:
        with pytest.raises(DBAPIError):
            async with owner.begin() as conn:
                await conn.execute(
                    text(
                        "INSERT INTO audit_log (actor, action, details) "
                        "VALUES ('a', 'b', CAST(:d AS jsonb))"
                    ),
                    {"d": json.dumps({"x": "y" * 3000})},
                )
