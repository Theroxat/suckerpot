"""Provider keys against a real TimescaleDB, as the least-privileged API role."""

import base64
import json
import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from analytics_seed import api_engine, owner_engine
from argon2 import PasswordHasher
from sqlalchemy import text
from suckerpot_db import create_session_factory
from suckerpot_db.secretbox import ENV_VAR, SecretBox

import api.auth as auth_mod
from api.auth import AuthSettings
from api.main import create_app

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

PASSWORD = "correct horse battery staple"
HASH = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash(PASSWORD)
MASTER = bytes(range(32))
SAMPLE = "placeholder-secret-for-tests-0007777"
ORIGIN = "https://testserver"


@pytest.fixture
async def client(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[httpx.AsyncClient]:
    monkeypatch.setattr(auth_mod, "FAILURE_DELAY_S", 0.0)
    monkeypatch.setenv(ENV_VAR, base64.b64encode(MASTER).decode())
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text(
                "TRUNCATE provider_secrets, provider_test_requests, enrichment_status, "
                "enrichment_quota"
            )
        )
    engine = api_engine()
    settings = AuthSettings(password_hash=HASH, secret=b"k" * 40)
    app = create_app(create_session_factory(engine), enable_live=False, auth_settings=settings)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as c,
    ):
        r = await c.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": PASSWORD},
            headers={"Origin": ORIGIN},
        )
        assert r.status_code == 204
        c.headers.update({"Origin": ORIGIN, "X-CSRF-Token": c.cookies["__Host-sp_csrf"]})
        yield c
    await engine.dispose()


async def status(name: str, detail: dict[str, object]) -> None:
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO enrichment_status (name, detail) VALUES (:n, CAST(:d AS jsonb)) "
                "ON CONFLICT (name) DO UPDATE SET detail = CAST(:d AS jsonb)"
            ),
            {"n": name, "d": json.dumps(detail)},
        )


async def test_full_flow_never_returns_the_key(client: httpx.AsyncClient) -> None:
    before = (await client.get("/api/v1/settings/enrichment")).json()
    assert before["key_editing"] == {"enabled": True, "reason": None}
    assert before["abuseipdb"]["source"] is None and before["abuseipdb"]["last4"] is None

    r = await client.put(
        "/api/v1/settings/providers/abuseipdb", json={"key": SAMPLE, "password": PASSWORD}
    )
    assert r.status_code == 200 and SAMPLE not in r.text

    got = await client.get("/api/v1/settings/enrichment")
    assert SAMPLE not in got.text and PASSWORD not in got.text
    abuse = got.json()["abuseipdb"]
    assert (abuse["source"], abuse["last4"], abuse["configured"]) == ("settings", "7777", True)
    assert abuse["pending_apply"] is True and abuse["updated_at"]

    async with owner_engine() as owner, owner.connect() as conn:
        row = (await conn.execute(text("SELECT * FROM provider_secrets"))).one()
    assert SAMPLE.encode() not in bytes(row.ciphertext) and row.updated_by == "admin"
    assert SecretBox(MASTER).decrypt("abuseipdb", row.ciphertext, row.nonce).key == SAMPLE

    # Ingest picks it up and reports where it comes from.
    await status("abuseipdb", {"configured": True, "source": "settings", "env_configured": False})
    assert (await client.get("/api/v1/settings/enrichment")).json()["abuseipdb"][
        "pending_apply"
    ] is False

    # Replace, then ask for a test; ingest answers it.
    again = await client.put(
        "/api/v1/settings/providers/abuseipdb",
        json={"key": SAMPLE[:-4] + "8888", "password": PASSWORD},
    )
    assert again.status_code == 200
    t = await client.post("/api/v1/settings/providers/abuseipdb/test")
    assert t.status_code == 202
    pending = (await client.get("/api/v1/settings/enrichment")).json()["abuseipdb"]
    assert pending["last4"] == "8888" and pending["test_pending"] is True
    checked = (datetime.now(UTC) + timedelta(seconds=1)).isoformat()
    await status(
        "abuseipdb",
        {
            "configured": True,
            "source": "settings",
            "env_configured": False,
            "test": {"ok": False, "error": "auth", "checked_at": checked},
        },
    )
    done = (await client.get("/api/v1/settings/enrichment")).json()["abuseipdb"]
    assert done["test_pending"] is False
    assert done["test"]["ok"] is False and done["test"]["error"] == "auth"

    gone = await client.request(
        "DELETE", "/api/v1/settings/providers/abuseipdb", json={"password": PASSWORD}
    )
    assert gone.status_code == 204
    after = (await client.get("/api/v1/settings/enrichment")).json()["abuseipdb"]
    assert after["last4"] is None and after["source"] is None


async def test_env_source_is_reported_and_settings_beat_it(client: httpx.AsyncClient) -> None:
    await status("greynoise", {"configured": True, "source": "env", "env_configured": True})
    gn = (await client.get("/api/v1/settings/enrichment")).json()["greynoise"]
    assert (gn["source"], gn["last4"]) == ("env", None)
    await client.put(
        "/api/v1/settings/providers/greynoise", json={"key": SAMPLE, "password": PASSWORD}
    )
    gn = (await client.get("/api/v1/settings/enrichment")).json()["greynoise"]
    assert (gn["source"], gn["last4"]) == ("settings", "7777")


async def test_undecryptable_key_is_flagged(client: httpx.AsyncClient) -> None:
    await client.put(
        "/api/v1/settings/providers/maxmind",
        json={"key": SAMPLE, "account_id": "42", "password": PASSWORD},
    )
    await status("maxmind", {"configured": False, "source": None, "secret_error": "cannot_decrypt"})
    mm = (await client.get("/api/v1/settings/enrichment")).json()["maxmind"]
    assert mm["secret_error"] == "cannot_decrypt" and mm["last4"] is None


async def test_test_without_any_key_is_refused(client: httpx.AsyncClient) -> None:
    r = await client.post("/api/v1/settings/providers/greynoise/test")
    assert r.status_code == 409


async def test_test_requests_are_capped_per_day_and_per_20_seconds(
    client: httpx.AsyncClient,
) -> None:
    await status("greynoise", {"configured": True, "source": "env", "env_configured": True})
    url = "/api/v1/settings/providers/greynoise/test"
    assert (await client.post(url)).status_code == 202
    assert (await client.post(url)).json()["code"] == "cooldown"
    for n in range(2, 11):  # tests 2..10 are allowed once the cooldown has passed
        async with owner_engine() as owner, owner.begin() as conn:
            await conn.execute(
                text("UPDATE provider_test_requests SET requested_at = now() - interval '1 minute'")
            )
        assert (await client.post(url)).status_code == 202, n
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text("UPDATE provider_test_requests SET requested_at = now() - interval '1 minute'")
        )
    capped = await client.post(url)
    assert capped.status_code == 429 and capped.json()["code"] == "daily_cap"
    async with owner_engine() as owner, owner.begin() as conn:  # a new day resets the count
        await conn.execute(text("UPDATE provider_test_requests SET tests_day = current_date - 1"))
    assert (await client.post(url)).status_code == 202
