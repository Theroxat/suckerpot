"""Provider keys from Settings: auth, CSRF, re-authentication, rate limit and no key leaks.

Runs without a database: the session is a recording fake. The round trip against a real
TimescaleDB is in ``test_provider_keys_integration.py``.
"""

import base64
import logging
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock

import pytest
from argon2 import PasswordHasher
from sqlalchemy.dialects import postgresql
from starlette.testclient import TestClient
from suckerpot_db import ProviderSecretRow, ProviderTestRequestRow
from suckerpot_db.secretbox import ENV_VAR, SecretBox

import api.auth as auth_mod
from api.auth import AuthSettings
from api.main import create_app

PASSWORD = "correct horse battery staple"
HASH = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash(PASSWORD)
MASTER = bytes(range(32))
MASTER_B64 = base64.b64encode(MASTER).decode()
SAMPLE = "placeholder-secret-for-tests-0007777"
CSRF_COOKIE = "__Host-sp_csrf"
ORIGIN = "https://testserver"


class FakeSession:
    def __init__(self) -> None:
        self.executed: list[Any] = []
        self.commits = 0
        self.store: dict[tuple[type, str], Any] = {}

    async def execute(self, stmt: Any) -> MagicMock:
        self.executed.append(stmt)
        return MagicMock()

    async def commit(self) -> None:
        self.commits += 1

    async def get(self, model: type, pk: str) -> Any:
        return self.store.get((model, pk))

    def params(self, index: int = -1) -> dict[str, Any]:
        dialect = postgresql.dialect()  # type: ignore[no-untyped-call]
        return dict(self.executed[index].compile(dialect=dialect).params)


@pytest.fixture(autouse=True)
def no_delay(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(auth_mod, "FAILURE_DELAY_S", 0.0)


@pytest.fixture
def db() -> FakeSession:
    return FakeSession()


def build(db: FakeSession, **kw: Any) -> TestClient:
    @asynccontextmanager
    async def session_cm() -> AsyncIterator[FakeSession]:
        yield db

    settings = AuthSettings(password_hash=HASH, secret=b"k" * 40, **kw)
    app = create_app(session_cm, enable_live=False, auth_settings=settings)  # type: ignore[arg-type]
    return TestClient(app, base_url="https://testserver")


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch, db: FakeSession) -> Iterator[TestClient]:
    monkeypatch.setenv(ENV_VAR, MASTER_B64)
    with build(db) as c:
        yield c


def login(c: TestClient) -> dict[str, str]:
    r = c.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": PASSWORD},
        headers={"Origin": ORIGIN},
    )
    assert r.status_code == 204
    return {"X-CSRF-Token": c.cookies[CSRF_COOKIE], "Origin": ORIGIN}


def put(c: TestClient, hdr: dict[str, str], provider: str = "abuseipdb", **body: Any) -> Any:
    payload = {"key": SAMPLE, "password": PASSWORD, **body}
    return c.put(f"/api/v1/settings/providers/{provider}", json=payload, headers=hdr)


# ---- session, CSRF, origin -------------------------------------------------------------------


def test_requires_a_session(client: TestClient) -> None:
    assert client.put("/api/v1/settings/providers/abuseipdb", json={}).status_code == 401
    assert client.request("DELETE", "/api/v1/settings/providers/abuseipdb").status_code == 401
    assert client.post("/api/v1/settings/providers/abuseipdb/test").status_code == 401


def test_requires_csrf(client: TestClient, db: FakeSession) -> None:
    login(client)
    body = {"key": SAMPLE, "password": PASSWORD}
    r = client.put("/api/v1/settings/providers/abuseipdb", json=body, headers={"Origin": ORIGIN})
    assert r.status_code == 403 and not db.executed
    r = client.request(
        "DELETE", "/api/v1/settings/providers/abuseipdb", json={"password": PASSWORD}
    )
    assert r.status_code == 403
    assert client.post("/api/v1/settings/providers/abuseipdb/test").status_code == 403
    assert not db.executed


def test_cross_origin_is_refused(client: TestClient, db: FakeSession) -> None:
    hdr = login(client)
    r = put(client, {**hdr, "Origin": "https://evil.example"})
    assert r.status_code == 403 and r.json()["code"] == "origin" and not db.executed


# ---- re-authentication and rate limit --------------------------------------------------------


def test_wrong_password_is_refused_and_logged(
    client: TestClient, db: FakeSession, caplog: pytest.LogCaptureFixture
) -> None:
    hdr = login(client)
    with caplog.at_level(logging.INFO):
        r = put(client, hdr, password="not the password")
    assert r.status_code == 403 and r.json()["code"] == "reauth_failed"
    assert not db.executed
    text = caplog.text
    assert SAMPLE not in text and "not the password" not in text
    assert client.get("/api/v1/auth/me").status_code == 200  # the session survives


def test_reauth_is_rate_limited_but_login_budget_is_separate(client: TestClient) -> None:
    hdr = login(client)
    codes = [put(client, hdr, password="nope").status_code for _ in range(7)]
    assert codes[:5] == [403] * 5 and codes[5:] == [429, 429]
    r = put(client, hdr)  # even the right password waits for the window
    assert r.status_code == 429 and "retry-after" in r.headers
    assert client.get("/api/v1/auth/me").status_code == 200


# ---- happy path, storage and leaks -----------------------------------------------------------


def test_set_key_encrypts_and_never_echoes(
    client: TestClient, db: FakeSession, caplog: pytest.LogCaptureFixture
) -> None:
    hdr = login(client)
    with caplog.at_level(logging.INFO):
        r = put(client, hdr)
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"provider", "source", "last4", "updated_at"}
    assert body["last4"] == "7777" and body["source"] == "settings"
    assert SAMPLE not in r.text and PASSWORD not in r.text
    params = db.params()
    assert params["last4"] == "7777" and params["updated_by"] == "admin"
    assert SAMPLE.encode() not in params["ciphertext"] and db.commits == 1
    plain = SecretBox(MASTER).decrypt("abuseipdb", params["ciphertext"], params["nonce"])
    assert plain.key == SAMPLE
    assert SAMPLE not in caplog.text and PASSWORD not in caplog.text
    assert any(
        "provider key set" in m and "provider=abuseipdb" in m and "actor=admin" in m
        for m in caplog.messages
    )


def test_maxmind_needs_an_account_id(client: TestClient, db: FakeSession) -> None:
    hdr = login(client)
    r = put(client, hdr, "maxmind")
    assert r.status_code == 422 and r.json()["code"] == "invalid_key" and not db.executed
    ok = put(client, hdr, "maxmind", account_id="424242")
    assert ok.status_code == 200
    stored = SecretBox(MASTER).decrypt("maxmind", db.params()["ciphertext"], db.params()["nonce"])
    assert (stored.key, stored.account_id) == (SAMPLE, "424242")


@pytest.mark.parametrize(
    "bad", ["short", "has space in the middle 1234567", "tab\there-1234567890123", "é" * 20]
)
def test_invalid_key_format_is_refused_without_echo(
    client: TestClient, db: FakeSession, bad: str
) -> None:
    r = put(client, login(client), key=bad)
    assert r.status_code == 422 and bad not in r.text and not db.executed


def test_oversized_key_is_refused_without_echo(client: TestClient, db: FakeSession) -> None:
    huge = "Q" * 400
    r = put(client, login(client), key=huge)
    assert r.status_code == 422 and huge not in r.text and not db.executed


def test_unknown_provider(client: TestClient) -> None:
    assert put(client, login(client), "shodan").status_code == 422


def test_remove_key(client: TestClient, db: FakeSession, caplog: pytest.LogCaptureFixture) -> None:
    hdr = login(client)
    url = "/api/v1/settings/providers/greynoise"
    assert client.request("DELETE", url, json={"password": "bad"}, headers=hdr).status_code == 403
    assert not db.executed
    with caplog.at_level(logging.INFO):
        r = client.request("DELETE", url, json={"password": PASSWORD}, headers=hdr)
    assert r.status_code == 204 and db.commits == 1
    assert any("provider key removed" in m and "provider=greynoise" in m for m in caplog.messages)


# ---- feature switch --------------------------------------------------------------------------


def test_editing_disabled_without_an_encryption_key(
    monkeypatch: pytest.MonkeyPatch, db: FakeSession
) -> None:
    monkeypatch.delenv(ENV_VAR, raising=False)
    with build(db) as c:
        r = put(c, login(c))
        assert r.status_code == 503 and r.json()["code"] == "editing_disabled"
        assert ENV_VAR in r.json()["detail"] and not db.executed


def test_unusable_encryption_key_disables_editing_without_leaking_it(
    monkeypatch: pytest.MonkeyPatch, db: FakeSession
) -> None:
    short = base64.b64encode(b"too-short-master-value").decode()
    monkeypatch.setenv(ENV_VAR, short)
    with build(db) as c:
        r = put(c, login(c))
        assert r.status_code == 503 and short not in r.text


# ---- test requests ---------------------------------------------------------------------------


def test_test_request_needs_a_key(client: TestClient, db: FakeSession) -> None:
    r = client.post("/api/v1/settings/providers/abuseipdb/test", headers=login(client))
    assert r.status_code == 409 and r.json()["code"] == "no_key" and not db.executed


def test_test_request_is_queued_then_rate_limited(client: TestClient, db: FakeSession) -> None:
    hdr = login(client)
    db.store[(ProviderSecretRow, "abuseipdb")] = object()
    r = client.post("/api/v1/settings/providers/abuseipdb/test", headers=hdr)
    assert r.status_code == 202 and r.json()["provider"] == "abuseipdb"
    params = db.params()
    assert params["requested_by"] == "admin" and params["handled_at"] is None
    db.store[(ProviderTestRequestRow, "abuseipdb")] = MagicMock(requested_at=datetime.now(UTC))
    again = client.post("/api/v1/settings/providers/abuseipdb/test", headers=hdr)
    assert again.status_code == 429 and again.json()["code"] == "cooldown"
