"""Settings-managed provider keys: precedence, hot-swap and key tests (no database)."""

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest
from suckerpot_db.secretbox import Credential, SecretBox

from ingest.enrichment import EnrichmentSettings
from ingest.enrichment.credentials import CredentialSync, changed_providers
from ingest.enrichment.reputation import ReputationWorker

MASTER = bytes(range(32))
BOX = SecretBox(MASTER)
ENV_VALUE = "envkeyenvkeyenvkey0001"
SET_VALUE = "settingskeysettingskey2"


def row(provider: str, key: str, account: str | None = None, box: SecretBox = BOX) -> Any:
    ct, nonce = box.encrypt(provider, Credential(key, account))
    return SimpleNamespace(provider=provider, ciphertext=ct, nonce=nonce, last4=key[-4:])


def sync(box: SecretBox | None = BOX, **env: str) -> CredentialSync:
    base = EnrichmentSettings.from_env(env)
    return CredentialSync(MagicMock(), base, box, on_change=lambda _s, _c: None, client=MagicMock())


def test_settings_value_overrides_env() -> None:
    s = sync(ABUSEIPDB_API_KEY=ENV_VALUE, GREYNOISE_API_KEY=ENV_VALUE)
    eff = s.effective({"abuseipdb": row("abuseipdb", SET_VALUE)})
    assert eff.abuseipdb_api_key == SET_VALUE and eff.greynoise_api_key == ENV_VALUE
    assert s.info["abuseipdb"].source == "settings" and s.info["greynoise"].source == "env"
    assert s.info["maxmind"].source is None


def test_env_is_the_fallback_when_no_row() -> None:
    s = sync(ABUSEIPDB_API_KEY=ENV_VALUE)
    assert s.effective({}).abuseipdb_api_key == ENV_VALUE


def test_maxmind_pair_from_settings() -> None:
    s = sync(MAXMIND_ACCOUNT_ID="1", MAXMIND_LICENSE_KEY=ENV_VALUE)
    eff = s.effective({"maxmind": row("maxmind", SET_VALUE, "424242")})
    assert (eff.maxmind_account_id, eff.maxmind_license_key) == ("424242", SET_VALUE)
    assert eff.maxmind_enabled


def test_wrong_encryption_key_falls_back_to_env_and_reports() -> None:
    s = sync(ABUSEIPDB_API_KEY=ENV_VALUE)
    other = SecretBox(bytes(reversed(MASTER)))
    eff = s.effective({"abuseipdb": row("abuseipdb", SET_VALUE, box=other)})
    assert eff.abuseipdb_api_key == ENV_VALUE
    assert s.info["abuseipdb"].error == "cannot_decrypt" and s.info["abuseipdb"].source == "env"
    assert SET_VALUE not in repr(s.status("abuseipdb")) + repr(s.info)


def test_no_encryption_key_ignores_rows() -> None:
    s = sync(box=None)
    eff = s.effective({"greynoise": row("greynoise", SET_VALUE)})
    assert eff.greynoise_api_key == ""
    assert s.info["greynoise"].error == "no_encryption_key"


def test_changed_providers() -> None:
    a = EnrichmentSettings.from_env({"ABUSEIPDB_API_KEY": ENV_VALUE})
    b = sync(ABUSEIPDB_API_KEY=ENV_VALUE).effective({"maxmind": row("maxmind", SET_VALUE, "7")})
    assert changed_providers(a, b) == {"maxmind"}
    assert changed_providers(a, a) == set()


def test_settings_repr_hides_keys() -> None:
    eff = sync().effective({"abuseipdb": row("abuseipdb", SET_VALUE)})
    assert SET_VALUE not in repr(eff)


async def test_worker_uses_new_key_after_apply_settings() -> None:
    seen: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req.headers["Key"])
        return httpx.Response(200, json={"data": {"abuseConfidenceScore": 1, "totalReports": 0}})

    old = EnrichmentSettings.from_env({"ABUSEIPDB_API_KEY": ENV_VALUE})
    w = ReputationWorker(
        MagicMock(), old, httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )
    w._disabled["abuseipdb"] = "auth"
    await w.check_abuseipdb("203.0.113.9")
    new = sync(ABUSEIPDB_API_KEY=ENV_VALUE).effective({"abuseipdb": row("abuseipdb", SET_VALUE)})
    w.apply_settings(new, {"abuseipdb"})
    assert w.enabled("abuseipdb")  # the old auth failure is forgotten
    await w.check_abuseipdb("203.0.113.9")
    assert seen == [ENV_VALUE, SET_VALUE]


async def test_failed_key_test_reports_auth_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(401)

    async def reserve(*_a: Any) -> bool:
        return True

    monkeypatch.setattr("ingest.enrichment.reputation.reserve_quota", reserve)
    base = EnrichmentSettings.from_env({"GREYNOISE_API_KEY": ENV_VALUE})
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    w = ReputationWorker(MagicMock(), base, client)
    result = await w.run_key_test("greynoise")
    assert result["ok"] is False and result["error"] == "auth"
    assert not w.enabled("greynoise")
    assert ENV_VALUE not in repr(await w.status())


async def test_key_test_without_a_key() -> None:
    w = ReputationWorker(MagicMock(), EnrichmentSettings.from_env({}))
    assert (await w.run_key_test("abuseipdb"))["error"] == "no_key"


async def test_maxmind_test_results(monkeypatch: pytest.MonkeyPatch) -> None:
    async def reserve(*_a: Any) -> bool:
        return True

    monkeypatch.setattr("ingest.enrichment.credentials.reserve_quota", reserve)
    codes = iter([200, 401])
    auths: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        auths.append(req.headers["Authorization"])
        return httpx.Response(next(codes))

    s = sync(MAXMIND_ACCOUNT_ID="99", MAXMIND_LICENSE_KEY=ENV_VALUE)
    s.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    assert (await s.test_maxmind())["ok"] is True
    assert (await s.test_maxmind())["error"] == "auth"
    assert s.status("maxmind")["test"]["error"] == "auth"
    assert ENV_VALUE not in repr(s.status("maxmind"))
    assert len(auths) == 2
