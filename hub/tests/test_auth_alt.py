"""Alternate hub signature header for a signing-key rollover (design M32 6.4)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest
from suckerpot_netproto import sign

from hub.config import ConfigError, Settings, load_signing_key
from hub.main import create_app

from .helpers import FakeClock


def _binding(nonce: str) -> sign.RequestBinding:
    return sign.RequestBinding.unsigned("GET", "/v1/info", nonce, b"")


async def _info(app: Any) -> tuple[httpx.Response, sign.RequestBinding]:
    nonce = sign.new_nonce()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("203.0.113.7", 1234)),
        base_url="http://hub.test",
    ) as http:
        resp = await http.get("/v1/info", headers={sign.H_NONCE: nonce})
    return resp, _binding(nonce)


def _app(**kw: Any) -> Any:
    settings = Settings(allow_documentation=True, **kw.pop("settings", {}))
    return create_app(settings, engine=_FakeEngine(), clock=FakeClock(), **kw)  # type: ignore[arg-type]


class _FakeEngine:
    """``create_app`` only builds a sessionmaker from it; /v1/info never touches the database."""

    def __getattr__(self, name: str) -> Any:  # pragma: no cover - never called
        raise AssertionError(name)


async def test_no_alternate_key_means_one_header() -> None:
    primary = sign.generate_private_key()
    app = _app(hub_private=primary)
    resp, binding = await _info(app)
    assert resp.status_code == 200
    assert sign.H_HUB_SIGNATURE_ALT not in resp.headers
    key = sign.node_key(sign.public_key_of(primary))
    assert sign.verify_response(key, resp.headers[sign.H_HUB_SIGNATURE], binding, 200, resp.content)


async def test_both_keys_sign_the_same_answer() -> None:
    primary, alt = sign.generate_private_key(), sign.generate_private_key()
    app = _app(hub_private=primary, hub_private_alt=alt)
    resp, binding = await _info(app)
    k1 = sign.node_key(sign.public_key_of(primary))
    k2 = sign.node_key(sign.public_key_of(alt))
    first, second = resp.headers[sign.H_HUB_SIGNATURE], resp.headers[sign.H_HUB_SIGNATURE_ALT]
    assert sign.verify_response(k1, first, binding, 200, resp.content)
    assert sign.verify_response(k2, second, binding, 200, resp.content)
    assert not sign.verify_response(k2, first, binding, 200, resp.content)
    assert not sign.verify_response(k1, second, binding, 200, resp.content)
    # /v1/info keeps hub_key = primary.
    assert resp.json()["hub_key"] == k1
    # A node pinning either key set accepts it (netproto's any-of check).
    assert sign.verify_response_any([k2, "x"], [first, second], binding, 200, resp.content)


def test_alt_key_file_is_loaded_from_settings(tmp_path: Path) -> None:
    alt = sign.generate_private_key()
    path = tmp_path / "alt.key"
    path.write_text(sign.b64u_encode(alt), encoding="ascii")
    app = _app(
        hub_private=sign.generate_private_key(), settings={"signing_key_alt_file": str(path)}
    )
    assert app.state.ctx.hub_private_alt == alt == load_signing_key(str(path))


def test_bad_alt_key_file_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "alt.key"
    path.write_text("not a key", encoding="ascii")
    with pytest.raises(ConfigError):
        _app(hub_private=sign.generate_private_key(), settings={"signing_key_alt_file": str(path)})
