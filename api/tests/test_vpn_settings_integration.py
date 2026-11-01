"""VPN configuration upload and trusted exits against a real TimescaleDB (M23).

The API runs as its least-privileged database role, like in production. The ``vpn-config``
volume is a temporary directory.
"""

import base64
import json
import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from analytics_seed import api_engine, owner_engine
from argon2 import PasswordHasher
from sqlalchemy import text
from suckerpot_db import create_session_factory

import api.auth as auth_mod
from api.auth import AuthSettings
from api.main import create_app

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

PASSWORD = "correct horse battery staple"
FAST = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
HASH = FAST.hash(PASSWORD)
GOOD = "a long passphrase for tests 2026"
ORIGIN = "https://testserver"
CSRF = "__Host-sp_csrf"
PRIVATE = base64.b64encode(b"\x01" * 32).decode()
PUBLIC = base64.b64encode(b"\x02" * 32).decode()
# 9.9.9.0/24 is global on purpose: documentation ranges are not "global" for Python.
EXIT_IP = "9.9.9.77"
CONF = f"""\
[Interface]
PrivateKey = {PRIVATE}
Address = 198.51.100.2/32
DNS = 198.51.100.1

[Peer]
PublicKey = {PUBLIC}
AllowedIPs = 0.0.0.0/0
Endpoint = 9.9.9.50:51820
"""
BASE = "/api/v1/settings/vpn"


def names(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir())


def read(path: Path) -> str:
    return path.read_text()


def mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


@pytest.fixture
def vpn_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("VPN_CONFIG_DIR", str(tmp_path))
    return tmp_path


@pytest.fixture
async def app(monkeypatch: pytest.MonkeyPatch, vpn_dir: Path) -> AsyncIterator[Any]:
    monkeypatch.setattr(auth_mod, "FAILURE_DELAY_S", 0.0)
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text(
                "TRUNCATE users, audit_log, egress_trusted_exits, enrichment_status, "
                "egress_check_requests "
                "RESTART IDENTITY"
            )
        )
    engine = api_engine()
    settings = AuthSettings(
        password_hash=HASH,
        secret=b"k" * 40,
        rate_per_ip=10_000,
        rate_global=10_000,
        rate_per_user=10_000,
    )
    app = create_app(create_session_factory(engine), enable_live=False, auth_settings=settings)
    app.state.auth._hasher = FAST
    async with app.router.lifespan_context(app):
        yield app
    await engine.dispose()


def browser(app: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("127.0.0.1", 50000)),
        base_url=ORIGIN,
        headers={"Origin": ORIGIN},
    )


async def sign_in(app: Any, username: str, password: str) -> httpx.AsyncClient:
    c = browser(app)
    r = await c.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert r.status_code == 204, r.text
    c.headers["X-CSRF-Token"] = c.cookies[CSRF]
    return c


@pytest.fixture
async def admin(app: Any) -> httpx.AsyncClient:
    return await sign_in(app, "admin", PASSWORD)


@pytest.fixture
async def viewer(app: Any, admin: httpx.AsyncClient) -> httpx.AsyncClient:
    r = await admin.post(
        "/api/v1/users",
        json={"username": "colleague", "display_name": "Colleague", "role": "viewer",
              "password": PASSWORD},
    )  # fmt: skip
    assert r.status_code == 201, r.text
    c = await sign_in(app, "colleague", r.json()["temporary_password"])
    r = await c.post(
        "/api/v1/auth/password",
        json={"current_password": r.json()["temporary_password"], "new_password": GOOD},
    )
    assert r.status_code == 204, r.text
    return await sign_in(app, "colleague", GOOD)  # a fresh session and CSRF token


async def put_status(name: str, **detail: Any) -> None:
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO enrichment_status (name, detail) VALUES (:n, CAST(:d AS jsonb)) "
                "ON CONFLICT (name) DO UPDATE SET detail = CAST(:d AS jsonb)"
            ),
            {"n": name, "d": json.dumps(detail)},
        )


async def closed_gate(
    name: str = "egress", ip: str | None = EXIT_IP, *, age: timedelta = timedelta(minutes=1),
    reason: str = "ip_not_allowed",
) -> None:  # fmt: skip
    checked = (datetime.now(UTC) - age).isoformat()
    await put_status(name, open=False, reason=reason, egress_ip=ip, checked_at=checked)


async def rows(sql: str) -> list[Any]:
    async with owner_engine() as owner, owner.begin() as conn:
        return list((await conn.execute(text(sql))).all())


def body(**kw: Any) -> dict[str, Any]:
    return {"conf": CONF, "password": PASSWORD, **kw}


async def delete(c: httpx.AsyncClient, path: str, payload: dict[str, Any]) -> httpx.Response:
    return await c.request("DELETE", path, json=payload)


# ---- read -------------------------------------------------------------------------------------


async def test_get_with_nothing_uploaded(admin: httpx.AsyncClient) -> None:
    r = await admin.get(BASE)
    assert r.status_code == 200, r.text
    assert r.json() == {
        "source": "env",
        "uploaded_at": None,
        "uploaded_by": None,
        "endpoint_ip": None,
        "endpoint_port": None,
        "addresses": None,
        "peer_key_fingerprint": None,
        "gate": {
            "state": "closed",
            "reason": "no_status",
            "egress_ip": None,
            "egress_asn": None,
            "egress_org": None,
            "checked_at": None,
        },
        "trusted_exits": [],
        "trust_candidate": None,
        "trust_blocked": None,
        "config_writable": True,
        "last_check_request": None,
    }


async def test_a_viewer_gets_403_on_every_route(viewer: httpx.AsyncClient) -> None:
    calls = [
        ("GET", BASE, None),
        ("PUT", BASE, body()),
        ("DELETE", BASE, {"password": GOOD}),
        ("POST", f"{BASE}/trusted-exits", {"password": GOOD}),
        ("DELETE", f"{BASE}/trusted-exits/1", {"password": GOOD}),
    ]
    for method, path, payload in calls:
        r = await viewer.request(method, path, json=payload)
        assert r.status_code == 403, (method, path, r.status_code, r.text)
        assert r.json()["code"] == "admin_required"


async def test_anonymous_gets_401(app: Any) -> None:
    r = await browser(app).get(BASE)
    assert r.status_code == 401


# ---- upload -----------------------------------------------------------------------------------


async def test_upload_writes_files_audits_and_never_returns_the_key(
    admin: httpx.AsyncClient, vpn_dir: Path
) -> None:
    r = await admin.put(BASE, json=body())
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["source"] == "upload"
    assert (data["endpoint_ip"], data["endpoint_port"]) == ("9.9.9.50", 51820)
    assert data["addresses"] == ["198.51.100.2/32"]
    assert data["uploaded_by"] == "admin" and len(data["peer_key_fingerprint"]) == 12
    assert PRIVATE not in r.text
    env = read(vpn_dir / "wg.env")
    assert f"WIREGUARD_PRIVATE_KEY={PRIVATE}\n" in env and "WIREGUARD_ENDPOINT_PORT=51820\n" in env
    assert mode(vpn_dir / "wg.env") == 0o644
    again = (await admin.get(BASE)).json()
    assert again["source"] == "upload" and again["endpoint_ip"] == "9.9.9.50"
    assert PRIVATE not in json.dumps(again)

    audit = await rows("SELECT actor, action, target, details FROM audit_log WHERE action ~ '^vpn'")
    found = [(a.actor, a.action, a.target) for a in audit]
    assert found == [("admin", "vpn.upload", "9.9.9.50:51820")]
    dump = json.dumps([list(a) for a in audit], default=str)
    assert PRIVATE not in dump and PUBLIC not in dump


async def test_upload_replaces_the_previous_file(admin: httpx.AsyncClient, vpn_dir: Path) -> None:
    assert (await admin.put(BASE, json=body())).status_code == 200
    second = CONF.replace("9.9.9.50", "9.9.9.60")
    assert (await admin.put(BASE, json=body(conf=second))).status_code == 200
    assert "WIREGUARD_ENDPOINT_IP=9.9.9.60\n" in read(vpn_dir / "wg.env")
    assert names(vpn_dir) == ["meta.json", "wg.env"]


async def test_wrong_password_is_refused_and_nothing_is_written(
    admin: httpx.AsyncClient, vpn_dir: Path
) -> None:
    r = await admin.put(BASE, json=body(password="not the password"))
    assert r.status_code == 403 and r.json()["code"] == "reauth_failed"
    assert names(vpn_dir) == []
    assert await rows("SELECT 1 FROM audit_log WHERE action LIKE 'vpn.%'") == []


async def test_invalid_config_gives_codes_and_never_echoes_the_input(
    admin: httpx.AsyncClient, vpn_dir: Path
) -> None:
    secret = "MarkerValueThatMustNeverComeBack"
    bad = CONF.replace("DNS = 198.51.100.1", f"PostUp = {secret}") + "[Peer]\n"
    r = await admin.put(BASE, json=body(conf=bad))
    assert r.status_code == 422
    assert r.json()["code"] == "invalid_wireguard_config"
    assert r.json()["problems"] == ["duplicate_section", "forbidden_key"]
    assert secret not in r.text and PRIVATE not in r.text
    assert names(vpn_dir) == []


async def test_oversize_is_413(admin: httpx.AsyncClient, vpn_dir: Path) -> None:
    r = await admin.put(BASE, json=body(conf=CONF + "#" * 4096))
    assert r.status_code == 413 and r.json()["code"] == "too_large"
    assert names(vpn_dir) == []


async def test_missing_or_read_only_volume_is_503(
    admin: httpx.AsyncClient, vpn_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("VPN_CONFIG_DIR", str(vpn_dir / "missing"))
    for r in (
        await admin.put(BASE, json=body()),
        await delete(admin, BASE, {"password": PASSWORD}),
    ):
        assert r.status_code == 503 and r.json()["code"] == "vpn_config_unavailable"
    got = await admin.get(BASE)
    assert got.status_code == 200 and got.json()["config_writable"] is False
    assert got.json()["source"] == "env"
    assert await rows("SELECT 1 FROM audit_log WHERE action LIKE 'vpn.%'") == []


# ---- revert -----------------------------------------------------------------------------------


async def test_revert_deletes_the_files(admin: httpx.AsyncClient, vpn_dir: Path) -> None:
    assert (await admin.put(BASE, json=body())).status_code == 200
    bad = await delete(admin, BASE, {"password": "nope"})
    assert bad.status_code == 403 and "wg.env" in names(vpn_dir)
    r = await delete(admin, BASE, {"password": PASSWORD})
    assert r.status_code == 204
    assert names(vpn_dir) == []
    assert (await admin.get(BASE)).json()["source"] == "env"
    actions = [a.action for a in await rows("SELECT action FROM audit_log ORDER BY id")]
    assert actions[-2:] == ["vpn.upload", "vpn.revert"]
    # reverting again is harmless
    assert (await delete(admin, BASE, {"password": PASSWORD})).status_code == 204


# ---- trusted exits ----------------------------------------------------------------------------


async def test_get_offers_the_candidate_the_gate_observed(admin: httpx.AsyncClient) -> None:
    await closed_gate()
    data = (await admin.get(BASE)).json()
    assert data["trust_candidate"] == "9.9.9.0/24"
    assert data["gate"]["state"] == "closed" and data["gate"]["reason"] == "ip_not_allowed"
    assert data["gate"]["egress_ip"] == EXIT_IP


async def test_trust_stores_the_observed_range_and_audits(admin: httpx.AsyncClient) -> None:
    await closed_gate()
    r = await admin.post(f"{BASE}/trusted-exits", json={"password": PASSWORD})
    assert r.status_code == 201, r.text
    created = r.json()
    assert created["cidr"] == "9.9.9.0/24" and created["created_by"] == "admin"
    assert set(created) == {"id", "cidr", "created_at", "created_by"}
    data = (await admin.get(BASE)).json()
    assert [t["cidr"] for t in data["trusted_exits"]] == ["9.9.9.0/24"]
    assert data["trust_candidate"] is None  # already trusted
    audit = await rows("SELECT action, target FROM audit_log WHERE action = 'vpn.trust_exit'")
    assert [(a.action, a.target) for a in audit] == [("vpn.trust_exit", "9.9.9.0/24")]
    again = await admin.post(f"{BASE}/trusted-exits", json={"password": PASSWORD})
    assert again.status_code == 409 and again.json()["code"] == "no_candidate"


async def test_the_collector_row_is_never_used(admin: httpx.AsyncClient) -> None:
    await closed_gate("egress_collector", "2606:4700::1111")
    assert (await admin.get(BASE)).json()["trust_candidate"] is None
    r = await admin.post(f"{BASE}/trusted-exits", json={"password": PASSWORD})
    assert r.status_code == 409 and r.json()["code"] == "no_candidate"


async def test_an_ipv6_exit_gives_a_slash_48(admin: httpx.AsyncClient) -> None:
    await closed_gate(ip="2606:4700::1111")
    r = await admin.post(f"{BASE}/trusted-exits", json={"password": PASSWORD})
    assert r.status_code == 201 and r.json()["cidr"] == "2606:4700::/48"


async def test_the_client_cannot_choose_the_range(admin: httpx.AsyncClient) -> None:
    await closed_gate()
    r = await admin.post(f"{BASE}/trusted-exits", json={"password": PASSWORD, "cidr": "0.0.0.0/0"})
    assert r.status_code == 201 and r.json()["cidr"] == "9.9.9.0/24"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"age": timedelta(minutes=11)},  # stale
        {"reason": "tunnel_down"},
        {"reason": "ip_not_global"},
        {"ip": "10.1.2.3"},  # gitleaks:allow
        {"ip": "203.0.113.9"},
        {"ip": None},
    ],
)
async def test_no_candidate_when_the_gate_row_does_not_qualify(
    admin: httpx.AsyncClient, kwargs: dict[str, Any]
) -> None:
    await closed_gate(**kwargs)
    assert (await admin.get(BASE)).json()["trust_candidate"] is None
    r = await admin.post(f"{BASE}/trusted-exits", json={"password": PASSWORD})
    assert r.status_code == 409 and r.json()["code"] == "no_candidate"
    assert await rows("SELECT 1 FROM egress_trusted_exits") == []


async def test_an_open_gate_has_no_candidate(admin: httpx.AsyncClient) -> None:
    await put_status(
        "egress", open=True, reason="ok", egress_ip=EXIT_IP,
        checked_at=datetime.now(UTC).isoformat(),
    )  # fmt: skip
    assert (await admin.get(BASE)).json()["trust_candidate"] is None


async def test_trust_needs_the_password(admin: httpx.AsyncClient) -> None:
    await closed_gate()
    r = await admin.post(f"{BASE}/trusted-exits", json={"password": "nope"})
    assert r.status_code == 403 and r.json()["code"] == "reauth_failed"
    assert await rows("SELECT 1 FROM egress_trusted_exits") == []


async def test_at_most_eight_ranges(admin: httpx.AsyncClient) -> None:
    async with owner_engine() as owner, owner.begin() as conn:
        for n in range(8):
            await conn.execute(
                text("INSERT INTO egress_trusted_exits (cidr) VALUES (:c)"),
                {"c": f"192.0.2.{n * 32}/27"},
            )
    await closed_gate()
    r = await admin.post(f"{BASE}/trusted-exits", json={"password": PASSWORD})
    assert r.status_code == 409 and r.json()["code"] == "too_many"
    assert len(await rows("SELECT 1 FROM egress_trusted_exits")) == 8


async def test_untrust_removes_and_audits(admin: httpx.AsyncClient) -> None:
    await closed_gate()
    created = (await admin.post(f"{BASE}/trusted-exits", json={"password": PASSWORD})).json()
    path = f"{BASE}/trusted-exits/{created['id']}"
    bad = await delete(admin, path, {"password": "nope"})
    assert bad.status_code == 403 and len(await rows("SELECT 1 FROM egress_trusted_exits")) == 1
    assert (await delete(admin, path, {"password": PASSWORD})).status_code == 204
    assert await rows("SELECT 1 FROM egress_trusted_exits") == []
    audit = await rows("SELECT action, target FROM audit_log WHERE action = 'vpn.untrust_exit'")
    assert [(a.action, a.target) for a in audit] == [("vpn.untrust_exit", "9.9.9.0/24")]
    assert (await delete(admin, path, {"password": PASSWORD})).status_code == 204  # idempotent
    assert len(await rows("SELECT 1 FROM audit_log WHERE action = 'vpn.untrust_exit'")) == 1


async def test_audit_rows_hold_no_key_material(admin: httpx.AsyncClient) -> None:
    await admin.put(BASE, json=body())
    await closed_gate()
    await admin.post(f"{BASE}/trusted-exits", json={"password": PASSWORD})
    await delete(admin, BASE, {"password": PASSWORD})
    dump = json.dumps(
        [list(a) for a in await rows("SELECT * FROM audit_log WHERE action LIKE 'vpn.%'")],
        default=str,
    )
    assert "vpn.upload" in dump and "vpn.revert" in dump
    for secret in (PRIVATE, PUBLIC, PASSWORD):
        assert secret not in dump


# ---- the owner's own address and denied networks ----------------------------------------------


async def add_self_term(
    value: str, kind: str = "address", source: str = "manual", confirmed: bool = False
) -> None:
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO report_self_terms (kind, value, source, confirmed) "
                "VALUES (:k, :v, :s, :c)"
            ),
            {"k": kind, "v": value, "s": source, "c": confirmed},
        )


@pytest.fixture(autouse=True)
async def clean_self_terms(app: Any) -> None:
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(text("DELETE FROM report_self_terms"))


@pytest.mark.parametrize(
    ("value", "kind", "source", "confirmed"),
    [
        ("9.9.9.200", "address", "manual", False),  # same /24, another host
        ("9.9.9.0/25", "cidr", "manual", False),
        ("9.9.9.1", "address", "sensor", False),
        ("9.9.9.2", "address", "learned", True),
        (EXIT_IP, "address", "manual", False),
    ],
)
async def test_a_range_holding_a_self_address_is_never_offered(
    admin: httpx.AsyncClient, value: str, kind: str, source: str, confirmed: bool
) -> None:
    await add_self_term(value, kind, source, confirmed)
    await closed_gate()
    data = (await admin.get(BASE)).json()
    assert data["trust_candidate"] is None and data["trust_blocked"] == "exit_is_self"
    r = await admin.post(f"{BASE}/trusted-exits", json={"password": PASSWORD})
    assert r.status_code == 409 and r.json()["code"] == "exit_is_self"
    assert await rows("SELECT 1 FROM egress_trusted_exits") == []


async def test_unconfirmed_learned_addresses_do_not_block(admin: httpx.AsyncClient) -> None:
    await add_self_term("9.9.9.2", "address", "learned", False)
    await closed_gate()
    assert (await admin.get(BASE)).json()["trust_candidate"] == "9.9.9.0/24"


async def test_an_unrelated_self_address_does_not_block(admin: httpx.AsyncClient) -> None:
    await add_self_term("198.51.100.7")
    await closed_gate()
    data = (await admin.get(BASE)).json()
    assert data["trust_candidate"] == "9.9.9.0/24" and data["trust_blocked"] is None


async def test_the_gate_reason_exit_is_self_is_reported(admin: httpx.AsyncClient) -> None:
    await closed_gate(reason="exit_is_self")
    data = (await admin.get(BASE)).json()
    assert data["trust_candidate"] is None and data["trust_blocked"] == "exit_is_self"
    r = await admin.post(f"{BASE}/trusted-exits", json={"password": PASSWORD})
    assert r.status_code == 409 and r.json()["code"] == "exit_is_self"


async def test_denied_asn_blocks_the_candidate(
    admin: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("EGRESS_DENY_ASNS", "AS64496, 64511 ,junk")
    await put_status(
        "egress",
        open=False,
        reason="ip_not_allowed",
        egress_ip=EXIT_IP,
        egress_asn=64511,
        egress_org="Example Net",
        checked_at=datetime.now(UTC).isoformat(),
    )
    data = (await admin.get(BASE)).json()
    assert data["trust_candidate"] is None and data["trust_blocked"] == "exit_asn_denied"
    assert data["gate"]["egress_asn"] == 64511 and data["gate"]["egress_org"] == "Example Net"
    r = await admin.post(f"{BASE}/trusted-exits", json={"password": PASSWORD})
    assert r.status_code == 409 and r.json()["code"] == "exit_asn_denied"
    monkeypatch.setenv("EGRESS_DENY_ASNS", "64500")
    assert (await admin.get(BASE)).json()["trust_candidate"] == "9.9.9.0/24"


async def test_gate_asn_fields_are_null_when_unknown(admin: httpx.AsyncClient) -> None:
    await closed_gate()
    gate = (await admin.get(BASE)).json()["gate"]
    assert gate["egress_asn"] is None and gate["egress_org"] is None


# ---- input bounds and leftovers ---------------------------------------------------------------


async def test_a_huge_conf_is_refused_before_parsing(admin: httpx.AsyncClient) -> None:
    r = await admin.put(BASE, json=body(conf="#" * 9000))
    assert r.status_code in (413, 422)
    r = await admin.put(BASE, json=body(password="x" * 2000))
    assert r.status_code == 422


async def test_stale_temp_files_are_removed_on_write(
    admin: httpx.AsyncClient, vpn_dir: Path
) -> None:
    stale = vpn_dir / ".wg.env.crashed.tmp"
    stale.write_text("left over")
    os.utime(stale, (1, 1))
    assert (await admin.put(BASE, json=body())).status_code == 200
    assert names(vpn_dir) == ["meta.json", "wg.env"]


# ---- M24: check now, reconnect -----------------------------------------------------------------


async def test_check_now_files_a_request_and_is_rate_limited(admin: httpx.AsyncClient) -> None:
    r = await admin.post(f"{BASE}/check")  # no password
    assert r.status_code == 202, r.text
    assert set(r.json()) == {"requested_at"}
    found = await rows("SELECT requested_by, done_at FROM egress_check_requests")
    assert [(f.requested_by, f.done_at) for f in found] == [("admin", None)]
    again = await admin.post(f"{BASE}/check")
    assert again.status_code == 429 and again.json()["code"] == "too_soon"
    assert int(again.headers["Retry-After"]) >= 1
    assert len(await rows("SELECT 1 FROM egress_check_requests")) == 1
    last = (await admin.get(BASE)).json()["last_check_request"]
    assert last["requested_at"] and last["done_at"] is None
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(text("UPDATE egress_check_requests SET done_at = now()"))
    assert (await admin.get(BASE)).json()["last_check_request"]["done_at"] is not None


async def test_check_now_works_again_after_ten_seconds(admin: httpx.AsyncClient) -> None:
    assert (await admin.post(f"{BASE}/check")).status_code == 202
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text("UPDATE egress_check_requests SET requested_at = now() - interval '11 seconds'")
        )
    assert (await admin.post(f"{BASE}/check")).status_code == 202
    assert len(await rows("SELECT 1 FROM egress_check_requests")) == 2


async def test_check_now_is_admin_only(viewer: httpx.AsyncClient) -> None:
    for path, payload in ((f"{BASE}/check", None), (f"{BASE}/reconnect", {"password": GOOD})):
        r = await viewer.post(path, json=payload)
        assert r.status_code == 403 and r.json()["code"] == "admin_required"
    assert await rows("SELECT 1 FROM egress_check_requests") == []


async def test_reconnect_needs_the_password(admin: httpx.AsyncClient, vpn_dir: Path) -> None:
    r = await admin.post(f"{BASE}/reconnect", json={"password": "nope"})
    assert r.status_code == 403 and r.json()["code"] == "reauth_failed"
    assert names(vpn_dir) == []
    assert await rows("SELECT 1 FROM audit_log WHERE action = 'vpn.reconnect'") == []


async def test_reconnect_writes_the_marker_and_audits(
    admin: httpx.AsyncClient, vpn_dir: Path
) -> None:
    r = await admin.post(f"{BASE}/reconnect", json={"password": PASSWORD})
    assert r.status_code == 202, r.text
    marker = vpn_dir / "restart"
    assert names(vpn_dir) == ["restart"]  # no temp file left, nothing else touched
    assert mode(marker) == 0o644
    stamp = datetime.fromisoformat(read(marker).strip())
    assert abs(datetime.now(UTC) - stamp) < timedelta(seconds=30)
    assert read(marker) == stamp.isoformat() + "\n"  # a timestamp, nothing else
    assert r.json()["requested_at"]
    audit = await rows("SELECT action, target FROM audit_log WHERE action = 'vpn.reconnect'")
    assert [(a.action, a.target) for a in audit] == [("vpn.reconnect", "vpn")]


async def test_reconnect_at_most_once_a_minute(admin: httpx.AsyncClient, vpn_dir: Path) -> None:
    assert (await admin.post(f"{BASE}/reconnect", json={"password": PASSWORD})).status_code == 202
    first = read(vpn_dir / "restart")
    again = await admin.post(f"{BASE}/reconnect", json={"password": PASSWORD})
    assert again.status_code == 429 and again.json()["code"] == "too_soon"
    assert read(vpn_dir / "restart") == first
    old = datetime.now(UTC) - timedelta(seconds=61)
    (vpn_dir / "restart").write_text(old.isoformat() + "\n")
    assert (await admin.post(f"{BASE}/reconnect", json={"password": PASSWORD})).status_code == 202
    assert read(vpn_dir / "restart") != first
    assert len(await rows("SELECT 1 FROM audit_log WHERE action = 'vpn.reconnect'")) == 2


async def test_reconnect_without_a_writable_volume(
    admin: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("VPN_CONFIG_DIR", str(tmp_path / "missing"))
    r = await admin.post(f"{BASE}/reconnect", json={"password": PASSWORD})
    assert r.status_code == 503 and r.json()["code"] == "vpn_config_unavailable"


async def test_reconnect_waits_for_the_advisory_lock(
    admin: httpx.AsyncClient, vpn_dir: Path
) -> None:
    import asyncio

    from api.vpn_settings import RECONNECT_LOCK_KEY

    async with owner_engine() as owner, owner.connect() as conn:
        await conn.execute(text("SELECT pg_advisory_lock(:k)"), {"k": RECONNECT_LOCK_KEY})
        task = asyncio.create_task(admin.post(f"{BASE}/reconnect", json={"password": PASSWORD}))
        await asyncio.sleep(0.5)
        assert not task.done()  # serialised behind the lock
        assert not (vpn_dir / "restart").exists()
        await conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": RECONNECT_LOCK_KEY})
        r = await asyncio.wait_for(task, 5)
    assert r.status_code == 202
