import asyncio
import json
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from api.live import (
    ClientQueue,
    LiveHub,
    LivePoller,
    _origin_ok,
    allowed_origins,
    build_summary,
    normalize_origin,
    rows_to_live,
)
from api.main import create_app
from api.schemas import LiveEvent


def test_queue_drops_oldest_and_counts() -> None:
    q = ClientQueue(maxsize=3)
    for i in range(5):
        q.put((i, str(i)))
    assert [i for i, _ in q.items] == [2, 3, 4]
    assert q.take_dropped() == 2
    assert q.take_dropped() == 0


async def test_queue_get_and_close() -> None:
    q = ClientQueue(maxsize=2)
    waiter = asyncio.create_task(q.get())
    await asyncio.sleep(0)
    q.put((1, "a"))
    assert await waiter == (1, "a")
    waiter = asyncio.create_task(q.get())
    await asyncio.sleep(0)
    q.close()
    assert await waiter is None


def _event(i: int = 1) -> LiveEvent:
    return LiveEvent(
        id=i, ts=datetime(2026, 10, 24, tzinfo=UTC), sensor="ssh", session_id="s",
        type="command", src_ip="203.0.113.7", src_port=1, dst_port=2, summary="ran `id`",
        country=None, city=None, asn=None, org=None, abuse_score=None, known_scanner=None,
        tags=[],
    )  # fmt: skip


def test_hub_limits_and_broadcast() -> None:
    hub = LiveHub(max_clients=2)
    a, b = hub.add(), hub.add()
    assert a is not None and b is not None
    assert hub.add() is None
    hub.broadcast_event(_event(7))
    assert a.items[0][0] == 7
    msg = json.loads(a.items[0][1])
    assert msg["kind"] == "event"
    assert msg["event"]["id"] == 7 and msg["event"]["ts"].startswith("2026-10-24T00:00:00")
    assert set(msg["event"]) == {
        "id", "ts", "sensor", "session_id", "type", "src_ip", "src_port", "dst_port",
        "summary", "country", "city", "asn", "org", "abuse_score", "known_scanner", "tags",
        "benign",
    }  # fmt: skip
    hub.remove(a)
    assert hub.add() is not None


@pytest.mark.parametrize(
    ("etype", "data", "expected"),
    [
        ("connect", {}, "connected"),
        ("login_attempt", {"username": "root", "password": "123456", "success": False},
         "login root/123456 failed"),
        ("login_attempt", {"username": "admin", "password": "x", "success": True},
         "login admin/x succeeded"),
        ("command", {"input": "uname -a"}, "ran `uname -a`"),
        ("http_request", {"method": "GET", "path": "/wp-login.php", "status": 404},
         "GET /wp-login.php → 404"),
        ("http_request", {"method": "POST", "path": "/x"}, "POST /x"),
        ("download_attempt", {"url": "http://198.51.100.9/x.sh", "tool": "wget"},
         "download http://198.51.100.9/x.sh via wget"),
        ("disconnect", {"duration_s": 12.4}, "disconnected after 12s"),
        ("disconnect", {}, "disconnected"),
        ("scan", {}, "probe"),
        ("scan", {"kind": "tcp_forward_attempt", "host": "192.0.2.5", "port": 25},
         "port-forward attempt to 192.0.2.5:25"),
        ("scan", {"kind": "banner_grab"}, "probe (banner_grab)"),
        ("command", {"input": "scp -t /tmp", "output": "", "scp_upload": [
            {"name": "x.sh", "mode": "0755", "size": 10, "sha256": "ab"}]},
         "scp upload x.sh"),
        ("command", {"input": "scp -t /tmp", "scp_upload": [{"name": "a"}, {"name": "b"}]},
         "scp upload a (+1 more)"),
        ("command", {"input": "id", "output": "uid=0", "prompt": "root@h:~#", "cwd": "/root",
                     "user": "root", "status": 0}, "ran `id`"),
        ("disconnect", {"duration_s": 9.0, "reason": "closed", "replay": [[0.1, "o", "hi"]],
                        "commands": 1}, "disconnected after 9s"),
        ("weird", None, "weird"),
    ],
)  # fmt: skip
def test_build_summary(etype: str, data: dict[str, object] | None, expected: str) -> None:
    assert build_summary(etype, data) == expected


def test_summary_sanitises_and_truncates() -> None:
    s = build_summary("command", {"input": "a\x1b[31m\nb" + "x" * 500})
    assert "\x1b" not in s and "\n" not in s
    assert len(s) <= 110
    assert len(build_summary("login_attempt", {"username": "u" * 500, "password": "p" * 500})) < 150


def test_ws_rejects_when_full_and_bad_origin() -> None:
    app = create_app(None, enable_live=False)
    app.state.hub.max_clients = 0
    with TestClient(app) as c:
        with pytest.raises(WebSocketDisconnect) as full:
            with c.websocket_connect("/api/v1/live") as ws:
                ws.receive_text()
        assert full.value.code == 1013
        for origin in ("https://evil.example", "null"):
            with pytest.raises(WebSocketDisconnect) as bad:
                with c.websocket_connect("/api/v1/live", headers={"origin": origin}):
                    pass
            assert bad.value.code == 1008


def test_summary_strips_invisible_and_bidi() -> None:
    nasty = "a\u202eb\u200bc\ufeffd\u2028e\ud800f\ue000g"
    assert build_summary("command", {"input": nasty}) == "ran `abcdefg`"


def test_hub_per_ip_cap() -> None:
    hub = LiveHub(max_per_ip=2)
    a, b = hub.add("192.0.2.1"), hub.add("192.0.2.1")
    assert a and b and hub.add("192.0.2.1") is None
    assert hub.add("192.0.2.2") is not None
    hub.remove(a)
    assert hub.add("192.0.2.1") is not None
    hub.remove(a)  # double remove must not corrupt counts
    assert hub.per_ip["192.0.2.1"] == 2


@pytest.mark.parametrize(
    ("raw", "norm"),
    [
        ("https://Example.COM", "https://example.com"),
        ("https://example.com:443/", "https://example.com"),
        ("http://example.com:8080", "http://example.com:8080"),
        ("http://[2001:db8::1]:80", "http://[2001:db8::1]"),
        ("null", None),
        ("", None),
        ("ftp://example.com", None),
        ("https://example.com/path", None),
        ("https://user@example.com", None),
        ("https://example.com:99999", None),
        ("example.com", None),
    ],
)
def test_normalize_origin(raw: str, norm: str | None) -> None:
    assert normalize_origin(raw) == norm


def test_allowed_origins_ignores_malformed() -> None:
    got = allowed_origins("https://a.example, nonsense ,http://b.example:81,")
    assert got == {"https://a.example", "http://b.example:81"}


def _ws(origin: str | None, host: str = "dash.example:8443", scheme: str = "ws") -> Any:
    headers = {"host": host}
    if origin is not None:
        headers["origin"] = origin
    return SimpleNamespace(headers=headers, url=SimpleNamespace(scheme=scheme))


def test_origin_check(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("API_ALLOWED_ORIGINS", raising=False)
    assert _origin_ok(_ws(None))
    assert _origin_ok(_ws("http://dash.example:8443"))
    assert not _origin_ok(_ws("https://dash.example:8443"))  # scheme must match too
    assert not _origin_ok(_ws("http://dash.example:9999"))
    assert not _origin_ok(_ws("null"))
    assert _origin_ok(_ws("https://dash.example:8443", scheme="wss"))
    monkeypatch.setenv("API_ALLOWED_ORIGINS", "https://public.example, junk")
    assert _origin_ok(_ws("https://public.example"))


def test_rows_to_live_skips_bad_rows() -> None:
    good = SimpleNamespace(
        id=1, ts=datetime(2026, 10, 24, tzinfo=UTC), sensor="ssh", session_id="s", type="connect",
        src_ip="203.0.113.7", src_port=1, dst_port=2, data={}, country=None, city=None,
        asn=None, org=None, abuse_score=None, known_scanner=None, tags=None,
    )  # fmt: skip
    bad = SimpleNamespace(**{**vars(good), "id": 2, "data": "not-a-mapping", "type": "command"})
    out = rows_to_live([bad, good])
    assert [e.id for e in out] == [1]


async def test_poller_advances_past_bad_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    bad = SimpleNamespace(id=9, data=object(), type="command")

    async def fake_fetch(_s: Any, _last: int, limit: int = 500) -> list[Any]:
        return [bad]

    class Ctx:
        async def __aenter__(self) -> "Ctx":
            return self

        async def __aexit__(self, *a: Any) -> None:
            return None

    monkeypatch.setattr("api.live.fetch_after", fake_fetch)
    hub = LiveHub()
    q = hub.add("x")
    poller = LivePoller(lambda: Ctx(), hub)  # type: ignore[arg-type]
    poller.last_id = 5
    assert await poller.poll_once() == 1
    assert poller.last_id == 9 and q is not None and not q.items


@pytest.mark.parametrize(
    ("sensor", "etype", "data", "expected"),
    [
        (
            "redis",
            "command",
            {"input": "CONFIG SET dir /var/spool/cron"},
            "redis CONFIG SET dir /var/spool/cron",
        ),
        (
            "redis",
            "login_attempt",
            {"password": "x", "success": False},
            "redis login default failed",
        ),
        (
            "docker",
            "http_request",
            {
                "method": "POST",
                "path": "/containers/create",
                "flags": ["container_create", "privileged", "image:alpine"],
            },
            "docker create privileged alpine",
        ),
        (
            "docker",
            "http_request",
            {"method": "GET", "path": "/version", "status": 200},
            "GET /version → 200",
        ),
        (
            "mysql",
            "login_attempt",
            {"username": "root", "success": False},
            "mysql login root failed",
        ),
        ("mssql", "login_attempt", {"username": "sa", "success": True}, "mssql login sa succeeded"),
        (
            "mssql",
            "command",
            {"input": "EXEC xp_cmdshell 'whoami'"},
            "mssql EXEC xp_cmdshell 'whoami'",
        ),
        ("adb", "command", {"input": "getprop", "flags": ["adb_shell"]}, "adb shell getprop"),
        ("adb", "command", {"input": "shell getprop", "flags": ["adb_shell"]}, "adb shell getprop"),
        (
            "adb",
            "command",
            {"input": "/sdcard/x.apk", "flags": ["adb_install"]},
            "adb install /sdcard/x.apk",
        ),
        ("sip", "scan", {"method": "INVITE", "to": "+41791234567"}, "SIP INVITE to +41791234567"),
        ("sip", "scan", {"flags": ["options_scan"]}, "SIP OPTIONS scan"),
        (
            "synology",
            "http_request",
            {"method": "POST", "path": "/webapi/entry.cgi", "flags": ["dsm_api", "sid_forge"]},
            "Synology DSM forged session id (CVE-2026-13639)",
        ),
        (
            "synology",
            "login_attempt",
            {"username": "admin", "password": "x", "success": False},
            "Synology DSM login admin failed",
        ),
        ("synology", "http_request", {"method": "GET", "path": "/", "status": 200}, "GET / → 200"),
        (
            "smb",
            "scan",
            {"kind": "smb1_negotiate", "smb1_outcome": "reset", "flags": ["smbv1"]},
            "SMBv1 negotiate (reset)",
        ),
        (
            "smb",
            "scan",
            {"kind": "smb1_negotiate", "smb1_outcome": "steer_smb2_wildcard"},
            "SMBv1 negotiate (steer smb2 wildcard)",
        ),
        (
            "smb",
            "scan",
            {"kind": "smb1_command", "smb1_command_name": "trans2", "flags": ["smbv1"]},
            "SMBv1 trans2",
        ),
        ("smb", "scan", {"kind": "non_smb", "protocol_guess": "http"}, "SMB non smb"),
        (
            "smb",
            "login_attempt",
            {
                "username": "admin",
                "domain": "WORKGROUP",
                "method": "ntlm",
                "success": False,
                "password": None,
            },
            "SMB NTLM login WORKGROUP\\admin",
        ),
        (
            "smb",
            "login_attempt",
            {"username": "", "anonymous": True, "flags": ["null_session"]},
            "SMB null session",
        ),
        (
            "sip",
            "login_attempt",
            {"username": "100", "method": "REGISTER", "response_code": 401},
            "SIP REGISTER 100",
        ),
        (
            "sip",
            "command",
            {
                "input": "INVITE sip:0041@x SIP/2.0",
                "dialled": "+41791234567",
                "method": "INVITE",
                "response_code": 100,
                "flags": ["invite"],
            },
            "SIP INVITE to +41791234567 100",
        ),
        (
            "sip",
            "scan",
            {"kind": "sip_summary", "messages": 40},
            "SIP session summary (40 messages)",
        ),
        (
            "sip",
            "scan",
            {
                "kind": "options_scan",
                "method": "OPTIONS",
                "user_agent": "friendly-scanner",
                "flags": ["options_scan", "scanner_ua"],
            },
            "SIP OPTIONS scan (friendly-scanner)",
        ),
        (
            "adb",
            "command",
            {"input": "adb push /sdcard/x.sh", "flags": ["adb_push"]},
            "adb push /sdcard/x.sh",
        ),
        ("adb", "scan", {"kind": "adb_service", "service": "tcp:22"}, "ADB open tcp:22"),
        (
            "redis",
            "scan",
            {"kind": "redis_replication", "master_host": "192.0.2.9", "master_port": 6379},
            "Redis replication from 192.0.2.9:6379",
        ),
        (
            "redis",
            "scan",
            {"kind": "cross_protocol", "protocol_guess": "http"},
            "Redis cross-protocol (http)",
        ),
        (
            "docker",
            "command",
            {
                "kind": "container_create",
                "image": "alpine",
                "flags": ["container_create", "docker_sock_mount"],
            },
            "docker create host-mount alpine",
        ),
        ("docker", "command", {"kind": "exec", "input": "sh -c id"}, "docker exec sh -c id"),
        (
            "docker",
            "login_attempt",
            {"username": "u", "method": "registry_auth", "success": False},
            "docker login u failed",
        ),
        ("docker", "scan", {"kind": "non_http"}, "Docker probe (non http)"),
        ("smb", "scan", {"flags": ["eternalblue"]}, "SMB EternalBlue exploit attempt"),
        ("smb", "scan", {"kind": "negotiate", "dialect": "3.1.1"}, "SMB negotiate (SMB 3.1.1)"),
        ("smb", "scan", {"kind": "negotiate", "dialect": "SMB 2.1"}, "SMB negotiate (SMB 2.1)"),
        ("smb", "scan", {"flags": ["smbv1"]}, "SMBv1 probe"),
        ("smb", "scan", {}, "SMB probe"),
        (
            "sip",
            "scan",
            {"flags": ["options_scan"], "user_agent": "friendly-scanner"},
            "SIP OPTIONS scan (friendly-scanner)",
        ),
        ("sip", "scan", {"method": "REGISTER", "status": 100}, "SIP REGISTER 100"),
        ("redis", "scan", {"kind": "non_resp"}, "Redis probe (non resp)"),
        ("docker", "scan", {"flags": ["bad_json"]}, "Docker probe (bad json)"),
        ("adb", "scan", {"kind": "cnxn_garbage"}, "ADB probe (cnxn garbage)"),
        ("mysql", "scan", {}, "MySQL probe"),
        ("ssh", "command", {"input": "id"}, "ran `id`"),
        (
            "rdp",
            "login_attempt",
            {
                "method": "rdp-ntlm",
                "domain": "OFFICE",
                "username": "administrator",
                "password": None,
                "client_tool": "FreeRDP",
            },
            "RDP NTLM login OFFICE\\administrator (FreeRDP)",
        ),
        (
            "rdp",
            "login_attempt",
            {
                "method": "rdp-ntlm",
                "username": "administrator",
                "password": "P@ssw0rd",
                "success": True,
                "client_tool": "unknown",
            },
            "RDP login administrator / P@ssw0rd (weak password)",
        ),
        (
            "rdp",
            "login_attempt",
            {"method": "rdp-ntlm", "username": "", "anonymous": True, "client_tool": "nmap"},
            "RDP null session (nmap)",
        ),
        (
            "rdp",
            "login_attempt",
            {
                "method": "rdp-nla-off",
                "username": "evil",
                "password": "x",
                "client_tool": "rdesktop",
            },
            "RDP cleartext login evil (rdesktop)",
        ),
        ("rdp", "disconnect", {"flags": ["rdp_ntlm", "bluekeep_probe"]}, "BlueKeep probe"),
        ("rdp", "disconnect", {"duration_s": 2, "flags": ["rdp_ntlm"]}, "disconnected after 2s"),
        (
            "rdp",
            "login_attempt",
            {"method": "rdp-cookie", "username": "nmap", "password": None, "success": False},
            "RDP connection request nmap",
        ),
        ("redis", "disconnect", {"duration_s": 3}, "disconnected after 3s"),
    ],
)
def test_build_summary_per_sensor(
    sensor: str, etype: str, data: dict[str, object], expected: str
) -> None:
    assert build_summary(etype, data, sensor) == expected


def test_service_summary_sanitises() -> None:
    s = build_summary("command", {"input": "SET a \x1b[31m‮x" + "y" * 300}, "redis")
    assert "\x1b" not in s and "‮" not in s and len(s) <= 160


def test_scan_summary_sanitises_attacker_strings() -> None:
    s = build_summary(
        "scan", {"flags": ["options_scan"], "user_agent": "evil\x1b[2J‮" + "a" * 200}, "sip"
    )
    assert "\x1b" not in s and "‮" not in s and len(s) <= 160
    assert "\n" not in build_summary("scan", {"kind": "x\ny" * 50}, "redis")


def test_rdp_summary_sanitises_attacker_strings() -> None:
    s = build_summary(
        "login_attempt",
        {
            "method": "rdp-ntlm",
            "username": "a\x1b[2J‮" + "u" * 200,
            "domain": "d\n" * 50,
            "password": "p\x07" + "w" * 200,
            "client_tool": "t\x1b" * 20,
        },
        "rdp",
    )
    assert "\x1b" not in s and "‮" not in s and "\n" not in s and "\x07" not in s
    assert len(s) <= 200


async def test_session_watch_gives_up_after_repeated_database_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sqlalchemy.exc import OperationalError

    import api.live as live

    monkeypatch.setattr(live, "SESSION_RECHECK_S", 0.001)
    calls = 0

    class Auth:
        async def resolve(self, *_: object) -> object:
            nonlocal calls
            calls += 1
            raise OperationalError("select", {}, Exception("down"))

    assert await live._session_watch(Auth(), "t", None) is False  # close with 1013
    assert calls == live.MAX_SESSION_CHECK_FAILURES


async def test_session_watch_survives_a_short_hiccup_then_reports_revocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sqlalchemy.exc import OperationalError

    import api.live as live

    monkeypatch.setattr(live, "SESSION_RECHECK_S", 0.001)
    answers: list[object] = [OperationalError("s", {}, Exception("x"))] * 5 + [object(), None]

    class Auth:
        async def resolve(self, *_: object) -> object:
            a = answers.pop(0)
            if isinstance(a, Exception):
                raise a
            return a

    assert await live._session_watch(Auth(), "t", None) is True  # revoked, not unavailable
