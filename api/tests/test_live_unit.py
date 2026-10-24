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
