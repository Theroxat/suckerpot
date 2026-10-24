import asyncio
import json
from datetime import UTC, datetime

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from api.live import ClientQueue, LiveHub, build_summary
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
        with pytest.raises(WebSocketDisconnect) as bad:
            with c.websocket_connect("/api/v1/live", headers={"origin": "https://evil.example"}):
                pass
        assert bad.value.code == 1008
