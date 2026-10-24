from __future__ import annotations

import asyncio
import ipaddress
import json
from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

import pytest
from suckerpot_common import Event, EventType, SensorName

from demo.cli import main, parse_args, run
from demo.generator import Generator
from demo.ips import is_acceptable, random_public_ip

NOW = datetime(2026, 10, 24, 12, 0, tzinfo=UTC)
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def gen_events(seed: int = 42, sessions: int = 3000, days: int = 30) -> list[Event]:
    return Generator(seed=seed, now=NOW, days=days).backfill(sessions)


@pytest.fixture(scope="module")
def events() -> list[Event]:
    return gen_events()


def by_session(evs: Sequence[Event]) -> dict[str, list[Event]]:
    out: dict[str, list[Event]] = {}
    for e in evs:
        out.setdefault(e.session_id, []).append(e)
    return out


def test_deterministic_for_seed() -> None:
    a = [e.model_dump_json() for e in gen_events(7, 300, 10)]
    b = [e.model_dump_json() for e in gen_events(7, 300, 10)]
    c = [e.model_dump_json() for e in gen_events(8, 300, 10)]
    assert a == b
    assert a != c


def test_session_count_and_ids(events: list[Event]) -> None:
    sessions = by_session(events)
    assert len(sessions) == 3000
    assert all(len(e.session_id) == 16 for e in events)


def test_events_validate_through_stream_roundtrip(events: list[Event]) -> None:
    for e in events[:2000]:
        assert Event.from_stream_fields(e.to_stream_fields()) == e


def test_sensor_mix(events: list[Event]) -> None:
    firsts = [s[0].sensor for s in by_session(events).values()]
    counts = Counter(firsts)
    total = len(firsts)
    target = {
        SensorName.ssh: 0.50,
        SensorName.web: 0.25,
        SensorName.telnet: 0.15,
        SensorName.rdp: 0.10,
    }
    for sensor, share in target.items():
        assert abs(counts[sensor] / total - share) < 0.08, (sensor, counts)


def test_ports_match_sensor(events: list[Event]) -> None:
    allowed = {
        SensorName.ssh: {22},
        SensorName.telnet: {23},
        SensorName.web: {80, 443},
        SensorName.rdp: {3389},
    }
    assert all(e.dst_port in allowed[e.sensor] for e in events)


def test_no_private_reserved_or_doc_ips(events: list[Event]) -> None:
    for ip in {str(e.src_ip) for e in events}:
        addr = ipaddress.ip_address(ip)
        assert addr.is_global
        assert not addr.is_multicast
        assert not any(addr in n for n in DOC_NETS)
        assert is_acceptable(ip)


def test_ip_generator_never_bad() -> None:
    import random

    rng = random.Random(1)
    for _ in range(5000):
        assert is_acceptable(random_public_ip(rng))
    assert not is_acceptable("10.1.2.3")  # gitleaks:allow (private range must be rejected)
    assert not is_acceptable("198.51.100.4")
    assert not is_acceptable("127.0.0.1")
    assert not is_acceptable("224.0.0.1")


def test_timestamps_inside_window(events: list[Event]) -> None:
    start = NOW - timedelta(days=30)
    assert all(start <= e.ts <= NOW for e in events)
    assert [e.ts for e in events] == sorted(e.ts for e in events)


def test_session_shape(events: list[Event]) -> None:
    for sid, evs in by_session(events).items():
        evs.sort(key=lambda e: e.ts)
        assert evs[0].type is EventType.connect, sid
        assert evs[-1].type is EventType.disconnect, sid
        assert len({(e.src_ip, e.src_port, e.sensor) for e in evs}) == 1
        dur = (evs[-1].ts - evs[0].ts).total_seconds()
        assert abs(evs[-1].data["duration_s"] - dur) < 0.01


def test_repeat_offenders_span_sensors(events: list[Event]) -> None:
    sensors_by_ip: dict[str, set[SensorName]] = {}
    sessions_by_ip: Counter[str] = Counter()
    for evs in by_session(events).values():
        ip = str(evs[0].src_ip)
        sensors_by_ip.setdefault(ip, set()).add(evs[0].sensor)
        sessions_by_ip[ip] += 1
    assert sum(1 for n in sessions_by_ip.values() if n >= 10) >= 5
    assert sum(1 for s in sensors_by_ip.values() if len(s) >= 2) >= 10


def test_ssh_content(events: list[Event]) -> None:
    ssh = [e for e in events if e.sensor is SensorName.ssh]
    logins = [e for e in ssh if e.type is EventType.login_attempt]
    assert any(e.data["success"] for e in logins)
    assert sum(1 for e in logins if not e.data["success"]) > sum(
        1 for e in logins if e.data["success"]
    )
    assert any(
        e.data.get("username") == "root" and e.data.get("password") == "123456" for e in logins
    )
    cmds = " ".join(e.data["input"] for e in ssh if e.type is EventType.command)
    for needle in ("uname -a", "authorized_keys", "xmrig", "| sh", "bins.sh"):
        assert needle in cmds


def test_downloads_are_synthetic_and_recorded(events: list[Event]) -> None:
    dls = [e for e in events if e.type is EventType.download_attempt]
    assert dls
    for e in dls:
        assert e.data["tool"] in {"wget", "curl", "tftp"}
        assert e.data["url"].split("://")[0] in {"http", "tftp"}
        host = e.data["url"].split("://")[1].split("/")[0]
        if host[0].isdigit():
            assert is_acceptable(host)
        else:
            assert host.rsplit(".", 1)[1] in {
                "xyz", "top", "site", "click", "online", "icu", "cyou", "buzz", "sbs", "shop",
            }  # fmt: skip


def test_telnet_mirai_flow(events: list[Event]) -> None:
    cmds = [
        e.data["input"]
        for e in events
        if e.sensor is SensorName.telnet and e.type is EventType.command
    ]
    assert {"enable", "system", "shell", "sh"} <= set(cmds)
    assert any(c.startswith("/bin/busybox ") for c in cmds)
    assert any("tftp" in c for c in cmds)


def test_web_content(events: list[Event]) -> None:
    reqs = [e for e in events if e.type is EventType.http_request]
    paths = {e.data["path"] for e in reqs}
    for p in ("/.env", "/wp-login.php", "/xmlrpc.php", "/phpmyadmin/", "/.git/config", "/cgi-bin/"):
        assert p in paths, p
    uas = " ".join(e.data["user_agent"] for e in reqs)
    for ua in ("curl/", "python-requests", "zgrab", "Go-http-client", "masscan", "Chrome/"):
        assert ua in uas
    assert {200, 404, 403} <= {e.data["status"] for e in reqs}


def test_php2shell_only_after_disclosure(events: list[Event]) -> None:
    hits = [
        e
        for e in events
        if e.type is EventType.http_request
        and e.data["method"] == "POST"
        and "PHP_SESSION_UPLOAD_PROGRESS" in e.data["body_preview"]
    ]
    assert len(hits) > 50
    assert all(h.data["path"].endswith(".php") for h in hits)
    assert min(h.ts for h in hits) >= NOW - timedelta(days=3, hours=1)
    recent = sum(1 for e in events if e.ts >= NOW - timedelta(days=3))
    assert recent > 0


def test_rdp_content(events: list[Event]) -> None:
    rdp = [e for e in events if e.sensor is SensorName.rdp]
    logins = [e for e in rdp if e.type is EventType.login_attempt]
    assert logins
    assert all("password" not in e.data for e in logins)
    scans = [e for e in rdp if e.type is EventType.scan]
    assert scans
    assert any(bytes.fromhex(e.data["payload_preview"]).startswith(b"\x03\x00") for e in scans)


def test_burst_days_exist(events: list[Event]) -> None:
    per_day = Counter(e.ts.date() for e in events if e.type is EventType.connect)
    avg = sum(per_day.values()) / len(per_day)
    assert max(per_day.values()) > 1.5 * avg
    telnet_day = Counter(
        e.ts.date() for e in events if e.type is EventType.connect and e.sensor is SensorName.telnet
    )
    assert max(telnet_day.values()) > 100


def test_small_window_works() -> None:
    evs = gen_events(1, 50, 1)
    assert evs
    assert all(NOW - timedelta(days=1) <= e.ts <= NOW for e in evs)


def test_dry_run_cli(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(
        ["--dry-run", "--sessions", "20", "--days", "2", "--seed", "3", "--now", NOW.isoformat()]
    )
    assert rc == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) >= 40
    for line in lines:
        Event.model_validate_json(line)
        json.loads(line)


def test_env_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEMO_DAYS", "5")
    monkeypatch.setenv("DEMO_SESSIONS", "11")
    monkeypatch.setenv("DEMO_SEED", "9")
    a = parse_args([])
    assert (a.days, a.sessions, a.seed) == (5, 11, 9)
    b = parse_args(["--days", "2", "--sessions", "3", "--seed", "1"])
    assert (b.days, b.sessions, b.seed) == (2, 3, 1)


class ListSink:
    def __init__(self) -> None:
        self.events: list[Event] = []

    async def emit(self, events: Sequence[Event]) -> None:
        self.events.extend(events)

    async def close(self) -> None:
        pass


async def test_live_only_uses_current_time() -> None:
    args = parse_args(
        ["--live-only", "--dry-run", "--live-limit", "4", "--live-min", "0", "--live-max", "0.01",
         "--live-speed", "1000"]
    )  # fmt: skip
    sink = ListSink()
    before = datetime.now(UTC)
    await asyncio.wait_for(run(args, sink), timeout=60)
    after = datetime.now(UTC)
    assert len(by_session(sink.events)) == 4
    assert all(before <= e.ts <= after for e in sink.events)


async def test_backfill_then_live_via_publisher() -> None:
    from suckerpot_common import EventPublisher

    from demo.sinks import RedisSink

    class Fake:
        def __init__(self) -> None:
            self.cmds: list[str] = []
            self.pending = 0

        def pipeline(self, transaction: bool = True) -> Fake:
            self.pending = 0
            return self

        def xadd(self, *a: object, **k: object) -> Fake:
            self.cmds.append("xadd")
            self.pending += 1
            return self

        async def execute(self, raise_on_error: bool = True) -> list[str]:
            return ["1-0"] * self.pending

        async def aclose(self) -> None:
            pass

    fake = Fake()
    args = parse_args(["--sessions", "30", "--days", "2", "--now", NOW.isoformat()])
    await run(args, RedisSink(EventPublisher(host="x", client=fake)))
    assert fake.cmds
    assert set(fake.cmds) == {"xadd"}


async def test_redis_sink_retries_dropped_events() -> None:
    from suckerpot_common import EventPublisher

    from demo.sinks import RedisSink

    evs = gen_events(1, 5, 1)[:6]

    class Pipe:
        def __init__(self, r: Flaky) -> None:
            self.r, self.n = r, 0

        def xadd(self, *a: object, **k: object) -> Pipe:
            self.n += 1
            return self

        async def execute(self, raise_on_error: bool = True) -> list[object]:
            from redis.exceptions import ResponseError

            self.r.rounds += 1
            if self.r.rounds <= 2:
                return [ResponseError("OOM command not allowed")] * self.n
            self.r.ok += self.n
            return ["1-0"] * self.n

    class Flaky:
        rounds = 0
        ok = 0

        def pipeline(self, transaction: bool = True) -> Pipe:
            return Pipe(self)

        async def aclose(self) -> None:
            pass

    fake = Flaky()
    sink = RedisSink(EventPublisher(host="x", client=fake), max_backoff=0.001)
    await sink.emit(evs)
    assert fake.ok == len(evs)
    assert sink.gave_up == 0


async def test_redis_sink_gives_up_when_bounded() -> None:
    from redis.exceptions import ConnectionError as RedisConnectionError
    from suckerpot_common import EventPublisher

    from demo.sinks import RedisSink

    class Dead:
        def pipeline(self, transaction: bool = True) -> Dead:
            return self

        def xadd(self, *a: object, **k: object) -> Dead:
            return self

        async def execute(self, raise_on_error: bool = True) -> list[object]:
            raise RedisConnectionError("down")

        async def aclose(self) -> None:
            pass

    sink = RedisSink(EventPublisher(host="x", client=Dead()), max_retries=2, max_backoff=0.001)
    await sink.emit(gen_events(1, 3, 1)[:4])
    assert sink.gave_up == 4


async def test_redis_sink_uses_per_sensor_streams() -> None:
    from suckerpot_common import EventPublisher

    from demo.sinks import RedisSink

    class Pipe:
        def __init__(self, log: list[tuple[str, str]]) -> None:
            self.log, self.n = log, 0

        def xadd(self, stream: str, fields: dict[str, str], **k: object) -> Pipe:
            self.log.append((stream, Event.from_stream_fields(fields).sensor.value))
            self.n += 1
            return self

        async def execute(self, raise_on_error: bool = True) -> list[str]:
            return ["1-0"] * self.n

    class R:
        def __init__(self) -> None:
            self.log: list[tuple[str, str]] = []

        def pipeline(self, transaction: bool = True) -> Pipe:
            return Pipe(self.log)

        async def aclose(self) -> None:
            pass

    r = R()
    sink = RedisSink(EventPublisher(host="x", client=r, stream="events"))
    await sink.emit(gen_events(2, 200, 3))
    assert r.log
    assert {s for _, s in r.log} == {"ssh", "web", "telnet", "rdp"}
    assert all(stream == f"events:{sensor}" for stream, sensor in r.log)
