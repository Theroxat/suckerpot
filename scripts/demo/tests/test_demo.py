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
from demo.plans import CAMPAIGN_HOSTS

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
        SensorName.ssh: 0.375,
        SensorName.web: 0.19,
        SensorName.telnet: 0.11,
        SensorName.rdp: 0.075,
    }
    for sensor, share in target.items():
        assert abs(counts[sensor] / total - share) < 0.08, (sensor, counts)
    service = sum(counts[s] for s in SensorName) - sum(counts[s] for s in list(SensorName)[:4])
    assert 0.15 < service / total < 0.35
    assert all(counts[s] >= 20 for s in list(SensorName)[4:]), counts


def test_ports_match_sensor(events: list[Event]) -> None:
    allowed = {
        SensorName.ssh: {22},
        SensorName.telnet: {23},
        SensorName.web: {80, 443},
        SensorName.rdp: {3389},
        SensorName.redis: {6379},
        SensorName.docker: {2375},
        SensorName.mysql: {3306},
        SensorName.adb: {5555},
        SensorName.mssql: {1433},
        SensorName.smb: {445},
        SensorName.sip: {5060},
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
        assert e.data["tool"] in {"wget", "curl", "tftp", "powershell"}
        assert e.data["url"].split("://")[0] in {"http", "tftp"}
        host = e.data["url"].split("://")[1].split("/")[0]
        if host in CAMPAIGN_HOSTS:
            continue
        if host[0].isdigit():
            assert any(ipaddress.ip_address(host) in n for n in DOC_NETS), host
        else:
            assert host.rsplit(".", 1)[1] in {"example", "test"}, host  # reserved: never real


def test_campaign_hosts_are_shared_documentation_values(events: list[Event]) -> None:
    for host in CAMPAIGN_HOSTS:
        if host[0].isdigit():
            assert any(ipaddress.ip_address(host) in n for n in DOC_NETS), host
        else:
            assert host.endswith((".example.net", ".example.org", ".example.com")), host
    dls = [e for e in events if e.type is EventType.download_attempt]
    per_host: dict[str, set[str]] = {}
    for e in dls:
        host = e.data["url"].split("://")[1].split("/")[0]
        if host in CAMPAIGN_HOSTS:
            per_host.setdefault(host, set()).add(str(e.src_ip))
    assert per_host and max(len(ips) for ips in per_host.values()) >= 20  # shared infrastructure
    hashed = [e.data["sha256"] for e in dls if "sha256" in e.data]
    assert hashed and all(len(h) == 64 and set(h) <= set("0123456789abcdef") for h in hashed)


def test_every_event_is_marked_as_demo(events: list[Event]) -> None:
    assert all(e.data.get("demo") is True for e in events)


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
    reqs = [e for e in events if e.type is EventType.http_request and e.sensor is SensorName.web]
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
        and e.sensor is SensorName.web
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
    assert all("password" not in e.data for e in logins if e.data["method"] == "rdp-cookie")
    scans = [e for e in rdp if e.type is EventType.scan]
    assert scans
    assert any(bytes.fromhex(e.data["payload_preview"]).startswith(b"\x03\x00") for e in scans)


def test_rdp_ntlm_sessions(events: list[Event]) -> None:
    rdp = [e for e in events if e.sensor is SensorName.rdp]
    ntlm = [e for e in rdp if e.type is EventType.login_attempt and e.data["method"] == "rdp-ntlm"]
    assert len(ntlm) > 20
    assert all(e.data["client_tool"] for e in ntlm)
    assert len({e.data["client_tool"] for e in ntlm}) >= 3
    assert all(e.data["domain"] is not None and "ntlm_version" in e.data for e in ntlm)
    # A password only ever appears together with a decoy match.
    matched = [e for e in ntlm if e.data["password"] is not None]
    assert matched
    assert all(e.data["success"] is True for e in matched)
    assert all(e.data["success"] is False for e in ntlm if e.data["password"] is None)
    disconnects = [e for e in rdp if e.type is EventType.disconnect]
    flags = {f for e in disconnects for f in e.data.get("flags", [])}
    assert {"rdp_ntlm", "weak_password_match", "bluekeep_probe", "rdp_nla_off"} <= flags
    nla_off = [
        e for e in rdp if e.type is EventType.login_attempt and e.data["method"] == "rdp-nla-off"
    ]
    assert nla_off and all(e.data["password"] for e in nla_off)


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
    await sink.emit(gen_events(2, 600, 3))
    assert r.log
    assert {s for _, s in r.log} == {n.value for n in SensorName}
    assert all(stream == f"events:{sensor}" for stream, sensor in r.log)


# ---- the seven service sensors ------------------------------------------------------------


def of(events: Sequence[Event], sensor: SensorName, etype: EventType | None = None) -> list[Event]:
    return [e for e in events if e.sensor is sensor and (etype is None or e.type is etype)]


def flags_of(events: Sequence[Event]) -> Counter[str]:
    c: Counter[str] = Counter()
    for e in events:
        c.update(f for f in e.data.get("flags", []) if isinstance(f, str))
    return c


def test_every_sensor_is_present(events: list[Event]) -> None:
    assert {e.sensor for e in events} == set(SensorName)


def test_redis_content(events: list[Event]) -> None:
    cmds = of(events, SensorName.redis, EventType.command)
    flags = flags_of(cmds)
    for f in (
        "cron_write",
        "ssh_key_write",
        "slaveof",
        "module_load",
        "miner",
        "ransom_note",
        "flushall",
    ):
        assert flags[f] > 0, f
    assert any(e.data["input"] == "CONFIG SET dir /var/spool/cron" for e in cmds)
    assert all({"input", "command", "argc", "flags"} <= set(e.data) for e in cmds)
    assert of(events, SensorName.redis, EventType.download_attempt)
    assert any(
        e.data["kind"] == "redis_replication"
        for e in of(events, SensorName.redis, EventType.scan)
        if "kind" in e.data
    )


def test_docker_content(events: list[Event]) -> None:
    dk = of(events, SensorName.docker)
    flags = flags_of(dk)
    for f in ("container_create", "privileged", "host_mount", "miner", "docker_sock_mount"):
        assert flags[f] > 0, f
    assert any(
        p.data["path"] == "/version" for p in of(events, SensorName.docker, EventType.http_request)
    )
    creates = [e for e in dk if e.type is EventType.command]
    assert creates and all(e.data["kind"] == "container_create" for e in creates)


def test_mysql_content(events: list[Event]) -> None:
    my = of(events, SensorName.mysql)
    flags = flags_of(my)
    for f in ("load_file", "into_outfile", "drop_database", "ransom_note", "udf"):
        assert flags[f] > 0, f
    logins = of(events, SensorName.mysql, EventType.login_attempt)
    assert len(logins) > 100 and Counter(e.data["username"] for e in logins)["root"] > 50
    assert any(e.data["success"] for e in logins)


def test_mssql_content(events: list[Event]) -> None:
    ms = of(events, SensorName.mssql)
    flags = flags_of(ms)
    for f in ("xp_cmdshell", "sp_configure", "sp_oacreate", "drop_database", "ransom_note"):
        assert flags[f] > 0, f
    assert {e.data["username"] for e in of(events, SensorName.mssql, EventType.login_attempt)} >= {
        "sa"
    }
    assert any(
        e.data["tool"] == "powershell"
        for e in of(events, SensorName.mssql, EventType.download_attempt)
    )


def test_adb_content(events: list[Event]) -> None:
    adb = of(events, SensorName.adb)
    flags = flags_of(adb)
    for f in ("adb_shell", "adb_push", "adb_install"):
        assert flags[f] > 0, f
    assert not of(events, SensorName.adb, EventType.login_attempt)  # ADB has no login
    assert any("busybox" in e.data["input"] for e in of(events, SensorName.adb, EventType.command))


def test_smb_content(events: list[Event]) -> None:
    scans = of(events, SensorName.smb, EventType.scan)
    kinds = Counter(e.data["kind"] for e in scans)
    assert kinds["smb1_negotiate"] > 0 and kinds["smb1_command"] > 0
    names = Counter(e.data["smb1_command_name"] for e in scans if e.data["kind"] == "smb1_command")
    assert names["trans2"] > 0
    logins = of(events, SensorName.smb, EventType.login_attempt)
    assert logins and all(e.data["password"] is None and e.data["method"] == "ntlm" for e in logins)
    assert any(e.data.get("dialect") for e in of(events, SensorName.smb, EventType.disconnect))
    # plain SMBv1 negotiates far outnumber exploit-looking commands
    assert kinds["smb1_negotiate"] > kinds["smb1_command"]


def test_sip_content(events: list[Event]) -> None:
    sip = of(events, SensorName.sip)
    flags = flags_of(sip)
    for f in ("options_scan", "scanner_ua", "register", "invite", "toll_fraud"):
        assert flags[f] > 0, f
    assert all("source_verified" in e.data for e in sip if e.type is not EventType.disconnect)
    users = {e.data["username"] for e in of(events, SensorName.sip, EventType.login_attempt)}
    assert {"100", "1000"} <= users
    dialled = [e.data["dialled"] for e in of(events, SensorName.sip, EventType.command)]
    assert dialled and all(d.startswith(("+", "00")) for d in dialled)
    agents = Counter(e.data["user_agent"] for e in sip if e.data.get("user_agent"))
    assert agents["friendly-scanner"] > 0


def test_service_heavy_hitters_persist(events: list[Event]) -> None:
    for sensor in list(SensorName)[4:]:
        per_ip = Counter(str(evs[0].src_ip) for evs in by_session(of(events, sensor)).values())
        assert max(per_ip.values()) >= 5, sensor


def test_service_events_stay_small(events: list[Event]) -> None:
    for e in events:
        if e.sensor in list(SensorName)[4:]:
            assert len(e.model_dump_json()) < 8000


def test_volume_and_runtime_similar_to_before() -> None:
    import time

    t0 = time.perf_counter()
    evs = gen_events(5, 3000, 30)
    assert time.perf_counter() - t0 < 20
    assert 8000 < len(evs) < 60000
