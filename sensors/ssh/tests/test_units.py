from __future__ import annotations

import asyncio
import json

from suckerpot_common import Event

from ssh_sensor.config import Config, parse_credentials
from ssh_sensor.events import EventSink
from ssh_sensor.replay import ReplayRecorder
from ssh_sensor.shell.parser import ParseError, parse


def test_config_defaults_and_env() -> None:
    cfg = Config.from_env({})
    assert cfg.banner == "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.14"
    assert cfg.software_version == "OpenSSH_9.6p1 Ubuntu-3ubuntu13.14"
    assert ("root", "123456") in cfg.accept_credentials
    cfg = Config.from_env(
        {"SSH_ACCEPT_CREDENTIALS": "a:b:c, x:y", "SSH_PUBLIC_PORT": "2200", "SSH_MAX_PER_IP": "9"}
    )
    assert cfg.accept_credentials == {("a", "b:c"), ("x", "y")}
    assert cfg.public_port == 2200 and cfg.max_per_ip == 9


def test_config_rejects_bad_values() -> None:
    for env in ({"SSH_BANNER": "hello"}, {"SSH_HOSTNAME": "a b"}, {"SSH_ACCEPT_RANDOM_PROB": "2"}):
        try:
            Config.from_env(env)
        except ValueError:
            continue
        raise AssertionError(env)


def test_parse_credentials() -> None:
    assert parse_credentials("a:b,,bad,:x") == {("a", "b")}


def test_parser_chains() -> None:
    items = parse("a && b || c; d | e > f")
    assert [i.op for i in items] == [";", "&&", "||", ";"]
    assert len(items[3].pipeline.commands) == 2
    for bad in ("| a", "a &&", "a ;; b", "(a)"):
        try:
            parse(bad)
        except ParseError:
            continue
        raise AssertionError(bad)


def test_replay_export_is_bounded() -> None:
    rec = ReplayRecorder()
    for i in range(500):
        rec.add("o" if i % 2 else "i", f"line {i} " + "x" * 200 + "\r\n")
    frames, truncated = rec.export(12 * 1024)
    assert truncated
    assert len(json.dumps(frames, separators=(",", ":"))) <= 12 * 1024
    assert "line 499" in str(frames[-1][2])


class _Pub:
    def __init__(self) -> None:
        self.events: list[Event] = []

    async def publish(self, event: Event) -> bool:
        self.events.append(event)
        return True

    async def close(self) -> None:
        return None


async def test_sink_rate_limit_and_queue_cap() -> None:
    pub = _Pub()
    sink = EventSink(pub, rate=0.0001, burst=5, queue_size=3, dst_port=22)
    for _ in range(20):
        sink.emit(session_id="s", src_ip="203.0.113.5", src_port=1, type_=_t("connect"), data={})
    assert sink.rate_limited == 15
    assert sink.queue_full == 2 and sink.emitted == 3
    sink.start()
    await sink.flush()
    assert len(pub.events) == 3
    await asyncio.sleep(0)
    await sink.close()


def _t(name: str):  # type: ignore[no-untyped-def]
    from suckerpot_common import EventType

    return EventType(name)


async def test_oversized_replay_stays_valid(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        conn = await h.connect()
        proc = await conn.create_process(term_type="xterm", encoding="utf-8")
        for _ in range(40):
            proc.stdin.write("cat /proc/cpuinfo\r")
        proc.stdin.write("exit\r")
        await proc.wait_closed()
        conn.close()
        disc = (await h.events("disconnect"))[0]
        assert disc.data["replay_truncated"] is True
        assert len(json.dumps(disc.data["replay"], separators=(",", ":"))) <= 12 * 1024


async def test_loopback_is_quiet_by_default(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(quiet_loopback=True) as h:
        conn = await h.connect()
        await conn.run("echo x")
        conn.close()
        assert await h.events() == []
