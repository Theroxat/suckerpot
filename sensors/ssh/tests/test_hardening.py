"""Regression tests for the security review findings (ReDoS, memory, auth pipelining, ...)."""

from __future__ import annotations

import asyncio
import time
from dataclasses import replace

import asyncssh
import pytest
from asyncssh.packet import Boolean, String
from suckerpot_common import EventType

from ssh_sensor.config import Config
from ssh_sensor.events import EventSink
from ssh_sensor.shell.baseimage import build_base_image, derive_profile
from ssh_sensor.shell.interp import Shell
from ssh_sensor.watchdog import LoopWatchdog


def make_shell(**overrides: object) -> Shell:
    cfg = replace(Config(command_delay=False), **overrides)  # type: ignore[arg-type]
    profile = derive_profile("hardening-secret", "srv-web01")
    return Shell(
        cfg=cfg,
        base=build_base_image(profile),
        profile=profile,
        username="root",
        client_ip="203.0.113.9",
        client_port=40000,
        interactive=False,
        tty=False,
    )


def timed(sh: Shell, line: str) -> tuple[float, str, int]:
    start = time.perf_counter()
    res = sh.run_line(line)
    return time.perf_counter() - start, res.output, res.status


# ---- H1: ReDoS / CPU ----------
@pytest.mark.parametrize(
    "line",
    [
        "awk '{print" + " " * 4000 + "' /etc/hostname",
        "awk '/" + " " * 4000 + "' /etc/hostname",
        "awk '{print $1" + " " * 4000 + "}' /etc/passwd",
        "sed 's" + "/" * 2000 + "' /etc/hostname",
        "sed 's/" + " " * 4000 + "/x/g' /etc/passwd",
        "sed 's/a/" + "b" * 4000 + "/g' /etc/passwd",
        "grep '" + "a*" * 90 + "b' /etc/passwd",
        "grep -E '" + "(a+)+" * 30 + "$' /etc/passwd",
        "grep '" + ".*" * 90 + "x' /proc/cpuinfo",
        "echo " + " " * 4000 + "| cut -d ' ' -f1",
        "cat /proc/cpuinfo | sort -n | uniq -c | tr a-z A-Z | head -5",
        "scp " + ":" * 4000,
        "exit " + "9" * 4000,
        "kill " + "9" * 4000,
        "printf '%d' " + "9" * 4000,
        "head -" + "9" * 4000 + " /etc/passwd",
        "sed -n '" + "9" * 4000 + "p' /etc/passwd",
    ],
)
def test_attacker_input_is_cheap(line: str) -> None:
    sh = make_shell()
    elapsed, _, _ = timed(sh, line)
    assert elapsed < 0.5, f"{line[:40]!r} took {elapsed:.2f}s"


def test_awk_and_sed_still_work() -> None:
    sh = make_shell()
    assert (
        sh.run_line("awk -F: '{print $1,$NF}' /etc/passwd | head -1").output == "root /bin/bash\n"
    )
    assert sh.run_line("echo hello world | awk '{print $2}'").output == "world\n"
    assert sh.run_line("echo a-b-c | sed 's/-/+/g'").output == "a+b+c\n"
    assert sh.run_line("echo abc | sed 's#b#X#'").output == "aXc\n"


def test_line_time_budget_aborts_line() -> None:
    sh = make_shell(line_budget=0.0)
    res = sh.run_line("echo a; echo b; echo c")
    assert res.status == 137 and "Killed" in res.output
    sh.cfg = replace(sh.cfg, line_budget=1.0)
    assert sh.run_line("echo ok").output == "ok\n"


def test_unexpected_exception_is_contained(monkeypatch: pytest.MonkeyPatch) -> None:
    from ssh_sensor.shell import commands

    def boom(sh: Shell, io: object) -> int:
        raise ValueError("bug")

    monkeypatch.setitem(commands.COMMANDS, "whoami", boom)
    sh = make_shell()
    res = sh.run_line("whoami")
    assert res.status == 2 and "fork: retry" in res.output
    assert sh.run_line("echo still alive").output == "still alive\n"


async def test_watchdog_exits_when_loop_is_blocked() -> None:
    stalls: list[float] = []
    dog = LoopWatchdog(limit=0.3, interval=0.05, on_stall=stalls.append)
    dog.start()
    await asyncio.sleep(0.2)
    assert not stalls
    time.sleep(0.8)  # noqa: ASYNC251 - this is the point of the test
    await asyncio.sleep(0.1)
    dog.stop()
    assert stalls and stalls[0] > 0.3


# ---- H2: memory ----------
def test_variable_flood_is_capped() -> None:
    sh = make_shell()
    for i in range(3000):
        sh.run_line(f"v{i}={'x' * 500}")
    assert len(sh.shell_vars) + len(sh.env) <= 256
    total = sum(len(k) + len(v) for k, v in {**sh.shell_vars, **sh.env}.items())
    assert total <= 2 * 64 * 1024
    assert "cannot allocate" in sh.run_line("zzz=" + "y" * 4000).output
    sh.run_line("export " + " ".join(f"e{i}=1" for i in range(300)))
    assert len(sh.env) <= 256


def test_expansion_cannot_balloon() -> None:
    sh = make_shell()
    sh.run_line("a=" + "x" * 4000)
    res = sh.run_line("echo " + "$a" * 1000 + " | wc -c")
    assert int(res.output) <= 64 * 1024 + 1


def test_history_is_bounded_by_bytes() -> None:
    sh = make_shell(max_line=4096)
    sh.interactive = True
    for _ in range(200):
        sh.run_line("echo " + "h" * 3000)
    assert sum(len(h) + 1 for h in sh.history) <= 64 * 1024 + 4000


def test_fs_cap_is_shared_between_shells() -> None:
    first = make_shell(max_fs_bytes=100_000)
    second = Shell(
        cfg=first.cfg,
        base=first.base,
        profile=first.profile,
        username="root",
        client_ip="203.0.113.9",
        client_port=2,
        shared_fs=first.fs,
    )
    for sh in (first, second):
        for _ in range(30):
            sh.run_line("echo " + "z" * 3000 + " >> /tmp/f$RANDOM")
    assert first.fs.used_bytes <= 100_000
    assert first.fs is second.fs


async def test_channel_cap_per_connection(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(max_channels=2) as h:
        conn = await h.connect()
        p1 = await conn.create_process(term_type="xterm")
        p2 = await conn.create_process(term_type="xterm")
        with pytest.raises(asyncssh.ChannelOpenError):
            await conn.create_process(term_type="xterm")
        p1.close()
        await p1.wait_closed()
        await asyncio.sleep(0.2)
        p3 = await conn.create_process(term_type="xterm")  # a slot is free again
        for p in (p2, p3):
            p.close()
        conn.close()


async def test_1000_channels_are_refused_and_connection_dropped(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(max_channels=2, max_refused_requests=20) as h:
        conn = await h.connect()
        opened = 0
        for _ in range(1000):
            try:
                await conn.create_process(term_type="xterm")
                opened += 1
            except (asyncssh.Error, OSError):
                if conn.is_closed():
                    break
        assert opened <= 2
        assert h.sensor.channel_count() <= 2 if hasattr(h.sensor, "channel_count") else True
        await asyncio.sleep(0.2)
        assert conn.is_closed()
        disc = (await h.events("disconnect"))[0]
        assert disc.data["reason"] == "too many refused requests"


async def test_forward_flood_disconnects(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(max_refused_requests=5) as h:
        conn = await h.connect()
        for _ in range(30):
            try:
                await conn.open_connection("198.51.100.99", 25)
            except (asyncssh.Error, OSError):
                if conn.is_closed():
                    break
        await asyncio.sleep(0.2)
        assert conn.is_closed()


async def test_global_memory_budget(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(memory_budget=40_000) as h:
        conn = await h.connect()
        proc = await conn.create_process(term_type="xterm", encoding="utf-8")
        for _ in range(8):
            proc.stdin.write("echo " + "m" * 3500 + " >> /tmp/big\r")
            await asyncio.sleep(0.05)
        await asyncio.sleep(0.3)
        proc.stdin.write("echo hi\r")
        await asyncio.sleep(0.3)
        cmds = await h.events("command")
        assert any(e.data["status"] == 12 for e in cmds)
        assert "Cannot allocate memory" in cmds[-1].data["output"]
        other = await h.connect()
        with pytest.raises(asyncssh.ChannelOpenError):
            await other.create_process(term_type="xterm")
        conn.close()
        other.close()


# ---- M1: pipelined authentication ----------
async def test_pipelined_auth_is_capped(make_harness) -> None:  # type: ignore[no-untyped-def]
    from asyncssh.connection import SSHClientConnection, SSHClientConnectionOptions, _connect

    async with make_harness(max_auth_attempts=6, auth_fail_delay=(2.0, 2.0)) as h:
        loop = asyncio.get_running_loop()
        options = SSHClientConnectionOptions(
            host="127.0.0.1", port=h.port, username="root", known_hosts=None, client_keys=None
        )
        conn = await _connect(
            options,
            (),
            loop,
            0,
            None,
            lambda: SSHClientConnection(loop, options, wait="auth_methods"),
            "test",
        )
        start = time.perf_counter()
        for i in range(2000):
            try:
                await conn.send_userauth_request(b"password", Boolean(False), String(f"guess{i}"))
            except (asyncssh.Error, OSError):
                break
        await asyncio.sleep(0.5)
        elapsed = time.perf_counter() - start
        logins = await h.events("login_attempt")
        assert len(logins) <= 6, len(logins)
        assert h.sensor.rejected == 0
        assert elapsed < 10
        disc = await h.events("disconnect")
        assert disc and disc[0].data["reason"].startswith("too many authentication")
        conn.abort()


async def test_correct_password_after_cap_is_refused(make_harness) -> None:  # type: ignore[no-untyped-def]
    from ssh_sensor.server import Connection

    async with make_harness(max_auth_attempts=3, auth_fail_delay=(0.0, 0.0)) as h:
        c = Connection(h.sensor)
        results = await asyncio.gather(
            *[c._attempt("root", "wrong" if i < 5 else "root", "password") for i in range(8)]
        )
        assert results == [False] * 8
        assert c.attempts == 8


# ---- M2: event starvation ----------
class _Pub:
    def __init__(self) -> None:
        self.events: list[object] = []

    async def publish(self, event: object) -> bool:
        self.events.append(event)
        return True

    async def close(self) -> None:
        return None


def _emit(sink: EventSink, sid: str, type_: EventType, n: int = 1) -> int:
    return sum(
        sink.emit(session_id=sid, src_ip="203.0.113.5", src_port=1, type_=type_, data={})
        for _ in range(n)
    )


async def test_one_session_cannot_starve_another() -> None:
    sink = EventSink(_Pub(), noisy_rate=0.001, noisy_burst=5, global_rate=1e6, global_burst=1e6)
    assert _emit(sink, "flooder", EventType.login_attempt, 500) == 5
    assert _emit(sink, "victim", EventType.login_attempt, 3) == 3
    assert _emit(sink, "flooder", EventType.command, 3) == 3  # valuable quota is separate
    assert _emit(sink, "flooder", EventType.download_attempt, 3) == 3
    assert sink.end_session("flooder") == 495


async def test_global_cap_counts_disconnect_and_keeps_a_reserve() -> None:
    sink = EventSink(
        _Pub(), global_rate=0.001, global_burst=20, valuable_burst=1000, queue_size=100
    )
    assert _emit(sink, "a", EventType.command, 50) == 18  # 10% of the burst is held back
    assert sink.global_limited == 32
    # a disconnect without priority (session never logged in) cannot use the reserve
    assert _emit(sink, "b", EventType.disconnect, 1) == 0

    def urgent(*, priority: bool = False, force: bool = False) -> bool:
        return sink.emit(
            session_id="c",
            src_ip="203.0.113.5",
            src_port=1,
            type_=EventType.disconnect,
            data={},
            priority=priority,
            force=force,
        )

    # priority disconnects and forced events share the reserve, then they are dropped too
    assert [urgent(priority=True), urgent(force=True), urgent(priority=True)] == [
        True,
        True,
        False,
    ]
    assert sink.priority_dropped == 1


async def test_suppressed_count_reported_on_disconnect(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        h.sink._noisy.burst = 3
        h.sink._noisy.rate = 0.0001
        conn = await h.connect()
        for i in range(10):
            try:
                await conn.open_connection("198.51.100.99", 25 + i)
            except (asyncssh.Error, OSError):
                pass
        conn.close()
        await asyncio.sleep(0.2)
        disc = (await h.events("disconnect"))[0]
        assert disc.data["events_suppressed"] >= 6
        scans = [e for e in await h.events("scan") if e.data.get("kind") == "events_suppressed"]
        assert scans and scans[0].data["count"] == disc.data["events_suppressed"]


# ---- M3: exceptions ----------
@pytest.mark.parametrize(
    "line",
    [
        "exit ²",
        "kill ²",
        "printf '%d' ²",
        "head -² /etc/passwd",
        "cut -f² -d: /etc/passwd",
        "sed -n '²p' /etc/passwd",
        "test ² -eq 1",
        "echo x > /tmp/a; sort -n /tmp/a",
        "exit " + "1" * 5000,
    ],
)
def test_unicode_and_huge_numbers_do_not_raise(line: str) -> None:
    sh = make_shell()
    res = sh.run_line(line)
    assert res.status in range(0, 256)


def test_corrupt_passwd_does_not_break_new_sessions() -> None:
    sh = make_shell()
    sh.run_line("echo 'evil:x:²:²:x:/home/evil:/bin/bash' >> /etc/passwd")
    sh.run_line("echo 'evil2:x:" + "9" * 5000 + ":1:x:/h:/bin/sh' >> /etc/passwd")
    assert sh.run_line("su evil").status in (0, 1)
    assert sh.run_line("id").status == 0


async def test_exec_is_recorded_with_replay_frame(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        conn = await h.connect()
        await conn.run("exit ²", check=False)
        conn.close()
        cmds = await h.events("command")
        assert cmds and cmds[0].data["input"] == "exit ²"
        disc = (await h.events("disconnect"))[0]
        assert any(f[1] == "i" and "exit" in f[2] for f in disc.data["replay"])


# ---- M4: fingerprints ----------
def test_profile_depends_on_secret_not_public_data() -> None:
    a = derive_profile("secret-one", "srv-web01")
    b = derive_profile("secret-two", "srv-web01")
    assert (a.ip, a.mac, a.public_ip) != (b.ip, b.mac, b.public_ip)
    assert derive_profile("secret-one", "srv-web01").ip == a.ip


def test_no_documentation_or_example_addresses_leak() -> None:
    sh = make_shell()
    out = sh.run_line(
        "curl ifconfig.me; ping -c1 example.org; wget http://example.org/x -O /tmp/x; "
        "apt-get update; cat /var/log/auth.log; ip a; ifconfig; hostname -I"
    ).output
    for bad in ("203.0.113.", "198.51.100.", "192.0.2.", "93.184.216.34"):
        assert bad not in out.replace("198.51.100.7", "")
    ip = sh.profile.resolve("example.org")
    assert out.count(ip) >= 3  # ping, wget and apt use the same stable address
    assert sh.profile.public_ip in out


def test_secret_file_is_private(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from ssh_sensor.hostkeys import load_or_create_secret

    first = load_or_create_secret(tmp_path / "keys")
    assert len(first) == 64
    path = tmp_path / "keys" / "profile_secret"
    assert (path.stat().st_mode & 0o777) == 0o600
    assert load_or_create_secret(tmp_path / "keys") == first


def test_errors_go_to_stderr_without_pty() -> None:
    sh = make_shell()
    res = sh.run_line("ls /nope; echo out")
    assert res.chunks[0][0] is True and res.chunks[-1] == (False, "out\n")


def test_ls_columns_adapt_to_widest_entry() -> None:
    sh = make_shell()
    sh.run_line("cd /tmp; echo x > a; echo " + "y" * 20000 + " > b")
    lines = sh.run_line("ls -l /tmp/a /tmp/b").output.splitlines()
    sizes_end = [ln.index(" /tmp") for ln in lines]
    assert sizes_end[0] == sizes_end[1]


def test_python_and_perl_one_liners() -> None:
    sh = make_shell()
    assert sh.run_line("python3 -c 'print(\"hi\")'").output == "hi\n"
    out = sh.run_line("python3 -c 'import requests'").output
    assert "ModuleNotFoundError: No module named 'requests'" in out
    assert sh.run_line("perl -e 'print \"x\"'").output == "x"
    assert "can't open file" in sh.run_line("python3 /tmp/nope.py").output


async def test_sftp_subsystem_is_accepted_then_closed(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        conn = await h.connect()
        with pytest.raises(asyncssh.Error):
            async with conn.start_sftp_client():
                pass
        conn.close()
        cmds = await h.events("command")
        assert any(e.data["input"] == "subsystem sftp" for e in cmds)


async def test_line_flood_does_not_starve_the_event_loop(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        conn = await h.connect()
        proc = await conn.create_process(term_type="xterm", encoding="utf-8")
        proc.stdin.write("echo flood\r" * 3000)
        worst = 0.0
        for _ in range(20):
            start = time.perf_counter()
            await asyncio.sleep(0.01)
            worst = max(worst, time.perf_counter() - start)
        assert worst < 1.0, worst
        conn.close()


async def test_command_limit_ends_session(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(max_commands=5) as h:
        conn = await h.connect()
        proc = await conn.create_process(term_type="xterm", encoding="utf-8")
        proc.stdin.write("true\r" * 20)
        await asyncio.wait_for(proc.wait_closed(), 5)
        disc = (await h.events("disconnect"))[0]
        assert disc.data["reason"] == "command limit"
        conn.close()


def test_exit_error_message_is_kept() -> None:
    sh = make_shell()
    res = sh.run_line("exit ²")
    assert res.exit and res.status == 2 and "numeric argument required" in res.output
