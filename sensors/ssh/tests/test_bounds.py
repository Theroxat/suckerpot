"""Every output is bounded BEFORE it is built: large inputs give capped output, small peaks.

Each test feeds a moderately large input (at most 1 MB, allocated before measuring) and checks
both the size of the output and the peak of new allocations made while producing it.
"""

from __future__ import annotations

import asyncio
import logging
import tracemalloc
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

import asyncssh
import pytest
from suckerpot_common import EventType

from ssh_sensor.config import Config
from ssh_sensor.events import EventSink
from ssh_sensor.server import Connection, Sensor, _scp_size
from ssh_sensor.shell import cmd_fs, cmd_sys, cmd_text
from ssh_sensor.shell import interp as interp_mod
from ssh_sensor.shell.baseimage import build_base_image, derive_profile
from ssh_sensor.shell.core import MAX_IO_CHARS, CmdIO
from ssh_sensor.shell.fs import FSError
from ssh_sensor.shell.interp import MAX_WORD, Shell
from ssh_sensor.shell.util import MAX_LINE_CHARS, MAX_LINES, split_lines

MB = 1024 * 1024
BUDGET = 4 * MB  # peak of NEW allocations allowed while handling a 1 MB input

PROFILE = derive_profile("bounds-secret", "srv-web01")
BASE = build_base_image(PROFILE)


def make_shell(**overrides: object) -> Shell:
    cfg = replace(Config(command_delay=False, line_budget=30.0), **overrides)  # type: ignore[arg-type]
    return Shell(
        cfg=cfg,
        base=BASE,
        profile=PROFILE,
        username="root",
        client_ip="203.0.113.9",
        client_port=40000,
        interactive=True,
        tty=False,
    )


class Peak:
    value = 0


@contextmanager
def peak_memory() -> Iterator[Peak]:
    result = Peak()
    tracemalloc.start()
    try:
        yield result
    finally:
        _, result.value = tracemalloc.get_traced_memory()
        tracemalloc.stop()


def run_cmd(
    fn: Callable[[Shell, CmdIO], int], args: list[str], stdin: str | None = None
) -> tuple[CmdIO, int]:
    sh = make_shell()
    sh._deadline = float("inf")  # called outside run_line: no CPU budget
    io = CmdIO(args=args, stdin=stdin)
    with peak_memory() as peak:
        fn(sh, io)
    return io, peak.value


def out(io: CmdIO) -> str:
    return "".join(io.out)


def big_file(sh: Shell, path: str, data: bytes) -> None:
    sh.fs.write(path, data, append=False, owner="root")


# ---- split_lines ---------------------------------------------------------------------------
def test_split_lines_caps_every_line_and_the_count() -> None:
    one_line = "x" * MB
    many = "ab\n" * (MB // 3)
    with peak_memory() as peak:
        lines = split_lines(one_line)
        lines2 = split_lines(many)
    assert lines == ["x" * MAX_LINE_CHARS]
    assert len(lines2) == MAX_LINES and all(ln == "ab" for ln in lines2)
    assert peak.value < BUDGET


def test_split_lines_keeps_the_old_semantics() -> None:
    assert split_lines("") == []
    assert split_lines("\n") == [""]
    assert split_lines("a\n\nb") == ["a", "", "b"]
    assert split_lines("a\nb\n") == ["a", "b"]


# ---- sed -----------------------------------------------------------------------------------
@pytest.mark.parametrize("text", ["a" * MB, "a\n" * (MB // 2)])
def test_sed_replacement_is_bounded(text: str) -> None:
    io, peak = run_cmd(cmd_text.cmd_sed, ["s/a/" + "B" * 1000 + "/g"], text)
    result = out(io)
    assert len(result) <= MAX_IO_CHARS
    assert all(len(line) <= MAX_LINE_CHARS for line in result.split("\n"))
    assert "B" * 257 not in result  # replacement capped at 256 characters
    assert peak < BUDGET


def test_sed_bounded_replace_matches_str_replace() -> None:
    br = cmd_text._bounded_replace
    for line in ["", "abc", "aaa", "xaxbxa", "a-b-c"]:
        for old, new in [("a", "Z"), ("-", "+"), ("x", ""), ("ab", "QQ")]:
            assert br(line, old, new, True, 100) == line.replace(old, new)
            assert br(line, old, new, False, 100) == line.replace(old, new, 1)
    assert br("a" * 50, "a", "bb", True, 31) == "b" * 31


# ---- tr ------------------------------------------------------------------------------------
def test_tr_input_and_sets_are_bounded() -> None:
    io, peak = run_cmd(cmd_text.cmd_tr, ["a-z", "A-Z"], "abc" * (MB // 3))
    assert len(out(io)) <= MAX_IO_CHARS and out(io).startswith("ABCABC")
    assert peak < BUDGET
    huge_set = "\\x00-\\x7f" * 1000 + "a-z" * 1000
    assert len(cmd_text._expand_set(huge_set)) <= cmd_text.MAX_TR_SET
    io, peak = run_cmd(cmd_text.cmd_tr, ["a" * 4000, "b"], "a" * MB)  # padding of dst
    assert len(out(io)) <= MAX_IO_CHARS
    assert peak < BUDGET


# ---- cat -n, base64 ------------------------------------------------------------------------
def test_cat_n_is_bounded() -> None:
    sh = make_shell()
    big_file(sh, "/tmp/big", b"x\n" * (MB // 2 - 8))
    io = CmdIO(args=["-n", "/tmp/big", "/tmp/big", "/tmp/big"])
    with peak_memory() as peak:
        cmd_fs.cmd_cat(sh, io)
    assert len(out(io)) <= MAX_IO_CHARS
    assert out(io).startswith("     1\tx\n     2\tx\n")
    assert peak.value < BUDGET


def test_base64_decode_and_encode_are_bounded() -> None:
    import base64

    encoded = base64.b64encode(b"A" * (MB * 3 // 4 - 16)).decode()
    io, peak = run_cmd(cmd_text.cmd_base64, ["-d"], encoded)
    assert len(out(io)) <= MAX_IO_CHARS and out(io).startswith("AAAA")
    assert peak < BUDGET
    io, peak = run_cmd(cmd_text.cmd_base64, [], "z" * MB)
    assert len(out(io)) <= MAX_IO_CHARS
    assert all(len(line) <= 76 for line in out(io).split("\n"))
    assert peak < BUDGET


# ---- CmdIO callers, fs writes, nested output ----------------------------------------------
def test_run_argv_respects_the_callers_budget() -> None:
    sh = make_shell()
    big_file(sh, "/tmp/big", b"y" * (MB - 64))
    io = CmdIO(args=[])
    io.write("z" * (MAX_IO_CHARS - 10))
    with peak_memory() as peak:
        sh._deadline = float("inf")
        sh.run_argv(["cat", "/tmp/big"], io)
    assert io.size <= MAX_IO_CHARS and sum(map(len, io.out)) <= MAX_IO_CHARS
    assert peak.value < BUDGET


def test_fs_append_is_checked_before_concatenating() -> None:
    sh = make_shell()
    big_file(sh, "/tmp/big", b"q" * (900 * 1024))
    extra = b"r" * (200 * 1024)
    with peak_memory() as peak, pytest.raises(FSError, match="No space left"):
        sh.fs.write("/tmp/big", extra, append=True, owner="root")
    assert peak.value < 100 * 1024  # the 1.1 MB concatenation was never built
    assert len(sh.fs.read("/tmp/big")) == 900 * 1024


def test_redirect_append_is_refused_before_encoding() -> None:
    sh = make_shell()
    big_file(sh, "/tmp/big", b"q" * (900 * 1024))
    with peak_memory() as peak:
        res = sh.run_line("cat /tmp/big >> /tmp/big")
    assert "No space left on device" in res.output
    assert len(res.output) <= sh.cfg.max_output_per_line + 64
    assert peak.value < BUDGET


def test_tee_is_bounded() -> None:
    sh = make_shell()
    sh._deadline = float("inf")
    io = CmdIO(args=[f"/tmp/t{i}" for i in range(10)], stdin="w" * (600 * 1024))
    with peak_memory() as peak:
        status = cmd_text.cmd_tee(sh, io)
    assert status == 1 and "No space left on device" in "".join(io.err)
    assert io.size <= MAX_IO_CHARS
    assert sh.fs.used_bytes <= sh.cfg.max_fs_bytes
    assert peak.value < BUDGET


def test_script_and_nested_output_are_bounded() -> None:
    sh = make_shell()
    big_file(sh, "/tmp/big", b"s" * (512 * 1024))
    big_file(sh, "/tmp/run.sh", b"cat /tmp/big\n" * 300 + b"echo " + b"e" * 400_000 + b"\n")
    sh.fs.chmod("/tmp/run.sh", 0o755)
    io = CmdIO(args=[])
    with peak_memory() as peak:
        sh._deadline = float("inf")
        sh.run_script(sh.fs.read("/tmp/run.sh").decode(), io)
    assert io.size <= MAX_IO_CHARS
    assert peak.value < BUDGET
    with peak_memory() as peak:
        res = sh.run_line("sh -c 'cat /tmp/big; cat /tmp/big' 2>&1 | cat")
    assert len(res.output) <= sh.cfg.max_output_per_line + 64
    assert peak.value < BUDGET


def test_stdout_stderr_join_is_bounded() -> None:
    sh = make_shell()
    big_file(sh, "/tmp/big", b"j" * (900 * 1024))
    with peak_memory() as peak:
        res = sh.run_line("cat /tmp/big /nope 2>&1")
    assert len(res.output) <= sh.cfg.max_output_per_line + 64
    assert res.output.endswith("[output truncated]\n")
    assert peak.value < BUDGET


# ---- uniq / sort / wc / xargs --------------------------------------------------------------
@pytest.mark.parametrize(
    ("fn", "args"),
    [
        (cmd_text.cmd_sort, []),
        (cmd_text.cmd_sort, ["-n", "-u"]),
        (cmd_text.cmd_uniq, ["-c"]),
        (cmd_text.cmd_wc, []),
        (cmd_text.cmd_xargs, ["echo"]),
    ],
)
def test_line_and_word_commands_bound_their_input(
    fn: Callable[[Shell, CmdIO], int], args: list[str]
) -> None:
    io, peak = run_cmd(fn, args, "w1 w2\n" * (MB // 6))
    assert len(out(io)) <= MAX_IO_CHARS
    assert peak < BUDGET


def test_wc_counts_without_splitting() -> None:
    io, peak = run_cmd(cmd_text.cmd_wc, [], "a " * (MB // 2))
    assert out(io).split() == ["0", str(MB // 2), str(MB)]
    assert peak < 512 * 1024  # no 500k-element word list
    io, _ = run_cmd(cmd_text.cmd_wc, ["-c"], "é" * 1000)
    assert out(io).strip() == "2000"


# ---- expansion, history, date --------------------------------------------------------------
def test_expand_vars_checks_the_total_on_every_piece() -> None:
    sh = make_shell()
    assert sh.set_var("X", "v" * 4096)
    with peak_memory() as peak:
        word = sh._expand_vars("$X" * 200_000)
    assert len(word) <= MAX_WORD
    assert peak.value < BUDGET


def test_many_large_words_hit_the_argv_cap() -> None:
    sh = make_shell()
    assert sh.set_var("X", "v" * 4000)
    with peak_memory() as peak:
        res = sh.run_line("echo " + " ".join(['"$X$X$X$X$X$X$X$X"'] * 200))
    assert "Argument list too long" in res.output
    assert peak.value < BUDGET


def test_history_is_bounded_and_clear_resets_accounting() -> None:
    sh = make_shell()
    for i in range(1500):
        sh.run_line(f"echo {i} " + "h" * 200)
    io = CmdIO(args=[])
    with peak_memory() as peak:
        cmd_sys.cmd_history(sh, io)
    assert len(out(io)) <= 80 * 1024 and peak.value < BUDGET
    sh.run_line("history -c")
    for i in range(400):  # used to raise IndexError (byte count kept after -c)
        assert sh.run_line(f"echo {i} " + "k" * 300).status == 0


def test_date_format_and_output_are_capped() -> None:
    io, peak = run_cmd(cmd_sys.cmd_date, ["+" + "%c" * 100_000])
    assert len(out(io)) <= cmd_sys.MAX_DATE_OUTPUT + 1
    assert peak < BUDGET
    io, _ = run_cmd(cmd_sys.cmd_date, ["+%Y\x00%m"])
    assert io.out  # NUL in the format does not raise


# ---- scp size, secrets, error log ----------------------------------------------------------
@pytest.mark.parametrize("raw", ["-1", "+5", "1_000", "١٢", " 12", "", "9" * 13])
def test_scp_size_rejects_non_ascii_digits(raw: str) -> None:
    assert _scp_size(raw) is None


def test_scp_size_accepts_plain_digits() -> None:
    assert _scp_size("0") == 0 and _scp_size("1234") == 1234


async def test_scp_negative_size_is_not_recorded(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        conn = await h.connect()
        proc = await conn.create_process("scp -t /tmp/x", encoding=None)
        assert await proc.stdout.readexactly(1) == b"\0"
        proc.stdin.write(b"C0644 -5 evil.bin\n")
        await asyncio.wait_for(proc.wait_closed(), 5)
        conn.close()
        cmds = await h.events("command")
        assert cmds and cmds[0].data["scp_upload"] == []


def test_no_secret_in_reprs() -> None:
    secret = "very-private-seed-value"
    profile = derive_profile(secret, "srv-web01")
    assert secret not in repr(profile)
    cfg = replace(Config(), accept_credentials=frozenset({("root", "Sup3rS3cret!")}))
    assert "Sup3rS3cret!" not in repr(cfg)
    sh = Shell(
        cfg=cfg,
        base=BASE,
        profile=profile,
        username="root",
        client_ip="203.0.113.9",
        client_port=1,
    )
    assert secret not in repr(sh) and "Sup3rS3cret!" not in repr(sh)


def test_internal_error_log_is_rate_limited(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from ssh_sensor.shell import commands

    class Boom(Exception):
        pass

    def boom(sh: Shell, io: CmdIO) -> int:
        raise Boom("x")

    monkeypatch.setitem(commands.COMMANDS, "boom", boom)
    monkeypatch.setattr(interp_mod, "_last_traceback", {})
    sh = make_shell()
    with caplog.at_level(logging.WARNING, logger="ssh_sensor.shell"):
        for _ in range(20):
            assert sh.run_line("boom").status == 2
    records = [r for r in caplog.records if "internal error" in r.getMessage()]
    assert len(records) == 20
    assert sum(1 for r in records if r.exc_info) == 1
    assert all("\n" not in r.getMessage() for r in records)


# ---- event accounting: global bucket, per-IP admit bucket, summaries -----------------------
class _Pub:
    def __init__(self) -> None:
        self.events: list[Any] = []

    async def publish(self, event: Any) -> bool:
        self.events.append(event)
        return True

    async def close(self) -> None:
        return None


class _FakeConn:
    """Just enough of asyncssh.SSHServerConnection for connection_made/lost."""

    def __init__(self, ip: str, port: int) -> None:
        self.peer = (ip, port)
        self.aborted = False

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        return self.peer if name == "peername" else default

    def abort(self) -> None:
        self.aborted = True

    def close(self) -> None:
        return None


def _sensor(sink: EventSink, **overrides: object) -> Sensor:
    params: dict[str, object] = {"quiet_loopback": False, **overrides}
    cfg = replace(Config(), **params)  # type: ignore[arg-type]
    return Sensor(cfg, sink, PROFILE)


def _open(sensor: Sensor, ip: str, port: int) -> tuple[Connection, _FakeConn]:
    conn = Connection(sensor)
    fake = _FakeConn(ip, port)
    conn.connection_made(fake)  # type: ignore[arg-type]
    return conn, fake


async def test_preauth_connections_are_summarised_per_ip() -> None:
    pub = _Pub()
    sink = EventSink(pub, global_rate=1e6, global_burst=1e6)
    sensor = _sensor(sink, conn_rate_per_ip=0.0001, conn_burst_per_ip=10, max_per_ip=100)
    aborted = 0
    for i in range(25):
        conn, fake = _open(sensor, "198.51.100.20", 40000 + i)
        aborted += fake.aborted
        conn.connection_lost(None)  # closed without ever authenticating
    _open(sensor, "198.51.100.21", 1)[0].connection_lost(None)
    assert aborted == 15 and sensor.rate_rejected == 15
    assert sensor.total == 0 and sensor.per_ip == {}
    assert sink.emitted == 0  # no per-connection connect/disconnect events
    assert sink.flush_summaries() == 2
    sink.start()
    await sink.flush()
    by_ip = {str(e.src_ip): e for e in pub.events}
    first = by_ip["198.51.100.20"]
    assert first.type == EventType.scan and first.data["kind"] == "connection_summary"
    assert first.data["count"] == 25 and first.data["rejected"] == 15
    assert first.data["first_seen"] <= first.data["last_seen"]
    assert by_ip["198.51.100.21"].data["count"] == 1
    assert sink.flush_summaries() == 0  # entries are cleared once sent
    await sink.close()


async def test_engaged_disconnect_uses_the_reserve_and_others_do_not() -> None:
    pub = _Pub()
    sink = EventSink(pub, global_rate=0.0001, global_burst=20, rate=1e6, burst=1e6)
    sensor = _sensor(sink, conn_rate_per_ip=1e6, conn_burst_per_ip=1e6)
    # exhaust the non-reserved part of the global bucket
    while sink.emit(
        session_id="flood", src_ip="203.0.113.1", src_port=1, type_=EventType.connect, data={}
    ):
        pass
    tried, _ = _open(sensor, "203.0.113.2", 1)
    tried.begin_auth("root")  # asked to authenticate, never succeeded
    tried.connection_lost(None)
    engaged, _ = _open(sensor, "203.0.113.3", 2)
    engaged.begin_auth("root")
    engaged.logins_ok = 1
    engaged.commands = 1
    engaged.connection_lost(None)
    sink.start()
    await sink.flush()
    disconnects = [e for e in pub.events if e.type == EventType.disconnect]
    assert [str(e.src_ip) for e in disconnects] == ["203.0.113.3"]
    assert sink.priority_dropped == 0
    await sink.close()


async def test_summaries_refused_by_the_global_cap_are_kept() -> None:
    sink = EventSink(_Pub(), global_rate=0.0001, global_burst=12)
    for i in range(30):
        sink.note_connection(f"192.0.2.{i}")
    sent = sink.flush_summaries()
    assert 0 < sent < 30
    assert sink.stats()["summary_pending"] == 30 - sent
    sink.note_connection("192.0.2.29", rejected=True)  # merged into the pending entry
    assert sink.stats()["summary_pending"] == 30 - sent


async def test_summary_table_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    from ssh_sensor import events

    monkeypatch.setattr(events, "_MAX_TRACKED_IPS", 100)
    sink = EventSink(_Pub())
    for i in range(300):
        sink.note_connection(f"192.0.2.{i}" if i < 150 else f"198.51.100.{i - 150}")
    assert sink.stats()["summary_pending"] == 100 and sink.summary_overflow == 200


def test_summary_event_timestamps_are_utc() -> None:
    sink = EventSink(_Pub())
    sink.note_connection("192.0.2.1")
    entry = sink._summary["192.0.2.1"]
    assert entry[2].tzinfo is UTC and entry[2] <= datetime.now(UTC)


async def test_rejected_real_connections_are_counted(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(conn_rate_per_ip=0.0001, conn_burst_per_ip=2) as h:
        ok = 0
        for _ in range(4):
            try:
                conn = await h.connect()
                conn.close()
                await conn.wait_closed()
                ok += 1
            except (asyncssh.Error, OSError):
                pass
        assert ok == 2 and h.sensor.rate_rejected == 2
        h.sink.flush_summaries()
        summaries = [e for e in await h.events("scan") if e.data["kind"] == "connection_summary"]
        assert summaries and summaries[0].data["rejected"] == 2
