"""Caps, deadlines, budgets and hostile clients."""

from __future__ import annotations

import asyncio
import contextlib
import socket
import time
from pathlib import Path

from conftest import HarnessFactory

from mysql_sensor import wire
from mysql_sensor.memguard import MemoryGuard

Streams = tuple[asyncio.StreamReader, asyncio.StreamWriter]


async def read_packet(reader: asyncio.StreamReader, timeout: float = 5.0) -> tuple[int, bytes]:
    async with asyncio.timeout(timeout):
        head = await reader.readexactly(4)
        body = await reader.readexactly(int.from_bytes(head[:3], "little"))
    return head[3], body


async def open_raw(port: int) -> Streams:
    return await asyncio.open_connection("127.0.0.1", port)


async def expect_eof(reader: asyncio.StreamReader, timeout: float = 5.0) -> None:
    try:
        async with asyncio.timeout(timeout):
            while await reader.read(65536):
                pass
    except ConnectionError:
        pass  # closing with unread input resets the connection, like a real server


def native_response(user: bytes = b"root", db: bytes = b"") -> bytes:
    caps = (
        wire.CLIENT_PROTOCOL_41
        | wire.CLIENT_SECURE_CONNECTION
        | wire.CLIENT_PLUGIN_AUTH
        | wire.CLIENT_MULTI_RESULTS
        | wire.CLIENT_CONNECT_WITH_DB
    )
    out = caps.to_bytes(4, "little") + (1 << 24).to_bytes(4, "little") + b"\xff" + b"\x00" * 23
    return out + user + b"\x00\x00" + db + b"\x00" + b"mysql_native_password\x00"


async def login_raw(port: int) -> Streams:
    reader, writer = await open_raw(port)
    await read_packet(reader)  # handshake
    writer.write(wire.pack(1, native_response()))
    _, body = await read_packet(reader)
    assert body[0] == 0x00, body
    return reader, writer


def query_packet(sql: str) -> bytes:
    return wire.pack(0, bytes([wire.COM_QUERY]) + sql.encode())


async def test_per_ip_cap_answers_like_max_connect_errors(make_harness: HarnessFactory) -> None:
    async with make_harness(max_per_ip=2) as h:
        conns = [await open_raw(h.port) for _ in range(2)]
        for r, _ in conns:
            await read_packet(r)
        reader, writer = await open_raw(h.port)
        _, body = await read_packet(reader)
        assert body[0] == 0xFF and int.from_bytes(body[1:3], "little") == 1129
        assert b"is blocked because of many connection errors" in body
        await expect_eof(reader)
        writer.close()
        assert h.sensor.rejected == 1
        for _, w in conns:
            w.close()
        await h.wait_disconnects(2)
        assert h.sensor.total == 0 and h.sensor.per_ip == {} and h.sensor.held == 0


async def test_global_cap_too_many_connections(make_harness: HarnessFactory) -> None:
    async with make_harness(max_connections=2, max_per_ip=100) as h:
        conns = [await open_raw(h.port) for _ in range(2)]
        for r, _ in conns:
            await read_packet(r)
        reader, _w = await open_raw(h.port)
        _, body = await read_packet(reader)
        assert int.from_bytes(body[1:3], "little") == 1040 and b"Too many connections" in body
        for _, w in conns:
            w.close()


async def test_global_cap_evicts_old_unanswered_handshakes(make_harness: HarnessFactory) -> None:
    async with make_harness(max_connections=2, max_per_ip=100) as h:
        conns = [await open_raw(h.port) for _ in range(2)]
        for r, _ in conns:
            await read_packet(r)
        for session in h.sensor.sessions:
            session.started -= 5.0  # pretend both have been waiting for a while
        reader, writer = await open_raw(h.port)
        _, body = await read_packet(reader)
        assert body[0] == 10  # the newcomer gets a real handshake
        assert h.sensor.evicted == 1
        writer.close()
        for _, w in conns:
            w.close()


async def test_slow_handshake_times_out(make_harness: HarnessFactory) -> None:
    async with make_harness(handshake_timeout=0.5) as h:
        reader, writer = await open_raw(h.port)
        await read_packet(reader)
        writer.write(b"\x20\x00")  # half a header, then silence
        t0 = time.monotonic()
        await expect_eof(reader)
        assert time.monotonic() - t0 < 3
        disc = await h.wait_disconnects(1)
        assert disc[0].data["reason"] == "timeout" and disc[0].data["stage"] == "handshake_sent"
        writer.close()


async def test_idle_timeout_after_login(make_harness: HarnessFactory) -> None:
    async with make_harness(idle_timeout=0.4) as h:
        reader, writer = await login_raw(h.port)
        await expect_eof(reader)
        disc = await h.wait_disconnects(1)
        assert disc[0].data["reason"] == "idle_timeout" and disc[0].data["logged_in"] is True
        writer.close()


async def test_max_session(make_harness: HarnessFactory) -> None:
    async with make_harness(max_session=0.5, idle_timeout=30.0) as h:
        reader, writer = await login_raw(h.port)
        await expect_eof(reader)
        assert (await h.wait_disconnects(1))[0].data["reason"] == "max_session"
        writer.close()


async def test_oversized_packet_gets_error_1153(make_harness: HarnessFactory) -> None:
    async with make_harness(max_packet=1024 * 1024) as h:
        reader, writer = await login_raw(h.port)
        writer.write((2 * 1024 * 1024).to_bytes(3, "little") + b"\x00" + b"\x03select 1")
        _, body = await read_packet(reader)
        assert int.from_bytes(body[1:3], "little") == 1153
        assert b"max_allowed_packet" in body
        await expect_eof(reader)
        assert (await h.wait_disconnects(1))[0].data["reason"] == "packet_too_large"
        writer.close()


async def test_packet_at_limit_is_streamed_not_buffered(make_harness: HarnessFactory) -> None:
    async with make_harness(capture_bytes=1000) as h:
        reader, writer = await login_raw(h.port)
        payload = b"\x03select '" + b"B" * (1024 * 1024 - 20) + b"'"
        writer.write(wire.pack(0, payload))
        await writer.drain()
        _, body = await read_packet(reader)
        assert body[0] == 0x01  # one-column result set
        for _ in range(3):
            await read_packet(reader)  # column def, EOF, row (deprecate-eof off: client lacks it)
        cmd = (await h.events("command"))[-1].data
        assert cmd["truncated"] is True and len(cmd["input"]) <= 1000
        writer.close()


async def test_http_on_the_mysql_port_is_a_scan(make_harness: HarnessFactory) -> None:
    """A real server reads 'GET ' as a header with sequence id 0x20 and says so (error 1156)."""
    async with make_harness() as h:
        reader, writer = await open_raw(h.port)
        await read_packet(reader)
        writer.write(b"GET / HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n")
        _, body = await read_packet(reader)
        assert int.from_bytes(body[1:3], "little") == 1156
        assert body[3:9] == b"#08S01" and body.endswith(b"Got packets out of order")
        await expect_eof(reader)
        scans = await h.events("scan")
        assert scans[0].data["kind"] == "non_mysql" and scans[0].data["protocol_guess"] == "http"
        assert scans[0].data["payload_ascii"].startswith("GET / HTTP/1.1")
        writer.close()


async def test_huge_first_packet_gets_no_answer_like_a_real_server(
    make_harness: HarnessFactory,
) -> None:
    """Correct sequence id, 5 MB announced: a real server waits for the payload, silently."""
    async with make_harness(handshake_timeout=0.8) as h:
        reader, writer = await open_raw(h.port)
        await read_packet(reader)
        writer.write(b"\x47\x45\x54\x01" + b" / HTTP/1.0\r\n\r\n")
        t0 = time.monotonic()
        data = b"?"
        with contextlib.suppress(ConnectionError):
            async with asyncio.timeout(5):
                data = await reader.read(100)
        assert data in (b"", b"?")  # no error packet, just the close (or a reset)
        assert time.monotonic() - t0 >= 0.7
        scans = await h.events("scan")
        assert scans[0].data["kind"] == "non_mysql"
        disc = await h.wait_disconnects(1)
        assert disc[0].data["reason"] == "non_mysql"
        writer.close()


async def test_sequence_ids_are_enforced(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        # Wrong id on a command.
        reader, writer = await login_raw(h.port)
        writer.write(wire.pack(3, bytes([wire.COM_PING])))
        _, body = await read_packet(reader)
        assert int.from_bytes(body[1:3], "little") == 1156 and body[3:9] == b"#08S01"
        await expect_eof(reader)
        assert (await h.wait_disconnects(1))[0].data["reason"] == "packet_out_of_order"
        writer.close()
        # Wrong id on the handshake response.
        reader, writer = await open_raw(h.port)
        await read_packet(reader)
        writer.write(wire.pack(2, native_response()))
        _, body = await read_packet(reader)
        assert int.from_bytes(body[1:3], "little") == 1156
        writer.close()
        # Commands may be pipelined, each one starts at 0.
        reader, writer = await login_raw(h.port)
        writer.write(wire.pack(0, bytes([wire.COM_PING])) * 3)
        for _ in range(3):
            assert (await read_packet(reader))[1][0] == 0x00
        writer.close()


async def test_new_connections_per_source_are_rate_limited(make_harness: HarnessFactory) -> None:
    async with make_harness(
        connections_per_sec_per_ip=0.5, connections_burst_per_ip=3, refusal_delay=0.3
    ) as h:
        conns = [await open_raw(h.port) for _ in range(3)]
        for r, _ in conns:
            assert (await read_packet(r))[1][0] == 10  # the burst gets real handshakes
        t0 = time.monotonic()
        reader, writer = await open_raw(h.port)
        _, body = await read_packet(reader)
        assert int.from_bytes(body[1:3], "little") == 1129  # then the slow, real refusal
        assert time.monotonic() - t0 >= 0.25
        assert h.sensor.rate_limited == 1 and h.sensor.total == 3
        writer.close()
        for _, w in conns:
            w.close()


async def test_garbage_response_is_bad_handshake(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        reader, writer = await open_raw(h.port)
        await read_packet(reader)
        writer.write(wire.pack(1, b"\x01\x02\x03\x04" + b"\x99" * 40))
        _, body = await read_packet(reader)
        assert int.from_bytes(body[1:3], "little") == 1043
        await expect_eof(reader)
        scans = await h.events("scan")
        assert scans[0].data["kind"] == "malformed_mysql"
        writer.close()


async def test_client_that_never_reads_is_aborted(make_harness: HarnessFactory) -> None:
    async with make_harness(write_timeout=0.5) as h:
        reader, writer = await login_raw(h.port)
        for _ in range(60):
            writer.write(query_packet("select * from shop.customers"))
        await writer.drain()
        # We never read: the server's send buffer fills, the write times out and aborts.
        async with asyncio.timeout(10):
            while h.sensor.total:
                await asyncio.sleep(0.05)
        assert h.sensor.held == 0 and h.sensor.sessions == {}
        disc = await h.wait_disconnects(1)
        assert disc[0].data["reason"] in ("write_timeout", "client_reset")
        writer.close()


async def test_input_byte_limit(make_harness: HarnessFactory) -> None:
    async with make_harness(max_input_bytes=100_000) as h:
        reader, writer = await login_raw(h.port)
        junk = query_packet("select '" + "x" * 30_000 + "'")
        try:
            for _ in range(10):
                writer.write(junk)
                await writer.drain()
        except ConnectionError:
            pass
        await expect_eof(reader)
        assert (await h.wait_disconnects(1))[0].data["reason"] == "input_limit"
        writer.close()


async def test_command_limit(make_harness: HarnessFactory) -> None:
    async with make_harness(max_commands=5) as h:
        reader, writer = await login_raw(h.port)
        for _ in range(8):
            writer.write(wire.pack(0, bytes([wire.COM_PING])))
        await writer.drain()
        await expect_eof(reader)
        assert (await h.wait_disconnects(1))[0].data["reason"] == "command_limit"
        writer.close()


async def test_auth_attempt_cap(make_harness: HarnessFactory) -> None:
    async with make_harness(max_auth_attempts=2) as h:
        reader, writer = await login_raw(h.port)
        change = (
            bytes([wire.COM_CHANGE_USER]) + b"root\x00\x00\x00\xff\x00mysql_native_password\x00"
        )
        writer.write(wire.pack(0, change))
        _, body = await read_packet(reader)
        assert body[0] == 0x00  # second attempt allowed
        writer.write(wire.pack(0, change))
        await expect_eof(reader)
        assert (await h.wait_disconnects(1))[0].data["reason"] == "auth_limit"
        logins = await h.events("login_attempt")
        assert [lg.data["attempt"] for lg in logins] == [1, 2, 3]
        assert logins[2].data["incomplete"] == "auth_limit"
        writer.close()


async def test_command_event_budget_and_suppression_summary(make_harness: HarnessFactory) -> None:
    async with make_harness(session_command_events=5) as h:
        conn = await h.aconnect(ssl_disabled=True)

        def burst() -> None:
            with conn.cursor() as cur:
                for i in range(30):
                    cur.execute(f"select {i}")
                cur.execute("select load_file('/etc/passwd')")  # important: always recorded

        await asyncio.to_thread(burst)
        await asyncio.to_thread(conn.close)
        await h.wait_disconnects(1)
        cmds = await h.events("command")
        plain = [c for c in cmds if not c.data["flags"]]
        assert len(plain) == 5
        assert any("load_file" in c.data["flags"] for c in cmds)
        scan = [s for s in await h.events("scan") if s.data["kind"] == "events_suppressed"]
        assert scan and scan[0].data["suppressed_commands"] > 25


async def test_important_events_have_a_per_session_quota(make_harness: HarnessFactory) -> None:
    async with make_harness(session_important_events=4) as h:
        reader, writer = await login_raw(h.port)
        for _ in range(10):
            writer.write(query_packet("select load_file('/x')"))
        writer.write(wire.pack(0, bytes([wire.COM_QUIT])))
        await writer.drain()
        await expect_eof(reader)
        await h.wait_disconnects(1)
        important = [e for e in await h.events() if e.type in ("login_attempt", "command")]
        assert len(important) == 4
        scan = [s for s in await h.events("scan") if s.data["kind"] == "events_suppressed"]
        assert scan[0].data["suppressed_important"] == 7
        writer.close()


async def test_sampled_out_sessions_still_report_credentials(make_harness: HarnessFactory) -> None:
    async with make_harness(sink_kw={"per_ip_rate": 0.0001, "per_ip_burst": 1.0}) as h:
        for _ in range(4):
            r, w = await open_raw(h.port)
            await read_packet(r)
            w.write(wire.pack(1, native_response(b"admin")))
            await read_packet(r)
            w.close()
        await h.wait_disconnects(1)
        await asyncio.sleep(0.3)
        assert len(await h.events("login_attempt")) == 4
        # Each reported session starts with a (deferred) connect event, with the original time.
        assert len(await h.events("connect")) == 4
        assert len(await h.events("disconnect")) == 4


async def test_global_event_rate_limit(make_harness: HarnessFactory) -> None:
    async with make_harness(
        sink_kw={"events_rate": 1.0, "events_burst": 3.0, "important_ip_burst": 1.0}
    ) as h:
        for _ in range(10):
            r, w = await open_raw(h.port)
            await read_packet(r)
            w.close()
        await asyncio.sleep(0.5)
        assert h.sink.events_limited > 0
        assert len(await h.events()) < 20


async def test_event_ceiling_holds_for_a_mixed_burst(make_harness: HarnessFactory) -> None:
    """The documented ceiling: burst + rate * time, for routine and important events together."""
    async with make_harness(
        sink_kw={"events_rate": 50.0, "events_burst": 100.0, "important_ip_burst": 100000.0}
    ) as h:
        from datetime import UTC, datetime

        from suckerpot_common import EventType

        t0 = time.monotonic()
        for i in range(3000):
            h.sink.emit(
                session_id="s",
                src_ip="198.51.100.7",
                src_port=1,
                type_=EventType.login_attempt if i % 2 else EventType.command,
                data={"username": "u", "password": "p"},
                ts=datetime.now(UTC),
                important=bool(i % 2),
            )
        elapsed = time.monotonic() - t0
        assert h.sink.emitted <= 100 + 50 * elapsed + 5
        assert h.sink.emitted >= 90


async def test_flooding_source_cannot_starve_another_source(make_harness: HarnessFactory) -> None:
    """Lesson 18: a brute forcer hammering the sensor, and a victim whose logins must all arrive."""
    async with make_harness(
        max_per_ip=50,
        sink_kw={"important_ip_rate": 10.0, "important_ip_burst": 50.0},
    ) as h:
        stop = asyncio.Event()

        async def attempt(src: str, user: bytes) -> None:
            sock = socket.socket()
            sock.setblocking(False)
            sock.bind((src, 0))
            await asyncio.get_running_loop().sock_connect(sock, ("127.0.0.1", h.port))
            reader, writer = await asyncio.open_connection(sock=sock)
            try:
                await read_packet(reader)
                writer.write(wire.pack(1, native_response(user)))
                await read_packet(reader)
            finally:
                writer.transport.abort()

        async def flood(k: int) -> int:
            n = 0
            while not stop.is_set():
                with contextlib.suppress(Exception):
                    await attempt("127.0.0.2", f"guess{k}_{n % 7}".encode())
                n += 1
            return n

        flooders = [asyncio.create_task(flood(k)) for k in range(8)]
        for i in range(20):  # the victim: slow and steady
            await attempt("127.0.0.3", f"victim{i}".encode())
            await asyncio.sleep(0.1)
        stop.set()
        attempts = sum(await asyncio.gather(*flooders))
        await h.wait_disconnects(1)
        logins = await h.events("login_attempt")
        victim = [e for e in logins if str(e.src_ip) == "127.0.0.3"]
        flood_logins = [e for e in logins if str(e.src_ip) == "127.0.0.2"]
        print(
            f"flooder: {attempts} attempts, {len(flood_logins)} recorded individually; "
            f"victim: {len(victim)}/20 recorded"
        )
        assert len(victim) == 20
        assert attempts > 100  # it really was a flood
        assert len(flood_logins) < attempts
        h.sink.flush_suppressed(60.0)
        scans = [s for s in await h.events("scan") if s.data["kind"] == "suppressed_logins"]
        assert scans and str(scans[0].src_ip) == "127.0.0.2"
        agg = scans[0].data
        assert agg["count"] + len(flood_logins) >= attempts * 0.5
        assert 0 < len(agg["top_pairs"]) <= 10 and agg["top_pairs"][0]["count"] >= 1


async def test_loopback_is_quiet_by_default(make_harness: HarnessFactory) -> None:
    async with make_harness(quiet_loopback=True) as h:
        r, w = await open_raw(h.port)
        await read_packet(r)
        w.close()
        await asyncio.sleep(0.2)
        assert await h.events() == []


async def test_many_parallel_connections_release_everything(make_harness: HarnessFactory) -> None:
    async with make_harness(max_per_ip=500, max_connections=500) as h:
        conns = [await open_raw(h.port) for _ in range(150)]
        for r, _ in conns:
            await read_packet(r)
        assert h.sensor.total == 150
        assert h.sensor.held == 150 * h.cfg.conn_cost
        for _, w in conns:
            w.transport.abort()
        async with asyncio.timeout(10):
            while h.sensor.total:
                await asyncio.sleep(0.05)
        assert h.sensor.held == 0 and h.sensor.per_ip == {}


# --- memory guard --------------------------------------------------------------------------


def _cgroup(tmp: Path, current: int, limit: int = 100) -> Path:
    (tmp / "memory.current").write_text(str(current))
    (tmp / "memory.max").write_text(str(limit))
    (tmp / "memory.stat").write_text("anon 1\ninactive_file 0\n")
    return tmp


def test_memory_guard_thresholds(tmp_path: Path) -> None:
    guard = MemoryGuard(1000, cgroup=_cgroup(tmp_path, 50))
    assert guard.limit == 100 and guard.source == "cgroup"
    assert guard.sample() is False and guard.refusing is False
    (tmp_path / "memory.current").write_text("71")
    assert guard.sample() is False and guard.refusing is True
    (tmp_path / "memory.current").write_text("86")
    assert guard.sample() is True
    assert guard.excess() == 86 - 70


def test_memory_guard_inactive_file_is_not_counted(tmp_path: Path) -> None:
    _cgroup(tmp_path, 90)
    (tmp_path / "memory.stat").write_text("inactive_file 60\n")
    guard = MemoryGuard(1000, cgroup=tmp_path)
    assert guard.read() == 30


async def test_guard_refuses_and_sheds(make_harness: HarnessFactory, tmp_path: Path) -> None:
    async with make_harness(max_per_ip=100) as h:
        conns = [await open_raw(h.port) for _ in range(4)]
        for r, _ in conns:
            await read_packet(r)
        cg = _cgroup(tmp_path, 75)
        h.sensor.guard = MemoryGuard(100, cgroup=cg)
        h.sensor.guard.sample()
        reader, _w = await open_raw(h.port)
        _, body = await read_packet(reader)
        assert int.from_bytes(body[1:3], "little") == 1040  # refused while above 70 %
        (tmp_path / "memory.current").write_text("90")
        assert h.sensor.shed() >= 1
        disc = await h.wait_disconnects(1)
        assert disc[0].data["reason"] == "memory_shed"
        assert h.sensor.guard.aborted >= 1
        for _, w in conns:
            w.close()


async def test_spam_of_handshake_only_connections_is_cheap(make_harness: HarnessFactory) -> None:
    async with make_harness(max_per_ip=1000) as h:
        t0 = time.monotonic()
        for _ in range(100):
            r, w = await open_raw(h.port)
            await read_packet(r)
            w.close()
        assert time.monotonic() - t0 < 5


async def test_caching_sha2_empty_password_is_a_single_nul(make_harness: HarnessFactory) -> None:
    """libmysqlclient sends one NUL byte for an empty password with caching_sha2_password."""
    async with make_harness() as h:
        reader, writer = await open_raw(h.port)
        await read_packet(reader)
        caps = (
            wire.CLIENT_PROTOCOL_41
            | wire.CLIENT_SECURE_CONNECTION
            | wire.CLIENT_PLUGIN_AUTH
            | wire.CLIENT_PLUGIN_AUTH_LENENC
        )
        body = caps.to_bytes(4, "little") + (1 << 24).to_bytes(4, "little") + b"\xff" + b"\x00" * 23
        body += b"root\x00" + wire.lenenc_str(b"\x00") + b"caching_sha2_password\x00"
        writer.write(wire.pack(1, body))
        _, reply = await read_packet(reader)
        assert reply[0] == 0x00
        writer.close()


async def test_prepared_statements_and_unknown_commands(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        reader, writer = await login_raw(h.port)
        writer.write(wire.pack(0, bytes([wire.COM_STMT_PREPARE]) + b"select ?"))
        _, body = await read_packet(reader)
        assert int.from_bytes(body[1:3], "little") == 1295
        writer.write(wire.pack(0, bytes([wire.COM_STMT_EXECUTE]) + (7).to_bytes(4, "little")))
        _, body = await read_packet(reader)
        assert int.from_bytes(body[1:3], "little") == 1243 and b"(7)" in body
        writer.write(wire.pack(0, b"\x7f"))
        _, body = await read_packet(reader)
        assert int.from_bytes(body[1:3], "little") == 1047
        writer.write(wire.pack(0, bytes([wire.COM_STMT_CLOSE]) + b"\x01\x00\x00\x00"))
        writer.write(wire.pack(0, bytes([wire.COM_PING])))
        _, body = await read_packet(reader)
        assert body[0] == 0x00  # COM_STMT_CLOSE has no reply
        writer.close()
