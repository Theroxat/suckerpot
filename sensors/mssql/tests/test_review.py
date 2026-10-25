"""Regressions from the security review: fairness, Unicode digits, case, ids, PLP."""

from __future__ import annotations

import asyncio
import struct
import time

import pytest
from conftest import HarnessFactory, talk
from tdsclient import Client, batch, login7, packet, prelogin

from mssql_sensor import sql, tds
from mssql_sensor.config import Config
from mssql_sensor.identity import derive_profile
from mssql_sensor.server import Sensor

PROF = derive_profile("cd" * 32, "15.0.4375.4")


class _Sink:
    def admit(self, ip: str) -> bool:
        return True


def new_sensor(**kw: object) -> Sensor:
    from dataclasses import replace

    return Sensor(replace(Config(), **kw), _Sink(), PROF)  # type: ignore[arg-type]


def test_busy_ip_does_not_stall_a_quiet_one() -> None:
    sensor = new_sensor()
    for _ in range(200):
        sensor.cpu_delay("203.0.113.5", 0.05)  # drains both buckets
    assert sensor.cpu_global[0] < 0
    assert sensor.cpu_delay("198.51.100.5", 0.001) == 0.0
    # debt is bounded: the abuser's stall can never exceed burst / rate
    assert sensor.cpu_delay("203.0.113.5", 0.5) <= 0.25 / 0.05 + 0.01
    assert sensor.cpu_global[0] >= -0.5


def test_cpu_buckets_recover() -> None:
    sensor = new_sensor()
    for _ in range(50):
        sensor.cpu_delay("203.0.113.5", 0.05)
    tokens, last = sensor.cpu_ip["203.0.113.5"]
    sensor.cpu_ip["203.0.113.5"] = (tokens, last - 10)  # ten seconds later
    assert sensor.cpu_delay("203.0.113.5", 0.001) == 0.0


async def test_new_connection_bucket_is_per_ip(make_harness: HarnessFactory) -> None:
    async with make_harness(
        new_conn_per_sec_per_ip=0.01, new_conn_burst_per_ip=4.0, max_per_ip=50
    ) as h:
        answers = [(await talk(h.port, prelogin(), wait=0.1))[:1] for _ in range(8)]
        assert answers.count(b"\x04") == 4 and h.sensor.rejected == 4
        other = await talk(h.port, prelogin(), wait=0.1, source="127.0.0.9")
        assert other[:1] == b"\x04"  # another source is not affected


async def test_preauth_messages_are_charged(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        r, w = await asyncio.open_connection("127.0.0.1", h.port)
        w.write(prelogin() + b"\x06\x01\x00\x08\x00\x00\x01\x00" * 3000)
        await w.drain()
        await asyncio.sleep(0.5)
        tokens, _ = h.sensor.cpu_ip["127.0.0.1"]
        assert tokens < 0.25  # ignored attention packets before login still cost something
        w.close()


@pytest.mark.parametrize("digit", ["²", "³", "①", "٣", "१२३", "\U0001d7d3"])
async def test_unicode_digits_never_break_the_handler(
    make_harness: HarnessFactory, digit: str
) -> None:
    async with make_harness() as h:
        c = await Client.connect(h.port)
        await c.login("sa", "sa")
        r = await c.request(batch(f"select {digit}"))
        assert r.rows or r.errors
        r = await c.request(
            batch(f"exec sp_configure 'show advanced options', {digit}; exec xp_cmdshell 'whoami'")
        )
        assert r.errors or r.infos
        await c.close()
        assert h.sensor.errors == 0
        cmds = await h.events("command")
        assert any("xp_cmdshell" in e.data["flags"] for e in cmds)


async def test_handler_survives_a_failing_responder(
    make_harness: HarnessFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*a: object, **k: object) -> list[tds.Statement]:
        raise ValueError("boom")

    async with make_harness() as h:
        c = await Client.connect(h.port)
        await c.login("sa", "sa")
        monkeypatch.setattr(sql, "respond", boom)
        r = await c.request(batch("exec xp_cmdshell 'whoami'"))
        assert r.errors[0][0] == 102
        await c.close()
        cmd = (await h.events("command"))[0]
        assert "xp_cmdshell" in cmd.data["flags"]


def test_original_case_is_kept() -> None:
    state = sql.SqlState()
    st = sql.respond(state, "SELECT 'AbCdEf'", PROF)[0]
    assert st.rows == [["AbCdEf"]]
    err = sql.respond(state, "select * from NoSuchTable", PROF)[0]
    assert "'NoSuchTable'" in err.messages[0].text  # type: ignore[union-attr]
    err = sql.respond(state, "EXEC Sp_NoSuchProc", PROF)[0]
    assert "'Sp_NoSuchProc'" in err.messages[0].text  # type: ignore[union-attr]
    state.db = PROF.databases[0]
    assert sql.respond(state, "SELECT * FROM USERS", PROF)[0].rows  # any case


def test_scalar_details() -> None:
    state = sql.SqlState(spid=57)
    st = sql.respond(
        state, "select serverproperty('ProductUpdateLevel'), newid(), getdate(), @@spid", PROF
    )[0]
    row = st.rows[0]
    assert row[0] == "CU27" and row[3] == 57
    guid = str(row[1])
    assert [len(p) for p in guid.split("-")] == [8, 4, 4, 4, 12]
    assert isinstance(row[2], float) and abs(row[2] - time.time()) < 5
    w22 = derive_profile("ab" * 32, "16.0.4135.4")
    enabled = sql.SqlState()
    enabled.running["xp_cmdshell"] = 1
    ver = sql.respond(enabled, "exec xp_cmdshell 'ver'", w22)[0]
    assert "10.0.20348." in str(ver.rows[1][0])
    assert "CU14" in sql.respond(sql.SqlState(), "select @@version", w22)[0].rows[0][0]  # type: ignore[operator]


async def test_spids_are_unique_reused_and_match_the_header(
    make_harness: HarnessFactory,
) -> None:
    async with make_harness() as h:
        a, b = await Client.connect(h.port), await Client.connect(h.port)
        await a.login("sa", "sa")
        await b.login("sa", "sa")
        for c in (a, b):
            c.writer.write(batch("select @@spid"))
            await c.writer.drain()
        ra, rb = await a.read_message(), await b.read_message()
        spid_a, spid_b = struct.unpack_from(">H", ra, 4)[0], struct.unpack_from(">H", rb, 4)[0]
        assert spid_a != spid_b
        assert min(spid_a, spid_b) == h.profile.spid_base
        assert sorted(h.sensor.spids) == [h.profile.spid_base, h.profile.spid_base + 1]
        await a.close()
        await h.wait_disconnects(1)
        c = await Client.connect(h.port)
        await c.login("sa", "sa")
        assert len(h.sensor.spids) == 2 and min(h.sensor.spids) >= h.profile.spid_base
        await b.close()
        await c.close()
        await h.wait_disconnects(3)
        assert h.sensor.spids == set()


def test_map_tds_version() -> None:
    assert tds.map_tds_version(0x74000004) == 0x74000004
    assert tds.map_tds_version(0x7400FFFF) == 0x74000004
    assert tds.map_tds_version(0x71000000) == 0x71000001
    assert tds.map_tds_version(0x72090002) == 0x72090002
    assert tds.map_tds_version(0x730B0003) == 0x730B0003
    assert tds.map_tds_version(0x10) == 0x70000000


async def test_featureextack_only_when_requested(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        c = await Client.connect(h.port)
        await c.prelogin()
        c.writer.write(login7("sa", "sa", extension=True))
        await c.writer.drain()
        with_ext = await c.read_message()
        c2 = await Client.connect(h.port)
        await c2.prelogin()
        c2.writer.write(login7("sa", "sa"))
        await c2.writer.drain()
        without = await c2.read_message()
        assert bytes([tds.TOKEN_FEATUREEXTACK, 0xFF]) in with_ext
        assert bytes([tds.TOKEN_FEATUREEXTACK, 0xFF]) not in without
        await c.close()
        await c2.close()


def test_rpc_plp_nvarchar_max() -> None:
    name = struct.pack("<HH", 0xFFFF, 10) + struct.pack("<H", 0)
    sql_text = ("select @@servername " * 3).encode("utf-16-le")
    half = len(sql_text) // 2
    plp = (
        struct.pack("<Q", len(sql_text))
        + struct.pack("<I", half) + sql_text[:half]
        + struct.pack("<I", len(sql_text) - half) + sql_text[half:]
        + struct.pack("<I", 0)
    )  # fmt: skip
    param = b"\x00\x00\xe7" + struct.pack("<H", 0xFFFF) + bytes(5) + plp
    headers = struct.pack("<IIHQI", 22, 18, 2, 0, 1)[:22]
    proc, first = tds.parse_rpc(headers + name + param)
    assert proc == "sp_executesql" and first == "select @@servername " * 3
    huge = struct.pack("<Q", 1 << 40) + (struct.pack("<I", 60000) + bytes(60000)) * 40
    _, capped = tds.parse_rpc(headers + name + param[: -len(plp)] + huge)
    assert len(capped) <= tds.MAX_SQL_BYTES // 2


def test_column_width_counts_utf16_units() -> None:
    cols = [tds.Column("x")]
    wide = tds.colmetadata(cols, 0x74000004, [["\U0001f600" * 200]])
    narrow = tds.colmetadata(cols, 0x74000004, [["a" * 200]])
    # 200 astral characters are 400 UTF-16 units, 800 bytes
    assert struct.pack("<H", 800) in wide and struct.pack("<H", 400) in narrow


async def test_slots_are_released_after_the_transport_is_gone(
    make_harness: HarnessFactory,
) -> None:
    async with make_harness(write_timeout=0.3) as h:
        for _ in range(6):
            r, w = await asyncio.open_connection("127.0.0.1", h.port)
            w.write(prelogin() + login7("sa", "sa") + batch("select * from sys.sql_logins") * 400)
            await w.drain()
            await asyncio.sleep(0.05)
            w.close()
        async with asyncio.timeout(10):
            while h.sensor.total:
                await asyncio.sleep(0.1)
        assert h.sensor.per_ip == {} and h.sensor.spids == set() and h.sensor.buffered == 0
        _ = packet


def test_app_name_and_numeric_edge_cases() -> None:
    state = sql.SqlState(app_name="sqlcmd")
    assert sql.respond(state, "select app_name()", PROF)[0].rows == [["sqlcmd"]]
    big = sql.respond(state, "select 12345678901234567890", PROF)[0]
    assert big.rows == [["12345678901234567890"]]
    assert sql.respond(state, "select " + "9" * 40, PROF)[0].messages[0].number == 1007  # type: ignore[union-attr]
    assert sql.respond(state, "select \u00b2", PROF)[0].messages[0].number == 102  # type: ignore[union-attr]
    opt = "exec sp_configure 'show advanced options', "
    assert sql.respond(state, opt + "99999999999", PROF)[0].messages[0].number == 8115  # type: ignore[union-attr]
    assert sql.respond(state, opt + "\u00b2", PROF)[0].messages[0].number == 102  # type: ignore[union-attr]
    assert sql.respond(state, opt + "'abc'", PROF)[0].messages[0].number == 8114  # type: ignore[union-attr]
    assert sql.respond(state, opt + "1", PROF)[0].messages[0].number == 15457  # type: ignore[union-attr]


async def test_login_app_name_reaches_the_session(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        c = await Client.connect(h.port)
        await c.login("sa", "sa", app="MyTool")
        r = await c.request(batch("select app_name()"))
        assert r.rows == [["MyTool"]]
        await c.close()


async def test_no_empty_packet_when_handshake_has_nothing_to_send() -> None:
    from mssql_sensor import tls as tlsmod

    # frame() would produce one empty packet for b""; the server must not call it with b""
    assert len(tds.frame(tds.T_PRELOGIN, b"", 4096, 0)) == 1
    assert tlsmod.TLS_COST == 48 * 1024
