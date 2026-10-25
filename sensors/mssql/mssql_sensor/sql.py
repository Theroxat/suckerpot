"""A tiny canned responder for T-SQL batches. There is no SQL engine here.

The text is cut to a fixed size, lower-cased, whitespace-collapsed and split into at most 16
statements. Each statement is answered by looking at its first word and at a few substrings
(``str.find`` / ``in``; no regular expressions, no parsing beyond what picks a canned reply).
Nothing is executed, evaluated or looked up anywhere: the replies come from tables of constants
and from synthetic rows derived from the deployment secret.

``sp_configure`` / ``RECONFIGURE`` keep a little per-connection state so that ``xp_cmdshell`` and
the OLE automation procedures are refused until an attacker enables them the way a real server
requires, which makes the whole attack chain show up in the recorded commands.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from mssql_sensor import extract
from mssql_sensor.identity import Profile
from mssql_sensor.tds import (
    K_DATETIME,
    K_INT,
    Cell,
    Column,
    Env,
    Msg,
    Statement,
)

MAX_SQL_CHARS = 16 * 1024
MAX_STATEMENTS = 16
MAX_NAME = 64
SYSTEM_DBS = ("master", "tempdb", "model", "msdb")
CUR_SELECT, CUR_INSERT, CUR_DELETE, CUR_UPDATE = 0xC1, 0xC3, 0xC4, 0xC5

# Config options: name -> (minimum, maximum, default, advanced)
OPTIONS: dict[str, tuple[int, int, int, bool]] = {
    "show advanced options": (0, 1, 0, False),
    "xp_cmdshell": (0, 1, 0, True),
    "ole automation procedures": (0, 1, 0, True),
    "ad hoc distributed queries": (0, 1, 0, True),
    "clr enabled": (0, 1, 0, False),
    "remote access": (0, 1, 1, False),
    "max server memory (mb)": (128, 2147483647, 2147483647, True),
    "cost threshold for parallelism": (0, 32767, 5, True),
    "database mail xps": (0, 1, 0, True),
    "cross db ownership chaining": (0, 1, 0, False),
}

# (flag, needles): any needle present in the lower-cased text sets the flag.
FLAG_NEEDLES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("xp_cmdshell", ("xp_cmdshell",)),
    ("sp_oacreate", ("sp_oacreate", "sp_oamethod", "sp_oasetproperty")),
    ("sp_configure", ("sp_configure",)),
    ("reconfigure", ("reconfigure",)),
    ("ole_automation", ("ole automation procedures",)),
    ("drop_database", ("drop database",)),
    ("openrowset", ("openrowset", "opendatasource")),
    ("bulk_insert", ("bulk insert",)),
    ("xp_dirtree", ("xp_dirtree", "xp_fileexist", "xp_subdirs")),
    ("xp_regread", ("xp_regread", "xp_regwrite", "xp_regdeleteval", "xp_instance_reg")),
    ("add_login", ("sp_addlogin", "create login", "sp_addsrvrolemember", "sp_password")),
    ("backup", ("backup database", "backup log")),
    ("shell_command", ("powershell", "cmd.exe", "cmd /c", "net user", "net localgroup")),
    ("lolbin", ("certutil", "bitsadmin", "mshta", "regsvr32", "rundll32")),
    ("time_probe", ("waitfor delay", "waitfor time")),
    ("sqli_probe", ("union select", "' or '1'='1", "or 1=1")),
    ("unc_path", ("\\\\",)),
    ("linked_server", ("sp_addlinkedserver", "openquery")),
    ("clr_assembly", ("create assembly", "sp_add_trusted_assembly")),
)
PRIORITY_FLAGS = frozenset(
    {
        "xp_cmdshell",
        "sp_oacreate",
        "ole_automation",
        "drop_database",
        "ransom_note",
        "openrowset",
        "bulk_insert",
        "xp_dirtree",
        "xp_regread",
        "add_login",
        "shell_command",
        "lolbin",
        "download",
        "dropper",
        "reverse_shell",
        "miner",
        "unc_path",
        "clr_assembly",
        "linked_server",
        "backup",
        "ssh_key_payload",
        "webshell_payload",
    }
)


@dataclass
class SqlState:
    login: str = "sa"
    spid: int = 51
    app_name: str = "Microsoft SQL Server Management Studio"
    db: str = "master"
    running: dict[str, int] = field(default_factory=dict)
    pending: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name, (_lo, _hi, default, _adv) in OPTIONS.items():
            self.running.setdefault(name, default)
            self.pending.setdefault(name, default)


@dataclass
class Findings:
    flags: set[str] = field(default_factory=set)
    downloads: list[extract.Download] = field(default_factory=list)


def analyze(text: str) -> Findings:
    """Indicator flags and download URLs of one batch (scans at most 16 K characters)."""
    low = _lower(text[:MAX_SQL_CHARS])
    found = Findings()
    for flag, needles in FLAG_NEEDLES:
        if any(low.find(n) >= 0 for n in needles):
            found.flags.add(flag)
    scan = extract.analyze(low)
    found.flags |= scan.flags
    found.downloads = scan.downloads
    return found


# --- helpers ----------------------------------------------------------------------------

_NAME_CHARS = frozenset('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.#@$[]"-')
_LOWER = {c: c + 32 for c in range(65, 91)}


def _lower(text: str) -> str:
    """ASCII-only lower-casing: same length as the input, so offsets map back to the original."""
    return text.translate(_LOWER)


def _digits(text: str) -> bool:
    return text.isascii() and text.isdigit()


def _ident(text: str) -> str:
    """The first identifier-looking token of ``text`` (bounded)."""
    out: list[str] = []
    for ch in text[: MAX_NAME * 2]:
        if ch not in _NAME_CHARS:
            break
        out.append(ch)
    return "".join(out)[:MAX_NAME]


def _plain(name: str) -> str:
    return name.replace("[", "").replace("]", "").replace('"', "")


def _unquote(text: str) -> str:
    text = text.strip()
    if text.startswith("n'"):
        text = text[1:]
    return text.strip("'\"[] ")[: MAX_NAME * 2]


def _err(number: int, text: str, cls: int = 16, state: int = 1) -> Statement:
    return Statement(messages=[Msg(number, text, cls, state, error=True)], failed=True)


def _blocked(proc: str, component: str) -> Statement:
    return _err(
        15281,
        f"SQL Server blocked access to procedure 'sys.{proc}' of component '{component}' because "
        f"this component is turned off as part of the security configuration for this server. A "
        f"system administrator can enable the use of '{component}' by using sp_configure. For "
        f"more information about enabling '{component}', search for '{component}' in SQL Server "
        f"Books Online.",
    )


def _hash(prof: Profile, name: str) -> str:
    return (
        "0x0200" + prof.derive("salt/" + name, 4).hex() + prof.derive("hash/" + name, 32).hex() * 2
    )


FIRST = (
    "alice",
    "bob",
    "carol",
    "dave",
    "erin",
    "frank",
    "grace",
    "heidi",
    "ivan",
    "judy",
    "mallory",
    "niaj",
    "olivia",
    "peggy",
    "rupert",
    "sybil",
    "trent",
    "victor",
)
CITIES = ("Zurich", "Geneva", "Basel", "Bern", "Lausanne", "Lyon", "Milan", "Turin", "Munich")
STATUS = ("shipped", "pending", "paid", "cancelled")
DOMAINS = ("example.com", "mail.example.org", "corp.example.net")


def _fake_rows(prof: Profile, table: str) -> tuple[list[Column], list[list[Cell]]]:
    rows: list[list[Cell]] = []
    if table == "users":
        cols = [Column("Id", K_INT), Column("Username"), Column("Email"), Column("Role")]
        for i in range(1, 13):
            n = FIRST[prof.number(f"u{i}", 0, len(FIRST) - 1)]
            dom = DOMAINS[prof.number(f"d{i}", 0, len(DOMAINS) - 1)]
            role = "admin" if i == 1 else "user"
            rows.append([i, n if i > 1 else "admin", f"{n}@{dom}", role])
    elif table == "customers":
        cols = [Column("Id", K_INT), Column("Name"), Column("City"), Column("Email")]
        for i in range(1, 13):
            n = FIRST[prof.number(f"c{i}", 0, len(FIRST) - 1)]
            city = CITIES[prof.number(f"city{i}", 0, len(CITIES) - 1)]
            rows.append([i, n.capitalize(), city, f"{n}@{DOMAINS[i % len(DOMAINS)]}"])
    else:  # orders
        cols = [
            Column("Id", K_INT),
            Column("CustomerId", K_INT),
            Column("Total", K_INT),
            Column("Status"),
        ]
        for i in range(1, 16):
            rows.append(
                [
                    1000 + i,
                    prof.number(f"oc{i}", 1, 12),
                    prof.number(f"ot{i}", 15, 900),
                    STATUS[prof.number(f"os{i}", 0, 3)],
                ]
            )
    return cols, rows


def _pick(
    cols: list[Column], rows: list[list[Cell]], select_part: str
) -> tuple[list[Column], list[list[Cell]]]:
    """Choose the columns named in the select list (all of them for ``*`` or no match)."""
    if "count(" in select_part:
        return [Column("", K_INT)], [[len(rows)]]
    if "*" in select_part:
        return cols, rows
    idx = [i for i, c in enumerate(cols) if c.name.lower() in select_part]
    if not idx:
        return cols, rows
    return [cols[i] for i in idx], [[r[i] for i in idx] for r in rows]


# --- the catalog / user tables ----------------------------------------------------------


def _table(
    prof: Profile, state: SqlState, ident: str
) -> tuple[list[Column], list[list[Cell]]] | None:
    name = _lower(_plain(ident))
    tail = name.rsplit(".", 1)[-1]
    dbs = (*SYSTEM_DBS, *prof.databases)
    if name.endswith("sys.databases") or tail == "sysdatabases":
        cols = [
            Column("name"),
            Column("database_id", K_INT),
            Column("create_date", K_DATETIME),
            Column("compatibility_level", K_INT),
        ]
        base = int(time.time()) - prof.uptime_offset - 40 * 86400
        level = 150 if prof.version[0] == 15 else 160
        return cols, [[d, i + 1, base + i * 3600, level] for i, d in enumerate(dbs)]
    if name.endswith(("sys.tables", "sys.objects")) or tail == "sysobjects":
        cols = [
            Column("name"),
            Column("object_id", K_INT),
            Column("type"),
            Column("create_date", K_DATETIME),
        ]
        if state.db in SYSTEM_DBS:
            return cols, [["spt_fallback_db", 117575457, "U", int(time.time()) - 9_000_000]]
        base = int(time.time()) - 5_000_000
        return cols, [
            [t.capitalize(), 565577053 + i * 32, "U", base + i]
            for i, t in enumerate(("users", "customers", "orders"))
        ]
    if name.endswith("information_schema.tables"):
        cols = [
            Column("table_catalog"),
            Column("table_schema"),
            Column("table_name"),
            Column("table_type"),
        ]
        if state.db in SYSTEM_DBS:
            return cols, [[state.db, "dbo", "spt_fallback_db", "BASE TABLE"]]
        return cols, [
            [state.db, "dbo", t.capitalize(), "BASE TABLE"]
            for t in ("users", "customers", "orders")
        ]
    if name.endswith(("information_schema.columns", "sys.columns", "syscolumns")):
        cols = [
            Column("table_name"),
            Column("column_name"),
            Column("ordinal_position", K_INT),
            Column("data_type"),
        ]
        out: list[list[Cell]] = []
        for t in ("users", "customers", "orders"):
            for i, c in enumerate(_fake_rows(prof, t)[0], 1):
                out.append([t.capitalize(), c.name, i, "int" if c.kind == K_INT else "nvarchar"])
        return cols, out
    if name.endswith(("sys.sql_logins", "sys.server_principals", "syslogins")):
        cols = [
            Column("name"),
            Column("principal_id", K_INT),
            Column("type_desc"),
            Column("password_hash"),
        ]
        logins = ("sa", "##MS_PolicyEventProcessingLogin##", "NT SERVICE\\MSSQLSERVER", "app_user")
        return cols, [
            [n, 1 + i, "SQL_LOGIN" if "\\" not in n else "WINDOWS_LOGIN", _hash(prof, n)]
            for i, n in enumerate(logins)
        ]
    if tail in ("users", "customers", "orders") and state.db not in SYSTEM_DBS:
        return _fake_rows(prof, tail)
    return None


_SCALARS: tuple[str, ...] = (
    "@@version", "@@servername", "@@spid", "@@language", "@@microsoftversion", "@@rowcount",
    "@@trancount", "@@servicename", "@@connections", "@@max_connections", "host_name()",
    "db_name()", "system_user", "suser_name()", "suser_sname()", "original_login()", "user_name()",
    "current_user", "session_user", "is_srvrolemember", "is_member", "getdate()", "sysdatetime()",
    "getutcdate()", "current_timestamp", "app_name()", "newid()",
)  # fmt: skip


def _scalar(needle: str, prof: Profile, state: SqlState) -> tuple[Column, Cell]:
    v = prof.version
    if needle == "@@version":
        return Column(""), prof.banner
    if needle in ("@@servername", "host_name()"):
        return Column(""), prof.server_name
    if needle == "@@spid":
        return Column("", K_INT), state.spid
    if needle == "@@language":
        return Column(""), "us_english"
    if needle == "@@servicename":
        return Column(""), "MSSQLSERVER"
    if needle == "@@microsoftversion":
        return Column("", K_INT), (v[0] << 24) | (v[1] << 16) | v[2]
    if needle in ("@@rowcount", "@@trancount"):
        return Column("", K_INT), 0
    if needle == "@@connections":
        return Column("", K_INT), prof.number("conns", 900, 20000)
    if needle == "@@max_connections":
        return Column("", K_INT), 32767
    if needle == "db_name()":
        return Column(""), state.db
    if needle in ("system_user", "suser_name()", "suser_sname()", "original_login()"):
        return Column(""), state.login
    if needle in ("user_name()", "current_user", "session_user"):
        return Column(""), "dbo"
    if needle in ("is_srvrolemember", "is_member"):
        return Column("", K_INT), 1
    if needle == "app_name()":
        return Column(""), state.app_name
    if needle == "newid()":
        raw = prof.derive("guid" + str(time.time_ns()), 16).hex().upper()
        return Column(""), f"{raw[:8]}-{raw[8:12]}-{raw[12:16]}-{raw[16:20]}-{raw[20:32]}"
    return Column("", K_DATETIME), time.time()


def _server_property(name: str, prof: Profile, state: SqlState) -> Cell:
    v = prof.version
    props: dict[str, Cell] = {
        "productversion": prof.version_text,
        "productmajorversion": str(v[0]),
        "productlevel": "RTM",
        "productupdatelevel": prof.update_level,
        "edition": "Standard Edition (64-bit)",
        "engineedition": "2",
        "servername": prof.server_name,
        "machinename": prof.server_name,
        "computernamephysicalnetbios": prof.server_name,
        "instancename": None,
        "isclustered": "0",
        "isintegratedsecurityonly": "0",
        "ishadrenabled": "0",
        "isfulltextinstalled": "0",
        "collation": "SQL_Latin1_General_CP1_CI_AS",
        "processid": str(prof.number("pid", 1200, 9800)),
        "instancedefaultdatapath": "C:\\Program Files\\Microsoft SQL Server\\MSSQL"
        f"{v[0]}.MSSQLSERVER\\MSSQL\\DATA\\",
    }
    return props.get(name)


def _scalar_select(low: str, prof: Profile, state: SqlState) -> Statement | None:
    items: list[tuple[int, Column, Cell]] = []
    for needle in _SCALARS:
        at = low.find(needle)
        if needle == "user_name()" and at > 0 and low[at - 1] == "s":
            at = -1  # that is suser_name()
        if at >= 0:
            col, cell = _scalar(needle, prof, state)
            items.append((at, col, cell))
    pos = 0
    while len(items) < 24:
        at = low.find("serverproperty(", pos)
        if at < 0:
            break
        pos = at + 15
        end = low.find(")", pos, pos + 80)
        if end < 0:
            break
        prop = low[pos:end].strip().lstrip("n").strip("'\" ")
        items.append((at, Column(""), _server_property(prop, prof, state)))
    if not items:
        return None
    items.sort(key=lambda t: t[0])
    cols = [c for _, c, _ in items]
    return Statement(columns=cols, rows=[[cell for _, _, cell in items]], curcmd=CUR_SELECT)


def _select(orig: str, prof: Profile, state: SqlState) -> Statement:
    low = _lower(orig)
    at = low.find(" from ")
    if at >= 0:
        select_part = low[:at]
        ident = _ident(orig[at + 6 :].lstrip())
        found = _table(prof, state, ident)
        if found is None:
            return _err(208, f"Invalid object name '{_plain(ident)}'.", 16, 1)
        cols, rows = _pick(found[0], found[1], select_part)
        return Statement(columns=cols, rows=rows, curcmd=CUR_SELECT)
    scalar = _scalar_select(low, prof, state)
    if scalar is not None:
        return scalar
    body = orig[6:].strip()
    digits = body.split(" ", 1)[0].rstrip(",;")
    if _digits(digits):
        if len(digits) < 10:
            return Statement(columns=[Column("", K_INT)], rows=[[int(digits)]], curcmd=CUR_SELECT)
        if len(digits) <= 38:  # a numeric constant: shown as its digits
            return Statement(columns=[Column("")], rows=[[digits]], curcmd=CUR_SELECT)
        return _err(
            1007,
            f"The number '{digits[:38]}' is out of the range for numeric representation "
            "(maximum precision 38).",
            15,
        )
    if digits and digits[0].isdigit():  # a non-ASCII digit is not a number to T-SQL
        return _err(102, f"Incorrect syntax near '{digits[:32]}'.", 15)
    if body.startswith(("'", "N'")):
        lit = body.lstrip("N").lstrip("'").split("'", 1)[0][:128]
        return Statement(columns=[Column("")], rows=[[lit]], curcmd=CUR_SELECT)
    return Statement(columns=[Column("", K_INT)], rows=[[1]], curcmd=CUR_SELECT)


# --- EXEC -------------------------------------------------------------------------------


def _config_rows(state: SqlState, only: str | None) -> Statement:
    cols = [
        Column("name"),
        Column("minimum", K_INT),
        Column("maximum", K_INT),
        Column("config_value", K_INT),
        Column("run_value", K_INT),
    ]
    rows: list[list[Cell]] = []
    for name in sorted(OPTIONS):
        if only is not None and name != only:
            continue
        lo, hi, _d, adv = OPTIONS[name]
        if adv and not state.running["show advanced options"] and only is None:
            continue
        rows.append([name, lo, hi, state.pending[name], state.running[name]])
    return Statement(columns=cols, rows=rows, curcmd=CUR_SELECT)


def _sp_configure(rest: str, state: SqlState) -> Statement:
    parts = rest.split(",", 2)
    name = _unquote(parts[0]) if parts and parts[0].strip() else ""
    if not name:
        return _config_rows(state, None)
    option = _lower(name) if _lower(name) in OPTIONS else ""
    if option and OPTIONS[option][3] and not state.running["show advanced options"]:
        option = ""
    if not option:
        return _err(
            15123,
            f"The configuration option '{name[:64]}' does not exist, "
            "or it may be an advanced option.",
        )
    if len(parts) < 2:
        return _config_rows(state, option)
    raw = parts[1].strip().rstrip(";").strip("'\" ")
    if _digits(raw):
        if len(raw) >= 10:
            return _err(8115, "Arithmetic overflow error converting expression to data type int.")
        value = int(raw)
    elif raw and raw[0].isdigit():
        return _err(102, f"Incorrect syntax near '{raw[:32]}'.", 15)
    else:
        return _err(8114, "Error converting data type varchar to int.")
    lo, hi, _d, _a = OPTIONS[option]
    if not lo <= value <= hi:
        return _err(
            15129, f"{value} is not a valid value for configuration option '{option}'.", 16, 1
        )
    old = state.pending[option]
    state.pending[option] = value
    return Statement(
        messages=[
            Msg(
                15457,
                f"Configuration option '{option}' changed from {old} to {value}. "
                "Run the RECONFIGURE statement to install.",
                0,
                1,
            )
        ]
    )


def _xp_cmdshell(rest: str, prof: Profile, state: SqlState) -> Statement:
    if not state.running["xp_cmdshell"]:
        return _blocked("xp_cmdshell", "xp_cmdshell")
    cmd = _unquote(rest.split(",", 1)[0])
    word = _lower(cmd.split(" ", 1)[0])
    if "no_output" in _lower(rest):
        return Statement()
    out: list[Cell]
    if word == "whoami":
        out = ["nt service\\mssqlserver"]
    elif word == "hostname":
        out = [prof.server_name.lower()]
    elif word == "ver":
        patch = prof.number("winpatch", 1000, 6000)
        out = [
            "",
            f"Microsoft Windows [Version 10.0.{prof.win_build}.{patch}]",
        ]
    else:
        out = []
    rows: list[list[Cell]] = [[line] for line in out] + [[None]]
    return Statement(columns=[Column("output")], rows=rows, curcmd=CUR_SELECT)


_OK_PROCS = frozenset(
    {
        "sp_addlogin", "sp_addsrvrolemember", "sp_password", "sp_adduser", "sp_grantdbaccess",
        "sp_addrolemember", "sp_addlinkedserver", "sp_addlinkedsrvlogin", "sp_dropserver",
        "sp_executesql", "sp_msforeachdb", "sp_msforeachtable", "sp_helpsrvrolemember",
        "sp_prepare", "sp_execute", "sp_unprepare", "sp_prepexec", "xp_regread", "xp_regwrite",
        "xp_regdeleteval", "xp_servicecontrol", "xp_loginconfig", "xp_availablemedia",
        "sp_add_trusted_assembly", "sp_setapprole", "sp_droplogin", "sp_dropsrvrolemember",
        "sp_cursor", "sp_cursoropen", "sp_cursorclose", "sp_cursorfetch", "sp_cursorexecute",
        "sp_cursorprepare", "sp_cursoroption", "sp_cursorunprepare", "sp_cursorprepexec",
    }
)  # fmt: skip
_OLE = frozenset(
    {"sp_oacreate", "sp_oamethod", "sp_oasetproperty", "sp_oagetproperty", "sp_oadestroy",
     "sp_oageterrorinfo", "sp_oastop"}
)  # fmt: skip


def _exec(rest: str, prof: Profile, state: SqlState) -> Statement:
    rest = rest.strip()
    if rest.startswith("("):
        return Statement()  # dynamic SQL: recorded, not looked into
    if rest.startswith("@") and "=" in rest.split(" ", 2)[0]:
        rest = rest.split("=", 1)[1].strip()  # exec @rc = proc ...
    ident = _plain(_ident(rest))
    proc = _lower(ident.rsplit(".", 1)[-1])
    args = rest[len(_ident(rest)) :].strip()
    if proc == "sp_configure":
        return _sp_configure(args, state)
    if proc == "xp_cmdshell":
        return _xp_cmdshell(args, prof, state)
    if proc in _OLE:
        if state.running["ole automation procedures"]:
            return Statement()
        return _blocked(proc.replace("sp_oacreate", "sp_OACreate"), "Ole Automation Procedures")
    if proc == "xp_dirtree" or proc == "xp_subdirs":
        return Statement(
            columns=[Column("subdirectory"), Column("depth", K_INT)], rows=[], curcmd=CUR_SELECT
        )
    if proc == "xp_fixeddrives":
        return Statement(
            columns=[Column("drive"), Column("MB free", K_INT)],
            rows=[["C", prof.number("cfree", 20000, 90000)]],
            curcmd=CUR_SELECT,
        )
    if proc == "xp_fileexist":
        cols = [Column("File Exists", K_INT), Column("File is a Directory", K_INT),
                Column("Parent Directory Exists", K_INT)]  # fmt: skip
        return Statement(columns=cols, rows=[[0, 0, 1]], curcmd=CUR_SELECT)
    if proc in ("sp_databases", "sp_helpdb"):
        dbs = (*SYSTEM_DBS, *prof.databases)
        cols = [Column("DATABASE_NAME"), Column("DATABASE_SIZE", K_INT), Column("REMARKS")]
        rows: list[list[Cell]] = [[d, 8192 + 1024 * i, None] for i, d in enumerate(dbs)]
        return Statement(columns=cols, rows=rows, curcmd=CUR_SELECT)
    if proc in ("sp_who", "sp_who2"):
        cols = [Column("spid", K_INT), Column("status"), Column("loginame"), Column("hostname"),
                Column("dbname"), Column("cmd")]  # fmt: skip
        rows = [[state.spid, "runnable", state.login, prof.server_name, state.db, "SELECT"]]
        return Statement(columns=cols, rows=rows, curcmd=CUR_SELECT)
    if proc in _OK_PROCS:
        return Statement()
    return _err(2812, f"Could not find stored procedure '{ident or proc}'.", 16, 62)


def _use(rest: str, prof: Profile, state: SqlState) -> Statement:
    name = _plain(_ident(rest.strip()))
    if _lower(name) in (*SYSTEM_DBS, *prof.databases):
        name = _lower(name)
        old, state.db = state.db, name
        return Statement(
            messages=[Env(1, name, old), Msg(5701, f"Changed database context to '{name}'.", 0, 2)]
        )
    return _err(
        911, f"Database '{name}' does not exist. Make sure that the name is entered correctly."
    )


_DML = {"insert": CUR_INSERT, "update": CUR_UPDATE, "delete": CUR_DELETE}
_NOOP = frozenset(
    {"declare", "set", "print", "if", "while", "begin", "end", "go", "waitfor", "kill", "dbcc",
     "create", "alter", "drop", "truncate", "backup", "restore", "grant", "revoke", "deny", "bulk",
     "merge", "with", "commit", "rollback", "checkpoint", "shutdown", "raiserror", "try", "catch",
     "else", "return", "goto", "open", "close", "fetch", "deallocate", "use"}
)  # fmt: skip


def _statement(orig: str, prof: Profile, state: SqlState) -> Statement:
    low = _lower(orig)
    head = low.split(" ", 1)[0]
    rest_o = orig[len(head) + 1 :]
    if head == "select":
        return _select(orig, prof, state)
    if head in ("exec", "execute"):
        return _exec(rest_o, prof, state)
    if head.startswith(("sp_", "xp_")):
        return _exec(orig, prof, state)
    if head == "use":
        return _use(rest_o, prof, state)
    if head == "reconfigure":
        state.running.update(state.pending)
        return Statement()
    if head in _DML:
        return Statement(count=1, curcmd=_DML[head])
    if head in _NOOP:
        return Statement()
    token = "".join(c for c in orig[: len(head)][:32] if c.isprintable() and c != "'")
    return _err(102, f"Incorrect syntax near '{token}'.", 15, 1)


def respond(state: SqlState, text: str, prof: Profile) -> list[Statement]:
    """Canned replies for one batch, one :class:`Statement` per piece (bounded)."""
    orig = " ".join(text[:MAX_SQL_CHARS].split())
    low = _lower(orig)
    # Statement boundaries: ';' and the keywords that start a statement without one.
    cuts = {i for i, ch in enumerate(low) if ch == ";"}
    for kw in (" exec ", " execute ", " reconfigure"):
        at = low.find(kw)
        while at >= 0 and len(cuts) < 4 * MAX_STATEMENTS:
            cuts.add(at)
            at = low.find(kw, at + 1)
    out: list[Statement] = []
    start = 0
    for cut in [*sorted(cuts), len(orig)]:
        piece = orig[start:cut].strip()
        start = cut + 1 if orig[cut : cut + 1] == ";" else cut
        if not piece:
            continue
        out.append(_statement(piece, prof, state))
        if len(out) >= MAX_STATEMENTS:
            break
    return out or [Statement()]
