"""The canned SQL responder: recognises a handful of statement shapes, no SQL engine.

State is per connection (a few databases and tables the attacker created, user variables,
changed system variables), all bounded. Nothing is executed, evaluated or written anywhere:
every answer is generated from constants and from :mod:`mysql_sensor.fakedata`.
"""

from __future__ import annotations

import hashlib
from collections import OrderedDict
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from mysql_sensor import fakedata, wire
from mysql_sensor.sqlish import IDENT, NUM, STR, SYM, WORD, Tok

MAX_ROWS = 200  # rows returned by one SELECT
MAX_ITERATE = 6000  # rows examined while filtering
MAX_CREATED_DBS = 20
MAX_CREATED_TABLES = 40
MAX_COLUMNS = 32
MAX_USER_VARS = 32
MAX_VALUE = 256
MAX_SLEEP = 5.0
IDENT_MAX = 64
PLUGIN_DIR = "/usr/lib/mysql/plugin/"
MAX_ALLOWED_PACKET = 64 * 1024 * 1024  # the 8.0 default, as reported by @@max_allowed_packet
STATEMENT_STEPS = 4  # work charged for any statement, whatever it does
MAX_CACHED_SCANS = 8  # filtered scans remembered per connection
MAX_MATCH_INDEXES = 1000  # matching row numbers kept per cached scan
INTERRUPTED = (1317, "70100", "Query execution was interrupted")


@dataclass(frozen=True)
class Ok:
    affected: int = 0
    info: str = ""
    last_insert_id: int = 0


@dataclass(frozen=True)
class Err:
    code: int
    state: str
    message: str


@dataclass
class ResultSet:
    columns: list[wire.Column]
    rows: list[tuple[str | None, ...]]
    delay: float = 0.0


Result = Ok | Err | ResultSet


def like_match(pattern: str, value: str) -> bool:
    """SQL LIKE (``%`` and ``_``, case-insensitive) without regular expressions."""
    p, v = pattern.lower()[:128], value.lower()[:128]
    pi = vi = 0
    star = -1
    mark = 0
    while vi < len(v):
        if pi < len(p) and p[pi] in (v[vi], "_") and p[pi] != "%":
            pi += 1
            vi += 1
        elif pi < len(p) and p[pi] == "%":
            star, mark = pi, vi
            pi += 1
        elif star >= 0:
            pi = star + 1
            mark += 1
            vi = mark
        else:
            return False
    while pi < len(p) and p[pi] == "%":
        pi += 1
    return pi == len(p)


def _col(name: str, kind: str = "str", length: int = 0) -> wire.Column:
    if kind == "long":
        return wire.Column(name, wire.TYPE_LONG, length or 11, 0x80)
    if kind == "longlong":
        return wire.Column(name, wire.TYPE_LONGLONG, length or 20, 0x80)
    if kind == "decimal":
        return wire.Column(name, wire.TYPE_NEWDECIMAL, length or 12, 0x80, 2)
    if kind == "datetime":
        return wire.Column(name, wire.TYPE_DATETIME, length or 19, 0x80)
    return wire.Column(name, wire.TYPE_VAR_STRING, length or 1020)


def _simple(names: list[str], rows: Sequence[tuple[str | None, ...]]) -> ResultSet:
    return ResultSet([_col(n) for n in names], list(rows))


_VERSION_VARS = {
    "version_comment": "(Ubuntu)",
    "version_compile_os": "Linux",
    "version_compile_machine": "x86_64",
}
BOOL_VARS = frozenset(
    {"autocommit", "general_log", "slow_query_log", "local_infile", "skip_networking",
     "log_bin", "read_only", "super_read_only", "foreign_key_checks", "unique_checks"}
)  # fmt: skip

_KNOWN_FUNCS = frozenset(
    "CONCAT CONCAT_WS GROUP_CONCAT HEX UNHEX MD5 SHA1 SHA2 LENGTH CHAR_LENGTH LOWER UPPER "
    "SUBSTRING SUBSTR LEFT RIGHT REPLACE TRIM IFNULL IF COALESCE NULLIF CAST CONVERT ASCII "
    "ORD CHAR RAND ABS FLOOR CEIL ROUND COUNT SUM AVG MIN MAX LAST_INSERT_ID ROW_COUNT "
    "FOUND_ROWS UUID UNIX_TIMESTAMP FROM_UNIXTIME DATE_FORMAT EXTRACTVALUE UPDATEXML "
    "JSON_EXTRACT ENCODE DECODE TO_BASE64 FROM_BASE64 COMPRESS UNCOMPRESS INET_ATON "
    "INET_NTOA BIN OCT CONV REVERSE REPEAT LPAD RPAD LOCATE INSTR POSITION".split()
)


@dataclass
class TableDef:
    columns: list[tuple[str, str, str]]  # name, wire kind, SQL type text
    rows: int = 0
    gen: str | None = None  # key in fakedata.GENERATORS


@dataclass(frozen=True)
class _Scan:
    total: int  # rows matching a filter
    indexes: list[int]  # the first MAX_MATCH_INDEXES of them


@dataclass
class Source:
    columns: list[wire.Column]
    total: int
    row: Callable[[int], tuple[str | None, ...]]
    key: str = ""  # identity of a generated table, for the scan cache; empty: do not cache


class Responder:
    """Answers the statements of one connection."""

    def __init__(
        self,
        *,
        version: str,
        hostname: str,
        user: str,
        client_ip: str,
        client_port: int,
        conn_id: int,
        uptime: Callable[[], int],
        seed: str = "",
        query_steps: int = 6000,
        sleep_per_query: float = 10.0,
        sleep_per_connection: float = 30.0,
    ) -> None:
        self.query_steps = query_steps
        self.steps_left = query_steps  # work budget of the COM_QUERY being answered
        self.steps_used = 0  # work done since begin_query(), read by the server to charge CPU
        self.sleep_per_query = sleep_per_query
        self.sleep_query_left = sleep_per_query
        self.sleep_conn_left = sleep_per_connection
        self._scans: OrderedDict[tuple[str, tuple[tuple[int, str, str], ...]], _Scan] = (
            OrderedDict()
        )
        self.version = version
        self.hostname = hostname
        self.user = user
        self.client_ip = client_ip
        self.client_port = client_port
        self.conn_id = conn_id
        self.uptime = uptime
        self.seed = seed
        self.db: str | None = None
        self.queries = 0
        self.user_vars: dict[str, str | None] = {}
        self.vars = self._default_vars()
        self.created_dbs = 0
        self.created_tables = 0
        self.dbs: dict[str, dict[str, TableDef]] = {}
        for name, tables in fakedata.SYSTEM_TABLES.items():
            self.dbs[name] = {t.lower(): TableDef([]) for t in tables}
        shop: dict[str, TableDef] = {}
        for tname, schema in fakedata.SHOP_SCHEMAS.items():
            shop[tname] = TableDef(list(schema), fakedata.SHOP_ROWS[tname], tname)
        self.dbs["shop"] = shop
        self._handlers: dict[str, Callable[[list[Tok], str], Result]] = {
            "SELECT": self._select,
            "SHOW": self._show,
            "USE": self._use,
            "SET": self._set,
            "CREATE": self._create,
            "DROP": self._drop,
            "INSERT": self._insert,
            "REPLACE": self._insert,
            "UPDATE": self._update,
            "DELETE": self._delete,
            "TRUNCATE": self._truncate,
            "ALTER": self._alter,
            "RENAME": self._alter,
            "DESC": self._describe,
            "DESCRIBE": self._describe,
            "EXPLAIN": self._describe,
            "LOAD": self._load,
            "CALL": self._call,
        }
        for verb in (
            "GRANT REVOKE FLUSH BEGIN START COMMIT ROLLBACK SAVEPOINT RELEASE LOCK UNLOCK "
            "KILL RESET PURGE DO ANALYZE OPTIMIZE REPAIR CHECK PREPARE EXECUTE DEALLOCATE "
            "XA HANDLER"
        ).split():
            self._handlers[verb] = self._plain_ok

    # --- variables -----------------------------------------------------------------------

    def _default_vars(self) -> dict[str, str]:
        v = {
            "autocommit": "ON",
            "basedir": "/usr/",
            "bind_address": "*",
            "character_set_client": "utf8mb4",
            "character_set_connection": "utf8mb4",
            "character_set_database": "utf8mb4",
            "character_set_results": "utf8mb4",
            "character_set_server": "utf8mb4",
            "collation_connection": "utf8mb4_0900_ai_ci",
            "collation_database": "utf8mb4_0900_ai_ci",
            "collation_server": "utf8mb4_0900_ai_ci",
            "datadir": "/var/lib/mysql/",
            "default_authentication_plugin": "caching_sha2_password",
            "general_log": "OFF",
            "general_log_file": f"/var/lib/mysql/{self.hostname}.log",
            "have_ssl": "YES",
            "hostname": self.hostname,
            "init_connect": "",
            "innodb_version": self.version.split("-")[0],
            "interactive_timeout": "28800",
            "lc_messages_dir": "/usr/share/mysql/",
            "license": "GPL",
            "local_infile": "OFF",
            "log_error": "/var/log/mysql/error.log",
            "log_bin": "ON",
            "lower_case_table_names": "0",
            "max_allowed_packet": str(wire_max_packet()),
            "max_connections": "151",
            "net_buffer_length": "16384",
            "performance_schema": "ON",
            "pid_file": "/var/run/mysqld/mysqld.pid",
            "plugin_dir": PLUGIN_DIR,
            "port": "3306",
            "protocol_version": "10",
            "read_only": "OFF",
            "secure_file_priv": "/var/lib/mysql-files/",
            "server_id": "1",
            "skip_networking": "OFF",
            "slow_query_log": "OFF",
            "socket": "/var/run/mysqld/mysqld.sock",
            "sql_mode": (
                "ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,"
                "ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION"
            ),
            "system_time_zone": "UTC",
            "time_zone": "SYSTEM",
            "transaction_isolation": "REPEATABLE-READ",
            "tx_isolation": "REPEATABLE-READ",
            "version": self.version,
            "wait_timeout": "28800",
        }
        v.update(_VERSION_VARS)
        return v

    def _status(self) -> list[tuple[str, str]]:
        up = self.uptime()
        return [
            ("Aborted_clients", str(up // 5000)),
            ("Aborted_connects", str(up // 900)),
            ("Bytes_received", str(up * 211)),
            ("Bytes_sent", str(up * 1420)),
            ("Connections", str(up // 60 + 90)),
            ("Created_tmp_tables", str(up // 700)),
            ("Innodb_buffer_pool_pages_total", "8192"),
            ("Max_used_connections", "9"),
            ("Open_tables", "214"),
            ("Queries", str(up // 3 + 100)),
            ("Questions", str(up // 3 + 60 + self.queries)),
            ("Slow_queries", "0"),
            ("Ssl_cipher", ""),
            ("Threads_connected", "2"),
            ("Threads_running", "2"),
            ("Uptime", str(up)),
        ]

    # --- entry point ---------------------------------------------------------------------

    def begin_query(self) -> None:
        """Start a COM_QUERY: fresh work and SLEEP() budgets for all its statements."""
        self.steps_left = self.query_steps
        self.steps_used = 0
        self.sleep_query_left = self.sleep_per_query

    def charge(self, steps: int) -> bool:
        """Spend ``steps`` of the query's work budget; False (nothing spent) if it is not there."""
        if steps > self.steps_left:
            return False
        self.steps_left -= steps
        self.steps_used += steps
        return True

    def respond(self, stmt: list[Tok], text: str) -> Result:
        """Answer one statement. ``text`` is the whole query the statement came from."""
        self.queries += 1
        if not stmt:
            return Err(1065, "42000", "Query was empty")
        if not self.charge(STATEMENT_STEPS):
            return Err(*INTERRUPTED)
        verb = stmt[0].upper if stmt[0].kind == WORD else ""
        handler = self._handlers.get(verb)
        if handler is None:
            return self.syntax_error(stmt, 0, text)
        try:
            return handler(stmt, text)
        except IndexError:
            return self.syntax_error(stmt, len(stmt) - 1, text)

    @staticmethod
    def syntax_error(stmt: list[Tok], at: int, text: str) -> Err:
        at = max(0, min(at, len(stmt) - 1))
        near = text[stmt[at].start : stmt[at].start + 80] if stmt else ""
        return Err(
            1064,
            "42000",
            "You have an error in your SQL syntax; check the manual that corresponds to your "
            f"MySQL server version for the right syntax to use near '{near}' at line 1",
        )

    def use_db(self, name: str) -> Result:
        found = self._find_db(name)
        if found is None:
            return Err(1049, "42000", f"Unknown database '{name[:IDENT_MAX]}'")
        self.db = found
        return Ok()

    def _find_db(self, name: str) -> str | None:
        low = name.lower() if name.lower() in fakedata.SYSTEM_DATABASES else name
        return low if low in self.dbs else None

    def _plain_ok(self, stmt: list[Tok], text: str) -> Result:
        return Ok()

    # --- name parsing --------------------------------------------------------------------

    @staticmethod
    def _name(stmt: list[Tok], i: int) -> tuple[str | None, str, int] | None:
        """Parse ``[db.]name`` at ``i``; returns (db, name, next index)."""
        if i >= len(stmt) or stmt[i].kind not in (WORD, IDENT):
            return None
        tok = stmt[i]
        if tok.kind == WORD and "." in tok.text:
            db, _, name = tok.text.partition(".")
            return db, name, i + 1
        if i + 2 < len(stmt) and stmt[i + 1].text == "." and stmt[i + 1].kind == SYM:
            if stmt[i + 2].kind in (WORD, IDENT):
                return tok.text, stmt[i + 2].text, i + 3
        return None, tok.text, i + 1

    @staticmethod
    def _skip_words(stmt: list[Tok], i: int, words: frozenset[str]) -> int:
        while i < len(stmt) and stmt[i].kind == WORD and stmt[i].upper in words:
            i += 1
        return i

    def _resolve_table(self, db: str | None, name: str) -> tuple[str, TableDef] | Err:
        schema = self._find_db(db) if db is not None else self.db
        if db is None and self.db is None:
            return Err(1046, "3D000", "No database selected")
        if schema is None:
            return Err(1049, "42000", f"Unknown database '{(db or '')[:IDENT_MAX]}'")
        tables = self.dbs[schema]
        key = name.lower() if schema in fakedata.SYSTEM_DATABASES else name
        table = tables.get(key)
        if table is None:
            return Err(1146, "42S02", f"Table '{schema}.{name[:IDENT_MAX]}' doesn't exist")
        return schema, table

    # --- SELECT --------------------------------------------------------------------------

    _SELECT_END = frozenset(
        {"FROM", "WHERE", "LIMIT", "INTO", "ORDER", "GROUP", "HAVING", "UNION", "FOR", "LOCK"}
    )

    def _select_items(self, stmt: list[Tok]) -> tuple[list[list[Tok]], int]:
        i = self._skip_words(
            stmt, 1, frozenset({"DISTINCT", "ALL", "SQL_CALC_FOUND_ROWS", "HIGH_PRIORITY"})
        )
        items: list[list[Tok]] = [[]]
        depth = 0
        while i < len(stmt):
            t = stmt[i]
            if t.kind == SYM and t.text == "(":
                depth += 1
            elif t.kind == SYM and t.text == ")":
                depth = max(0, depth - 1)
            elif depth == 0 and t.kind == WORD and t.upper in self._SELECT_END:
                break
            elif depth == 0 and t.kind == SYM and t.text == ",":
                items.append([])
                i += 1
                continue
            items[-1].append(t)
            i += 1
        return [it for it in items if it][:MAX_COLUMNS], i

    def _select(self, stmt: list[Tok], text: str) -> Result:
        items, end = self._select_items(stmt)
        if not items:
            return self.syntax_error(stmt, min(1, len(stmt) - 1), text)
        rest = stmt[end:]
        for idx in range(len(rest) - 1):
            if rest[idx].upper == "INTO" and rest[idx + 1].upper in ("OUTFILE", "DUMPFILE"):
                return Err(
                    1290,
                    "HY000",
                    "The MySQL server is running with the --secure-file-priv option so it "
                    "cannot execute this statement",
                )
        if rest and rest[0].upper == "FROM":
            return self._select_from(items, rest, text)
        return self._select_scalar(items, text)

    def _item_name_and_expr(self, item: list[Tok], text: str) -> tuple[str, list[Tok]]:
        expr = item
        alias: str | None = None
        if len(item) >= 3 and item[-2].kind == WORD and item[-2].upper == "AS":
            alias, expr = item[-1].text, item[:-2]
        elif len(item) >= 2 and item[-1].kind in (STR, IDENT) and item[-2].text != ".":
            alias, expr = item[-1].text, item[:-1]
        name = alias or text[item[0].start : item[-1].end]
        return name[:MAX_VALUE], expr

    def _select_scalar(self, items: list[list[Tok]], text: str) -> Result:
        columns: list[wire.Column] = []
        row: list[str | None] = []
        delay = 0.0
        for item in items:
            name, expr = self._item_name_and_expr(item, text)
            got = self._scalar(expr)
            if isinstance(got, Err):
                return got
            col, value, d = got
            columns.append(wire.Column(name, col.type, col.length, col.flags, col.decimals))
            row.append(value)
            delay = max(delay, d)
        return ResultSet(columns, [tuple(row)], delay)

    def _sysvar(self, word: str) -> tuple[wire.Column, str | None] | Err:
        name = word[2:].lower()
        for prefix in ("global.", "session.", "local.", "persist."):
            if name.startswith(prefix):
                name = name[len(prefix) :]
        value = self.vars.get(name)
        if value is None:
            return Err(1193, "HY000", f"Unknown system variable '{name[:IDENT_MAX]}'")
        if name in BOOL_VARS and value in ("ON", "OFF"):
            return _col("v", "longlong", 1), "1" if value == "ON" else "0"
        if value.isdigit():
            return _col("v", "longlong"), value
        return _col("v"), value

    def _scalar(self, expr: list[Tok]) -> tuple[wire.Column, str | None, float] | Err:
        """Value of a simple expression; unknown shapes give NULL, never an error."""
        null = (_col("NULL", "str", 0), None, 0.0)
        if not expr:
            return null
        first = expr[0]
        if len(expr) == 1:
            if first.kind == NUM:
                return _col("n", "longlong"), first.text, 0.0
            if first.kind == STR:
                return _col("s", "str", max(1, len(first.text) * 4)), first.text, 0.0
            if first.kind == WORD:
                u = first.upper
                if u == "NULL":
                    return null
                if u.startswith("@@"):
                    sv = self._sysvar(first.text)
                    return sv if isinstance(sv, Err) else (sv[0], sv[1], 0.0)
                if u.startswith("@"):
                    return _col("v"), self.user_vars.get(first.text[1:].lower()), 0.0
                if u in ("CURRENT_USER", "SESSION_USER", "SYSTEM_USER"):
                    return self._func(u, [])
                if u in ("CURRENT_TIMESTAMP", "CURRENT_DATE", "NOW"):
                    return self._func(u, [])
            return null
        if first.kind == WORD and expr[1].kind == SYM and expr[1].text == "(":
            if expr[-1].kind == SYM and expr[-1].text == ")":
                return self._func(first.upper, expr[2:-1])
        return null

    def _func(self, name: str, args: list[Tok]) -> tuple[wire.Column, str | None, float] | Err:
        text = _col("f")
        if name == "VERSION":
            return text, self.version, 0.0
        if name in ("DATABASE", "SCHEMA"):
            return text, self.db, 0.0
        if name in ("USER", "SESSION_USER", "SYSTEM_USER"):
            return text, f"{self.user}@{self.client_ip}", 0.0
        if name == "CURRENT_USER":
            return text, f"{self.user}@%", 0.0
        if name == "CONNECTION_ID":
            return _col("f", "longlong"), str(self.conn_id), 0.0
        if name in ("NOW", "SYSDATE", "CURRENT_TIMESTAMP", "LOCALTIME", "LOCALTIMESTAMP"):
            return _col("f", "datetime"), fakedata.now_stamp(self.uptime()), 0.0
        if name in ("CURDATE", "CURRENT_DATE"):
            return text, fakedata.now_stamp(self.uptime())[:10], 0.0
        if name == "SLEEP":
            try:
                secs = float(args[0].text) if args and args[0].kind == NUM else 0.0
            except ValueError:
                secs = 0.0
            # A real server sleeps the whole time; this one at most MAX_SLEEP per call (the
            # SLEEP(10) -> 5 s tell) and within the per-query and per-connection budgets.
            secs = max(0.0, min(secs, MAX_SLEEP, self.sleep_query_left, self.sleep_conn_left))
            self.sleep_query_left -= secs
            self.sleep_conn_left -= secs
            return _col("f", "longlong"), "0", secs
        if name == "BENCHMARK":
            return _col("f", "longlong"), "0", 0.0
        if name == "LOAD_FILE":
            return _col("f"), None, 0.0  # secure_file_priv: NULL, like a real server
        if name == "UUID":
            digest = hashlib.md5(self.seed.encode(), usedforsecurity=False).hexdigest()
            return (
                text,
                f"{digest[:8]}-{digest[8:12]}-4{digest[13:16]}-8{digest[17:20]}-{digest[20:32]}",
                0.0,
            )
        if name == "COUNT":
            return _col("f", "longlong"), "1", 0.0
        if name in _KNOWN_FUNCS:
            return _col("f"), None, 0.0
        return Err(1305, "42000", f"FUNCTION {name.lower()[:IDENT_MAX]} does not exist")

    # --- SELECT ... FROM -----------------------------------------------------------------

    def _source(self, db: str | None, name: str) -> Source | Err:
        low_db = (db or "").lower()
        if low_db == "information_schema" or (db is None and self.db == "information_schema"):
            virtual = self._virtual(name.lower())
            if virtual is not None:
                return virtual
        if low_db == "mysql" or (db is None and self.db == "mysql"):
            if name.lower() == "user":
                return self._mysql_user()
        found = self._resolve_table(db, name)
        if isinstance(found, Err):
            return found
        schema, table = found
        cols = [_col(c, k) for c, k, _ in table.columns]
        cols = [
            wire.Column(c.name, c.type, c.length, c.flags, c.decimals, name, schema) for c in cols
        ]
        gen = fakedata.GENERATORS.get(table.gen or "")
        if gen is None:
            return Source(cols, 0, lambda i: ())
        return Source(cols, table.rows, gen, f"{schema}.{name}".lower())

    def _virtual(self, name: str) -> Source | None:
        rows: list[tuple[str | None, ...]]
        if name == "schemata":
            names = ["CATALOG_NAME", "SCHEMA_NAME", "DEFAULT_CHARACTER_SET_NAME",
                     "DEFAULT_COLLATION_NAME", "SQL_PATH"]  # fmt: skip
            rows = [("def", d, "utf8mb4", "utf8mb4_0900_ai_ci", None) for d in self.dbs]
        elif name == "tables":
            names = ["TABLE_CATALOG", "TABLE_SCHEMA", "TABLE_NAME", "TABLE_TYPE", "ENGINE",
                     "TABLE_ROWS"]  # fmt: skip
            rows = []
            for d, tables in self.dbs.items():
                kind = "SYSTEM VIEW" if d == "information_schema" else "BASE TABLE"
                for t, td in tables.items():
                    rows.append(("def", d, t, kind, "InnoDB", str(td.rows)))
        elif name == "columns":
            names = ["TABLE_CATALOG", "TABLE_SCHEMA", "TABLE_NAME", "COLUMN_NAME",
                     "ORDINAL_POSITION", "DATA_TYPE", "COLUMN_TYPE"]  # fmt: skip
            rows = []
            for d, tables in self.dbs.items():
                for t, td in tables.items():
                    for pos, (c, _, sqltype) in enumerate(td.columns, 1):
                        rows.append(("def", d, t, c, str(pos), sqltype.split("(")[0], sqltype))
        else:
            return None
        cols = [
            _col(n, "longlong" if n in ("ORDINAL_POSITION", "TABLE_ROWS") else "str") for n in names
        ]
        return Source(cols, len(rows), lambda i: rows[i])

    def _mysql_user(self) -> Source:
        fake = "$A$005$THISISACOMBINATIONOFINVALIDSALTANDPASSWORDTHATMUSTNEVERBRBEUSED"
        digest = hashlib.sha256((self.seed + "user-hash").encode()).hexdigest()
        real = "$A$005$" + digest[:20].upper() + digest[20:63].translate({ord("0"): "/"})
        rows: list[tuple[str | None, ...]] = [
            ("localhost", "debian-sys-maint", "caching_sha2_password", real, "N"),
            ("localhost", "mysql.infoschema", "caching_sha2_password", fake, "Y"),
            ("localhost", "mysql.session", "caching_sha2_password", fake, "Y"),
            ("localhost", "mysql.sys", "caching_sha2_password", fake, "Y"),
            ("localhost", "root", "caching_sha2_password", "", "N"),
        ]
        cols = [
            _col(n) for n in ("Host", "User", "plugin", "authentication_string", "account_locked")
        ]
        return Source(cols, len(rows), lambda i: rows[i])

    @staticmethod
    def _conditions(rest: list[Tok]) -> list[tuple[str, str, str]] | None:
        """``col = value`` / ``col LIKE value`` terms of a WHERE joined by AND, else None.

        Returns None when the clause has an OR (the filter would be meaningless), and an empty
        list when there is no WHERE.
        """
        where = next((i for i, t in enumerate(rest) if t.kind == WORD and t.upper == "WHERE"), -1)
        if where < 0:
            return []
        out: list[tuple[str, str, str]] = []
        i = where + 1
        while i < len(rest):
            t = rest[i]
            if t.kind == WORD and t.upper in ("LIMIT", "ORDER", "GROUP", "HAVING", "UNION", "INTO"):
                break
            if t.kind == WORD and t.upper == "OR":
                return None
            if (
                t.kind in (WORD, IDENT)
                and i + 2 < len(rest)
                and rest[i + 2].kind in (STR, NUM)
                and (rest[i + 1].text == "=" or rest[i + 1].upper == "LIKE")
            ):
                op = "like" if rest[i + 1].upper == "LIKE" else "="
                out.append((t.text.rsplit(".", 1)[-1].lower(), op, rest[i + 2].text))
                i += 3
                continue
            i += 1
        return out[:8]

    @staticmethod
    def _limit(rest: list[Tok]) -> tuple[int, int]:
        """(offset, count) of a LIMIT clause; count defaults to MAX_ROWS."""
        for i, t in enumerate(rest):
            if t.kind == WORD and t.upper == "LIMIT":
                nums: list[int] = []
                j = i + 1
                while j < len(rest) and len(nums) < 2:
                    if rest[j].kind == NUM and rest[j].text.isdigit():
                        nums.append(min(int(rest[j].text), 1 << 31))
                    elif rest[j].text not in (",",) and rest[j].upper != "OFFSET":
                        break
                    j += 1
                if len(nums) == 2:
                    if j - 1 > i + 2 and rest[j - 2].upper == "OFFSET":
                        return nums[1], nums[0]
                    return nums[0], nums[1]
                if len(nums) == 1:
                    return 0, nums[0]
        return 0, MAX_ROWS

    def _select_from(self, items: list[list[Tok]], rest: list[Tok], text: str) -> Result:
        ref = self._name(rest, 1)
        if ref is None:
            return _simple([text[it[0].start : it[-1].end][:MAX_VALUE] for it in items], [])
        db, name, nxt = ref
        src = self._source(db, name)
        if isinstance(src, Err):
            return src
        tail = rest[nxt:]
        by_name = {c.name.lower(): n for n, c in enumerate(src.columns)}
        # plan entries: ("col", index, None) | ("count", 0, None) | ("const", 0, value)
        plan: list[tuple[str, int, str | None]] = []
        out_cols: list[wire.Column] = []
        for item in items:
            label, expr = self._item_name_and_expr(item, text)
            star = len(expr) == 1 and expr[0].text == "*"
            qualified_star = len(expr) == 3 and expr[1].text == "." and expr[2].text == "*"
            if star or qualified_star:
                for n, c in enumerate(src.columns):
                    plan.append(("col", n, None))
                    out_cols.append(c)
                continue
            if expr and expr[0].kind == WORD and expr[0].upper == "COUNT":
                plan.append(("count", 0, None))
                out_cols.append(_col(label, "longlong", 21))
                continue
            if len(expr) == 1 and expr[0].kind in (WORD, IDENT):
                key = expr[0].text.rsplit(".", 1)[-1].lower()
                if key in by_name:
                    plan.append(("col", by_name[key], None))
                    shape = src.columns[by_name[key]]
                    out_cols.append(
                        wire.Column(label, shape.type, shape.length, shape.flags, shape.decimals)
                    )
                    continue
                if expr[0].kind == IDENT or not _is_constant_word(expr[0].upper):
                    return Err(
                        1054,
                        "42S22",
                        f"Unknown column '{expr[0].text[:IDENT_MAX]}' in 'field list'",
                    )
            got = self._scalar(expr)
            if isinstance(got, Err):
                return got
            plan.append(("const", 0, got[1]))
            out_cols.append(
                wire.Column(label, got[0].type, got[0].length, got[0].flags, got[0].decimals)
            )
        conds = self._conditions(tail)
        offset, limit = self._limit(tail)
        filters = [(by_name[c], op, v) for c, op, v in conds or [] if c in by_name]
        is_count = any(kind == "count" for kind, _, _ in plan)
        scan = self._scan(src, tuple(filters), offset, min(limit, MAX_ROWS), is_count)
        if isinstance(scan, Err):
            return scan
        total, indexes = scan
        if is_count:
            counts = tuple(str(total) if kind == "count" else val for kind, _, val in plan)
            return ResultSet(out_cols, [counts])
        if not self.charge(len(indexes)):
            return Err(*INTERRUPTED)
        rows = [
            tuple((r[n] if n < len(r) else None) if kind == "col" else val for kind, n, val in plan)
            for r in (src.row(i) for i in indexes)
        ]
        return ResultSet(out_cols, rows)

    def _scan(
        self,
        src: Source,
        filters: tuple[tuple[int, str, str], ...],
        offset: int,
        count: int,
        is_count: bool,
    ) -> tuple[int, list[int]] | Err:
        """(matching rows, row numbers to return) without generating more than needed.

        Unfiltered: pure arithmetic. Filtered: a scan of at most ``MAX_ITERATE`` rows, charged
        to the query's work budget, stopping early when enough rows were found; the result of
        a complete scan is remembered so the same filter is never scanned twice.
        """
        n = min(src.total, MAX_ITERATE)
        if not filters:
            return n, list(range(min(offset, n), min(n, offset + count)))
        key = (src.key, filters)
        cached = self._scans.get(key) if src.key else None
        if cached is not None:
            self._scans.move_to_end(key)
            total, known = cached.total, cached.indexes
            if is_count or offset + count <= len(known) or total <= len(known):
                return total, known[offset : offset + count]
            return total, []  # beyond the remembered matches: nothing (a documented limit)
        want = (1 << 31) if is_count else offset + count
        budget = min(n, self.steps_left)
        total = 0
        found: list[int] = []
        scanned = 0
        row = src.row
        for i in range(budget):
            scanned += 1
            if not all(_row_matches(row(i), f) for f in filters):
                continue
            total += 1
            if len(found) < MAX_MATCH_INDEXES:
                found.append(i)
            if total >= want:
                break
        complete = scanned == n
        satisfied = total >= want
        self.charge(scanned)
        if not complete and not satisfied:
            return Err(*INTERRUPTED)
        if complete and src.key:
            self._scans[key] = _Scan(total, found)
            while len(self._scans) > MAX_CACHED_SCANS:
                self._scans.popitem(last=False)
        return total, found[offset : offset + count]

    # --- SHOW / DESCRIBE -----------------------------------------------------------------

    def _like_arg(self, stmt: list[Tok], start: int) -> str | None:
        for i in range(start, len(stmt) - 1):
            if stmt[i].kind == WORD and stmt[i].upper == "LIKE" and stmt[i + 1].kind == STR:
                return stmt[i + 1].text
        return None

    def _show(self, stmt: list[Tok], text: str) -> Result:
        i = self._skip_words(stmt, 1, frozenset({"FULL", "GLOBAL", "SESSION", "EXTENDED"}))
        what = stmt[i].upper if i < len(stmt) else ""
        if what in ("DATABASES", "SCHEMAS"):
            like = self._like_arg(stmt, i)
            rows = [
                (d,) for d in sorted(self.dbs, key=str.lower) if like is None or like_match(like, d)
            ]
            return _simple(["Database"], rows)
        if what == "TABLES":
            return self._show_tables(stmt, i, full=stmt[1].upper == "FULL")
        if what in ("COLUMNS", "FIELDS"):
            return self._describe_name(
                stmt, self._skip_words(stmt, i + 1, frozenset({"FROM", "IN"})), text
            )
        if what in ("VARIABLES", "STATUS"):
            like = self._like_arg(stmt, i)
            pairs = (
                sorted((k, v) for k, v in self.vars.items())
                if what == "VARIABLES"
                else self._status()
            )
            pairs = [(k, v) for k, v in pairs if like is None or like_match(like, k)]
            return _simple(["Variable_name", "Value"], pairs[:MAX_ROWS])
        if what == "GRANTS":
            grant = f"GRANT ALL PRIVILEGES ON *.* TO `{self.user}`@`%` WITH GRANT OPTION"
            return _simple([f"Grants for {self.user}@%"], [(grant,)])
        if what == "PROCESSLIST":
            return self._processlist()
        if what == "CREATE" and i + 1 < len(stmt):
            return self._show_create(stmt, i + 1, text)
        if what in ("WARNINGS", "ERRORS"):
            return _simple(["Level", "Code", "Message"], [])
        if what == "ENGINES":
            names = ["Engine", "Support", "Comment", "Transactions", "XA", "Savepoints"]
            engines: list[tuple[str | None, ...]] = [
                (
                    "MEMORY",
                    "YES",
                    "Hash based, stored in memory, useful for temporary tables",
                    "NO",
                    "NO",
                    "NO",
                ),
                (
                    "InnoDB",
                    "DEFAULT",
                    "Supports transactions, row-level locking, and foreign keys",
                    "YES",
                    "YES",
                    "YES",
                ),
                ("CSV", "YES", "CSV storage engine", "NO", "NO", "NO"),
                ("MyISAM", "YES", "MyISAM storage engine", "NO", "NO", "NO"),
            ]
            return _simple(names, engines)
        if what == "MASTER":
            names = ["File", "Position", "Binlog_Do_DB", "Binlog_Ignore_DB", "Executed_Gtid_Set"]
            return _simple(names, [("binlog.000042", "157", "", "", "")])
        if what in ("SLAVE", "REPLICA"):
            return _simple(["Slave_IO_State"], [])
        if what in ("INDEX", "INDEXES", "KEYS"):
            names = ["Table", "Non_unique", "Key_name", "Seq_in_index", "Column_name"]
            return _simple(names, [])
        return self.syntax_error(stmt, min(i, len(stmt) - 1), text)

    def _show_tables(self, stmt: list[Tok], i: int, *, full: bool) -> Result:
        db = self.db
        j = i + 1
        if j + 1 < len(stmt) and stmt[j].upper in ("FROM", "IN"):
            ref = self._name(stmt, j + 1)
            if ref is not None:
                found = self._find_db(ref[1])
                if found is None:
                    return Err(1049, "42000", f"Unknown database '{ref[1][:IDENT_MAX]}'")
                db = found
        if db is None:
            return Err(1046, "3D000", "No database selected")
        like = self._like_arg(stmt, i)
        kind = "SYSTEM VIEW" if db == "information_schema" else "BASE TABLE"
        names = sorted(self.dbs[db], key=str.lower)
        names = [n for n in names if like is None or like_match(like, n)]
        if db == "information_schema":
            names = [n.upper() for n in names]
        head = f"Tables_in_{db}"
        if full:
            return _simple([head, "Table_type"], [(n, kind) for n in names])
        return _simple([head], [(n,) for n in names])

    def _processlist(self) -> ResultSet:
        names = ["Id", "User", "Host", "db", "Command", "Time", "State", "Info"]
        rows: list[tuple[str | None, ...]] = [
            (
                "5",
                "event_scheduler",
                "localhost",
                None,
                "Daemon",
                str(self.uptime()),
                "Waiting on empty queue",
                None,
            ),
            (
                str(self.conn_id),
                self.user,
                f"{self.client_ip}:{self.client_port}",
                self.db,
                "Query",
                "0",
                "init",
                "show processlist",
            ),
        ]
        cols = [_col(n, "longlong" if n in ("Id", "Time") else "str") for n in names]
        return ResultSet(cols, rows)

    def _describe(self, stmt: list[Tok], text: str) -> Result:
        if len(stmt) > 1 and stmt[1].upper in ("SELECT", "FORMAT", "ANALYZE", "FORMAT"):
            # EXPLAIN SELECT ...: a plain one-row plan.
            names = ["id", "select_type", "table", "type", "rows", "Extra"]
            return _simple(names, [("1", "SIMPLE", None, None, None, "No tables used")])
        return self._describe_name(stmt, 1, text)

    def _describe_name(self, stmt: list[Tok], i: int, text: str) -> Result:
        ref = self._name(stmt, i)
        if ref is None:
            return self.syntax_error(stmt, min(i, len(stmt) - 1), text)
        db, name, nxt = ref
        if db is None and nxt + 1 < len(stmt) and stmt[nxt].upper in ("FROM", "IN"):
            other = self._name(stmt, nxt + 1)
            if other is not None:
                db = other[1]
        found = self._resolve_table(db, name)
        if isinstance(found, Err):
            return found
        _, table = found
        names = ["Field", "Type", "Null", "Key", "Default", "Extra"]
        rows: list[tuple[str | None, ...]] = []
        for n, (cname, _, sqltype) in enumerate(table.columns):
            key = "PRI" if n == 0 and table.gen else ""
            extra = "auto_increment" if n == 0 and table.gen else ""
            rows.append((cname, sqltype, "NO" if n == 0 else "YES", key, None, extra))
        return _simple(names, rows)

    def _show_create(self, stmt: list[Tok], i: int, text: str) -> Result:
        kind = stmt[i].upper
        if kind in ("DATABASE", "SCHEMA"):
            ref = self._name(
                stmt, self._skip_words(stmt, i + 1, frozenset({"IF", "NOT", "EXISTS"}))
            )
            if ref is None:
                return self.syntax_error(stmt, i, text)
            found = self._find_db(ref[1])
            if found is None:
                return Err(1049, "42000", f"Unknown database '{ref[1][:IDENT_MAX]}'")
            ddl = (
                f"CREATE DATABASE `{found}` /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE "
                "utf8mb4_0900_ai_ci */ /*!80016 DEFAULT ENCRYPTION='N' */"
            )
            return _simple(["Database", "Create Database"], [(found, ddl)])
        if kind != "TABLE":
            return self.syntax_error(stmt, i, text)
        ref = self._name(stmt, i + 1)
        if ref is None:
            return self.syntax_error(stmt, i, text)
        found_t = self._resolve_table(ref[0], ref[1])
        if isinstance(found_t, Err):
            return found_t
        _, table = found_t
        lines = [
            f"  `{c}` {t}{' NOT NULL' if n == 0 else ' DEFAULT NULL'}"
            for n, (c, _, t) in enumerate(table.columns)
        ]
        if table.gen and lines:
            lines.append("  PRIMARY KEY (`id`)")
        ddl = (
            f"CREATE TABLE `{ref[1][:IDENT_MAX]}` (\n"
            + ",\n".join(lines)
            + "\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci"
        )
        return _simple(["Table", "Create Table"], [(ref[1][:IDENT_MAX], ddl)])

    # --- USE / SET -----------------------------------------------------------------------

    def _use(self, stmt: list[Tok], text: str) -> Result:
        ref = self._name(stmt, 1)
        if ref is None:
            return self.syntax_error(stmt, 1, text)
        return self.use_db(ref[1])

    def _set(self, stmt: list[Tok], text: str) -> Result:
        i = self._skip_words(
            stmt, 1, frozenset({"GLOBAL", "SESSION", "LOCAL", "PERSIST", "PERSIST_ONLY"})
        )
        if i >= len(stmt):
            return self.syntax_error(stmt, len(stmt) - 1, text)
        t = stmt[i]
        if t.kind == WORD and t.upper in (
            "NAMES",
            "CHARACTER",
            "CHARSET",
            "TRANSACTION",
            "PASSWORD",
            "ROLE",
            "RESOURCE",
            "DEFAULT",
        ):
            return Ok()
        if t.kind == WORD and t.upper.startswith("@") and not t.upper.startswith("@@"):
            value = self._assigned(stmt, i + 1)
            key = t.text[1:].lower()[:IDENT_MAX]
            if key in self.user_vars or len(self.user_vars) < MAX_USER_VARS:
                self.user_vars[key] = value
            return Ok()
        if t.kind in (WORD, IDENT):
            name = t.text.lower()
            if name.startswith("@@"):
                name = name[2:]
            for prefix in ("global.", "session.", "local.", "persist."):
                if name.startswith(prefix):
                    name = name[len(prefix) :]
            if name not in self.vars:
                return Err(1193, "HY000", f"Unknown system variable '{name[:IDENT_MAX]}'")
            value = self._assigned(stmt, i + 1)
            if value is not None:
                self.vars[name] = value.upper() if name in BOOL_VARS else value
            return Ok()
        return self.syntax_error(stmt, i, text)

    @staticmethod
    def _assigned(stmt: list[Tok], i: int) -> str | None:
        while i < len(stmt) and stmt[i].kind == SYM and stmt[i].text in "=:":
            i += 1
        if i < len(stmt) and stmt[i].kind in (STR, NUM, WORD):
            return stmt[i].text[:MAX_VALUE]
        return None

    # --- DDL / DML -----------------------------------------------------------------------

    def _create(self, stmt: list[Tok], text: str) -> Result:
        i = self._skip_words(
            stmt, 1, frozenset({"OR", "REPLACE", "TEMPORARY", "UNIQUE", "DEFINER"})
        )
        kind = stmt[i].upper if i < len(stmt) else ""
        if kind in ("DATABASE", "SCHEMA"):
            return self._create_db(stmt, i + 1)
        if kind == "TABLE":
            return self._create_table(stmt, i + 1)
        if kind == "FUNCTION":
            for n, t in enumerate(stmt):
                if t.upper == "SONAME" and n + 1 < len(stmt):
                    lib = stmt[n + 1].text[:IDENT_MAX]
                    return Err(
                        1126,
                        "HY000",
                        f"Can't open shared library '{lib}' (errno: 2 {PLUGIN_DIR}{lib}: "
                        "cannot open shared object file: No such file or directory)",
                    )
            return Ok()
        if kind in (
            "USER",
            "INDEX",
            "VIEW",
            "TRIGGER",
            "PROCEDURE",
            "EVENT",
            "ROLE",
            "ALGORITHM",
            "SQL",
        ):
            return Ok()
        return self.syntax_error(stmt, min(i, len(stmt) - 1), text)

    @staticmethod
    def _if_flag(stmt: list[Tok], i: int, *, negated: bool) -> tuple[bool, int]:
        want = ("IF", "NOT", "EXISTS") if negated else ("IF", "EXISTS")
        if all(i + n < len(stmt) and stmt[i + n].upper == w for n, w in enumerate(want)):
            return True, i + len(want)
        return False, i

    def _create_db(self, stmt: list[Tok], i: int) -> Result:
        if_not, i = self._if_flag(stmt, i, negated=True)
        ref = self._name(stmt, i)
        if ref is None:
            return self.syntax_error(stmt, min(i, len(stmt) - 1), "")
        name = ref[1]
        if len(name) > IDENT_MAX:
            return Err(1059, "42000", f"Identifier name '{name[:IDENT_MAX]}' is too long")
        if self._find_db(name) is not None or name.lower() in self.dbs:
            if if_not:
                return Ok(1, "")
            return Err(1007, "HY000", f"Can't create database '{name}'; database exists")
        if self.created_dbs >= MAX_CREATED_DBS:
            return Err(1114, "HY000", f"The table '{name}' is full")
        self.created_dbs += 1
        self.dbs[name] = {}
        return Ok(1)

    def _create_table(self, stmt: list[Tok], i: int) -> Result:
        if_not, i = self._if_flag(stmt, i, negated=True)
        ref = self._name(stmt, i)
        if ref is None:
            return self.syntax_error(stmt, min(i, len(stmt) - 1), "")
        db, name, nxt = ref
        schema = self._find_db(db) if db is not None else self.db
        if db is None and self.db is None:
            return Err(1046, "3D000", "No database selected")
        if schema is None:
            return Err(1049, "42000", f"Unknown database '{(db or '')[:IDENT_MAX]}'")
        if len(name) > IDENT_MAX:
            return Err(1059, "42000", f"Identifier name '{name[:IDENT_MAX]}' is too long")
        if schema in fakedata.SYSTEM_DATABASES:
            return Err(
                1044, "42000", f"Access denied for user '{self.user}'@'%' to database '{schema}'"
            )
        if name in self.dbs[schema]:
            if if_not:
                return Ok()
            return Err(1050, "42S01", f"Table '{name}' already exists")
        if self.created_tables >= MAX_CREATED_TABLES:
            return Err(1114, "HY000", f"The table '{name}' is full")
        self.created_tables += 1
        self.dbs[schema][name] = TableDef(self._parse_columns(stmt, nxt))
        return Ok()

    @staticmethod
    def _parse_columns(stmt: list[Tok], i: int) -> list[tuple[str, str, str]]:
        if i >= len(stmt) or stmt[i].text != "(":
            return []
        cols: list[tuple[str, str, str]] = []
        depth = 0
        part: list[Tok] = []
        parts: list[list[Tok]] = []
        for t in stmt[i:]:
            if t.kind == SYM and t.text == "(":
                depth += 1
                if depth == 1:
                    continue
            elif t.kind == SYM and t.text == ")":
                depth -= 1
                if depth == 0:
                    parts.append(part)
                    break
            elif t.kind == SYM and t.text == "," and depth == 1:
                parts.append(part)
                part = []
                continue
            part.append(t)
        skip = {
            "PRIMARY",
            "KEY",
            "INDEX",
            "UNIQUE",
            "CONSTRAINT",
            "FOREIGN",
            "FULLTEXT",
            "CHECK",
            "SPATIAL",
        }
        for p in parts[:MAX_COLUMNS]:
            if len(p) < 1 or (p[0].kind == WORD and p[0].upper in skip):
                continue
            ctype = p[1].upper if len(p) > 1 and p[1].kind == WORD else "VARCHAR"
            kind = {
                "INT": "long", "INTEGER": "long", "SMALLINT": "long", "TINYINT": "long",
                "BIGINT": "longlong", "DECIMAL": "decimal", "NUMERIC": "decimal",
                "DATETIME": "datetime", "TIMESTAMP": "datetime",
            }.get(ctype, "str")  # fmt: skip
            sqltype = ctype.lower() + ("(255)" if ctype in ("VARCHAR", "CHAR") else "")
            cols.append((p[0].text[:IDENT_MAX], kind, sqltype))
        return cols

    def _drop(self, stmt: list[Tok], text: str) -> Result:
        kind = stmt[1].upper if len(stmt) > 1 else ""
        if kind in ("DATABASE", "SCHEMA"):
            if_exists, i = self._if_flag(stmt, 2, negated=False)
            ref = self._name(stmt, i)
            if ref is None:
                return self.syntax_error(stmt, min(i, len(stmt) - 1), text)
            found = self._find_db(ref[1])
            if found is None:
                if if_exists:
                    return Ok()
                return Err(
                    1008,
                    "HY000",
                    f"Can't drop database '{ref[1][:IDENT_MAX]}'; database doesn't exist",
                )
            if found in fakedata.SYSTEM_DATABASES:
                return Err(
                    1044, "42000", f"Access denied for user '{self.user}'@'%' to database '{found}'"
                )
            count = len(self.dbs.pop(found))
            if self.db == found:
                self.db = None
            return Ok(count)
        if kind == "TABLE":
            return self._drop_tables(stmt)
        return Ok()

    def _drop_tables(self, stmt: list[Tok]) -> Result:
        i = self._skip_words(stmt, 2, frozenset({"TEMPORARY"}))
        if_exists, i = self._if_flag(stmt, i, negated=False)
        names: list[tuple[str | None, str]] = []
        while i < len(stmt) and len(names) < 16:
            ref = self._name(stmt, i)
            if ref is None:
                break
            names.append((ref[0], ref[1]))
            i = ref[2]
            if i < len(stmt) and stmt[i].text == ",":
                i += 1
            else:
                break
        if not names:
            return self.syntax_error(stmt, min(i, len(stmt) - 1), "")
        missing: list[str] = []
        for db, name in names:
            found = self._resolve_table(db, name)
            if isinstance(found, Err):
                if found.code == 1146:
                    missing.append(found.message.split("'")[1])
                    continue
                return found
            schema, _ = found
            if schema in fakedata.SYSTEM_DATABASES:
                return Err(
                    1044,
                    "42000",
                    f"Access denied for user '{self.user}'@'%' to database '{schema}'",
                )
            del self.dbs[schema][name]
        if missing and not if_exists:
            return Err(1051, "42S02", "Unknown table '" + "','".join(missing) + "'")
        return Ok()

    def _insert(self, stmt: list[Tok], text: str) -> Result:
        i = self._skip_words(
            stmt, 1, frozenset({"LOW_PRIORITY", "DELAYED", "HIGH_PRIORITY", "IGNORE", "INTO"})
        )
        ref = self._name(stmt, i)
        if ref is None:
            return self.syntax_error(stmt, min(i, len(stmt) - 1), text)
        found = self._resolve_table(ref[0], ref[1])
        if isinstance(found, Err):
            return found
        schema, table = found
        if schema in fakedata.SYSTEM_DATABASES:
            return Err(
                1044, "42000", f"Access denied for user '{self.user}'@'%' to database '{schema}'"
            )
        rows = 0
        seen_values = False
        depth = 0
        for t in stmt[ref[2] :]:
            if t.kind == WORD and t.upper in ("VALUES", "VALUE"):
                seen_values = True
            elif t.kind == SYM and t.text == "(":
                if seen_values and depth == 0:
                    rows += 1
                depth += 1
            elif t.kind == SYM and t.text == ")":
                depth = max(0, depth - 1)
        affected = max(1, rows)
        if table.gen:
            table.rows += affected
        return Ok(affected)

    @staticmethod
    def _has_where(stmt: list[Tok]) -> bool:
        return any(t.kind == WORD and t.upper == "WHERE" for t in stmt)

    def _write_target(self, stmt: list[Tok], i: int) -> tuple[str, TableDef] | Err:
        ref = self._name(stmt, i)
        if ref is None:
            return self.syntax_error(stmt, min(i, len(stmt) - 1), "")
        found = self._resolve_table(ref[0], ref[1])
        if isinstance(found, Err):
            return found
        if found[0] in fakedata.SYSTEM_DATABASES:
            return Err(
                1044, "42000", f"Access denied for user '{self.user}'@'%' to database '{found[0]}'"
            )
        return found

    def _update(self, stmt: list[Tok], text: str) -> Result:
        i = self._skip_words(stmt, 1, frozenset({"LOW_PRIORITY", "IGNORE"}))
        found = self._write_target(stmt, i)
        if isinstance(found, Err):
            return found
        _, table = found
        return Ok(1 if self._has_where(stmt) and table.rows else table.rows)

    def _delete(self, stmt: list[Tok], text: str) -> Result:
        i = self._skip_words(stmt, 1, frozenset({"LOW_PRIORITY", "QUICK", "IGNORE", "FROM"}))
        found = self._write_target(stmt, i)
        if isinstance(found, Err):
            return found
        _, table = found
        if self._has_where(stmt):
            affected = 1 if table.rows else 0
            table.rows = max(0, table.rows - affected)
            return Ok(affected)
        affected = table.rows
        table.rows = 0
        return Ok(affected)

    def _truncate(self, stmt: list[Tok], text: str) -> Result:
        i = self._skip_words(stmt, 1, frozenset({"TABLE"}))
        found = self._write_target(stmt, i)
        if isinstance(found, Err):
            return found
        found[1].rows = 0
        return Ok()

    def _alter(self, stmt: list[Tok], text: str) -> Result:
        if len(stmt) > 2 and stmt[1].upper == "TABLE":
            found = self._write_target(stmt, 2)
            if isinstance(found, Err):
                return found
        return Ok()

    def _load(self, stmt: list[Tok], text: str) -> Result:
        if any(t.upper == "LOCAL" for t in stmt):
            return Err(
                3948,
                "42000",
                "Loading local data is disabled; this must be enabled on both the client and "
                "server sides",
            )
        return Err(
            1290,
            "HY000",
            "The MySQL server is running with the --secure-file-priv option so it cannot "
            "execute this statement",
        )

    def _call(self, stmt: list[Tok], text: str) -> Result:
        ref = self._name(stmt, 1)
        name = ref[1] if ref else ""
        schema = ref[0] if ref and ref[0] else (self.db or "")
        if not schema:
            return Err(1046, "3D000", "No database selected")
        return Err(1305, "42000", f"PROCEDURE {schema}.{name[:IDENT_MAX]} does not exist")

    # --- other protocol-level answers ----------------------------------------------------

    def statistics(self) -> str:
        up = self.uptime()
        return (
            f"Uptime: {up}  Threads: 2  Questions: {up // 3 + 60 + self.queries}  "
            "Slow queries: 0  Opens: 214  Flush tables: 3  Open tables: 134  "
            f"Queries per second avg: {0.31 + (up % 7) / 100:.3f}"
        )


def wire_max_packet() -> int:
    return MAX_ALLOWED_PACKET


def _is_constant_word(upper: str) -> bool:
    return upper.startswith("@") or upper in (
        "NULL", "CURRENT_USER", "CURRENT_TIMESTAMP", "CURRENT_DATE", "NOW", "TRUE", "FALSE",
    )  # fmt: skip


def _row_matches(row: tuple[str | None, ...], flt: tuple[int, str, str]) -> bool:
    idx, op, want = flt
    have = row[idx] if idx < len(row) else None
    if have is None:
        return False
    if op == "like":
        return like_match(want, have)
    return have.lower() == want.lower()
