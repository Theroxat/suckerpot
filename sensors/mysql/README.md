# MySQL sensor

A low-interaction MySQL 8.0 server. It speaks the MySQL wire protocol (hand written, with
strict bounds), accepts a configurable set of weak logins, answers a small set of canned SQL
statements and records everything an attacker does. Run with `python -m mysql_sensor`. It
listens on container port 3306. Compose maps the host port `MYSQL_HOST_PORT` to it, and no
capability is needed.

There is no SQL engine, no storage and no execution of any kind. Every answer is generated
from constants and from a few synthetic rows.

## What it does

1. **Initial Handshake v10**, like an Ubuntu 8.0 build: server version
   `8.0.43-0ubuntu0.24.04.2` (`SENSOR_MYSQL_VERSION`), a fresh random 20 byte salt per connection
   (bytes 1 to 127, never `$`), the capability flags of a stock 8.0 server (lower word
   `0xFFDF`, a stock server says `0xFFFF`: only `CLIENT_COMPRESS` is missing, because the
   sensor has no bounded decompressor; `CLIENT_ZSTD_COMPRESSION_ALGORITHM` is off for the same
   reason) including `SESSION_TRACK`, `OPTIONAL_RESULTSET_METADATA` and `QUERY_ATTRIBUTES`, status `AUTOCOMMIT`, character set
   `utf8mb4_0900_ai_ci` and the default plugin `caching_sha2_password`. TLS is offered, as on a
   stock server.
2. **HandshakeResponse41 / SSLRequest** parsing. The user name, database, auth plugin, auth
   response and connection attributes (`_client_name`, `program_name`, ...) are parsed with
   length checks everywhere. A malformed response becomes a `scan` event
   (`kind = malformed_mysql`) and the client gets error 1043 ("Bad handshake"). Traffic that
   cannot be a MySQL packet (HTTP, TLS, SSH, SMB, ...) becomes a `scan` event
   (`kind = non_mysql`, with a protocol guess and a 64 byte preview) and is treated like a
   real server treats it: the first four bytes are read as a packet header, a wrong sequence id
   (every HTTP verb, TLS record, ... has one) gets error 1156 ("Got packets out of order",
   08S01) and a close, and a plausible sequence id with a huge announced length gets no answer
   at all until the handshake timeout.
   Sequence ids are enforced everywhere (handshake, authentication, every command starts at 0).
3. **Authentication** against the accounts in `SENSOR_MYSQL_ACCOUNTS` (default
   `root:,root:root,admin:admin,mysql:mysql`: `user:password` pairs, an empty password is
   allowed, the same user may repeat).
   - `mysql_native_password` and `caching_sha2_password` scrambles are *verified* against the
     configured passwords, since the sensor knows them. A match records the matched password
     (`password_source = scramble_match`). The sensor never tries to recover a password it does
     not know from a scramble: no cracking.
   - An empty password (zero length, or the single NUL byte libmysqlclient sends for
     `caching_sha2_password`) is recorded as the empty password.
   - If a `caching_sha2_password` client does not match, the sensor asks for the full
     authentication, as a freshly started MySQL 8 server does. The client then sends its
     cleartext password, either inside TLS (`password_source = tls_cleartext`) or encrypted
     with the server's RSA public key (`rsa_cleartext`). This is the standard protocol; it is
     how the mysql 8 client, PyMySQL, hydra and medusa end up giving up their passwords.
   - A client that offers another plugin gets an AuthSwitchRequest to the default plugin.
   - `SENSOR_CLEAR_PASSWORD_SWITCH=true` (off by default; a real server only does this with
     PAM) makes the sensor ask every client to switch to `mysql_clear_password`. Clients that
     are configured to allow it answer with the cleartext password (`cleartext_switch`).
   - Failures get the exact real error: `Access denied for user 'x'@'<ip>' (using password:
     YES|NO)` (1045, SQLSTATE 28000), then the connection is closed. Each connection allows
     `SENSOR_MAX_AUTH_ATTEMPTS` authentication attempts (login plus `COM_CHANGE_USER`).
4. **Commands**: `COM_QUERY`, `COM_INIT_DB`, `COM_PING`, `COM_QUIT`, `COM_CHANGE_USER`,
   `COM_FIELD_LIST`, `COM_STATISTICS`, `COM_SET_OPTION` (multi statements on/off) and
   `COM_RESET_CONNECTION`. `COM_STMT_PREPARE` is refused with error 1295, as on servers that do
   not support it for the statement; `COM_STMT_EXECUTE` answers 1243. Anything else gets error
   1047 ("Unknown command").
5. **Canned SQL** (per connection state, all bounded):
   - `SELECT` of system variables (`@@version`, `@@version_comment`, `@@datadir`,
     `@@secure_file_priv`, ...), user variables and functions (`version()`, `database()`,
     `user()`, `current_user()`, `connection_id()`, `now()`, `sleep(n)` (a delay of at most 5 s per call, 10 s per query and 30 s per connection;
     `SLEEP(10)` returns after 5 s, a known tell), `load_file()` which returns NULL like a server with `secure_file_priv`);
   - `SHOW DATABASES`, `SHOW TABLES [FROM db]`, `SHOW [FULL] COLUMNS / DESCRIBE`,
     `SHOW CREATE TABLE`, `SHOW VARIABLES [LIKE]`, `SHOW STATUS [LIKE]`, `SHOW GRANTS`,
     `SHOW [FULL] PROCESSLIST`, `SHOW ENGINES`, `SHOW WARNINGS`;
   - the fake `shop` database (`customers` 1,284 rows, `orders` 5,310, `products` 96):
     `SELECT * / col list / COUNT(*) FROM <table> [WHERE col = value AND ...] [LIMIT n]` returns
     synthetic rows (names, `@example.com` addresses, `+1-555-01xx` phone numbers), at most 200
     rows per statement; `information_schema.{schemata,tables,columns}` and `mysql.user` (with
     the placeholder hashes MySQL uses for locked system accounts);
   - `USE`, `SET` (system and user variables), `CREATE/DROP DATABASE` and `CREATE/DROP TABLE`
     (a few databases and tables per connection, so a ransomware script sees its own work in
     the next `SHOW DATABASES`), `INSERT/UPDATE/DELETE/TRUNCATE`, `GRANT`, `FLUSH`, `BEGIN` and
     similar statements get an OK packet with a plausible affected-rows count;
   - `INTO OUTFILE/DUMPFILE` and `LOAD DATA INFILE` fail with error 1290 (`secure-file-priv`),
     `LOAD DATA LOCAL` with 3948, `CREATE FUNCTION ... SONAME` with error 1126 ("Can't open
     shared library ... No such file or directory"). The sensor never asks a client for a local
     file;
   - everything else gets a real-looking error: 1064 (syntax error near ...), 1146 (no such
     table), 1049, 1054, 1193, 1305, 1065, ...;
   - multiple statements in one packet are answered one by one when the client enabled
     `CLIENT_MULTI_STATEMENTS` (or `COM_SET_OPTION`), otherwise with a syntax error;
   - work budget: all statements of one `COM_QUERY` share 6,000 "steps" (rows examined; the
     biggest fake table has 5,310). An unfiltered `COUNT(*)` or `LIMIT` is arithmetic, a
     filtered `COUNT(*)` result is cached per table and filter, and a statement that would
     exceed the budget gets error 1317 ("Query execution was interrupted"). At most 1,000
     matching rows of a filtered query are addressable (`LIMIT 5000,10` on a filter that
     matches more than that returns nothing);
   - clients that negotiate `CLIENT_SESSION_TRACK` get OK packets in the tracking format (empty
     state), clients that negotiate `CLIENT_OPTIONAL_RESULTSET_METADATA` get the metadata flag
     (always "full metadata"), and the attribute prefix of `COM_QUERY` is parsed and recorded
     (`query_attributes` in the `command` event) for clients that negotiate
     `CLIENT_QUERY_ATTRIBUTES`. A malformed prefix gets error 1835.

The fake identity lives under `SENSOR_DATA_DIR` (a volume), created on first start with every
file at mode 0600: `profile_secret`; `private_key.pem` / `public_key.pem` (RSA 2048, for the
caching_sha2 exchange, as MySQL does); a CA certificate (serial 1) and a server certificate (serial 2) named
`MySQL_Server_8.0.43_Auto_Generated_CA_Certificate` / `..._Server_Certificate` (10 years,
start date a few months in the past, renewed when the version changes or when an older build's
certificate with a random serial is found). Like mysqld, the server presents the leaf only;
`ca.pem` is for clients that pin it. The host name
(`@@hostname`, general log file name) and the claimed uptime (a few weeks) are derived from the
secret. Nothing in a banner, error, certificate or variable names the project.

Nothing is ever executed, evaluated, fetched or written outside `SENSOR_DATA_DIR`. The sensor
never opens outbound connections. `tests/test_static.py` checks this with an AST scan (no
`subprocess`, `eval`, `exec`, `pickle`, `getattr` dispatch, `re`, network clients, file writes).

## Events

All events use the shared `suckerpot_common.Event` model, stream `events:mysql`. `dst_port` is
`MYSQL_PUBLIC_PORT`. No events are emitted for connections from 127.0.0.1 or ::1 (the container
healthcheck).

| type | data |
| --- | --- |
| `connect` | `server_version` |
| `login_attempt` | `username`, `password` (the cleartext when known, else null), `success`, `method` (plugin), `password_source` (`empty`, `scramble_match`, `rsa_cleartext`, `tls_cleartext`, `cleartext`, `cleartext_switch`, `rsa_rate_limited`, `rsa_invalid` or null), `auth_response_len`, `auth_response_preview` (hex, first 8 bytes only), `client_plugin`, `database`, `tls`, `attempt`, `client_caps`, `charset`, `client_attrs`, `incomplete` (set when the client left in the middle of the exchange) |
| `command` | `input` (the SQL text, capped), `protocol_command` (`COM_QUERY`, `COM_INIT_DB`, ...), `database`, `statements`, `length` (real length), `truncated`, `flags`, `output_preview`, `query_attributes` (only when the client sent some) |
| `download_attempt` | `url`, `tool` (`wget`, `curl`, `tftp`, ... or `sql`), `command`, `protocol` = `mysql` (only recorded, never fetched) |
| `scan` | `kind` = `non_mysql` / `malformed_mysql` (`protocol_guess`, `payload_preview`, `payload_ascii`, `bytes_received`, `error`) / `events_suppressed` (`suppressed_commands`, `suppressed_important`) / `rate_limited` / `rate_limited_aggregate` (connections that were not recorded) / `suppressed_logins` (one per source and minute: `count` of logins that exceeded the source's own event budget, `other_events`, `top_pairs` = up to 10 `{username, password, count}`, `untracked_pairs`, `window_s`) / `suppressed_logins_aggregate` |
| `disconnect` | `duration_s`, `reason`, `stage`, `bytes_in`, `bytes_out`, `commands`, `auth_attempts`, `logged_in`, `tls`, `username`, `tls_version`, `tls_cipher`, `tls_error` |

`command.flags` (for the tagging rules in ingest): `into_outfile` (also `INTO DUMPFILE`),
`load_file`, `load_data_infile`, `drop_database`, `ransom_note` (a `CREATE`, `INSERT`,
`UPDATE`, `ALTER` or `RENAME` that mentions bitcoin, btc, ransom, recover, decrypt, wallet,
monero, please_read, read_me, ...), `udf` (`CREATE FUNCTION ... SONAME`, `sys_exec`,
`sys_eval`), `log_file_write` (`SET GLOBAL general_log_file / slow_query_log_file`),
`sql_delay` (`sleep()`, `benchmark()`), `user_dump` (`mysql.user`), `schema_recon`
(`information_schema`), `show_databases`, `privilege_change` (`GRANT`, `REVOKE`,
`CREATE/ALTER USER`).

`disconnect.reason`: `client_quit`, `client_closed`, `client_reset`, `access_denied`,
`bad_handshake`, `non_mysql`, `timeout` (no data within the deadline), `idle_timeout`,
`max_session`, `input_limit`, `output_limit`, `command_limit`, `auth_limit`,
`packet_too_large`, `packet_out_of_order`, `cpu_limit` (asked for more CPU than it can ever get),
`write_timeout` (the peer did not read), `tls_error`,
`tls_rate_limited`, `tls_busy`, `evicted`, `memory_shed`, `error` (internal, caught and logged).

## Limits

- Connections: at most `SENSOR_MAX_CONNECTIONS` (200) overall and `SENSOR_MAX_PER_IP` (8) per
  source. Over the per-source cap a new connection gets error 1129 ("Host ... is blocked
  because of many connection errors"), over the global cap or the memory thresholds error 1040
  ("Too many connections"): the real answers of a real server. At the global cap, a connection
  that has been sitting on the handshake for more than 2 s is dropped to make room.
  Before any of that, a per-source token bucket (`SENSOR_CONNECTIONS_PER_SEC_PER_IP`, 25/s,
  burst 50) limits new connections: over it the answer is the same 1129, but only after
  `refusal_delay` (1 s), so a brute forcer gains nothing by retrying. These slow refusals
  cost no slot and are capped at 64 at a time (beyond that the connection is reset).
- Packets: `max_allowed_packet` is reported as 64 MiB (`@@max_allowed_packet`, the 8.0
  default). A packet is never buffered: at most `capture_bytes` (16 KiB for a query, 8 KiB for
  a login) are kept, the rest is read and discarded, whatever the announced length, so one
  connection holds a few tens of KiB. At most 8 MiB is read from, and 4 MiB sent to, one
  connection (a larger query closes the connection silently: the sensor cannot execute 8 MiB
  queries, a real server would). The very first packet is limited to 64 KiB: a larger
  announced length is not a MySQL client (see "Fingerprint notes").
- Deadlines: `SENSOR_HANDSHAKE_TIMEOUT` (10 s) for the login, 10 s plus the time a 16 KiB/s
  client needs for one packet (at most 60 s extra), 10 s per write, `SENSOR_IDLE_TIMEOUT`
  (120 s) between commands and `SENSOR_MAX_SESSION` (600 s) overall. A peer that does not
  read its results is aborted (`transport.abort()`), which frees its buffers at once. Accepted
  sockets get `TCP_USER_TIMEOUT` 30 s and 32 KiB kernel buffers.
- CPU: TLS handshakes need a global slot (`SENSOR_MAX_TLS_HANDSHAKES`), a global token
  (`SENSOR_TLS_GLOBAL_PER_SEC`, 30/s burst 60) and a per-source token
  (`SENSOR_TLS_PER_SEC_PER_IP`); RSA decryptions are limited per source (3/s) and overall
  (`SENSOR_RSA_PER_SEC`, 30/s). Queries are tokenised in one linear pass over their first
  16 KiB with no regular expressions, and every response is capped (200 rows). SQL work is
  budgeted in steps (one step is a row examined, about 5 microseconds): 6,000 per `COM_QUERY`
  for all its statements together (`SENSOR_QUERY_STEPS`), the loop is yielded to after every
  statement, and the time actually spent is charged to three reservation-style token buckets:
  per connection (20,000 steps/s), per source (30,000/s) and overall (60,000/s, about a
  quarter of the loop). A connection over its share simply waits before its next command; one
  that would have to wait more than 5 s is closed with error 1105 (`cpu_limit`). Work under
  100 steps is never throttled. Tests run 4 to 64 KiB pathological inputs against a 0.5 s
  limit, and 24 connections from 3 sources sending 50 full-scan statements per query for 30 s
  against a loop lag limit of 1 s.
- Memory: each connection is budgeted `conn_cost` (192 KiB, measured under abuse at about 175
  KiB including TLS) against a 64 MiB budget, plus its pending output (the bytes built for the
  next write and whatever sits in the transport buffer; at most about 64 KiB per connection:
  replies are built lazily and nothing more is built until `drain()` has returned). A guard
  reads the cgroup `memory.current` once per second and on every admission (at most 10 times
  a second): above 70 % of the limit new connections are refused, above 85 % the connections
  holding the most bytes are aborted. The event loop watchdog exits the process if the loop
  stalls for 10 s so that `restart: unless-stopped` recovers it. 200 connections over 25
  sources that ask for big results and never read them hold about 40 MiB.
- Events: a connection produces few events. Routine events (`connect`, plain `command`,
  `disconnect`) are recorded per connection only if the per-source bucket
  (`SENSOR_SESSIONS_PER_SEC_PER_IP`) and the global one allow it, and each connection records
  at most 60 plain commands. Important events (every `login_attempt`, flagged commands,
  `download_attempt`) have a bucket per SOURCE (`SENSOR_IMPORTANT_EVENTS_PER_SEC_PER_IP`, 10/s,
  burst 50) and a per-connection quota of 100. What a source cannot get through its own bucket
  is not dropped silently: it is counted and, once a minute, reported as one `scan` event
  (`kind = suppressed_logins`) per source with the number of logins and the most frequent
  user/password pairs, so a brute force at hundreds of connections per second can neither
  starve the credentials of other sources nor disappear. A session that was sampled out still
  reports its credentials, preceded by a `connect` event with the real connection time (queued
  only if the source still has budget, and not charged to it). Hard ceiling: all events
  together, except those aggregates (at most 101 per kind and minute), are limited to
  `SENSOR_GLOBAL_EVENTS_PER_SEC` (200/s, burst 400); routine events may use at most 100/s and
  disconnects 40/s of it, so important events always keep at least 60/s. Important events
  have their own queue, published first, and everything goes through bounded queues, so
  handlers never wait for Redis.
- Errors: any exception in a handler is caught; the client gets a generic error 1105, never a
  traceback, and the `disconnect` event is still emitted.

## Environment variables

Tunables are `SENSOR_*`. The older `MYSQL_*` spelling of the same name (`MYSQL_PORT`,
`MYSQL_VERSION`, `MYSQL_ACCOUNTS`, ...) is still read when the `SENSOR_*` one is not set.
`MYSQL_PUBLIC_PORT` (set by compose from `MYSQL_HOST_PORT`) and the `REDIS_*` publisher
variables keep their names.

| variable | default | meaning |
| --- | --- | --- |
| `REDIS_HOST`, `REDIS_PORT`, `REDIS_USER`, `REDIS_PASSWORD`, `EVENTS_STREAM`, `EVENTS_MAXLEN` | see `suckerpot_common` | Redis stream publisher |
| `SENSOR_PORT` | `3306` | listen port inside the container |
| `MYSQL_PUBLIC_PORT` | `3306` | port reported as `dst_port` |
| `SENSOR_MYSQL_VERSION` | `8.0.43-0ubuntu0.24.04.2` | server version string (must start with `8.0.`) |
| `SENSOR_HOSTNAME` | derived | value of `@@hostname` |
| `SENSOR_DATA_DIR` | `/data` | secret, RSA keys, certificates (volume) |
| `SENSOR_MYSQL_ACCOUNTS` | `root:,root:root,admin:admin,mysql:mysql` | accepted `user:password` pairs |
| `SENSOR_DEFAULT_PLUGIN` | `caching_sha2_password` | plugin advertised in the handshake (or `mysql_native_password`) |
| `SENSOR_CLEAR_PASSWORD_SWITCH` | `false` | ask clients to switch to `mysql_clear_password` |
| `SENSOR_ENABLE_TLS` | `true` | offer TLS |
| `SENSOR_MAX_CONNECTIONS` / `SENSOR_MAX_PER_IP` | `200` / `8` | connection caps |
| `SENSOR_CONNECTIONS_PER_SEC_PER_IP` | `25` | new connections per source and second (burst 50) |
| `SENSOR_HANDSHAKE_TIMEOUT` / `SENSOR_IDLE_TIMEOUT` / `SENSOR_MAX_SESSION` | `10` / `120` / `600` | seconds |
| `SENSOR_MAX_AUTH_ATTEMPTS` / `SENSOR_MAX_COMMANDS` | `3` / `1000` | per connection |
| `SENSOR_MEMORY_LIMIT` | `268435456` | limit used by the memory guard when no cgroup limit is visible |
| `SENSOR_QUERY_STEPS` | `6000` | work budget (rows examined) of one `COM_QUERY` |
| `SENSOR_SESSIONS_PER_SEC_PER_IP` / `SENSOR_GLOBAL_SESSIONS_PER_SEC` | `2` / `50` | recorded connections |
| `SENSOR_GLOBAL_EVENTS_PER_SEC` | `200` | hard ceiling for all events but the aggregates |
| `SENSOR_ROUTINE_EVENTS_PER_SEC` / `SENSOR_DISCONNECT_EVENTS_PER_SEC` | `100` / `40` | shares of the ceiling |
| `SENSOR_IMPORTANT_EVENTS_PER_SEC_PER_IP` | `10` | important events per source and second (burst 50) |
| `SENSOR_TLS_PER_SEC_PER_IP` / `SENSOR_TLS_BURST_PER_IP` / `SENSOR_TLS_GLOBAL_PER_SEC` / `SENSOR_MAX_TLS_HANDSHAKES` | `5` / `20` / `30` / `16` | TLS handshake limits |
| `SENSOR_RSA_PER_SEC` / `SENSOR_RSA_PER_SEC_PER_IP` | `30` / `3` | RSA decryptions per second, overall and per source |

## Fingerprint notes (nmap from `instrumentisto/nmap`, the `mysql:8.0` client, PyMySQL, hydra, medusa)

- `nmap -sV -p 3306`: `3306/tcp open mysql MySQL 8.0.43-0ubuntu0.24.04.2`.
- `mysql-info`: protocol 10, capability flags 65503 (a stock 8.0 server says 65535: the
  missing bit is `CLIENT_COMPRESS`), auth plugin `caching_sha2_password`.
- `mysql-empty-password`: `root account has empty password` (with the default accounts).
- `ssl-cert`: `commonName=MySQL_Server_8.0.43_Auto_Generated_Server_Certificate`, issued by the
  matching `..._CA_Certificate`, RSA 2048, SHA-256.
- The mysql 8.0 client connects with TLS (`TLS_AES_256_GCM_SHA384`) and `\s` shows an Ubuntu
  server with a multi-week uptime.
- Known differences from a real server: no replication, no real data, no compression (flag
  0x20 and zstd are not offered), no prepared statements, no `LOCAL INFILE`, no X protocol
  (33060), state does not survive the connection, `SLEEP(10)` returns after 5 s, queries or
  packets above 8 MiB close the connection, a statement that needs more than 6,000 rows of
  work gets error 1317, and clients that negotiate `CLIENT_OPTIONAL_RESULTSET_METADATA` get
  the metadata flag placed after the column count (untested against a real client; the
  common clients do not negotiate it).
- Non-MySQL traffic: an HTTP request, TLS ClientHello, SSH banner, ... on 3306 gets error 1156
  (sequence id mismatch) like on a real server, which is also what `curl` shows as
  "Got packets out of order".

## Compose service

```yaml
  sensor-mysql:
    build:
      context: .
      dockerfile: sensors/mysql/Dockerfile
    <<: *hardening
    user: "10001:10001"
    environment:
      REDIS_HOST: redis
      REDIS_PORT: "6379"
      REDIS_USER: sensor-mysql
      REDIS_PASSWORD: ${REDIS_SENSOR_MYSQL_PASSWORD:?REDIS_SENSOR_MYSQL_PASSWORD must be set in .env}
      EVENTS_STREAM: events:mysql
      EVENTS_MAXLEN: ${EVENTS_MAXLEN:-10000}
      SENSOR_PORT: "3306"
      MYSQL_PUBLIC_PORT: ${MYSQL_HOST_PORT:-3306}
      SENSOR_DATA_DIR: /data
      SENSOR_MYSQL_ACCOUNTS: ${MYSQL_ACCOUNTS:-root:,root:root,admin:admin,mysql:mysql}
      SENSOR_MAX_CONNECTIONS: ${MYSQL_MAX_CONNECTIONS:-200}
      SENSOR_MAX_PER_IP: ${MYSQL_MAX_PER_IP:-8}
      SENSOR_MEMORY_LIMIT: "268435456"
    # Explicit IPv4 so Docker does not also publish on [::]. No capability needed.
    ports:
      - "0.0.0.0:${MYSQL_HOST_PORT:-3306}:3306"
    # Docker's embedded DNS still resolves service names; external names fail.
    dns: ["127.0.0.1"]
    # ingress: inbound only. sensors-mysql: internal link to Redis.
    networks: [ingress, sensors-mysql]
    volumes:
      # Profile secret, RSA keys and TLS certificates, generated on first start. Never committed.
      - mysql-data:/data
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001
    mem_limit: 256m
    memswap_limit: 256m
    cpus: 0.5
    pids_limit: 128
    restart: unless-stopped
```

The orchestrator also has to add the `mysql-data` volume, the `sensors-mysql` network
(`internal: true`), a `sensor-mysql` Redis ACL user limited to XADD on `events:mysql`, and
`REDIS_SENSOR_MYSQL_PASSWORD`, `MYSQL_HOST_PORT` and `MYSQL_ACCOUNTS` (optional) in
`.env.example`. The sensor container adds no capability and runs as uid 10001 with a read-only
root file system.

## Development

```
uv sync
uv run ruff check && uv run ruff format --check && uv run mypy . && uv run python -m pytest
sg docker -c "sh sensors/mysql/tests/blackbox.sh"  # from the repo root: real mysql, PyMySQL, hydra, medusa, nmap
sg docker -c "sh sensors/mysql/tests/flood.sh"     # 20 source addresses, ~75 s, memory and CPU sampled
```

The pytest suite uses PyMySQL as a real client against the running listener (plain, TLS with
certificate chain verification, RSA full authentication, multiple statements), raw sockets for
hostile clients (slow handshake, oversized packets, clients that never read, floods of
events), a CPU test (`tests/test_cpu.py`: 3 sources x 8 connections of 50-statement full scans
for 30 s with a loop lag probe, 200 non-reading connections over 25 sources, the work budget
and the SLEEP caps), a fairness test (a flooding source and a victim) and a fuzzer for the
packet parsers. `tests/scanclient.py` is the stand-alone version of the scan load generator.
