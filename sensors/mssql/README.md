# SuckerPot MSSQL sensor

An exposed Microsoft SQL Server 2019/2022 look-alike on TCP 1433 (container port 1433). It speaks
hand-written TDS well enough for `nmap -sV`, `sqlcmd`, impacket `mssqlclient` and `pymssql`, lets
a configurable weak set of logins in, and records everything the attacker sends. There is no SQL
engine: batches are answered from canned data, and nothing is ever executed or fetched.

## Behaviour

- PRELOGIN: version from the profile (15.0.x or 16.0.x), the option list of a real 2019/2022 server
  (VERSION, ENCRYPTION, INSTOPT, THREADID, MARS, FEDAUTHREQUIRED when asked). With TLS enabled the
  reply is `ENCRYPT_OFF` to a client that sent OFF and `ENCRYPT_ON` to ON/REQ clients, and the TLS
  handshake runs wrapped in PRELOGIN packets (self-signed `SSL_Self_Signed_Fallback` certificate
  created once under `/data`, mode 0600, TLS 1.2). With OFF only LOGIN7 is encrypted and the rest of
  the session is plaintext; with ON everything is. Credentials are recorded either way
  (`login_attempt.data.tls` says which). Clients that send NOT_SUP get NOT_SUP.
- LOGIN7: username, password, hostname, app name, client library, database are decoded with strict
  bounds. Default accepted logins: user `sa` with a short list of classic weak passwords. Anything
  else gets `Msg 18456, Level 14, State 1: Login failed for user 'x'.` and the connection closes.
- After login: `@@VERSION`, `SERVERPROPERTY(...)`, `DB_NAME()`, `SYSTEM_USER`,
  `IS_SRVROLEMEMBER`, `sys.databases`, catalog views, a few fake tables (`users`, `customers`,
  `orders`), `USE`, `sp_who`, `xp_fixeddrives`... `xp_cmdshell` and `sp_OACreate` are refused with the
  real "blocked ... turned off" error (15281) until the attacker runs `sp_configure` + `RECONFIGURE`
  as a real server requires, so the whole chain is captured. `xp_cmdshell` then returns a canned line
  for `whoami`/`hostname`/`ver` and nothing else.
- Windows authentication: a LOGIN7 with SSPI and an NTLM NEGOTIATE gets an NTLM CHALLENGE (machine
  and domain names derived from the secret, so `nmap ms-sql-ntlm-info` answers), the AUTHENTICATE
  message is recorded (`method: tds-ntlm`, user, domain, workstation, short hash preview) and refused.
- Non-TDS traffic: one `scan` event (`kind: non_tds`) with `protocol_guess` and a 64 byte hex preview.

## Configuration (environment)

`REDIS_HOST`, `REDIS_PORT`, `REDIS_USER`, `REDIS_PASSWORD`, `EVENTS_STREAM` belong to the event
publisher. Sensor tunables use the `SENSOR_` prefix.

| Variable | Default | Meaning |
| --- | --- | --- |
| `MSSQL_PUBLIC_PORT` | 1433 | `dst_port` reported in events |
| `SENSOR_PORT` | 1433 | container listen port |
| `SENSOR_DATA_DIR` | /data | holds `profile_secret` (0600); identity (server name, uptime, data) derives from it |
| `SENSOR_MSSQL_VERSION` | from secret | e.g. `15.0.4375.4` (major 15 or 16) |
| `SENSOR_MSSQL_ACCEPT_USERS` | sa | comma separated logins that can succeed |
| `SENSOR_MSSQL_ACCEPT_PASSWORDS` | 123456,password,Password1,P@ssw0rd,sa,admin | comma separated; empty string = nobody gets in |
| `SENSOR_MSSQL_ACCEPT_ANY` | false | accept every login |
| `SENSOR_MSSQL_TLS` | true | offer TLS (self-signed certificate) |
| `SENSOR_MAX_TLS` | 0 | live TLS streams (each budgeted at 48 KiB); 0 = as many as `SENSOR_MAX_CONNECTIONS`. A client is never answered NOT_SUP: without a slot it is slowly dropped |
| `SENSOR_MAX_TLS_PER_IP` | 3 | TLS streams one source IP may hold |
| `SENSOR_TLS_DEADLINE` | 10 | seconds from the PRELOGIN reply to the finished handshake, and from there to LOGIN7 |
| CPU buckets (constants in `server.py`, not env) | 0.05 / 0.25 s/s | per-IP / shared CPU budget (burst 0.25 / 0.5 s), plus 0.2 ms per message |
| `SENSOR_NEW_CONN_PER_SEC_PER_IP` / `SENSOR_NEW_CONN_BURST_PER_IP` / `SENSOR_GLOBAL_NEW_CONN_PER_SEC` | 3 / 40 / 200 | new-connection buckets, checked before any work |
| `SENSOR_MAX_CONNECTIONS` / `SENSOR_MAX_PER_IP` | 200 / 8 | connection caps |
| `SENSOR_FIRST_DATA_TIMEOUT` / `SENSOR_IDLE_TIMEOUT` / `SENSOR_MAX_SESSION` / `SENSOR_WRITE_TIMEOUT` | 15 / 45 / 240 / 10 s | timeouts |
| `SENSOR_MAX_COMMANDS` | 1000 | messages per connection |
| `SENSOR_MAX_BYTES_IN` / `SENSOR_MAX_BUFFERED` | 2 MiB / 12 MiB | per connection input, buffers+pending output of all connections |
| `SENSOR_MEMORY_LIMIT` | 256 MiB | used when the cgroup reports no limit |
| `SENSOR_*_PER_SEC*` | see `config.py` | session and event rate limits |

## Events

- `connect`, `disconnect` (`duration_s`, `reason`, `bytes_in/out`, `messages`, `logins`,
  `authenticated`, `flags`, `client_encryption`, `suppressed_events`, `config_changes`).
- `login_attempt`: `username`, `password`, `success`, `method` (`tds-sql`/`tds-sspi`), `hostname`,
  `app_name`, `client_library`, `database`, `tds_version`, `client_pid`.
- `command`: `input` (max 4096 chars), `kind` (`sql_batch`/`rpc`), `rpc`, `flags`, `output_preview`,
  `database`, `login`. Flags: `xp_cmdshell`, `sp_oacreate`, `sp_configure`, `reconfigure`,
  `ole_automation`, `drop_database`, `ransom_note`, `openrowset`, `bulk_insert`, `xp_dirtree`,
  `xp_regread`, `add_login`, `shell_command`, `lolbin`, `time_probe`, `sqli_probe`, `unc_path`, ...
- `download_attempt`: `url`, `tool`, `command` (recorded only).
- `scan`: `non_tds`, `tds_malformed`, `rate_limited`, `events_limited`.

## Limits and design notes

Parser holds at most one packet plus one read chunk; messages are capped at 128 KiB (rest counted);
statement text is cut before decoding; at most 16 statements per batch; replies are built from
constant-size tables. Work is time-sliced (10 ms per loop turn). Every message, including pre-login ones, is charged its
measured thread CPU time (plus a fixed cost) to a per-IP bucket; the shared bucket only slows IPs that
are already over half of their own budget, and debt is floored, so a quiet client never waits for a
noisy one and a heavy one stalls at most a few seconds (only its own connection). New connections
are rate-limited per IP and globally before anything else happens. TLS runs on memory BIOs
(no per-connection 256 KiB buffers). Pending output counts against the memory budget; the cgroup guard
refuses new connections above 70 % (also sampled at admission) and aborts the heaviest above 85 %; abort
on write timeout; a slot is released only after `connection_lost`; `SO_SNDBUF/RCVBUF` 64 KiB,
`TCP_USER_TIMEOUT` 30 s. Events: per-IP buckets (count and bytes) before a shared priority queue, repeats aggregated.
An event-loop watchdog exits the process if the loop stalls for 10 s.

Known fingerprint limits: TLS is 1.2 only and the certificate is generated, not issued; Windows
build strings and KB numbers are plausible, not authoritative; ODBC 18 with its default strict
certificate verification refuses the self-signed certificate, as it would against a real instance
with the fallback certificate.

## Compose block

```yaml
  sensor-mssql:
    build: { context: ., dockerfile: sensors/mssql/Dockerfile }
    restart: unless-stopped
    networks: [ingress, sensors-mssql]
    dns: ["127.0.0.1"]
    ports:
      - "0.0.0.0:${MSSQL_HOST_PORT:-1433}:1433"
    environment:
      REDIS_HOST: redis
      REDIS_USER: sensor-mssql
      REDIS_PASSWORD: ${REDIS_SENSOR_MSSQL_PASSWORD}
      EVENTS_STREAM: events:mssql
      EVENTS_MAXLEN: ${EVENTS_MAXLEN_LOW:-3000}
      MSSQL_PUBLIC_PORT: ${MSSQL_PUBLIC_PORT:-1433}
    volumes: [mssql-sensor-data:/data]
    read_only: true
    tmpfs: ["/tmp:rw,noexec,nosuid,size=16m"]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    mem_limit: 160m
    memswap_limit: 160m
    cpus: 0.5
    cpu_shares: 256
    oom_score_adj: 800
    pids_limit: 128
```
(`sensors-mssql` is an internal network shared with `redis`; add `mssql-sensor-data` to `volumes`.)

## Tests

`uv run pytest` (unit, framing, SQL responder, real-socket TDS client, limits). Real clients
(impacket, pymssql, sqlcmd, nmap) were run from throwaway containers; see the task report.
