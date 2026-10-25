# Redis sensor

An exposed, unauthenticated Redis 7.2 server, emulated entirely in memory. It speaks RESP2 and
RESP3, answers the commands that bots and scanners use with the replies a real server gives,
and records what they try. Run with `python -m redis_sensor`. It listens on container port
6379; compose maps the host port `REDIS_HOST_PORT` to it, and no capability is needed.

**Nothing is executed, loaded, fetched or replicated.** `EVAL` scripts and `MODULE LOAD`
paths are only recorded. `SLAVEOF` only records the target and never connects. `CONFIG SET
dir` / `dbfilename` followed by `SAVE` writes nothing: the values live in the object of that
one connection. The sensor never opens an outbound connection, and the only file it writes is
its profile secret under `SENSOR_DATA_DIR`. `tests/test_static.py` enforces this with an AST
scan (no `eval`/`exec`/`compile`/`subprocess`/`pickle`/`importlib`, no regular expressions, no
outbound sockets, no file writes elsewhere).

## What it does

- **Parser.** RESP arrays of bulk strings and inline commands (with `redis-cli` style
  quoting), written by hand. Bounds: 1024 arguments kept per command, 512 KiB kept per
  argument, 1 MiB per command, 64 KiB per inline line, 128 bytes per `*N` / `$N` header.
  Larger but legal input (an argument up to Redis' own 512 MiB, up to 1,048,576 arguments) is
  read and discarded in place, keeping a 1 KiB prefix of the argument and the flag
  `oversized_arg`, so a big payload behaves as on a real server (the connection's 4 MiB input
  cap still applies). Real framing errors get the real reply (`-ERR Protocol error: invalid
  bulk length`, `unbalanced quotes in request`, `too big inline request`, ...) and the
  connection is closed, as Redis does.
  `POST` / `Host:` as the first word (HTTP aimed at Redis) drops the connection silently, as
  Redis does after its cross-protocol warning, and is recorded as a `scan`.
- **Commands.** `PING ECHO INFO CONFIG GET/SET/RESETSTAT/REWRITE SET GET SETNX SETEX PSETEX
  APPEND STRLEN INCR DECR INCRBY DECRBY DEL UNLINK EXISTS MGET MSET TYPE TTL PTTL EXPIRE
  PEXPIRE KEYS SCAN RANDOMKEY FLUSHALL FLUSHDB DBSIZE SAVE BGSAVE BGREWRITEAOF LASTSAVE
  SLAVEOF REPLICAOF MODULE CLIENT COMMAND SELECT AUTH HELLO QUIT RESET EVAL EVALSHA SCRIPT
  TIME ROLE DEBUG SHUTDOWN SYNC PSYNC MONITOR MULTI EXEC DISCARD`, plus type-correct replies
  for the rest that bots probe (`LPUSH LRANGE LLEN HSET HGETALL SADD SMEMBERS ZADD RENAME
  XADD ACL FUNCTION MEMORY OBJECT SLOWLOG LATENCY CLUSTER MIGRATE SUBSCRIBE ...`): empty
  collections answer `*0` / `%0` / `~0` / nil, a key created by `LPUSH` then read with `GET`
  gives `-WRONGTYPE`, `CLUSTER` says cluster support is disabled and `MIGRATE` fails with
  `-IOERR` without connecting (collections are modelled by kind and size only, no members).
  Unknown commands get the exact text:
  `-ERR unknown command 'FOO', with args beginning with: 'a' 'b' `. Wrong argument counts get
  `-ERR wrong number of arguments for 'get' command`.
- **Fake keyspace.** Every connection starts with 3 to 5 plausible cached keys derived from
  the deployment secret (`session:...`, `cache:homepage`, ...) and has its own copy, so
  `FLUSHALL` by one bot is invisible to the next. Bounded: 64 keys, 256 bytes per key, 16 KiB
  per stored value (longer values are cut), 64 KiB per connection.
- **Per-connection config.** `CONFIG SET dir`, `dbfilename`, `appendonly`, `save`,
  `requirepass`, ... are accepted (with Redis' own validation errors: `dbfilename can't be a
  path`, `Unknown option`, `can't set immutable config`) and read back by `CONFIG GET` and
  `INFO` on the same connection. **Deliberate lure:** a real Redis 7.x refuses `CONFIG SET dir`
  and `dbfilename` unless `enable-protected-configs` is on (`can't set protected config`),
  which defeats the classic cron / SSH-key / webshell chains before they reveal their payload.
  The sensor accepts them on purpose, to capture the whole chain. A scanner that tests for
  that refusal can tell the difference; the trade-off is judged worth it for the data.
  Known tells of the same kind: `MODULE LOAD` always fails with "Error loading the extension"
  (a real server would load a valid module), `SLAVEOF` never actually replicates
  (`master_link_status` stays `down`), and `MIGRATE` always fails with `-IOERR`. A `requirepass` set by a ransom bot makes a later `AUTH` on
  that connection behave accordingly.
- **AUTH.** With no password configured: `-ERR AUTH <password> called without any password
  configured for the default user. Are you sure your configuration is correct?`, as Redis 7.2
  answers. `AUTH default <anything>` succeeds, other users get `-WRONGPASS`. Every attempt is
  a `login_attempt` carrying the clear-text username and password.
- **EVAL.** Recorded, never run. Scripts that touch `package`, `loadlib`, `require`, `io.`,
  `os.`, ... (the CVE-2022-0543 Lua sandbox escape) get `-ERR user_script:1: Script attempted
  to access nonexistent global variable 'package' ...`; `return <int>` returns the integer;
  anything else returns nil. `EVALSHA` returns `-NOSCRIPT`.
- **MODULE LOAD** returns `-ERR Error loading the extension. Please check the server logs.`;
  the path is recorded. The follow-up `system.exec` of rogue-server exploits then shows up as
  an unknown command, which is recorded too.
- **Downloads.** URLs found in command arguments (SET values, EVAL scripts, `CONFIG SET`
  values, ...) become `download_attempt` events: `http`, `https`, `ftp`, `tftp`, `sftp` URLs,
  and scheme-less `curl host/file` / `wget host/file` forms. The tool (`curl`, `wget`, ...) is
  taken from the text before the URL. Nothing is fetched.

### Fingerprint

- `nmap -sV -p 6379`: `redis  Redis key-value store 7.2.x` (the patch level is derived from
  the deployment secret, 7.2.4 to 7.2.9, or set with `SENSOR_REDIS_VERSION`).
- `INFO` follows the Redis 7.2 layout (all default sections, `# Keyspace` listing `db0` while
  keys exist). Uptime counts up from a per-deployment offset of 2 to 70 days; memory, CPU,
  stats and `run_id` / `master_replid` are generated from the secret. `os` is an Ubuntu 24.04
  kernel (`Linux 6.8.0-NN-generic x86_64`), `gcc_version` the one of the official image.
- redis-cli 7.4 and redis-py (RESP2 and RESP3) work unmodified. Differences from a real
  server: no pub/sub, no data types other than strings, and `COMMAND` (no arguments) returns
  an empty array.
- No banner is sent (Redis sends none). Nothing in a reply mentions the sensor.

## Events

All events use the shared `suckerpot_common.Event` model. `dst_port` is `REDIS_PUBLIC_PORT`.
No events are emitted for connections from 127.0.0.1 or ::1 (the container healthcheck).

| type | data |
| --- | --- |
| `connect` | (empty) |
| `login_attempt` | `username`, `password` (clear text), `success`, `method` (`redis-auth` / `redis-hello`), `flags` = `["auth"]` |
| `command` | `input` (redis-cli style line, 2048 characters at most), `command` (upper case name), `argc`, `flags`, `output_preview` (reply, 160 bytes), `db`, `repeated_before` (how many identical commands directly before this one were folded into it); for `MODULE LOAD`: `module_path`; for `SLAVEOF`: `master` (`host:port`); for `SAVE` / `BGSAVE`: `dir`, `dbfilename` as configured on the connection |
| `download_attempt` | `url`, `tool`, `command` (the input line, 512 characters), `via` (the Redis command) |
| `scan` | `kind` = `redis_replication` (`master_host`, `master_port`, `command`, `flags`) / `cross_protocol` (`input`, `protocol_guess`) / `redis_protocol_error` (`error`) / `rate_limited` / `rate_limited_aggregate` |
| `disconnect` | `duration_s`, `reason`, `bytes_in`, `bytes_out`, `commands`, `flags` (all indicator flags seen), `suppressed_events` (per bucket, when quotas were hit), `config_changes` (`dir`, `dbfilename`, ... final values when the attacker changed them), `config_history` (the first 10 `[name, value]` changes in order), `replicaof` |

`AUTH` produces a `login_attempt` and no `command` event.

`flags` on `command` events (ingest rules key on them):

| flag | meaning |
| --- | --- |
| `config_set`, `config_set_dir`, `config_set_dbfilename` | the attacker changed configuration |
| `cron_write` | `dir` under `/var/spool/cron`, `/etc/cron*`, `/etc/crontab`, ... or `dbfilename` is `root` (set on the `CONFIG SET` and again on `SAVE` / `BGSAVE`) |
| `ssh_key_write` | `dir` ends in `.ssh` and `dbfilename` is `authorized_keys` |
| `webshell_write` | `dbfilename` ends in `.php` / `.jsp` / ... in a web root |
| `save` | `SAVE` / `BGSAVE` |
| `slaveof` | `SLAVEOF` / `REPLICAOF` (also `config set replicaof`) |
| `module_load` | `MODULE LOAD` / `LOADEX` |
| `flushall`, `flushdb` | data wipe (ransom bots) |
| `eval`, `lua_sandbox_escape` | script submitted; script touching `package` / `io` / `os` / `loadlib` |
| `requirepass_set`, `aof_enabled` | lock-out or persistence changes |
| `oversized_arg`, `migrate`, `acl_setuser`, `function_load` | an argument was cut to a prefix; `MIGRATE`, `ACL SETUSER`, `FUNCTION LOAD` attempts |
| `psync`, `shutdown`, `debug`, `unknown_command` | replication handshake, shutdown attempt, `DEBUG`, a command Redis does not know |
| `cron_payload`, `ssh_key_payload`, `webshell_payload`, `reverse_shell`, `miner`, `kinsing`, `dropper`, `ransom_note`, `download` | indicators in the data they stored or sent |

`disconnect.reason`: `client_closed`, `client_reset`, `quit`, `no_data`, `idle`, `max_session`,
`protocol_error`, `cross_protocol`, `command_limit`, `input_limit`, `budget` (global buffer
budget), `memory_pressure`, `evicted`, `write_timeout`, `shutdown_command`, `error`, `shutdown`.

## Limits and abuse resistance

- **Connections.** At most `SENSOR_MAX_CONNECTIONS` (200) and `SENSOR_MAX_PER_IP` (8). At the
  global cap the oldest connection that has not sent anything is evicted; otherwise, and for
  the per-IP cap, the newcomer waits a random 50 to 350 ms and gets
  `-ERR max number of clients reached`, then is closed (at most 64 such connections at once,
  beyond that they are aborted).
- **Timeouts.** 15 s for the first bytes (nmap waits several seconds before its second probe),
  45 s idle, 240 s per connection, 10 s per write. A peer that does not read is aborted
  (`transport.abort()`), slots are released only when the transport is gone. Accepted sockets
  get `SO_SNDBUF` / `SO_RCVBUF` of about 64 KB and `TCP_USER_TIMEOUT` of 30 s.
- **Buffers and reply memory.** A connection holds parser input plus reply bytes the kernel has
  not taken yet; both are charged to a global budget (`SENSOR_MAX_BUFFERED`, 32 MiB) and the
  connection is aborted when it would exceed it. Replies are built at most 64 KiB at a time and
  written with `drain()` before more is built; large replies (`ECHO` / `PING` of a big
  argument, `MGET`) are generated piece by piece from the stored value, never built whole, and
  sizes are checked before anything is built. At most 4 MiB is read and 3000 commands are run
  per connection (`SENSOR_MAX_BYTES_IN`, `SENSOR_MAX_COMMANDS`).
- **CPU.** Command processing is sliced by wall-clock time: a connection yields to the event
  loop after 5 ms of work, whatever mix of commands it pipelined. Glob work (`KEYS`, `SCAN
  MATCH`, `CONFIG GET`) is counted in steps: at most 5000 per command, drawn from a bucket per
  connection (50 000 steps/s), per source IP (200 000/s) and for the process (500 000/s). A
  source whose bucket is empty gets plain empty results (`*0`) for those commands until it
  refills. A watchdog thread restarts the process if the loop is ever stalled for 10 s.
- **Memory guard.** On every admission (at most every 200 ms) and once a second the cgroup `memory.current` (minus page cache) is compared
  with `memory.max`: above 70 % new connections are refused, above 85 % the connections
  holding the most buffered bytes are aborted. Without cgroup v2 the process RSS against
  `SENSOR_MEMORY_LIMIT` is used. A flood test (26 source addresses, 208 connections each
  holding a half-sent 200 KB `SET`, 256 MiB limit) peaked at 88 MiB, 34 % of the limit.
- **Work bounds.** Glob patterns (`KEYS`, `SCAN MATCH`, `CONFIG GET`) are matched by a hand
  written matcher with a step budget (5000 per command, see CPU above) and caps of 128 bytes for the
  pattern and 512 for a key. Indicator extraction scans at most 16 KiB per command with plain
  `str.find`, at most 32 `curl` / `wget` hits per text; the scan is charged to the same CPU
  buckets (1 step per 4 characters), an identical repeated text is not scanned again, and an
  empty bucket skips the scan (the event is kept, flagged `scan_skipped`). There are timing tests with 4 to 100 KB pathological inputs.
- **Events.** A connection is recorded only if the per-IP bucket (`SENSOR_SESSIONS_PER_SEC_PER_IP`,
  burst 15 times that) and the global bucket allow it; unrecorded connections are counted
  and reported every 60 s as one `scan` (`rate_limited`) per top IP plus an aggregate. Inside
  a session, quotas apply: 20 noisy commands (`PING`, `INFO`, `GET`, ...), 50 other commands,
  100 flagged (priority) commands, 50 logins, 20 downloads, 300 events in total. Consecutive
  identical commands are aggregated: one event, and the next event carries
  `repeated_before`. Whatever exceeds a quota is counted in `disconnect.suppressed_events`.
- **Event fairness.** Before the shared queues, every source IP has its own token buckets:
  20 events/s (burst 200) for ordinary events, 10/s (burst 100) for urgent ones, and
  20 KB/s (burst 300 KB) of event bytes; one IP may also have at most 250 ordinary and 100
  urgent events waiting. Urgent events (`connect`, `disconnect`, `login_attempt`,
  `download_attempt` and flagged commands such as `slaveof` or `module_load`) go to their own
  small queue, which is published first. The shared buckets (session admission and the global
  event buckets) keep 30 % in reserve that only light sources can spend (a source is heavy once
  it has used more than half of its own per-IP burst), so flooding IPs cannot leave a quiet
  one unrecorded. A flooding source is therefore throttled alone and
  cannot crowd out the events of other sources (test: six flooding connections plus a victim
  IP with a slow publisher, every victim event arrives). `disconnect` events have a reserve of
  their own: a per-IP bucket of 4/s (burst 60) that bypasses the other per-IP buckets and
  queue caps (the global 60/s disconnect cap still applies), so no flooded session stays
  "open" in the UI. Global buckets: 200 ordinary events/s,
  300 urgent events/s, 60 disconnects/s. Handlers never wait for Redis. Every string in an
  event is cut to 2048 characters with `truncate_data`.
- **Errors.** Any exception in a handler is caught, a `disconnect` with `reason = error` is
  still emitted, and no error text reaches the client. A watchdog thread exits the process
  (code 70) when the event loop stalls for more than 10 s, so `restart: unless-stopped`
  recovers it.

## Environment variables

`REDIS_HOST`, `REDIS_PORT`, `REDIS_USER` and `REDIS_PASSWORD` are the event publisher's
(they point at the stream Redis, not at this sensor), so the sensor's own tunables use the
`SENSOR_` prefix. Only `REDIS_PUBLIC_PORT` follows the shared naming scheme.

| variable | default | meaning |
| --- | --- | --- |
| `REDIS_HOST`, `REDIS_PORT`, `REDIS_USER`, `REDIS_PASSWORD`, `EVENTS_STREAM`, `EVENTS_MAXLEN` | see `suckerpot_common` | Redis stream publisher |
| `SENSOR_PORT` | `6379` | listen port inside the container |
| `REDIS_PUBLIC_PORT` | `6379` | port reported as `dst_port` and in `INFO` |
| `SENSOR_REDIS_VERSION` | derived (`7.2.4` to `7.2.9`) | `7.2` or a full version such as `7.2.5` |
| `SENSOR_DATA_DIR` | `/data` | profile secret (volume) |
| `SENSOR_MAX_CONNECTIONS` / `SENSOR_MAX_PER_IP` | `200` / `8` | connection caps |
| `SENSOR_FIRST_DATA_TIMEOUT` / `SENSOR_IDLE_TIMEOUT` / `SENSOR_MAX_SESSION` / `SENSOR_WRITE_TIMEOUT` | `15` / `45` / `240` / `10` | seconds |
| `SENSOR_MAX_COMMANDS` / `SENSOR_MAX_BYTES_IN` | `3000` / `4194304` | per connection |
| `SENSOR_MAX_BUFFERED` | `33554432` | parser bytes across all connections |
| `SENSOR_MEMORY_LIMIT` | `268435456` | fallback limit when the cgroup has none |
| `SENSOR_SESSIONS_PER_SEC_PER_IP` / `SENSOR_GLOBAL_SESSIONS_PER_SEC` | `2` / `50` | recorded connections per second |
| `SENSOR_CPU_STEPS_PER_CONN` / `SENSOR_CPU_STEPS_PER_IP` / `SENSOR_CPU_STEPS_PER_SEC` | `50000` / `200000` / `500000` | glob work units per second (see CPU) |
| `SENSOR_GLOBAL_EVENTS_PER_SEC` / `SENSOR_PRIORITY_EVENTS_PER_SEC` / `SENSOR_DISCONNECT_EVENTS_PER_SEC` | `200` / `300` / `60` | global event buckets |

## Compose service

```yaml
  sensor-redis:
    build:
      context: .
      dockerfile: sensors/redis/Dockerfile
    <<: *hardening
    user: "10001:10001"
    environment:
      REDIS_HOST: redis
      REDIS_PORT: "6379"
      REDIS_USER: sensor-redis
      REDIS_PASSWORD: ${REDIS_SENSOR_REDIS_PASSWORD:?REDIS_SENSOR_REDIS_PASSWORD must be set in .env}
      EVENTS_STREAM: events:redis
      EVENTS_MAXLEN: ${EVENTS_MAXLEN:-10000}
      SENSOR_PORT: "6379"
      REDIS_PUBLIC_PORT: ${REDIS_HOST_PORT:-6379}
      SENSOR_REDIS_VERSION: ${SENSOR_REDIS_VERSION:-}
      SENSOR_DATA_DIR: /data
      SENSOR_MAX_CONNECTIONS: ${REDIS_MAX_CONNECTIONS:-200}
      SENSOR_MAX_PER_IP: ${REDIS_MAX_PER_IP:-8}
      SENSOR_MEMORY_LIMIT: "268435456"
    # Explicit IPv4 so Docker does not also publish on [::]. No capability needed.
    ports:
      - "0.0.0.0:${REDIS_HOST_PORT:-6379}:6379"
    # Docker's embedded DNS still resolves service names; external names fail.
    dns: ["127.0.0.1"]
    # ingress: inbound only. sensors-redis: internal link to the stream Redis.
    networks: [ingress, sensors-redis]
    volumes:
      # Profile secret, generated on first start. Never committed.
      - redis-sensor-data:/data
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001
    mem_limit: 256m
    memswap_limit: 256m
    cpus: 0.5
    pids_limit: 128
    restart: unless-stopped
```

The orchestrator also has to add the `redis-sensor-data` volume, the `sensors-redis` network
(`internal: true`, also attached to the `redis` service), a `sensor-redis` ACL user limited
to XADD on `events:redis`, and `REDIS_SENSOR_REDIS_PASSWORD` in `.env.example`. The compose
service name `sensor-redis` and the stream host `redis` are different things: the sensor
listens on 6379 as a decoy and publishes to the `redis` service.

## Development

```
uv sync
uv run ruff check && uv run ruff format --check && uv run mypy . && uv run python -m pytest
sg docker -c "sh sensors/redis/tests/blackbox.sh"   # from the repo root: redis-cli, redis-py, nmap -sV
```
