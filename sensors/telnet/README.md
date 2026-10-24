# Telnet sensor

A Telnet server that looks like a cheap embedded Linux device (an IP camera / DVR, or a home
router) running BusyBox. Run with `python -m telnet_sensor`; it listens on container port 2323
(compose maps the host port 23). Built for the Mirai family of bots, and it is equally happy with a
human typing.

## What it does

- Raw asyncio, no Telnet library. The server opens like BusyBox `telnetd` (`IAC DO ECHO, DO NAWS,
  WILL ECHO, WILL SGA`), so `nmap -sV` reports `telnet BusyBox telnetd`. It then prints
  `<hostname> login: ` and `Password: ` (no echo) and answers a wrong password with
  `Login incorrect`, like `login(1)`.
- Option negotiation is exactly what BusyBox telnetd does: the four-command opener, then nothing.
  WILL/WONT/DO/DONT from the client are recorded (`connect.client_options`) and never answered,
  so two peers cannot loop; the server never asks for TTYPE or LINEMODE. `NAWS` (window size) and
  a volunteered `TTYPE IS` are parsed. Subnegotiations are bounded to 64 bytes.
- The weak-credential list is the classic Mirai dictionary, trimmed (`TELNET_ACCEPT_CREDENTIALS`).
  Every attempt is recorded, successful or not. Optionally any non-empty password is accepted
  with `TELNET_ACCEPT_RANDOM_PROB`.
- After login the client gets BusyBox's `built-in shell (ash)` banner and a `~ # ` prompt. The
  shell is the SSH sensor's emulation (`suckerpot-sensor-ssh`, imported as a library) restricted
  to BusyBox applets and re-skinned: `sh: foo: not found`, `/bin/busybox FOO` -> `FOO: applet not
  found`, BusyBox-format `ps`, `free`, `df`, `ifconfig`, `netstat`, `ping`, `uname`, `uptime`,
  `wget`, `tftp`, `ftpget`. `enable`, `system`, `shell`, `linuxshell` are "not found" (as on a
  plain BusyBox) and `sh` just returns to the prompt. Echo-loader idioms work: `echo -ne
  '\x7f\x45...' >> f`, `>.t && cat .t`, `cat /bin/echo` returns a real ELF header of the device's
  architecture (so a loader that sniffs the architecture picks the ARM or MIPS binary).
- Nothing is ever executed or fetched. `wget`, `tftp`, `ftpget` (and `curl`, which the device does
  not have: it answers "not found" but the URL is still kept) only emit `download_attempt` events
  and drop a 400-byte stub file; running a dropped "binary" starts silently and does nothing.
- Personalities (`TELNET_PERSONALITY`): `dvr` (ARMv7, 64 MB RAM, BusyBox 1.19.4, kernel 3.0.8) and
  `router` (MIPS 74Kc, 32 MB RAM, BusyBox 1.17.3, kernel 2.6.31). `/proc/cpuinfo`, `meminfo`,
  `mounts`, `version`, `uname`, `ps`, `df` and `netstat` follow the personality.
- The device identity (hostname, LAN address, MAC, uptime) is derived from a random secret
  generated once in `TELNET_DATA_DIR/profile_secret` (mode 0600). Keep `/data` on a volume;
  a warning is logged when the secret is generated. Nothing in any output says "honeypot",
  "SSH", "Ubuntu", "bash", "x86" or "Python" (`tests/test_hardening.py` scans for it).

## Resource limits

Per connection: 1 MiB of input in total, 4 KiB per input line (extra characters are dropped and
not echoed), 2000 commands, 2 MiB of output, login within 60 s, 300 s idle,
30 min total, a 3 s delay after a wrong password (BusyBox `login`), 10 s to flush a write (a client that never reads is dropped). Per shell: the limits of
the SSH shell (1 MiB / 2000-node filesystem, 64 KiB output per command line, CPU budget per
line `TELNET_LINE_BUDGET` = 0.15 s, 200 simple commands per line). All sessions together may use at most `TELNET_SHELL_CPU_SHARE` (0.3) CPU-seconds of shell time per second: a session that overspends waits, and after 10 s of debt a line is answered `sh: can't fork: Resource temporarily unavailable`; lines are never run back to back without yielding to the event loop. Sensor-wide: 200 connections,
8 per source IP, new connections per IP rate limited (token bucket, before anything is sent), a
memory budget over all sessions (`TELNET_MEMORY_BUDGET_MB`: new connections are refused and commands answer `sh: can't fork: Cannot allocate memory`; running sessions are kept), and a watchdog thread that exits the
process (status 70, so `restart: unless-stopped` recovers) when the event loop stalls for 10 s.
Attacker text never reaches `re` with nested quantifiers (grep patterns become globs, awk and sed
are parsed by hand, in the shared shell).

Event limits (same scheme as the SSH sensor): `connect` per source IP, `login_attempt` and `scan`
per session, `command` and `download_attempt` in a separate per-session quota, `disconnect` never
rate limited, everything but `disconnect` capped sensor-wide. Dropped events are counted: the
`disconnect` event carries `events_suppressed` and a `scan` event with `kind = events_suppressed`
is emitted. A connection that never completes a login attempt produces no `connect` or
`disconnect`: it is summarised per source IP into a periodic `scan` event
(`kind = connection_summary`); if it sent bytes (an HTTP request on port 23, an exploit blob) a
`scan` event with `kind = raw_payload` carries the first 256 bytes as hex.

## Events

All events use the shared `suckerpot_common.Event` model, `dst_port` is the public port
(`TELNET_PUBLIC_PORT`). No events are emitted for connections from 127.0.0.1 (the container
healthcheck).

| type | data |
| --- | --- |
| `connect` | `banner` (pre-login text and login prompt), `client_options` (the `WILL/DO ...` the client sent), `window`, `terminal` |
| `login_attempt` | `username`, `password`, `success`, `method` = `telnet` |
| `command` | `input`, `output` (8 KiB cap), `output_preview` (256 chars), `cwd`, `user`, `prompt`, `status` |
| `download_attempt` | `url`, `tool` (`wget`, `tftp`, `ftpget`, `curl`), `command`, `cwd`, `user` |
| `scan` | `kind` = `raw_payload` (`payload_preview` hex, `bytes`, `client_options`), `connection_summary`, `events_suppressed` |
| `disconnect` | `duration_s`, `reason`, `login_attempts`, `commands`, `downloads`, `bytes_in`, `bytes_out`, `events_suppressed`, `replay`, `replay_truncated` |

### Terminal replay

Same format as the SSH sensor: `disconnect.data.replay` is a list of `[delta_seconds, "o" | "i",
text]` frames, `o` = what the client saw (banner, prompts, echo, output), `i` = what it typed after
login. Passwords are not in the replay (they are in `login_attempt`); the password prompt is
visible without any echo, as on the real thing. The newest frames that fit in 12 KiB are kept and
`replay_truncated` says if older ones were dropped.

## Environment variables

| variable | default | meaning |
| --- | --- | --- |
| `REDIS_HOST`, `REDIS_PORT`, `REDIS_USER`, `REDIS_PASSWORD`, `EVENTS_STREAM`, `EVENTS_MAXLEN` | see `suckerpot_common` | Redis stream publisher |
| `TELNET_PORT` | `2323` | listen port inside the container |
| `TELNET_PUBLIC_PORT` | `23` | port reported as `dst_port` |
| `TELNET_PERSONALITY` | `dvr` | `dvr` or `router` |
| `TELNET_HOSTNAME` | derived (`dvr-xxxx`) | device hostname, a plain label |
| `TELNET_LOGIN_PROMPT` | `{hostname} login: ` | prompt (`\r` and `\n` are expanded) |
| `TELNET_PRELOGIN_BANNER` | empty | text sent before the first prompt |
| `TELNET_MOTD` | BusyBox banner of the personality | text sent after a successful login |
| `TELNET_DATA_DIR` | `/data` | where `profile_secret` lives (volume) |
| `TELNET_ACCEPT_CREDENTIALS` | Mirai set (root:xc3511, root:vizxv, root:admin, admin:admin, ...) | comma list of `user:pass` |
| `TELNET_ACCEPT_RANDOM_PROB` | `0.0` | probability of accepting any non-empty password |
| `TELNET_MAX_AUTH_ATTEMPTS` | `6` | login attempts per connection |
| `TELNET_MAX_CONNECTIONS` / `TELNET_MAX_PER_IP` | `200` / `8` | connection caps |
| `TELNET_CONN_RATE_PER_IP` / `TELNET_CONN_BURST_PER_IP` | `1` / `10` | new connections per second per source IP |
| `TELNET_LOGIN_TIMEOUT` / `TELNET_IDLE_TIMEOUT` / `TELNET_MAX_SESSION` | `60` / `300` / `1800` | seconds |
| `TELNET_MAX_LINE` / `TELNET_MAX_COMMANDS` | `4096` / `2000` | per connection |
| `TELNET_LINE_BUDGET` | `0.15` | CPU seconds allowed per command line |
| `TELNET_SHELL_CPU_SHARE` | `0.3` | shell CPU-seconds per second, all sessions together |
| `TELNET_MEMORY_BUDGET_MB` | `48` | memory budget over all sessions |
| `TELNET_EVENTS_PER_SEC` / `TELNET_GLOBAL_EVENTS_PER_SEC` | `20` / `200` | `connect` events per IP / sensor-wide cap |
| `TELNET_SUMMARY_INTERVAL` | `60` | seconds between connection-summary events |

## Compose service

The orchestrator merges this block into `docker-compose.yml`. The network names, the Redis user and
the host port variable follow the other sensors.

```yaml
  sensor-telnet:
    build:
      context: .
      dockerfile: sensors/telnet/Dockerfile
    restart: unless-stopped
    networks: [ingress, sensors-telnet]
    dns: ["127.0.0.1"]
    ports:
      - "0.0.0.0:${TELNET_HOST_PORT:-23}:2323"
    environment:
      REDIS_HOST: redis
      REDIS_USER: sensor-telnet
      REDIS_PASSWORD: ${REDIS_SENSOR_TELNET_PASSWORD:?set it in .env}
      EVENTS_STREAM: events:telnet
      EVENTS_MAXLEN: ${EVENTS_MAXLEN:-100000}
      TELNET_PUBLIC_PORT: ${TELNET_HOST_PORT:-23}
    volumes:
      - telnet-data:/data
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
      test: ["CMD", "python", "-m", "telnet_sensor.healthcheck"]
      interval: 15s
      timeout: 5s
      retries: 3
      start_period: 20s
```

Also needed: the `sensors-telnet` network (`internal: true`, shared with `redis` only), the
`telnet-data` volume, and a Redis ACL user `sensor-telnet` limited to `XADD` on `events:telnet`.

## Design notes

- The SSH sensor package is a path dependency (`../ssh`), so the Telnet image also contains
  asyncssh (about 15 MB); only `ssh_sensor.shell`, `ssh_sensor.config.Config` (as the shell's
  settings object) and `ssh_sensor.shell.baseimage.derive_profile` are used. `events.py`,
  `replay.py` and `watchdog.py` are small copies, because the SSH ones are tied to the SSH sensor
  name.
- `DeviceShell` overrides `dispatch`, `_run_path`, `prompt`, `error_prefix`, `lookup("0")`
  and `_run_simple` (redirections without a command, e.g. `>.t`). The command table lives in
  `commands.py`; the base filesystem and personalities in `device.py`.
- Telnet is not encrypted and has no real authentication of the server; the sensor therefore
  never offers anything but ECHO and SGA, and never accepts LINEMODE, ENVIRON and the like.

## Development

```
uv sync
uv run ruff check && uv run ruff format --check && uv run mypy . && uv run python -m pytest
sg docker -c "sh tests/blackbox.sh"   # real telnet clients and nmap against the built image
```
