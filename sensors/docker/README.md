# Docker sensor

A low-interaction honeypot that looks like an exposed, unauthenticated Docker Engine API:
dockerd 27.3.1 (API 1.47) on Ubuntu 24.04, plain HTTP, no TLS, no authentication. It records
every request, every container or exec a bot asks for, and every URL it finds, and it never
runs, builds, pulls or fetches anything.

Run with `python -m docker_sensor`. Container port: **2375** (compose maps the public port).

## What is served

Everything is a canned or generated JSON document. Answers follow dockerd closely: the header
set and order (`Api-Version`, `Docker-Experimental`, `Ostype`, `Server: Docker/27.3.1 (linux)`,
then `Date`, `Content-Length`), the trailing newline of Go's JSON encoder, `{"message": ...}`
errors, Go's plain-text 400 for malformed requests, chunked JSON progress for pulls and the
`101 UPGRADED` raw stream for `attach` and `exec start`. The real `docker` CLI (`version`,
`info`, `ps`, `images`, `run`, `run -d`, `exec`, `login`, `swarm join`), `curl` and `nmap -sV`
all work (nmap reports `docker  Docker 27.3.1`).

| route (with or without a `/v1.NN` prefix, 1.24 to 1.47) | answer |
| --- | --- |
| `GET`/`HEAD /_ping` | `OK`, with `Builder-Version`, `Swarm: inactive`, cache headers |
| `GET /version`, `/info` | engine, containerd, runc, kernel, OS, CPUs, memory, counts from the per-deployment profile |
| `GET /containers/json`, `/images/json` | three or four plausible containers (proxy, database, cache, metrics) and their images; containers the same IP created appear too |
| `POST /images/create` | `fromImage` + `tag` recorded, bounded realistic pull progress; `fromSrc` URLs recorded |
| `POST /containers/create` | body recorded and analysed, `201` with a random 64-hex `Id` (`409` on a reused name) |
| `POST /containers/{id}/start`, `stop`, `kill`, `wait`, `attach`, `GET .../json`, `logs`, `top`, `DELETE` | state kept per source IP (bounded); output of trivial commands (`id`, `whoami`, `pwd`, `echo ...`) is produced by looking at the command, never running it |
| `POST /containers/{id}/exec`, `POST /exec/{id}/start`, `GET /exec/{id}/json` | `Cmd` recorded, `201`, empty or canned output |
| `POST /auth`, `X-Registry-Auth` header | credentials recorded as `login_attempt`, `401` |
| `POST /build`, `/images/load`, `/commit`, `PUT /containers/{id}/archive` | recorded (remote URLs too), generic failure or success |
| `GET /swarm`, `/nodes`, `/services`, `/tasks`, `/secrets`, `/configs` | `503 This node is not a swarm manager...`; `POST /swarm/init` and `/swarm/join` recorded |
| `/networks`, `/volumes`, `/plugins`, `/system/df`, `/events` | minimal plausible documents |
| anything else | `404 {"message":"page not found"}`; versions outside 1.24-1.47 get dockerd's "too old" / "too new" `400` |

Non-HTTP bytes (a TLS hello, other protocols, garbage) get Go's `400 Bad Request` and a `scan`
event (`kind=non_http`, hex and text preview, `tls_client_hello`).

## Events

Stream `events:docker`, `sensor` = `docker`, `dst_port` = `DOCKER_PUBLIC_PORT`. One session per
TCP connection. The docker CLI opens several connections per command, so one `docker run`
produces several sessions from the same IP.

| type | when | `data` keys |
| --- | --- | --- |
| `connect` | connection accepted | `transport` |
| `http_request` | every request (important when it creates, runs, pulls, builds, authenticates or joins a swarm) | `method`, `path`, `query`, `http_version`, `host`, `headers`, `user_agent`, `body_preview` (text bodies), `body_binary`, `body_sha256`, `body_length`, `body_truncated`, `status`, `route`, `api_version`, `flags`, plus `container` (image, cmd, entrypoint, env, binds, privileged, pid_mode, network_mode, cap_add, user, tty), `container_id`, `pull` (image, tag, registry), `swarm` |
| `command` | container create, exec create | `input` (entrypoint + cmd, joined), `kind` (`container_create` / `exec`), `image` or `container`, `user`, `flags` |
| `download_attempt` | URL in Cmd, Entrypoint, Env, exec Cmd, `fromSrc`, build `remote` | `url`, `tool` (`wget` / `curl` / `tftp` / ... / `unknown`), `command`, `source` |
| `login_attempt` | `POST /auth`, `X-Registry-Auth` | `username`, `password`, `success` (false), `method` (`registry_auth`), `server` |
| `scan` | non-HTTP bytes, incomplete request, refused connections | `kind` (`non_http`, `incomplete_request`, `rate_limited`), `payload_preview`, `text_preview` |
| `disconnect` | connection closed | `duration_s`, `reason`, `requests`, `commands`, `logins`, `downloads`, `bytes_out`, `flags`, `statuses`, `suppressed` |

Flags (in `data.flags` of `http_request` and `command`): `container_create`, `privileged`,
`host_mount` (a bind from `/`, `/host...`, `/etc`, `/root`, `/proc`, `/sys`, `/home`, the docker
socket, ...), `docker_sock_mount`, `pid_host`, `net_host`, `cap_add`, `image:<name>`, `miner`
(image, command or environment contains xmrig, kinsing, c3pool, monero, ... found with plain
substring checks), `exec`, `image_pull`, `custom_registry`, `image_build`, `image_load`,
`image_import`, `commit`, `archive_put`, `container_start`, `container_stop`,
`container_remove`, `registry_credentials`, `swarm_init`, `swarm_join`, `recon`,
`unparsed_body` (a create body that was too big or too deep to parse, still scanned for URLs
and miner names), `incomplete_body`.

## Limits

Global 150 connections, 8 per IP, 5 new connections per second per IP (burst 20), all checked
before any work. Request line 8190 bytes, head 32 KB and 64 headers, then `431`/`414`. Body:
read and hashed up to 8 MB, only the first 256 KB are kept and parsed (larger bodies are
reported as `body_truncated`, then the connection is closed). JSON is parsed only after a size
check and a nesting check (depth 24); Python's parser never sees deeper documents. Head within
20 s, body reads 10 s each with a 500 B/s floor after 5 s and 60 s in total, keep-alive 15 s,
200 requests and 300 s per connection, 10 s write timeout (a client that does not read is
aborted, not closed). Kernel socket buffers 64 KB, `TCP_USER_TIMEOUT` 30 s. Answers are small
(largest: `/info`, about 2 KB), so a client that pipelines requests and never reads cannot grow
memory.

Per-IP state (containers and execs the IP created, so `docker run` makes sense across
connections): 512 IPs, 8 containers and 16 execs each, least recently used out first.

Events: 20/s per session (burst 100), a separate guaranteed bucket for commands, downloads,
logins and creating requests, 20/s per IP for those, 200/s per sensor. Queue: 5000 events and
4 MB. Every field group is capped before the event is built (headers 3 KB, path and query
1.5 KB each, body preview 2.5 KB, container summary about 5 KB), so no event reaches the 16 KB
limit. Connections from 127.0.0.1 (the healthcheck) are never refused and never reported.

CPU: each request's processing time is charged to three buckets (per connection 0.05 s/s, per IP
0.10 s/s, whole sensor 0.35 s/s, applied only to IPs already using more than half of their own burst); an empty bucket makes the connection wait (it is never
refused), and every request yields to the loop. Output: every write is charged to the byte
budget, at most 64 KiB at a time, with `drain()` before anything more is built; the memory guard
is also sampled on admission. Events: a per-IP rate bucket and a per-IP byte bucket sit in front
of one priority queue (connect, disconnect, login, download and flagged events first); an IP may
hold at most 100 queued events per class; identical ordinary requests in one session are kept
three times, then counted (`repeats` in `disconnect`). Each IP also has its own disconnect
bucket and the queue keeps reserved slots for disconnects, so a flooding IP cannot stop its own
sessions from closing in the UI; whatever is still dropped is counted per IP and sent as one
`scan` event (`kind: events_suppressed`, with `disconnects_lost`) every 15 s.

Memory: a byte budget (96 MB) charged per connection (96 KB) and per body in flight (4x the
256 KB cap), plus a cgroup guard (`memory.current` minus page cache): above 70 % of the limit
new connections are refused, above 85 % the connections holding the most are aborted. The
event-loop watchdog exits the process (code 70) if the loop stalls for 10 s, so
`restart: unless-stopped` brings it back.

Measured in the hardened container (read-only, `cap_drop: ALL`, `no-new-privileges`, 160 MB =
memswap, 0.5 CPU, 128 pids; `tests/flood.py` from throwaway containers on an internal network):
3 IPs x 8 connections of 240 KB URL-filled create bodies plus pipelined `/containers/json`, 3 IPs
x 8 reconnecting non-reading clients and 1 IP x 8 pipelining non-readers for 60 s, with a victim
IP running `GET /_ping` twice a second: victim p50 2 ms, worst 12 ms, 0 failures (idle: 17 ms),
sensor CPU about 9 %, memory 35 MB flat (peak 51 MB of 160 MB), no watchdog exit, back to 0.2 %
CPU afterwards. An earlier run in the 256 MB container (19 client containers, the global cap of
150 connections, trickled bodies and non-readers) peaked at 45-61 MB; six clients reconnecting
for 2 minutes without reading (3400 connections) stayed at 37-41 MB.

## Environment variables

| variable | default | meaning |
| --- | --- | --- |
| `REDIS_HOST`, `REDIS_PORT`, `REDIS_USER`, `REDIS_PASSWORD`, `EVENTS_STREAM`, `EVENTS_MAXLEN` | see `suckerpot_common` | publisher (`EVENTS_STREAM=events:docker`) |
| `DOCKER_PORT` | `2375` | container port |
| `DOCKER_PUBLIC_PORT` | `2375` | reported as `dst_port` |
| `DOCKER_HOSTNAME` | `srv-app02` | `Name` in `/info` |
| `DOCKER_ENGINE_VERSION` | `27.3.1` | must be 27.x.y |
| `DOCKER_DATA_DIR` | `/data` | profile secret (volume) |
| `DOCKER_MAX_CONNECTIONS` / `DOCKER_MAX_PER_IP` | `150` / `8` | caps |
| `DOCKER_CONN_RATE` / `DOCKER_CONN_BURST` | `5` / `20` | new connections per IP |
| `DOCKER_MEMORY_BUDGET_MB` | `96` | connection and body byte budget |
| `DOCKER_MEMORY_LIMIT_MB` | `256` | guard limit when the cgroup has none (keep equal to `mem_limit`) |
| `DOCKER_EVENTS_PER_SEC` / `DOCKER_GLOBAL_EVENTS_PER_SEC` | `20` / `200` | |

The per-deployment identity (daemon ID, kernel build, CPU count, memory, container and image IDs,
dates, bridge subnet) is derived from a random secret created once in `/data/profile.json`
(mode 0600). Nothing comes from public data and no documentation address ranges appear in
answers.

## Design notes

* Hand written HTTP: a general server framework would normalise or reject malformed requests in
  ways that identify it. No regular expressions anywhere (ReDoS); URLs and miner names are found
  with `str` methods.
* Nothing is executed: `tests/test_static.py` walks the AST and fails on `subprocess`, `eval`,
  `exec`, `compile`, `pickle`, `re`, `importlib`, file writes outside `profile.py` and outbound
  network clients. `canned_output` only compares the command with a few known words.
* Downloads are recorded as `download_attempt` events only. The sensor has no outbound code.

## Compose block

```yaml
  sensor-docker:
    build:
      context: .
      dockerfile: sensors/docker/Dockerfile
    image: suckerpot-sensor-docker:latest
    restart: unless-stopped
    networks: [ingress, sensors-docker]
    dns: ["127.0.0.1"]
    ports:
      - "0.0.0.0:${DOCKER_HOST_PORT:-2375}:2375"
    environment:
      REDIS_HOST: redis
      REDIS_USER: sensor-docker
      REDIS_PASSWORD: ${REDIS_SENSOR_DOCKER_PASSWORD:?set REDIS_SENSOR_DOCKER_PASSWORD}
      EVENTS_STREAM: events:docker
      DOCKER_PUBLIC_PORT: ${DOCKER_PUBLIC_PORT:-2375}
    volumes:
      - sensor-docker-data:/data
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001
    user: "10001:10001"
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    mem_limit: 160m
    memswap_limit: 160m
    cpus: 0.5
    pids_limit: 128
    healthcheck:
      test: ["CMD", "python", "-m", "docker_sensor.healthcheck"]
      interval: 15s
      timeout: 5s
      retries: 3
      start_period: 15s
```

Also needed (orchestrator): a `sensors-docker` network with `internal: true` that `redis` joins,
the `sensor-docker-data` volume, a Redis ACL user `sensor-docker` limited to `XADD` on
`events:docker`, and `DOCKER_HOST_PORT` / `DOCKER_PUBLIC_PORT` in `.env.example`.

## Development

```
uv sync
uv run ruff check && uv run ruff format --check && uv run mypy . && uv run pytest
```

`tests/blackbox.sh` runs the real docker CLI, curl and nmap against a built image on a
throwaway internal network. `tests/flood.py` and `tests/load/*.sh` are the manual memory tools
(`run_load.sh body|pipeline|mixed <seconds>`, `run_churn.sh`); they expect a hardened sensor
container named `sp-docker-lt` on the network `sp-docker-lt-net`.
