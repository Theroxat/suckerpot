# Architecture

This page describes how SuckerPot is built: the services, the networks, the queue, the database and the API. For the threat model and the controls, see [Security](SECURITY.md).

```{admonition} Build status
:class: note

**Built and wired in Compose:** Redis, the database and its migrations, ingest (multi-stream, with GeoIP, reputation and tagging), the API with its REST endpoints and live WebSocket feed, the SSH, RDP, Telnet and web sensors, the seven sensors of M9 (Redis, Docker, MySQL, MSSQL, ADB, SMB and SIP), and the web UI (served by the API once built).

**Under security review:** the web sensor (M6) and the M9 sensors. The sensor pages show the status of each one.

**In progress:** the analytics API (M5).

**Built since:** insights, trends and malware endpoints and pages (M7), and dashboard login (M8).

**Built since:** retention, compressed storage, kept-forever aggregates and the database disk guard (see [Data retention](retention.md)), and backups (`just backup`).
```

## Overview

SuckerPot runs as a set of Docker Compose services on one host. Fake services, called sensors, take the attacks. Each attack becomes an event. Events go through Redis streams (one per sensor), are checked, enriched and stored by ingest, and end up in PostgreSQL with TimescaleDB. The API reads the database and serves the dashboard.

```
Internet
   │
   ▼
Router or hypervisor firewall
   │
   ▼
Host (nftables table "suckerpot_host", see Deployment)
   │
   ├─► 11 sensors      ─┐  each sensor: sp-ingress (inbound only)
   │   remote shells:     │  + its own internal network to Redis
   │     ssh, telnet, adb │
   │   web and APIs:      │
   │     web, docker      │
   │   databases:         │
   │     redis, mysql,    │
   │     mssql            │
   │   Windows and VoIP:  │
   │     rdp, smb, sip   ─┘
                │  XADD events:<sensor>   (one Redis user per sensor)
                ▼
          Redis Streams  ◄── demo (just demo, network "tools")
                │  XREADGROUP / XACK / XTRIM / XAUTOCLAIM
                ▼
             ingest ──► GeoIP, reputation, tagging (egress network only)
                │
                │  INSERT / UPDATE (role suckerpot_ingest)
                ▼
     PostgreSQL + TimescaleDB
                │  SELECT (role suckerpot_api)
                ▼
     API (FastAPI: REST, WebSocket, built SPA)   network "dashboard"
                ▲
                │  reverse tunnel, such as cloudflared
                │
           Web UI (browser)
```

## Services

| Service | Networks | Role | Status |
| --- | --- | --- | --- |
| `redis` | `sensors-ssh`, `sensors-rdp`, `sensors-telnet`, `sensors-web`, `sensors-redis`, `sensors-docker`, `sensors-mysql`, `sensors-mssql`, `sensors-adb`, `sensors-smb`, `sensors-sip`, `tools`, `backend` | Redis Streams queue. Named ACL users (see below). AOF persistence on `redis-data`. | Built |
| `db` | `backend` | PostgreSQL 17 with TimescaleDB 2.22.1, on `db-data`. Runs only as the owner role. | Built |
| `migrate` | `backend` | One-shot. Checks the secrets policy, runs `alembic upgrade head`, then re-applies the application roles and their passwords, and exits with code 0. | Built |
| `ingest` | `backend`, `egress` | Reads all sensor streams, validates events, enriches and tags them, writes them to the database. | Built. GeoIP files live on the `geoip-data` volume. |
| `api` | `backend`, `dashboard` | FastAPI (512 MB memory limit). REST endpoints, WebSocket feed, `/healthz`, and the built web UI when present. The only service with a dashboard port. | Built |
| `sensor-ssh` | `ingress`, `sensors-ssh` | SSH honeypot. See [SSH sensor](sensors/ssh.md). | Built |
| `sensor-telnet` | `ingress`, `sensors-telnet` | BusyBox-style Telnet sensor. See [Telnet](sensors/telnet.md). Stream `events:telnet`. | Built |
| `sensor-adb` | `ingress`, `sensors-adb` | Android TV box with `adbd`. See [ADB](sensors/adb.md). Stream `events:adb`. | Built (M9) |
| `sensor-web` | `ingress`, `sensors-web` | See [Web](sensors/web.md). Stream `events:web`. | Built (M6), under security review |
| `sensor-docker` | `ingress`, `sensors-docker` | Exposed Docker Engine API. See [Docker](sensors/docker.md). Stream `events:docker`. | Built (M9) |
| `sensor-redis` | `ingress`, `sensors-redis` | Redis 7.2 with no password. See [Redis](sensors/redis.md). Stream `events:redis`. | Built (M9) |
| `sensor-mysql` | `ingress`, `sensors-mysql` | MySQL 8.0 with weak logins. See [MySQL](sensors/mysql.md). Stream `events:mysql`. | Built (M9) |
| `sensor-mssql` | `ingress`, `sensors-mssql` | SQL Server look-alike. See [MSSQL](sensors/mssql.md). Stream `events:mssql`. | Built (M9) |
| `sensor-rdp` | `ingress`, `sensors-rdp` | RDP sensor (NLA and NTLM). See [RDP](sensors/rdp.md). Stream `events:rdp`. | Built |
| `sensor-smb` | `ingress`, `sensors-smb` | SMB file service, observation only. See [SMB](sensors/smb.md). Stream `events:smb`. | Built (M9) |
| `sensor-sip` | `ingress`, `sensors-sip` | Asterisk-style PBX on UDP and TCP 5060. See [SIP](sensors/sip.md). Stream `events:sip`. | Built (M9) |
| `demo` | `tools` | Synthetic attack generator. Runs only with `--profile tools`. | Built |

Start order: `redis` and `db` first. `migrate` runs once the database is healthy. `ingest` and `api` start after `migrate` has finished with code 0. Sensors start after Redis is healthy.

## Networks

Each network has a single job. The point of the layout is that a compromised sensor can talk to Redis and to nothing else, and cannot reach another sensor.

| Network | Docker name | Outbound internet | Connected services | Why |
| --- | --- | --- | --- | --- |
| `ingress` | `sp-ingress` | None. Masquerading off, inter-container communication off. | Every sensor | Inbound traffic from attackers. Sensors cannot reach each other or the internet. |
| `sensors-<name>`, one per sensor (`sensors-ssh`, `sensors-web`, `sensors-sip`, ...) | (project prefix) | None (`internal: true`) | `redis` and one sensor | The one link between a sensor and Redis. One network per sensor. |
| `tools` | (project prefix) | None (`internal: true`) | `redis`, `demo` | The demo generator reaches Redis and nothing else. |
| `backend` | (project prefix) | None (`internal: true`) | `redis`, `db`, `migrate`, `ingest`, `api` | Storage and processing stay off the internet. |
| `egress` | (project prefix) | Outbound | `ingest` only | The one place for outbound calls (GeoIP downloads, reputation lookups, CVE feeds). |
| `dashboard` | `sp-dashboard` | None. Masquerading off. | `api` only | The published dashboard port. |

`sp-ingress` and `sp-dashboard` have fixed bridge names, so the [host firewall](deployment.md#host-firewall) can match them by name.

### Sensors need two networks

Docker does not publish ports on an `internal: true` network. So each sensor joins two networks:

- `sp-ingress` receives the attacker's connection. With masquerading off, the sensor has no usable route back out to the internet, and with inter-container communication off it cannot talk to the other sensors.
- Its own internal network (`sensors-ssh`, ...) links it to Redis. Because the network is per sensor, one sensor cannot even see another sensor's traffic to Redis.

Each sensor also gets `dns: ["127.0.0.1"]` (external names do not resolve), and is published on an explicit IPv4 address (`0.0.0.0:<port>`), so Docker does not also listen on `[::]`.

### Why `backend` is internal

The `backend` network is created with `internal: true`. Docker gives it no route to the internet. Redis and the database sit on this network. Nothing on it can call out, and nothing outside can reach it directly.

### The `dashboard` network, and what it does not do

The `dashboard` network is a normal bridge with IP masquerading turned off. The published dashboard port works for inbound traffic. The API container also gets `dns: 127.0.0.1`, so it cannot resolve external names through Docker's resolver.

```{warning}
This is **not** a complete block on outbound traffic. Without masquerading, packets from the container keep their container address. If the host has a route for that address and no firewall rule drops them, they can still leave. The DNS setting does not stop a connection to a raw IP address. The host firewall in [Deployment](deployment.md#host-firewall) drops new connections from `sp-ingress` and `sp-dashboard`. Keep it loaded, and filter egress upstream as well.
```

### Why only `ingest` has `egress`

Only `ingest` needs outbound calls: GeoIP database downloads, AbuseIPDB and GreyNoise checks, the daily CVE feeds (`www.cisa.gov`, `services.nvd.nist.gov`, `api.github.com`), and (in the future) optional payload fetches. The database and Redis are not reachable from the internet, and a sensor cannot reach the database.

## Redis

### Streams

Each sensor writes to its own stream: `events:ssh`, `events:telnet`, `events:adb`, `events:web`, `events:docker`, `events:redis`, `events:mysql`, `events:mssql`, `events:rdp`, `events:smb` and `events:sip`. The demo generator writes to the same streams. One stream per sensor means a flood on one sensor cannot hide the events of another, and each stream is trimmed on its own.

### Users and permissions

Redis runs with the `default` user disabled. Each named user has its own password from `.env`. The entrypoint writes the ACL file to a `tmpfs` at start-up, storing SHA-256 hashes instead of clear-text passwords. Permissions below are copied from `redis/entrypoint.sh`.

| User | Password variable | ACL | Used by |
| --- | --- | --- | --- |
| `default` | none | `off` | Nothing. Anonymous access is refused. |
| `admin` | `REDIS_PASSWORD` | `~* &* +@all` | Operators only |
| `health` | `REDIS_HEALTH_PASSWORD` | `resetkeys -@all +ping +hello +auth` | The Redis health check |
| `sensor-ssh` | `REDIS_SENSOR_SSH_PASSWORD` | `resetkeys ~events:ssh -@all +xadd +hello +auth` | `sensor-ssh` |
| `sensor-rdp` | `REDIS_SENSOR_RDP_PASSWORD` | `resetkeys ~events:rdp -@all +xadd +hello +auth` | `sensor-rdp` |
| `sensor-telnet` | `REDIS_SENSOR_TELNET_PASSWORD` | `resetkeys ~events:telnet -@all +xadd +hello +auth` | `sensor-telnet` |
| `sensor-web` | `REDIS_SENSOR_WEB_PASSWORD` | `resetkeys ~events:web -@all +xadd +hello +auth` | `sensor-web` |
| `sensor-redis` | `REDIS_SENSOR_REDIS_PASSWORD` | `resetkeys ~events:redis -@all +xadd +hello +auth` | `sensor-redis` |
| `sensor-docker` | `REDIS_SENSOR_DOCKER_PASSWORD` | `resetkeys ~events:docker -@all +xadd +hello +auth` | `sensor-docker` |
| `sensor-mysql` | `REDIS_SENSOR_MYSQL_PASSWORD` | `resetkeys ~events:mysql -@all +xadd +hello +auth` | `sensor-mysql` |
| `sensor-mssql` | `REDIS_SENSOR_MSSQL_PASSWORD` | `resetkeys ~events:mssql -@all +xadd +hello +auth` | `sensor-mssql` |
| `sensor-adb` | `REDIS_SENSOR_ADB_PASSWORD` | `resetkeys ~events:adb -@all +xadd +hello +auth` | `sensor-adb` |
| `sensor-smb` | `REDIS_SENSOR_SMB_PASSWORD` | `resetkeys ~events:smb -@all +xadd +hello +auth` | `sensor-smb` |
| `sensor-sip` | `REDIS_SENSOR_SIP_PASSWORD` | `resetkeys ~events:sip -@all +xadd +hello +auth` | `sensor-sip` |
| `demo` | `REDIS_DEMO_PASSWORD` | `resetkeys ~events:* -@all +xadd +hello +auth` | The demo generator |
| `ingest` | `REDIS_INGEST_PASSWORD` | `resetkeys ~events:* -@all +xreadgroup +xack +xgroup\|create +xautoclaim +xtrim +hello +auth` | `ingest` |

Every sensor user can only `XADD` to its own stream (`~events:<name>`). Ingest checks the `sensor` field of each event against the stream it came from, so a sensor cannot write as another sensor even if its user had wider rights.

A sensor user can only append to its own stream. It cannot read it, delete it or change its settings. The publisher turns off client info commands so the sensor users do not need `CLIENT SETINFO`. All Redis passwords must be at least 24 characters and pairwise different, or the container refuses to start.

### Server settings

| Setting | Value | Why |
| --- | --- | --- |
| Persistence | AOF, `everysec`. No RDB snapshots. | Keeps events across restarts |
| `maxmemory` | 192 MB | Bounds memory use |
| `maxmemory-policy` | `noeviction` | When memory is full, writes fail. Events are never silently evicted. |
| `proto-max-bulk-len` | 1 MB | Limits one command's payload |
| `client-query-buffer-limit` | 1 MB | Limits one client's input buffer |
| `maxclients` | 512 | Bounds connections |

Redis is never published on the host. It listens only on the internal networks.

## Event flow

1. A sensor (or the demo generator) builds an `Event` and calls `XADD` on its own stream. The stream is capped with `MAXLEN ~ EVENTS_MAXLEN` (default 10,000 entries per stream).
2. If Redis is unavailable, full or refusing the write, the publisher does not raise. It drops the event, counts it, and logs the error at most once every 30 seconds per error kind. It keeps no unbounded buffer.
3. `ingest` reads all streams (`INGEST_STREAMS`) as one consumer in the group `ingest`, with a single `XREADGROUP` call. It creates the group on each stream if needed.
4. An entry with a raw `event` field larger than 64 KiB is rejected before JSON parsing. Any other invalid entry is logged, truncated, and acknowledged so it does not block the stream.
5. **Sensor/stream check.** An event whose `sensor` field differs from the stream suffix (`sensor = rdp` on `events:ssh`) is dropped, counted and acknowledged. A compromised sensor cannot write as another sensor, even if Redis permissions were wrong.
6. Valid events are enriched (GeoIP, ASN, cached reputation) and tagged, then written in batches. The batch size is `INGEST_BATCH_SIZE` (default 100, maximum 500). The `sessions` table is updated with the counters for each session, and session-level tag rules run on the updated counters.
7. After the database commit, `ingest` acknowledges the entries. Entries are never acknowledged before they are stored.
8. After the acknowledgement, `ingest` trims **that stream** with `XTRIM MINID ~` up to the last acknowledged ID. This assumes one consumer, so run exactly one ingest instance.
9. A message that fails writing 5 times in a row because of its own content (a data error) is logged with its ID and acknowledged: dead-lettered. Outages, timeouts and permission errors are never counted. They retry forever, which turns the heartbeat stale and the container unhealthy.

### Per-stream trimming and recovery

State is kept per stream, so one slow or broken stream does not affect the others.

- **Start-up.** Ingest takes over every pending entry on every stream (`XAUTOCLAIM` with no idle minimum), whoever it was delivered to. Then it re-reads each stream from the start of its pending list ("draining") before it reads new entries.
- **No trim while draining.** A stream is trimmed only once its pending list is empty, so entries that were never read cannot be trimmed away.
- **Periodic reclaim.** Every `INGEST_RECLAIM_INTERVAL_S` (60 s), entries idle for more than `INGEST_CLAIM_IDLE_MS` are reclaimed, and the stream goes back to draining.
- **After an error** (Redis or database), all streams go back to draining and the loop retries with a backoff from 1 s to 30 s.
- **Forged IDs.** A producer that sends an explicit entry ID far in the future would make `MINID` trimming wipe the stream. Ingest reports such IDs and never uses them as a trim target.

Delivery is at least once. A batch replayed after a crash between the database commit and the acknowledgement can count twice. Idempotent replay is on the [roadmap](ROADMAP.md).

The exact field layout is in [Event schema](event-schema.md).

## Database

PostgreSQL 17 with TimescaleDB, managed by Alembic migrations in `db/`.

| Object | Kind | Content |
| --- | --- | --- |
| `events` | Hypertable on `ts`, one chunk per day | One row per event, with enrichment columns and `tags` |
| `sessions` | Regular table | One row per session, with counters, first and last times, enrichment and tags |
| `ip_reputation` | Regular table | Cached AbuseIPDB and GreyNoise answers per IP (24 hours) |
| `enrichment_quota` | Regular table | Lookups used per provider and day |
| `enrichment_status` | Regular table | Status of the GeoIP database, the reputation providers and the CVE feeds, shown in Settings |
| `cve` | Regular table | Public vulnerabilities (CISA KEV, NVD, GitHub advisories), one row per CVE id, with a `relevance` (high, medium, none), the matched services and the tags that show it exploited. Public data, not captured data. |
| `cve_sync_state` | Regular table | Last run, last success, last error and item count per feed |

Raw events are dropped after `RETENTION_DAYS` (90), compressed after 7 days, and four continuous aggregates plus `sessions_daily` are kept forever. A disk guard drops the oldest raw chunks when the database grows past `DB_MAX_SIZE_GB`. See [Data retention](retention.md).

### Database roles

Each service connects with its own role. Only the migration step can change the schema.

| Role | Used by | Rights | Statement timeout |
| --- | --- | --- | --- |
| Owner (`POSTGRES_USER`) | `db`, `migrate` | Owns the schema. Used for migrations only. | Not set |
| `suckerpot_ingest` | `ingest` | Insert and update on the tables ingest writes. No schema changes, no role changes. | 30 s |
| `suckerpot_api` | `api` | `SELECT` only | 5 s |

Neither application role is a superuser. Neither can create databases or roles. The `migrate` service sets both role passwords on **every** run, from the environment. The password is sent as a SCRAM-SHA-256 verifier, so it never appears in the database logs. This is how you rotate them: see [Rotating secrets](deployment.md#rotating-secrets).

## Enrichment and tagging

```{admonition} Status
:class: note

Built (M4) and wired into Compose: ingest gets the provider variables and the `geoip-data` volume. Without keys it uses the key-less DB-IP Lite database, and reputation lookups stay off.
```

- **GeoIP and ASN** are read from local MMDB files, never from a web service per event. The provider is MaxMind GeoLite2 when `MAXMIND_ACCOUNT_ID` and `MAXMIND_LICENSE_KEY` are set, otherwise DB-IP Lite (no key, CC BY 4.0, attribution shown in the dashboard). Ingest downloads and refreshes the files itself, with a size cap and a check that the file opens. `GEOIP_PROVIDER=off` turns it off.
- **Reputation** (AbuseIPDB and GreyNoise Community) runs in a background worker, not in the event path. It picks the busiest addresses with no fresh answer, spends one unit of a persisted daily quota per lookup (`ABUSEIPDB_DAILY_QUOTA`, `GREYNOISE_DAILY_QUOTA`), caches the answer for 24 hours, and pauses for an hour after a rate-limit answer. It only reads. Nothing is ever reported to AbuseIPDB.
- **CVE watch** (`ingest/ingest/cve/`) is a background job. Every 15 minutes it checks which of three feeds is more than 24 hours old, and fetches only those: the CISA KEV catalogue, NVD API 2.0 (CVEs published in the last 30 days, or since the last success) and GitHub reviewed security advisories (only those with a CVE id). Each request spends a persisted daily quota (`CVE_NVD_DAILY_QUOTA`, `CVE_GITHUB_DAILY_QUOTA`; KEV is capped at a few requests a day), a failing feed is retried after an hour and does not stop the others, and the NVD is paced to its rate limit (5 requests per 30 s, 50 with `NVD_API_KEY`). The optional NVD key and GitHub token use the same Settings mechanism as the other provider keys. Records are merged per CVE id: each feed only fills the columns it is authoritative for. After a sync, ingest applies the relevance mapping in `ingest/rules/cve/relevance.yaml` to every row: a service (Apache + PHP, OpenSSH, Redis, ...) matches **high** when a CPE or the vendor or product name matches and **medium** when only the title or description mentions it. The same file maps CVE ids to our tags (for example `php2shell`), and the API counts sessions carrying those tags as "seen in our traffic". CVEs that are neither in KEV nor relevant are deleted after 180 days. The job only reads public data and never deploys or builds anything.
- **Tags** come from a declarative rules engine. Rules are YAML files in `ingest/rules/` (`shell.yaml` for commands, `web.yaml` for HTTP, `services.yaml` for the database, container, mobile, file-sharing and VoIP sensors, and `session.yaml` for session counters). A rule can match URL patterns, typical shell commands, user agents or CVE signatures. Tags include `recon`, `mirai`, `crypto-miner`, `exec-attempt`, `malware-drop`, `credential-stuffing`, `scanner`, `php2shell`, for the M9 sensors `persistence`, `container-escape`, `sql-rce`, `db-ransom`, `eternalblue` and `sip-fraud`, and for the RDP sensor `bluekeep`, `weak-credentials` and `rdp-cleartext`. A broken rule file stops ingest at start-up.

A **session** is one connection. It is the unit the dashboard tells as a story, such as "tried 37 SSH passwords, then ran a crypto-miner".

## API

The API is FastAPI. It serves:

- REST endpoints under `/api/v1`, listed in [API](api.md).
- A WebSocket feed at `/api/v1/live`.
- A health check at `/healthz`.
- Dashboard authentication (`/api/v1/auth/*`): one admin account, a signed `HttpOnly` session cookie and CSRF protection. A middleware guards every other `/api/v1` path, and the WebSocket checks the cookie in its handshake. Its state is in memory, so the API runs as **one** worker. See [API](api.md#authentication).
- The built web UI, when `WEB_DIST_DIR` contains an `index.html`. Unknown paths return the app shell so client-side routes work, and `/api/*` paths never fall back to it.
- The OpenAPI documents at `/docs`, `/redoc` and `/openapi.json`. These are **off** unless `API_ENABLE_DOCS=true`.

The API has no Redis access. It reads the database only.

### Live feed

One background task in the API polls the `events` table for rows newer than the last one it sent (once per second, up to 500 rows per tick). It sends the new rows to each connected WebSocket client through a bounded queue of 200 messages. A slow client loses its oldest messages, and is told how many were lost. The hub accepts at most 50 clients in total and 5 per source address. Details are in [API](api.md#live-feed).

### Security headers

Every response carries `nosniff`, `Referrer-Policy: no-referrer`, a restrictive `Permissions-Policy` and `Cross-Origin-Resource-Policy: same-origin`. Pages carry a Content Security Policy (`default-src 'self'`, `connect-src 'self'`, no framing). API responses are `Cache-Control: no-store`. Only the documentation pages relax the policy, and only when `API_ENABLE_DOCS=true`.

The WebSocket checks the `Origin` header. Requests with no `Origin` (non-browser clients) are accepted. Browser requests must come from the same host, or from an origin listed in `API_ALLOWED_ORIGINS`.

## Stack

| Layer | Choice |
| --- | --- |
| Sensors | Python 3.13, asyncio, asyncssh (SSH), raw asyncio (Telnet, RDP, ADB, Redis, MySQL, MSSQL, SMB and SIP), hand-written HTTP servers (web and Docker API) |
| Ingest and API | FastAPI, SQLAlchemy 2 with asyncpg, Alembic |
| Queue | Redis 7.4 Streams |
| Database | PostgreSQL 17 with TimescaleDB 2.22.1 |
| Enrichment | MaxMind GeoLite2 or DB-IP Lite (local files), AbuseIPDB, GreyNoise Community |
| Web UI | React, Vite, TypeScript (strict), Tailwind, shadcn/ui, TanStack Query. The Live page is a flat SVG map, with no WebGL. Terminal replay planned. |
| Python tooling | uv, ruff, mypy (strict), pytest |
| Web tooling | pnpm, eslint, prettier, vitest, Playwright |
| Task runner | `justfile`. See [Development](development.md). |

## Containers

Every service follows the same rules:

- A multi-stage Dockerfile with a pinned base image.
- A non-root user (UID and GID 10001 for application services).
- A read-only root file system, with `tmpfs` mounts where a service must write.
- `cap_drop: [ALL]` and `no-new-privileges`.
- Memory, CPU and process limits. Sensors also have no swap, so overload fails fast.
- A health check, plus a watchdog inside each sensor (Docker does not restart a container that is only unhealthy).
- Logs rotated by Docker (10 MB, 3 files).

### Resource priorities

When the host runs short of memory, the kernel must pick a victim. `oom_score_adj` sets the order, and `cpu_shares` sets the CPU share when the host is busy. Compose sets them as follows.

| Service | `oom_score_adj` | `cpu_shares` | Why |
| --- | --- | --- | --- |
| `redis`, `db` | `-500` | default | The data path. Last to be killed. |
| `ingest` | `-200` | default | Keeps the events flowing into the database. |
| `api` | `300` | default | The dashboard. Killed before the data path, after the sensors. |
| All eleven `sensor-*` services | `800` | `256` | Sensors take attacker load, so they are the first to be killed under memory pressure, and get a smaller CPU share when the host is busy. Docker restarts them. |

Each sensor has a memory limit (`mem_limit`), no swap, a CPU limit (`cpus`) and a process limit (`pids_limit`). The sensors' combined share can also be capped with an optional systemd slice. See [Deployment](deployment.md#host-safeguards).

The rules are explained in [Security](SECURITY.md#containers).

## Repository layout

```
suckerpot/
├── docker-compose.yml
├── justfile
├── .env.example
├── redis/             # Redis image, ACL entrypoint and config
├── sensors/           # common (Event schema) and the eleven sensors: ssh, telnet, adb, web, docker, redis, mysql, mssql, rdp, smb, sip
├── ingest/            # consumer, writer, enrichment, tagging, rules/*.yaml
├── api/               # FastAPI app: REST, live feed, SPA serving
├── db/                # SQLAlchemy models, Alembic migrations, roles, secrets check
├── web/               # React app (design system in web/DESIGN.md)
├── scripts/
│   ├── demo/          # demo data generator
│   ├── host/          # host firewall (nftables) and its systemd unit
│   ├── check-ports.sh # port layout guard
│   └── ssh-test.sh    # end-to-end check of the SSH sensor
└── docs/              # documentation (this site)
```
