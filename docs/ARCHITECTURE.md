# Architecture

This page describes how SuckerPot is built. It covers the services, the networks, the queue, the database and the API. For the threat model and the controls, see [Security](SECURITY.md).

```{admonition} Build status
:class: note

Milestone M1 is built: Redis, the database and its migrations, ingest, and the API with its REST endpoints and a live WebSocket feed. The sensors (M2 and M6), enrichment (M4), the full web UI (M3 and M5) and dashboard login (M8) are **planned**. Each planned item is marked as such.
```

## Overview

SuckerPot runs as a set of Docker Compose services on one host. Fake services, called sensors, take the attacks. Each attack becomes an event. Events go through a Redis stream, are checked and stored by ingest, and end up in PostgreSQL with TimescaleDB. The API reads the database and serves the dashboard.

```
Internet
   │
   ▼
Router or hypervisor firewall
   │
   ▼
Host
   │
   ├─► sensor-ssh     (planned, M2)
   ├─► sensor-telnet  (planned, M6)
   ├─► sensor-web     (planned, M6)
   └─► sensor-rdp     (planned, M6)
                │  events (XADD)
                ▼
          Redis Streams  ◄── demo (just demo, M1)
                │  XREADGROUP / XACK / XTRIM
                ▼
             ingest ──► enrichment and tagging (planned, M4)
                │
                │  INSERT / UPDATE (role suckerpot_ingest)
                ▼
     PostgreSQL + TimescaleDB
                │  SELECT (role suckerpot_api)
                ▼
     API (FastAPI: REST, WebSocket, built SPA)
                ▲
                │  reverse tunnel, such as cloudflared
                │
           Web UI (planned, M3 and M5)
```

## Services

| Service | Networks | Role | Milestone |
| --- | --- | --- | --- |
| `redis` | `sensors`, `backend` | Redis Streams queue. Four ACL users (`admin`, `sensor`, `ingest`, `health`). AOF persistence on `redis-data`. | M1 |
| `db` | `backend` | PostgreSQL 17 with TimescaleDB 2.22.1, on `db-data`. Runs only as the owner role. | M1 |
| `migrate` | `backend` | One-shot. Checks the secrets policy, runs `alembic upgrade head` (schema and roles), and exits with code 0. | M1 |
| `ingest` | `backend`, `egress` | Reads the stream, validates events, writes them to the database. | M1 (enrichment in M4) |
| `api` | `backend`, `dashboard` | FastAPI. REST endpoints, WebSocket feed, `/healthz`, and the built web UI when present. The only published port. | M1 |
| `demo` | `sensors` | Synthetic attack generator. Runs only with `--profile tools`. | M1 |
| `sensor-ssh`, `sensor-telnet`, `sensor-web`, `sensor-rdp` | `sensors` (and `ingress` in M2) | Fake services that log attacks. | M2, M6 |

Start order: `redis` and `db` first. `migrate` runs once the database is healthy. `ingest` and `api` start after `migrate` has finished with code 0.

## Networks

The stack has four networks. Each one has a single job.

| Network | Internet access | Connected services | Why |
| --- | --- | --- | --- |
| `sensors` | None (`internal: true`) | `redis`, `demo`, sensors (planned) | Sensors can reach the queue and nothing else |
| `backend` | None (`internal: true`) | `redis`, `db`, `migrate`, `ingest`, `api` | Storage and processing stay off the internet |
| `egress` | Outbound | `ingest` only | The one place for outbound calls (enrichment, planned) |
| `dashboard` | Inbound only (intended) | `api` only | Published dashboard port, with IP masquerading off |

### Why `backend` is internal

The `backend` network is created with `internal: true`. Docker gives it no route to the internet. Redis and the database sit on this network. Nothing on it can call out, and nothing outside can reach it directly.

### The `dashboard` network, and what it does not do

The `dashboard` network is a normal bridge with IP masquerading turned off (`com.docker.network.bridge.enable_ip_masquerade: "false"`). The published dashboard port works for inbound traffic. The API container also gets `dns: 127.0.0.1`, so it cannot resolve external names through Docker's resolver.

```{warning}
This is **not** a complete block on outbound traffic from the API. Without masquerading, packets from the API keep their container address. If the host has a route for that address and no firewall rule drops them, they can still leave. The DNS setting does not stop a connection to a raw IP address. Egress must also be filtered on the host or on the hypervisor. This is an owner action, listed in [Deployment](deployment.md).
```

### Why only `ingest` has `egress`

Only `ingest` needs outbound calls: GeoIP lookups, AbuseIPDB and GreyNoise checks, and optional payload fetches (M4 and later). The database and Redis are not reachable from the internet, and a sensor cannot reach the database.

### Planned: sensor networking (M2)

Sensors must receive connections from attackers, and Docker does not publish ports on an `internal: true` network. The planned design for M2 is:

- A separate `ingress` bridge network with a fixed name, masquerading off and inter-container communication off.
- Sensors join `ingress` for inbound traffic and `sensors` for Redis.
- Each sensor is published on an explicit IPv4 address and port.
- `dns: 127.0.0.1` on each sensor.
- One Redis stream and one ACL user per sensor, so a compromised sensor cannot write as another sensor.

This is not built yet. The M2 security review will check it.

## Redis

### Users and permissions

Redis runs with the default user disabled. Four named users exist. Each has its own password from `.env`. The entrypoint writes the ACL file to a tmpfs at start-up, storing SHA-256 hashes instead of clear-text passwords.

| User | Password variable | Permissions (from `redis/entrypoint.sh`) | Used by |
| --- | --- | --- | --- |
| `default` | none | Off | Nothing. Anonymous access is refused. |
| `admin` | `REDIS_PASSWORD` | All keys, all commands (`~* &* +@all`) | Operators only |
| `sensor` | `REDIS_SENSOR_PASSWORD` | Key `events` only: `XADD`, plus `HELLO` and `AUTH` | Sensors and the demo generator |
| `ingest` | `REDIS_INGEST_PASSWORD` | Key `events` only: `XREADGROUP`, `XACK`, `XGROUP CREATE`, `XAUTOCLAIM`, `XTRIM`, plus `HELLO` and `AUTH` | `ingest` |
| `health` | `REDIS_HEALTH_PASSWORD` | `PING`, `HELLO` and `AUTH` only | The Redis health check |

The sensor user cannot read the stream, delete it or change its settings. The publisher turns off client info commands so the sensor user does not need `CLIENT SETINFO`.

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

1. A sensor (or the demo generator) builds an `Event` and calls `XADD` on the `events` stream. The stream is capped with `MAXLEN ~ EVENTS_MAXLEN` (default 10,000 entries).
2. If Redis is unavailable, full or refusing the write, the publisher does not raise. It drops the event, counts it, and logs the error at most once every 30 seconds per error kind. It keeps no buffer, so memory stays bounded.
3. `ingest` reads the stream as part of the consumer group `ingest`. It creates the group if it does not exist.
4. An entry with a raw `event` field larger than 64 KiB is rejected before JSON parsing. Any other invalid entry is logged, truncated, and acknowledged so it does not block the stream.
5. Valid events are written in batches. The batch size is `INGEST_BATCH_SIZE` (default 100, maximum 500). The `sessions` table is updated with the counters for each session.
6. After the database commit, `ingest` acknowledges the entries. Entries are never acknowledged before they are stored.
7. After the acknowledgement, `ingest` trims the stream with `XTRIM MINID ~` up to the last acknowledged ID. This assumes one consumer. Several consumers would need a different rule.
8. A message that fails writing 5 times in a row is logged with its ID and acknowledged, so it is dead-lettered. The count is kept in memory.

The exact field layout is in [Event schema](event-schema.md).

## Database

PostgreSQL 17 with TimescaleDB, managed by Alembic migrations in `db/`.

| Object | Kind | Content |
| --- | --- | --- |
| `events` | Hypertable on `ts`, one chunk per day | One row per event |
| `sessions` | Regular table | One row per session, with counters and the first and last times |

Enrichment columns (`country`, `city`, `asn`, `org`, `abuse_score`, `known_scanner`) and `tags` exist in M1 but stay empty until M4.

Retention (deleting raw events after 90 days) is planned for M8. Until then, raw events are kept.

### Database roles

Each service connects with its own role. Only the migration step can change the schema.

| Role | Used by | Rights | Statement timeout |
| --- | --- | --- | --- |
| Owner (`POSTGRES_USER`) | `db`, `migrate` | Owns the schema. Used for migrations only. | Not set |
| `suckerpot_ingest` | `ingest` | `SELECT`, `INSERT` on `events`. `SELECT`, `INSERT`, `UPDATE` on `sessions`. Sequence use. | 30 s |
| `suckerpot_api` | `api` | `SELECT` on `events` and `sessions` | 5 s |

Neither application role is a superuser. Neither can create databases or roles. Migration 0002 creates the roles and sets their passwords from the environment at migration time. The passwords are never written to a file or to the log.

## API

The API is FastAPI. It serves:

- REST endpoints under `/api/v1`, listed in [API](api.md).
- A WebSocket feed at `/api/v1/live`.
- A health check at `/healthz`.
- The built web UI, when `WEB_DIST_DIR` contains an `index.html`. M1 has no UI build yet, so only the API is served.
- The OpenAPI documents at `/docs`, `/redoc` and `/openapi.json`. These are **off** unless `API_ENABLE_DOCS=true`.

The API has no Redis access. It reads the database only.

### Live feed

One background task in the API polls the `events` table for rows newer than the last one it sent (at most once per second, up to 500 rows per tick). It then sends the new rows to each connected WebSocket client through a bounded queue. The queue has 200 slots per client, and the hub accepts at most 50 clients. A slow client loses its oldest messages, and is told how many were lost.

### Security headers

Every response carries `nosniff`, `Referrer-Policy: no-referrer`, a restrictive `Permissions-Policy`, and `Cross-Origin-Resource-Policy: same-origin`. Pages carry a Content Security Policy. Only the documentation pages relax it, and only when `API_ENABLE_DOCS=true`.

The WebSocket checks the `Origin` header. Requests with no `Origin` (non-browser clients) are accepted. Browser requests must come from the same host, or from a host listed in `API_ALLOWED_ORIGINS`.

## Enrichment and tagging (planned, M4)

Enrichment adds GeoIP, ASN and organisation data (MaxMind GeoLite2, read locally), AbuseIPDB scores and GreyNoise classifications. Results are cached per IP for 24 hours, and daily quotas are enforced.

Tags come from a declarative rules engine. Rules are YAML files in `ingest/rules/`. A rule can match URL patterns, typical shell commands, user agents or CVE signatures. Examples of tags: `recon`, `mirai`, `crypto-miner`, `malware-drop` and `php2shell`.

A **session** is one connection, or a group of events that belong to the same attack. It is the unit the dashboard will tell as a story. Each session will have a one-line summary, for example "tried 37 SSH passwords, then ran a crypto-miner".

## Stack

| Layer | Choice |
| --- | --- |
| Sensors | Python 3.13, asyncio, asyncssh (SSH), raw asyncio (Telnet and RDP), Starlette (web). Planned. |
| Ingest and API | FastAPI, SQLAlchemy 2 with asyncpg, Alembic |
| Queue | Redis 7.4 Streams |
| Database | PostgreSQL 17 with TimescaleDB 2.22.1 |
| Enrichment | MaxMind GeoLite2, AbuseIPDB, GreyNoise Community. Planned, M4. |
| Web UI | React, Vite, TypeScript (strict), Tailwind, shadcn/ui, globe.gl, xterm.js. Planned, M3 and later. |
| Python tooling | uv, ruff, mypy (strict), pytest |
| Web tooling | pnpm, eslint, prettier, vitest, Playwright |
| Task runner | `justfile`. See [Development](development.md). |

## Containers

Every service follows the same rules:

- A multi-stage Dockerfile with a pinned base image.
- A non-root user (UID and GID 10001 for application services).
- A read-only root file system, with `tmpfs` mounts where a service must write.
- `cap_drop: [ALL]` and `no-new-privileges`.
- Memory, CPU and process limits.
- A health check.

The rules are explained in [Security](SECURITY.md#containers).

## Repository layout

```
suckerpot/
├── docker-compose.yml
├── justfile
├── .env.example
├── redis/             # Redis image, ACL entrypoint and config
├── sensors/common/    # shared Event schema (Python package)
├── ingest/            # consumer, writer, health check
├── api/               # FastAPI app: REST, live feed, SPA serving
├── db/                # SQLAlchemy models, Alembic migrations, secrets check
├── scripts/demo/      # demo data generator
├── web/               # React app (planned, M3)
└── docs/              # documentation (this site)
```

The sensors other than `common` are planned.
