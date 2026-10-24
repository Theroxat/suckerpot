# Architecture

This page describes how SuckerPot is built. For the threat model and the controls, see [SECURITY.md](SECURITY.md).

## Overview

SuckerPot runs as a set of Docker Compose services on one host VM. Fake services (sensors) take the attacks. Each attack becomes an event. The events go through a queue, get enriched and tagged, and end up in a database. A web dashboard reads from the database.

```
Internet
   │
   ▼
Router (DMZ, all ports forwarded to the host VM)
   │
   ▼
Host VM
   │
   ├─► sensor-ssh ─┐
   ├─► sensor-telnet ─┤
   ├─► sensor-web ─┤
   └─► sensor-rdp ─┘
                    │  events (XADD)
                    ▼
                 Redis Streams
                    │
                    ▼
                  ingest  ──► enrichment (GeoIP, ASN, reputation)
                    │          tagging (rules engine)
                    ▼
        PostgreSQL + TimescaleDB
                    │
                    ▼
            API (FastAPI: REST + WebSocket)
                    ▲
                    │
   Reverse tunnel, such as cloudflared, to the dashboard port
                    │
                    ▼
          Web UI (React, served by the API)
```

## Services and networks

| Service | Networks | Notes |
| --- | --- | --- |
| `sensor-ssh`, `sensor-telnet`, `sensor-web`, `sensor-rdp` | `sensors` | The only services published to the internet. They can reach Redis and nothing else. |
| `redis` | `sensors`, `backend` | Password set. A sensor ACL user can only `XADD` to the events stream. |
| `ingest` | `backend`, `egress` | Enrichment and tagging. The only service with outbound internet access. |
| `db` | `backend` | PostgreSQL with TimescaleDB, on a named volume. |
| `api` | `backend`, `dashboard` | FastAPI. Serves the REST and WebSocket endpoints and the built web UI. |

### Why `backend` is internal

The `backend` network is created with `internal: true`. Docker gives it no route to the internet. Redis and the database sit on this network, so nothing on it can call out, and nothing outside can reach it directly.

Only `ingest` has a second network (`egress`) with internet access. That is the one place where outbound calls happen: GeoIP lookups, AbuseIPDB and GreyNoise checks, and optional payload fetches. If a sensor is compromised, it cannot reach the database, the API or the internet. It can only write to the stream.

## Event schema

Every sensor emits the same event shape. The model lives in `sensors/common` as a Pydantic model.

| Field | Content |
| --- | --- |
| `ts` | Timestamp, UTC |
| `sensor` | The sensor that produced the event |
| `session_id` | Groups all events of one connection |
| `src_ip`, `src_port`, `dst_port` | Source and target |
| `type` | One of: `connect`, `login_attempt`, `command`, `http_request`, `download_attempt`, `disconnect`, `scan` |
| `data` | Raw details, as JSON |

Ingest adds these fields after enrichment and tagging:

| Field | Content |
| --- | --- |
| `country`, `city` | From GeoLite2 |
| `asn`, `org` | Autonomous system and organisation |
| `abuse_score` | AbuseIPDB score, if available |
| `known_scanner` | GreyNoise classification, if available |
| `tags[]` | Labels from the rules engine |

## Sessions and tags

- A **session** is one connection, or a group of events that belong to the same attack. It is the unit the UI tells as a story. Each session has a one-line summary, for example "tried 37 SSH passwords, then ran a crypto-miner".
- **Tags** come from a declarative rules engine. Rules are YAML files in `ingest/rules/`. A rule can match URL patterns, typical shell commands, user-agents or CVE signatures. Examples of tags: `recon`, `mirai`, `crypto-miner`, `malware-drop`, `php2shell`.

## Stack

| Layer | Choice |
| --- | --- |
| Sensors | Python 3.12+, asyncio, asyncssh (SSH), raw asyncio (Telnet, RDP), Starlette (web) |
| Ingest and API | FastAPI, SQLAlchemy 2 with asyncpg, Alembic |
| Queue | Redis Streams |
| Database | PostgreSQL 16+ with TimescaleDB (hypertables and continuous aggregates) |
| Enrichment | MaxMind GeoLite2 (local), AbuseIPDB, GreyNoise Community. Results are cached per IP for 24 hours, and daily quotas are enforced. |
| Web UI | React, Vite, TypeScript (strict), Tailwind, shadcn/ui, Recharts or Tremor, globe.gl, xterm.js, TanStack Query and Table |
| Python tooling | uv, ruff, mypy, pytest |
| Web tooling | pnpm, eslint, prettier, vitest, Playwright |
| Task runner | `justfile`: `just up`, `just down`, `just test`, `just lint`, `just demo` |

## Repository layout

```
suckerpot/
├── docker-compose.yml
├── justfile
├── .env.example
├── sensors/{common,ssh,telnet,web,rdp}/
├── ingest/            # consumer, enrichment, rules/*.yaml
├── api/               # FastAPI app, also serves web/dist
├── web/               # React app
├── db/                # migrations
├── scripts/demo/      # demo data generator
└── docs/              # ROADMAP, PROGRESS, ARCHITECTURE, SECURITY
```

## Demo data

`just demo` generates fake but realistic attack sessions over the last 30 days. The UI is built against this data, so it never waits for real traffic. Screenshots in the README only ever use demo data. They never show real attacks.
