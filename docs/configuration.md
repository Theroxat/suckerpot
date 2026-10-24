# Configuration

SuckerPot is configured with environment variables. You set them in `.env`, which Docker Compose reads. The template is `.env.example`. Copy it, then replace every placeholder.

```bash
cp .env.example .env
```

Never commit `.env`. It holds passwords. The `.gitignore` already excludes it.

## Secrets

Compose refuses to start until the required secrets are set. Each secret must be at least 24 characters long, and no two may be equal. The Redis and migration containers check this at start-up and refuse to run otherwise. Generate each one separately:

```bash
openssl rand -base64 32
```

| Secret | Used by | Purpose |
| --- | --- | --- |
| `POSTGRES_PASSWORD` | `db`, `migrate` | Owner account of the database. Used for schema changes only. |
| `POSTGRES_INGEST_PASSWORD` | `migrate`, `ingest` | Password of the `suckerpot_ingest` role |
| `POSTGRES_API_PASSWORD` | `migrate`, `api` | Password of the `suckerpot_api` role (read-only) |
| `REDIS_PASSWORD` | `redis` | Password of the Redis `admin` user (operators only) |
| `REDIS_SENSOR_PASSWORD` | `redis`, `demo` (sensors later) | Password of the Redis `sensor` user. It can only add events. |
| `REDIS_INGEST_PASSWORD` | `redis`, `ingest` | Password of the Redis `ingest` user. It can only read and acknowledge events. |
| `REDIS_HEALTH_PASSWORD` | `redis` | Password of the Redis `health` user. It can only run `PING`. |

```{warning}
The template uses `change-me` as a placeholder. It is too short for the policy, so the stack refuses to start until you replace it. `SUCKERPOT_ALLOW_DEFAULT_SECRETS=1` turns the check off. Set it only in CI or throwaway tests.
```

## Variables used today

The **Status** column says whether a variable is used by the code now. "Planned" means it is in the template for a future milestone and has no effect yet.

### Compose and dashboard

| Variable | Default | Required | Status | Description |
| --- | --- | --- | --- | --- |
| `COMPOSE_PROJECT_NAME` | `suckerpot` | No | M1 | Prefix for container, network and volume names |
| `DASHBOARD_BIND` | `127.0.0.1` | No | M1 | Host address the dashboard port binds to. `127.0.0.1` keeps it on the host. Set a LAN address only when a tunnel on another machine must reach it, and then filter the port upstream. Published Docker ports bypass ordinary host `INPUT` rules. |
| `DASHBOARD_PORT` | `8443` | No | M1 | Host port for the dashboard (the API). Must never be 22, 23, 80, 443, 3389 or the host's admin SSH port. |
| `API_ENABLE_DOCS` | `false` | No | M1 | Serve `/docs`, `/redoc` and `/openapi.json`. Keep `false` unless you are developing. |
| `API_ALLOWED_ORIGINS` | empty | No | M1 | Comma-separated list of extra origins (`https://host.example`) that browsers may use for the WebSocket feed. Same-host origins are always allowed. Read by the API, not set in `.env.example`. |
| `WEB_DIST_DIR` | `/app/web` | No | M1 | Folder with the built web UI. The UI is served only when it contains an `index.html`. Read by the API. |

### Database

| Variable | Default | Required | Status | Description |
| --- | --- | --- | --- | --- |
| `POSTGRES_DB` | `suckerpot` | No | M1 | Database name |
| `POSTGRES_USER` | `suckerpot` | No | M1 | Owner account. Used by `db` and `migrate` only. |
| `POSTGRES_PASSWORD` | none | **Yes** | M1 | Owner password (see [Secrets](#secrets)) |
| `POSTGRES_INGEST_USER` | `suckerpot_ingest` | No | M1 | Role name used by ingest |
| `POSTGRES_INGEST_PASSWORD` | none | **Yes** | M1 | Password of the ingest role |
| `POSTGRES_API_USER` | `suckerpot_api` | No | M1 | Role name used by the API (read-only) |
| `POSTGRES_API_PASSWORD` | none | **Yes** | M1 | Password of the API role |

### Redis

| Variable | Default | Required | Status | Description |
| --- | --- | --- | --- | --- |
| `REDIS_PASSWORD` | none | **Yes** | M1 | Password of the `admin` user. Not used by ingest or the API. |
| `REDIS_SENSOR_PASSWORD` | none | **Yes** | M1 | Password of the `sensor` user |
| `REDIS_INGEST_PASSWORD` | none | **Yes** | M1 | Password of the `ingest` user |
| `REDIS_HEALTH_PASSWORD` | none | **Yes** | M1 | Password of the `health` user |
| `EVENTS_MAXLEN` | `10000` | No | M1 | Approximate maximum length of the events stream (`XADD MAXLEN ~`). Read by the publisher. |
| `SUCKERPOT_ALLOW_DEFAULT_SECRETS` | `0` | No | M1 | Set to `1` only in CI or throwaway tests. It turns off the length and uniqueness checks. |

### Demo data

| Variable | Default | Required | Status | Description |
| --- | --- | --- | --- | --- |
| `DEMO_DAYS` | `30` | No | M1 | Number of days the demo data covers |
| `DEMO_SESSIONS` | `3000` | No | M1 | Number of sessions the backfill creates |
| `DEMO_SEED` | `42` | No | M1 | Random seed. The same seed gives the same data. |

See [Demo data](demo-data.md) for the command-line options that override these.

### Ingest

These are read by the ingest service. Their defaults are set in code, so you can leave them out of `.env`.

| Variable | Default | Description |
| --- | --- | --- |
| `INGEST_BATCH_SIZE` | `100` | Events per database write, between 1 and 500 |
| `INGEST_BLOCK_MS` | `1000` | How long one stream read waits for new entries, in milliseconds |
| `INGEST_CLAIM_IDLE_MS` | `60000` | Pending messages idle for longer than this are taken over from dead consumers |
| `INGEST_GROUP` | `ingest` | Consumer group name |
| `INGEST_CONSUMER` | host name | Consumer name inside the group |
| `INGEST_HEARTBEAT_PATH` | `/tmp/ingest-heartbeat` | File touched on each healthy loop. The health check reads it. |

## Variables planned for later milestones

These names are in `.env.example`, but the code does not read them yet. Setting them has no effect today.

| Variable | Default | Milestone | Description |
| --- | --- | --- | --- |
| `SSH_HOST_PORT` | `22` | M2 | Host port for the SSH sensor |
| `TELNET_HOST_PORT` | `23` | M6 | Host port for the Telnet sensor |
| `HTTP_HOST_PORT` | `80` | M6 | Host port for the web sensor |
| `RDP_HOST_PORT` | `3389` | M6 | Host port for the RDP sensor |
| `SSH_HOSTNAME` | `srv-web01` | M2 | Hostname the fake SSH service shows to clients |
| `SSH_BANNER` | `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5` | M2 | SSH banner sent to clients |
| `ADMIN_USERNAME` | `admin` | M8 | Name of the single admin account |
| `ADMIN_PASSWORD_HASH` | empty | M8 | Argon2 hash of the admin password |
| `SESSION_SECRET` | `change-me` | M8 | Secret that signs session cookies |
| `RETENTION_DAYS` | `90` | M8 | Days to keep raw events. Aggregates are kept. |
| `MAXMIND_ACCOUNT_ID` | empty | M4 | MaxMind account ID for GeoLite2 downloads |
| `MAXMIND_LICENSE_KEY` | empty | M4 | MaxMind licence key for GeoLite2 downloads |
| `ABUSEIPDB_API_KEY` | empty | M4 | AbuseIPDB API key |
| `ABUSEIPDB_DAILY_QUOTA` | `1000` | M4 | Maximum AbuseIPDB checks per day |
| `GREYNOISE_API_KEY` | empty | M4 | GreyNoise Community API key |
| `GREYNOISE_DAILY_QUOTA` | `50` | M4 | Maximum GreyNoise checks per day |
| `FETCH_PAYLOADS` | `false` | no milestone yet | If `true`, ingest fetches files from captured download URLs |
| `PAYLOAD_MAX_BYTES` | `10485760` | no milestone yet | Maximum size of one fetched payload |
| `PAYLOAD_TIMEOUT_SECONDS` | `20` | no milestone yet | Timeout for one payload fetch |

## Set by Compose

Compose sets these for each service. You do not need to put them in `.env`, and you should not change them there.

| Variable | Value | Services | Description |
| --- | --- | --- | --- |
| `POSTGRES_HOST` | `db` | `migrate`, `ingest`, `api` | Database host on the `backend` network |
| `POSTGRES_PORT` | `5432` | `migrate`, `ingest`, `api` | Database port |
| `POSTGRES_USER` | role name | `ingest`, `api` | The restricted role of the service |
| `POSTGRES_PASSWORD` | role password | `ingest`, `api` | Password of that role |
| `REDIS_HOST` | `redis` | `ingest`, `demo` | Redis host on the internal networks |
| `REDIS_PORT` | `6379` | `ingest`, `demo` | Redis port |
| `REDIS_USER` | `ingest` or `sensor` | `ingest`, `demo` | Redis user of the service |
| `REDIS_PASSWORD` | the user's password | `ingest`, `demo` | Password of that user |
| `EVENTS_STREAM` | `events` | `ingest`, `demo` | Name of the Redis stream |
