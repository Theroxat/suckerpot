# Configuration

SuckerPot is configured with environment variables. You set them in `.env`, which Docker Compose reads. The template is `.env.example`. Copy it, then replace every placeholder.

```bash
cp .env.example .env
chmod 600 .env
```

Never commit `.env`. It holds passwords. The `.gitignore` already excludes it.

This page lists every variable the code reads today. "In `.env`" means Compose passes it through from your `.env`. "Fixed by Compose" means Compose sets it, and you should not change it. A variable that the code reads but Compose does not pass through can only be changed by editing `docker-compose.yml` (an override file is the clean way).

## Secrets

Compose refuses to start until the required secrets are set. Each secret must be at least 24 characters long, and no two may be equal. The Redis and migration containers check this at start-up and refuse to run otherwise. The message names the variable, never its value.

```bash
openssl rand -base64 32
```

| Secret | Used by | Purpose |
| --- | --- | --- |
| `POSTGRES_PASSWORD` | `db`, `migrate` | Database owner. Schema changes only. |
| `POSTGRES_INGEST_PASSWORD` | `migrate`, `ingest` | Role `suckerpot_ingest` |
| `POSTGRES_API_PASSWORD` | `migrate`, `api` | Role `suckerpot_api` (read-only) |
| `REDIS_PASSWORD` | `redis` | Redis `admin` user (operators only) |
| `REDIS_HEALTH_PASSWORD` | `redis` | Redis `health` user. It can only run `PING`. |
| `REDIS_INGEST_PASSWORD` | `redis`, `ingest` | Redis `ingest` user. It reads and acknowledges the event streams. |
| `REDIS_SENSOR_SSH_PASSWORD` | `redis`, `sensor-ssh` | Redis `sensor-ssh` user. It can only `XADD` to `events:ssh`. |
| `REDIS_SENSOR_RDP_PASSWORD` | `redis`, `sensor-rdp` | Redis `sensor-rdp` user. It can only `XADD` to `events:rdp`. |
| `REDIS_SENSOR_TELNET_PASSWORD` | `redis`, `sensor-telnet` | Redis `sensor-telnet` user. It can only `XADD` to `events:telnet`. |
| `REDIS_SENSOR_WEB_PASSWORD` | `redis`, `sensor-web` | Redis `sensor-web` user. It can only `XADD` to `events:web`. |
| `REDIS_SENSOR_REDIS_PASSWORD` | `redis`, `sensor-redis` | Redis `sensor-redis` user. It can only `XADD` to `events:redis`. |
| `REDIS_SENSOR_DOCKER_PASSWORD` | `redis`, `sensor-docker` | Redis `sensor-docker` user. It can only `XADD` to `events:docker`. |
| `REDIS_SENSOR_MYSQL_PASSWORD` | `redis`, `sensor-mysql` | Redis `sensor-mysql` user. It can only `XADD` to `events:mysql`. |
| `REDIS_SENSOR_MSSQL_PASSWORD` | `redis`, `sensor-mssql` | Redis `sensor-mssql` user. It can only `XADD` to `events:mssql`. |
| `REDIS_SENSOR_ADB_PASSWORD` | `redis`, `sensor-adb` | Redis `sensor-adb` user. It can only `XADD` to `events:adb`. |
| `REDIS_SENSOR_SMB_PASSWORD` | `redis`, `sensor-smb` | Redis `sensor-smb` user. It can only `XADD` to `events:smb`. |
| `REDIS_SENSOR_SIP_PASSWORD` | `redis`, `sensor-sip` | Redis `sensor-sip` user. It can only `XADD` to `events:sip`. |
| `REDIS_SENSOR_SYNOLOGY_PASSWORD` | `redis`, `sensor-synology` | Redis `sensor-synology` user. It can only `XADD` to `events:synology`. |
| `REDIS_DEMO_PASSWORD` | `redis`, `demo` | Redis `demo` user. It can only `XADD` to `events:*`. |
| `SESSION_SECRET` | `api` | Signs the dashboard session cookie (at least 32 bytes). See [Dashboard authentication](#dashboard-authentication). |
| `ADMIN_PASSWORD_HASH` | `api` | Argon2 hash of the dashboard password. A hash, not a password, but treat it as a secret. |
| `SETTINGS_ENCRYPTION_KEY` | `api`, `ingest` | Optional. Encrypts the enrichment API keys you enter on the Settings page. Make it with `openssl rand -base64 32` (at least 32 random bytes). See [Enrichment keys in Settings](#enrichment-keys-in-settings). |

Each of the twelve sensors has its own Redis secret, `REDIS_SENSOR_<NAME>_PASSWORD`, for SSH, Telnet, RDP, web, Redis, Docker, MySQL, MSSQL, ADB, SMB, SIP and Synology. To rotate secrets, see [Deployment](deployment.md#rotating-secrets).

```{warning}
The template uses `change-me` as a placeholder. It is too short for the policy, so the stack refuses to start until you replace it. `SUCKERPOT_ALLOW_DEFAULT_SECRETS=1` turns the check off. Set it only in CI or throwaway tests.
```

## Compose and host

| Variable | Default | Source | Description |
| --- | --- | --- | --- |
| `COMPOSE_PROJECT_NAME` | `suckerpot` | `.env` | Prefix for container, network and volume names |
| `DASHBOARD_BIND` | `127.0.0.1` | `.env` | Host address the dashboard port binds to. Keep `127.0.0.1` unless a tunnel on another machine must reach it, and then [filter the port upstream](deployment.md#dashboard-bind-and-upstream-filtering). |
| `DASHBOARD_PORT` | `8443` | `.env` | Host port for the dashboard. Never 22, 23, 80, 443, 3389 or the admin SSH port. |
| `ADMIN_SSH_PORT` | empty | `.env` | Optional. The port of the host's own admin SSH daemon. Read only by `scripts/check-ports.sh`, to refuse a collision. |
| `SSH_HOST_PORT` | `22` | `.env` | Host port of the SSH sensor (IPv4 only) |
| `TELNET_HOST_PORT` | `23` | `.env` | Host port of the Telnet sensor |
| `HTTP_HOST_PORT` | `80` | `.env` | Host port of the web sensor (IPv4 only) |
| `HTTPS_HOST_PORT` | `443` | `.env` | Host port of the web sensor's TLS listener (IPv4 only) |
| `RDP_HOST_PORT` | `3389` | `.env` | Host port of the RDP sensor |
| `REDIS_HOST_PORT` | `6379` | `.env` | Host port of the Redis sensor (IPv4 only) |
| `DOCKER_HOST_PORT` | `2375` | `.env` | Host port of the Docker API sensor (IPv4 only) |
| `MYSQL_HOST_PORT` | `3306` | `.env` | Host port of the MySQL sensor (IPv4 only) |
| `MSSQL_HOST_PORT` | `1433` | `.env` | Host port of the MSSQL sensor (IPv4 only) |
| `ADB_HOST_PORT` | `5555` | `.env` | Host port of the ADB sensor (IPv4 only) |
| `SMB_HOST_PORT` | `445` | `.env` | Host port of the SMB sensor (IPv4 only). The sensor listens on container port 4450. |
| `SIP_HOST_PORT` | `5060` | `.env` | Host port of the SIP sensor, for both UDP and TCP (IPv4 only) |
| `SYNOLOGY_HTTP_HOST_PORT` | `5000` | `.env` | Host port of the Synology sensor's HTTP listener (IPv4 only) |
| `SYNOLOGY_HTTPS_HOST_PORT` | `5001` | `.env` | Host port of the Synology sensor's HTTPS listener (IPv4 only) |
| `SUCKERPOT_ALLOW_DEFAULT_SECRETS` | `0` | `.env` | `1` turns off the secret length and uniqueness checks. CI and throwaway tests only. |

## Database

| Variable | Default | Source | Description |
| --- | --- | --- | --- |
| `POSTGRES_DB` | `suckerpot` | `.env` | Database name |
| `POSTGRES_USER` | `suckerpot` | `.env` | Owner account. Used by `db` and `migrate` only. |
| `POSTGRES_PASSWORD` | none | `.env`, required | Owner password |
| `POSTGRES_INGEST_USER` | `suckerpot_ingest` | `.env` | Role name used by ingest |
| `POSTGRES_INGEST_PASSWORD` | none | `.env`, required | Password of the ingest role |
| `POSTGRES_API_USER` | `suckerpot_api` | `.env` | Role name used by the API |
| `POSTGRES_API_PASSWORD` | none | `.env`, required | Password of the API role |
| `POSTGRES_HOST` | `db` | Fixed by Compose | Database host on the `backend` network |
| `POSTGRES_PORT` | `5432` | Fixed by Compose | Database port |

Inside `ingest` and `api`, Compose sets `POSTGRES_USER` and `POSTGRES_PASSWORD` to that service's own role, not to the owner.

## Redis

| Variable | Default | Source | Description |
| --- | --- | --- | --- |
| `REDIS_PASSWORD` and the other `REDIS_*_PASSWORD` secrets | none | `.env`, required | See [Secrets](#secrets) |
| `EVENTS_MAXLEN` | `10000` | `.env` | Approximate maximum length of each sensor's stream (`XADD MAXLEN ~`) for SSH, Telnet, Web and RDP |
| `EVENTS_MAXLEN_LOW` | `3000` | `.env` | The same cap for the seven M9 sensors (Redis, Docker, MySQL, MSSQL, ADB, SMB and SIP) and the Synology sensor. Kept short so a burst on seven more streams cannot fill Redis memory. Ingest drains the streams, and a sensor drops an event when `XADD` fails. |
| `DEMO_EVENTS_MAXLEN` | `100000` | `.env` | The same cap, for the demo generator only. Keep it above the number of events per sensor in a backfill, or entries ingest has not read yet are trimmed. |
| `EVENTS_MAX_BYTES_PER_SEC` | `200000` | Code default | Publisher backstop for **every** sensor: a token bucket on serialized event bytes per second. Beyond it the publisher drops events and counts them. |
| `EVENTS_MAX_BYTES_BURST` | `2000000` | Code default | Burst of that bucket, in bytes |
| `REDIS_HOST` | `redis` | Fixed by Compose | Redis host |
| `REDIS_PORT` | `6379` | Fixed by Compose | Redis port |
| `REDIS_USER` | per service | Fixed by Compose | `ingest`, `demo`, and one `sensor-<name>` user per sensor |
| `EVENTS_STREAM` | per service | Fixed by Compose | Stream a sensor writes to (`events:ssh`). The code default is `events`. |

Inside each service, Compose sets `REDIS_PASSWORD` to the password of that service's own Redis user.

## API

| Variable | Default | Source | Description |
| --- | --- | --- | --- |
| `API_ENABLE_DOCS` | `false` | `.env` | Serve `/docs`, `/redoc` and `/openapi.json`. Keep `false` unless you are developing. |
| `API_ALLOWED_ORIGINS` | empty | `.env` | Extra browser origins for the live WebSocket, comma-separated, full origins such as `https://dash.example.com`. Needed behind a TLS-terminating tunnel. Same-host origins are always allowed. |
| `WEB_DIST_DIR` | `/app/web` | Code default | Folder with the built web UI. Served only when it contains an `index.html`. |

## Dashboard authentication

```{admonition} Status
:class: note

Built in M8, security review passed. Compose passes all of these variables to the `api` service from your `.env`. `ADMIN_PASSWORD_HASH` and `SESSION_SECRET` are required: `docker compose up` and `just up` refuse to start, with a message that names the variable, until both are set. `API_AUTH_DISABLED` and `SUCKERPOT_DEMO` are set only by `docker-compose.ci.yml`.
```

The owner account lives in `.env`: it is always an administrator and works even when the database is down. Colleagues get their own accounts, with the role `admin` or `viewer`, from **Settings > Users** (see [Users and roles](#users-and-roles)). See [API](api.md#authentication) for how sign-in works.

| Variable | Default | Description |
| --- | --- | --- |
| `ADMIN_USERNAME` | `admin` | Name of the owner account. A user created in Settings cannot take this name. |
| `ADMIN_PASSWORD_HASH` | none, **required** | Argon2 hash of the admin password. Make it with `docker compose run --rm api python -m api.hashpw`. Put it in `.env` in **single quotes**, because it contains `$`. |
| `SESSION_SECRET` | none, **required** | Signs the session and CSRF cookies. At least 32 bytes. Generate it with `openssl rand -base64 48`. Different from every other secret. |
| `SESSION_TTL_HOURS` | `12` | How long a login lasts |
| `COOKIE_SECURE` | `true` | Cookies are `Secure` and named `__Host-sp_session` and `__Host-sp_csrf`. Keep `true`, also behind a TLS-terminating tunnel (the browser talks HTTPS to the tunnel). `false` gives the plain names `sp_session` and `sp_csrf` without `Secure`: local development over HTTP only. |
| `LOGIN_RATE` | `5` | Login attempts per client address per minute (every attempt counts) |
| `LOGIN_RATE_GLOBAL` | `30` | **Wrong passwords** per minute for the whole server; successful sign-ins do not count |
| `LOGIN_RATE_USER` | `10` | Wrong passwords per minute for one username (any letter case), from any address. Not applied to the owner's name. |
| `AUTH_TRUSTED_PROXIES` | empty | Comma-separated CIDR list of proxy addresses (such as `203.0.113.0/24`). Only from those peers does the API read `CF-Connecting-IP`, or the rightmost non-proxy `X-Forwarded-For` entry, as the client address. Empty means the headers are never trusted. Replaces the old `AUTH_TRUST_PROXY_HEADERS`. |
| `API_ALLOWED_HOSTS` | empty | Comma-separated host names the API answers to. If empty, the hosts of `API_ALLOWED_ORIGINS` are used. `localhost` and `127.0.0.1` are always allowed. If both are empty, any host is allowed and the API logs a warning: set one in production, for example the tunnel's host name. |
| `API_AUTH_DISABLED` | `false` | Turns authentication **off**. It takes effect only together with `SUCKERPOT_DEMO=1`, and Compose sets both only through `docker-compose.ci.yml` (`just up-test`). The base `docker-compose.yml` never does. Never use it in production. |
| `API_ALLOWED_ORIGINS` | empty | Also used by login: when set, the **full origin** of a login request (scheme, host, port) must be listed. When empty, only the host is compared with the `Host` header. Set it behind a tunnel. |

The API refuses to start when the hash or the secret is missing or weak. `SUCKERPOT_ALLOW_DEFAULT_SECRETS=1` accepts a weak setup for CI only.

### Users and roles

Added in M14. There is nothing to configure in `.env` for it (apart from `LOGIN_RATE_USER` above): users are created and managed in **Settings > Users**, by an administrator.

| | Owner | Administrator | Viewer |
| --- | --- | --- | --- |
| Where it lives | `.env` | database | database |
| Look at every page, export data, watch Live | yes | yes | yes |
| Change settings and provider keys | yes | yes | no |
| Manage users, read the audit log | yes | yes | no |
| Password changed | in `.env` only | by the user | by the user |
| Can be disabled, demoted or deleted | no | yes, by another administrator | yes |

- A new account gets a strong temporary password that the administrator sees **once**. The person must choose their own password at the first sign-in; until then nothing else works.
- Passwords have 12 to 256 characters, are not one of about a thousand very common passwords (the list is `api/api/data/common-passwords.txt`) and must not contain the username.
- Five wrong passwords from one address lock that address for that account for a minute (longer on repeats, up to 15 minutes); 50 in total lock the account for 15 minutes, but only for addresses the user never signed in from. An administrator can unlock at once.
- Every change to a user asks the administrator for their own password again, and is written to the audit log (kept for one year).
- Changing a password, disabling an account, changing its role, deleting it or choosing "Sign out everywhere" ends all of that user's sessions immediately.
- Optional two-factor sign-in is not built yet.

**Losing the owner password:** make a new hash with `docker compose run --rm api python -m api.hashpw`, put it in `.env` as `ADMIN_PASSWORD_HASH` and restart the API. The owner account never depends on the database, so this works even when users cannot sign in.

## Site (Live map home)

| Variable | Default | Description |
| --- | --- | --- |
| `SITE_HOME_LAT`, `SITE_HOME_LON` | `46.8`, `8.2` | Where attack arcs land on the Live map. Rounded to one decimal. Use a country-level point, never your real address. |
| `SITE_HOME_LABEL` | `Switzerland` | Name shown next to the home point on the Live map (64 characters at most) |

## Ingest

Defaults are set in code. Compose passes `INGEST_STREAMS` through from `.env`. The others can only be changed with an override file.

| Variable | Default | Source | Description |
| --- | --- | --- | --- |
| `INGEST_STREAMS` | `events:ssh,events:telnet,events:web,events:rdp,events:redis,events:docker,events:mysql,events:mssql,events:adb,events:smb,events:sip,events:synology` | `.env` | Streams to read, comma-separated. Letters, digits and `_ . : -`, up to 64 characters each. The suffix after the last `:` must be the sensor name: events whose `sensor` differs are dropped. |
| `INGEST_BATCH_SIZE` | `100` | Code default | Events per database write, 1 to 500 |
| `INGEST_BLOCK_MS` | `1000` | Code default | How long one stream read waits for new entries, in milliseconds |
| `INGEST_CLAIM_IDLE_MS` | `60000` | Code default | Pending entries idle for longer than this are reclaimed |
| `INGEST_RECLAIM_INTERVAL_S` | `60` | Code default | How often ingest looks for stale pending entries |
| `INGEST_GROUP` | `ingest` | Code default | Consumer group name |
| `INGEST_CONSUMER` | `ingest-1` | Code default | Consumer name inside the group. Keep it stable: a stable name makes restarts take over their own pending entries. |
| `INGEST_HEARTBEAT_PATH` | `/tmp/ingest-heartbeat` | Code default | File touched on each healthy loop. The health check reads it. |

## Enrichment and tagging

```{admonition} Status
:class: note

Built (M4). Compose passes these variables to `ingest` and mounts the `geoip-data` volume at `/data/geoip`. Every variable has a safe default. Without keys, GeoIP uses the key-less DB-IP Lite database and reputation lookups stay off.
```

The geolocation data has a licence that requires credit. See [Data sources and attribution](#data-sources-and-attribution).

| Variable | Default | Description |
| --- | --- | --- |
| `GEOIP_PROVIDER` | `auto` | `auto` (MaxMind if both MaxMind variables are set, else DB-IP), `maxmind`, `dbip` or `off` |
| `GEOIP_DIR` | `/data/geoip` | Folder for the downloaded MMDB files |
| `GEOIP_REFRESH_DAYS` | `30` | Re-download a database when it is older than this (at least 1) |
| `GEOIP_FAKE_FOR_PRIVATE` | `false` | Give private and documentation addresses a fake country. For demo screenshots only. |
| `SETTINGS_ENCRYPTION_KEY` | empty | Enables entering the keys below on the Settings page. See [Enrichment keys in Settings](#enrichment-keys-in-settings). |
| `MAXMIND_ACCOUNT_ID` | empty | MaxMind account ID for GeoLite2 downloads |
| `MAXMIND_LICENSE_KEY` | empty | MaxMind licence key. Optional. |
| `ABUSEIPDB_API_KEY` | empty | AbuseIPDB key. Without it, no lookups. |
| `ABUSEIPDB_DAILY_QUOTA` | `1000` | Maximum AbuseIPDB checks per day. Enforced, and persisted in the database. |
| `GREYNOISE_API_KEY` | empty | GreyNoise Community key. Without it, no lookups. |
| `GREYNOISE_DAILY_QUOTA` | `50` | Maximum GreyNoise checks per day |
| `CVE_WATCH_ENABLED` | `true` | Daily job that mirrors CISA KEV, NVD CVEs from the last 60 days and GitHub advisories. The feeds are read in chunks. See [Architecture](ARCHITECTURE.md). |
| `NVD_API_KEY` | empty | NVD key. Optional: raises the rate limit from 5 to 50 requests per 30 s |
| `GITHUB_ADVISORY_TOKEN` | empty | Token for the public GitHub advisories API. Optional: raises the limit from 60 requests per hour. Use a fine-grained token for public repositories only, read-only, with no permissions. Never your push token |
| `CVE_NVD_DAILY_QUOTA` | `200` | Maximum NVD requests per day. Enforced, and persisted in the database |
| `CVE_GITHUB_DAILY_QUOTA` | `100` | Maximum GitHub advisory requests per day |
| `REPUTATION_MIN_EVENTS` | `10` | An address is looked up only after this many events |
| `REPUTATION_INTERVAL_S` | `30` | Seconds between reputation cycles (at least 5) |
| `ABUSECH_AUTH_KEY` | empty | abuse.ch Auth-Key (free) for URLhaus and ThreatFox. Without it, no indicator lookups there. |
| `ABUSECH_DAILY_QUOTA` | `1000` | Maximum abuse.ch requests per day (URLhaus and ThreatFox share it). Enforced, and persisted. |
| `VIRUSTOTAL_API_KEY` | empty | VirusTotal key. Used for file hashes only. |
| `VIRUSTOTAL_DAILY_QUOTA` | `400` | Maximum VirusTotal requests per day (the free tier allows 500). Requests are also spaced 16 s apart. |
| `INTEL_INTERVAL_S` | `30` | Seconds between threat-intel cycles (at least 5) |
| `INDICATORS_ENABLED` | `true` | Extract indicators from recorded events |
| `INDICATORS_IGNORE` | empty | Comma-separated host names, addresses and CIDR blocks never recorded as indicators: **set it to your public IP and domains before going live**. A name also covers its subdomains. The hosts in `API_ALLOWED_HOSTS` and `API_ALLOWED_ORIGINS` are added automatically. |
| `INDICATORS_KEEP_DOCUMENTATION` | `false` | Keep documentation addresses and example domains as indicators. Demo events do not need it (they carry `demo: true`). They are never sent to an intel service either way. |
| `INDICATORS_MAX_ROWS` | `500000` | Most indicator rows kept (1,000 to 50 million). Read by `migrate`. The hourly job drops the least sighted, oldest single-source ones first. |
| `INDICATORS_LINK_CAP` | `500` | Most sessions linked to one indicator. Its counters stay exact beyond that. |
| `RULES_DIR` | `ingest/rules` (`/app/rules` in the image) | Folder with the tagging rules (`*.yaml`) |

### Enrichment keys in Settings

You can enter, replace and remove the AbuseIPDB, GreyNoise, MaxMind, abuse.ch and VirusTotal keys on the Settings page, with no restart.

1. Generate an encryption key and add it to `.env`: `SETTINGS_ENCRYPTION_KEY=$(openssl rand -base64 32)`. Then run `docker compose up -d` so `api` and `ingest` see it. Without it, the Settings page shows the keys as read-only and says why.
2. On the Settings page, choose **Set key** (or **Replace**) for a provider, paste the key and type the admin password to confirm. The key is encrypted before it is stored and is never shown again, only its last four characters.
3. Ingest checks for changes every 30 seconds, so a new key is used within a minute. A new MaxMind key also starts a database download.
4. **Test key** makes one real call to the provider and counts it against the daily quota. The result appears on the page.

A key set in Settings overrides the same key in `.env`. Remove it and the `.env` key is used again. The page shows where each key comes from. If you change or lose `SETTINGS_ENCRYPTION_KEY`, the saved keys cannot be decrypted: the page says so, and the `.env` keys keep working until you enter the keys again. See [Security](SECURITY.md) for the threat model.

## SSH sensor

The variables in the first group are passed through from `.env`. The second group is read by the sensor but not passed through by Compose. See [SSH sensor](sensors/ssh.md).

| Variable | Default | Description |
| --- | --- | --- |
| `SSH_HOSTNAME` | `srv-web01` | Host name shown to clients |
| `SSH_BANNER` | `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.14` | SSH version string. Keep it consistent with `SSH_OS_VERSION`. |
| `SSH_ACCEPT_CREDENTIALS` | `root:root,root:123456,root:password,admin:admin,ubuntu:ubuntu,pi:raspberry,user:user` | Comma-separated `user:password` pairs that log in. Weak on purpose. |
| `SSH_ACCEPT_RANDOM_PROB` | `0.0` | Probability (0 to 1) of accepting any non-empty password |
| `SSH_MAX_AUTH_ATTEMPTS` | `6` | Failed attempts per connection |
| `SSH_MAX_CONNECTIONS` | `200` | Simultaneous connections, in total |
| `SSH_MAX_PER_IP` | `5` | Simultaneous connections per source address |
| `SSH_PORT` | `2222` | Port inside the container (fixed by Compose) |
| `SSH_PUBLIC_PORT` | `22` | Port recorded as `dst_port` (set from `SSH_HOST_PORT`) |
| `SSH_HOSTKEY_DIR` | `/data/host_keys` | Host key folder, on a volume (fixed by Compose) |
| `SSH_LOGIN_TIMEOUT`, `SSH_IDLE_TIMEOUT`, `SSH_MAX_SESSION` | `30`, `300`, `1800` | Seconds: to log in, idle, whole session |
| `SSH_MAX_LINE` | `4096` | Longest accepted input line |
| `SSH_EVENTS_PER_SEC` | `20` | `connect` events per source address per second |
| `SSH_GLOBAL_EVENTS_PER_SEC` | `200` | Sensor-wide event cap |
| `SSH_CONN_RATE_PER_IP`, `SSH_CONN_BURST_PER_IP` | `1`, `10` | New connections per source address per second, and the burst |
| `SSH_SUMMARY_INTERVAL` | `60` | Seconds between summaries of suppressed events (at least 5) |
| `SSH_LINE_BUDGET` | `0.15` | CPU seconds allowed per command line |
| `SSH_MEMORY_BUDGET_MB` | `48` | Memory budget over all sessions |
| `SSH_MEMORY_SHARE_PER_IP` | `0.25` | Share of the memory budget one source address may hold (0.01 to 1) |
| `SSH_MEMORY_LIMIT_MB` | `256` | Memory limit the guard compares against when the cgroup limit cannot be read. Keep it equal to the container limit. |
| `SSH_MEMORY_PRESSURE` | `0.70` | Fraction of the limit above which new connections are refused and the biggest connections stop being read |
| `SSH_MEMORY_CRITICAL` | `0.85` | Fraction above which the biggest connections are closed |
| `SSH_CHANNEL_WINDOW_KB` | `32` | Flow-control window of a session channel, in KiB (8 to 1024). A session with more than four windows of unread input is closed. |
| `SSH_INBOUND_CONN_KB_PER_SEC` | `32` | Inbound data one connection may send per second, in KiB (metered before decryption). Also caps `scp` uploads. |
| `SSH_INBOUND_KB_PER_SEC` | `256` | The same, for all connections together |
| `SSH_SHELL_CPU_SHARE` | `0.3` | CPU-seconds of shell time per second for all sessions together (0.05 to 0.9), shared fairly between source addresses |
| `SSH_SHELL_CPU_BURST` | `0.2` | Burst of that budget, in CPU-seconds |
| `SSH_IP_EVENT_BYTES_PER_SEC`, `SSH_IP_EVENT_BYTES_BURST` | `20000`, `1000000` | Event bytes per source address per second, and the burst |
| `SSH_GLOBAL_EVENT_BYTES_PER_SEC`, `SSH_GLOBAL_EVENT_BYTES_BURST` | `200000`, `2000000` | Event bytes per second for the whole sensor, and the burst. Over budget, an event first loses its bulk (`output_omitted`, `replay_omitted`), then is dropped. |
| `SSH_STATS_INTERVAL` | `60` | Seconds between the sensor's own statistics log lines (at least 5) |
| `SSH_MAX_COMMANDS` | `5000` | Commands per session |
| `SSH_FAKE_IP` | derived | Private address shown by `ifconfig` and `ip a` |
| `SSH_OS_VERSION`, `SSH_KERNEL`, `SSH_KERNEL_BUILD` | `24.04.4`, `6.8.0-100-generic`, matching build | Fake OS and kernel versions |

## Web sensor

```{admonition} Status
:class: note

Built (M6) and wired into `docker-compose.yml`. It is still under security review. Compose sets the ports, the hostname and the Redis settings. The other variables use the defaults below unless you add them with an override file.
```

| Variable | Default | Description |
| --- | --- | --- |
| `WEB_HOSTNAME` | `srv-web01` | Host name (a plain label) |
| `WEB_HTTP_PORT`, `WEB_HTTPS_PORT` | `8080`, `8443` | Ports inside the container |
| `WEB_HTTP_PUBLIC_PORT`, `WEB_HTTPS_PUBLIC_PORT` | `80`, `443` | Ports recorded as `dst_port` and shown in error pages |
| `WEB_DATA_DIR` | `/data` | Folder for the generated profile and TLS certificate (a volume) |
| `WEB_SERVER_TOKEN` | `Apache/2.4.58 (Ubuntu)` | `Server` header. Must look like `Apache/2.4.N (Ubuntu)`. |
| `WEB_PHP_VERSION` | `8.3.6` | PHP version shown. Must be `8.3.N` with N below 36, the PHP2Shell-vulnerable range. |
| `WEB_EXPOSE_PHP` | `true` | Send `X-Powered-By` on PHP responses |
| `WEB_WP_VERSION`, `WEB_PMA_VERSION` | `6.8.1`, `5.2.1` | WordPress and phpMyAdmin versions shown |
| `WEB_UPLOAD_PROGRESS_NAME` | `PHP_SESSION_UPLOAD_PROGRESS` | Name of the upload-progress field the detector watches |
| `WEB_MAX_CONNECTIONS`, `WEB_MAX_PER_IP` | `200`, `10` | Connection caps |
| `WEB_MEMORY_BUDGET_MB` | `48` | Memory budget over all requests |
| `WEB_EVENTS_PER_SEC`, `WEB_GLOBAL_EVENTS_PER_SEC` | `20`, `200` | Event caps per source address and for the sensor |

## RDP sensor

```{admonition} Status
:class: note

Built. Compose sets the ports, `RDP_HOSTNAME`, the caps, and the NLA mode and decoy accounts. The rest use the defaults below unless you add them with an override file.
```

Set these in `.env`. Compose passes them to the sensor under the `SENSOR_RDP_` names shown in the first column. The `.env` names are in the second column, and `.env.example` lists them with comments.

| Variable | Default | Description |
| --- | --- | --- |
| `SENSOR_RDP_NLA_MODE` (`.env`: `RDP_NLA_MODE`) | `required` | `required` accepts NLA clients only. `optional` also accepts TLS-only clients and records the cleartext password they send. This is an owner opt-in, see [Security](SECURITY.md#credentials-the-sensors-record). Any other value stops the sensor at start-up. |
| `SENSOR_RDP_ACCOUNTS` (`.env`: `RDP_ACCOUNTS`) | `administrator:P@ssw0rd,administrator:123456,admin:admin` | Decoy `user:password` pairs, comma separated. Only these pairs are checked, and the pairs are public by design. |
| `RDP_PORT` | `3389` | Port inside the container |
| `RDP_PUBLIC_PORT` | `3389` | Port recorded as `dst_port` |
| `RDP_HOSTNAME` | derived | NetBIOS name in the certificate, 1 to 15 characters |
| `RDP_DATA_DIR` | `/data` | Profile secret, certificate and key (a volume) |
| `RDP_ENABLE_TLS` | `true` | Complete the TLS handshake after selecting CredSSP |
| `RDP_MAX_CONNECTIONS`, `RDP_MAX_PER_IP` | `200`, `8` | Connection caps |
| `RDP_MAX_TLS_PER_IP` | `4` | TLS handshakes allowed from one source at the same time (`.env` uses the same name) |
| `RDP_FIRST_DATA_TIMEOUT` | `8` | Seconds to wait for the first bytes |
| `RDP_HANDSHAKE_TIMEOUT` | `10` | Seconds per PDU and for the TLS handshake |
| `RDP_CREDSSP_TIMEOUT` | `10` | Seconds to wait for the first `TSRequest` |
| `RDP_MAX_SESSION` | `60` | Hard cap on one connection, in seconds |
| `RDP_SESSIONS_PER_SEC_PER_IP` | `2` | Recorded connections per source per second (burst 15 times that) |
| `RDP_GLOBAL_SESSIONS_PER_SEC` | `50` | Recorded connections per second overall (burst 2 times that) |
| `RDP_GLOBAL_EVENTS_PER_SEC` | `200` | Global event cap (all types except `disconnect`) |
| `RDP_DISCONNECT_EVENTS_PER_SEC` | `60` | Global cap on `disconnect` events |
| `RDP_TLS_PER_SEC_PER_IP`, `RDP_TLS_BURST_PER_IP` | `5`, `20` | TLS handshakes started per source |
| `RDP_MAX_TLS_HANDSHAKES` | `32` | TLS handshakes in progress at the same time |

## Telnet sensor

```{admonition} Status
:class: note

Built. Compose sets `TELNET_PUBLIC_PORT` (from `TELNET_HOST_PORT`) and the Redis settings. The other variables use the defaults below unless you add them with an override file. See [Telnet sensor](sensors/telnet.md).
```

| Variable | Default | Description |
| --- | --- | --- |
| `TELNET_PORT` | `2323` | Port inside the container |
| `TELNET_PUBLIC_PORT` | `23` | Port recorded as `dst_port` |
| `TELNET_PERSONALITY` | `dvr` | `dvr` or `router` |
| `TELNET_HOSTNAME` | derived | Host name (a plain label) |
| `TELNET_LOGIN_PROMPT` | `{hostname} login: ` | Login prompt. `\r` and `\n` are turned into line breaks. |
| `TELNET_PRELOGIN_BANNER`, `TELNET_MOTD` | empty | Texts before the login and after it. Empty means the personality's own text. At most 2048 characters. |
| `TELNET_DATA_DIR` | `/data` | Folder for the generated profile secret (a volume) |
| `TELNET_ACCEPT_CREDENTIALS` | trimmed Mirai list | Comma-separated `user:password` pairs that log in |
| `TELNET_ACCEPT_RANDOM_PROB` | `0.0` | Probability (0 to 1) of accepting any login |
| `TELNET_MAX_AUTH_ATTEMPTS` | `6` | Failed attempts per connection |
| `TELNET_MAX_CONNECTIONS`, `TELNET_MAX_PER_IP` | `200`, `8` | Connection caps |
| `TELNET_LOGIN_TIMEOUT`, `TELNET_IDLE_TIMEOUT`, `TELNET_MAX_SESSION` | `60`, `300`, `1800` | Seconds |
| `TELNET_MAX_LINE`, `TELNET_MAX_COMMANDS` | `4096`, `2000` | Longest input line, commands per session |
| `TELNET_LINE_BUDGET` | `0.15` | CPU seconds per command line |
| `TELNET_MEMORY_BUDGET_MB` | `48` | Memory budget over all sessions |
| `TELNET_EVENTS_PER_SEC`, `TELNET_GLOBAL_EVENTS_PER_SEC` | `20`, `200` | Event caps per source address and for the sensor |
| `TELNET_CONN_RATE_PER_IP`, `TELNET_CONN_BURST_PER_IP` | `1`, `10` | New connections per second per source address, and the burst |
| `TELNET_SUMMARY_INTERVAL` | `60` | Seconds between summaries of unrecorded connections (at least 5) |

## Sensors added in M9

Seven sensors were added in M9: Redis, Docker, MySQL, MSSQL, ADB, SMB and SIP. Compose wires each one with its own Redis user, stream and network. It sets the public port, the connection caps and the memory limit. The table lists the variables you can set in `.env`. The sensor's own tunables (timeouts, budgets, rate limits) keep their defaults unless you add them with an override file. Each sensor page lists them, and the sensor README has the full table.

| Variable | Default | Sensor | Description |
| --- | --- | --- | --- |
| `REDIS_MAX_CONNECTIONS`, `REDIS_MAX_PER_IP` | `200`, `8` | Redis | Connection caps, in total and per source address |
| `DOCKER_MAX_CONNECTIONS`, `DOCKER_MAX_PER_IP` | `200`, `8` | Docker | Connection caps |
| `MYSQL_MAX_CONNECTIONS`, `MYSQL_MAX_PER_IP` | `200`, `8` | MySQL | Connection caps |
| `MYSQL_ACCOUNTS` | `root:,root:root,admin:admin,mysql:mysql` | MySQL | Comma-separated `user:password` pairs that log in. Weak on purpose. |
| `MSSQL_MAX_CONNECTIONS`, `MSSQL_MAX_PER_IP` | `200`, `8` | MSSQL | Connection caps |
| `ADB_MAX_CONNECTIONS`, `ADB_MAX_PER_IP` | `200`, `8` | ADB | Connection caps |
| `SMB_MAX_CONNECTIONS`, `SMB_MAX_PER_IP` | `200`, `10` | SMB | Connection caps |
| `SMB_HOSTNAME`, `SMB_DOMAIN` | empty (derived) | SMB | NetBIOS computer name (1 to 15 characters) and domain or workgroup. Empty means a realistic name derived from the sensor's secret. |
| `SMB_SMB1_MODE` | `steer` | SMB | `steer` switches SMB1 clients to SMB2 and records them. `reset` records and drops them. |
| `SIP_MAX_CONNECTIONS`, `SIP_MAX_PER_IP` | `200`, `8` | SIP | TCP connection caps |
| `SIP_OWN_IPS` | empty | SIP | Comma-separated addresses of this host. The sensor never answers them, so it cannot be made to talk to itself. |

```{note}
For ADB, Docker and SIP, the connection caps that Compose sets (200 and 8) are higher than the defaults in the sensor README. When you run the stack, the Compose values apply.
```

Each of these sensors needs its own Redis password in `.env` (`REDIS_SENSOR_<NAME>_PASSWORD`). See [Secrets](#secrets). Each host port must differ from the others and from `DASHBOARD_PORT`. The [port guard](deployment.md#port-guard) checks this.

## Sensors added in M20

The Synology sensor (M20) has its own Redis user, stream and network, like the others. Compose sets its public ports, its connection caps and its memory limit. The ports are in [Compose and host](#compose-and-host). The table lists the variables you can set in `.env`. The sensor README has the full list of tunables.

| Variable | Default | Description |
| --- | --- | --- |
| `SYNOLOGY_MAX_CONNECTIONS`, `SYNOLOGY_MAX_PER_IP` | `200`, `8` | Connection caps, in total and per source address |
| `SYNOLOGY_CONN_RATE`, `SYNOLOGY_CONN_BURST` | `5`, `20` | New connections per second per source address, and the burst |
| `SYNOLOGY_MEMORY_BUDGET_MB` | `80` | Memory for connections and request bodies in flight. Compose sets `SYNOLOGY_MEMORY_LIMIT_MB` to 160, the container limit. |
| `SYNOLOGY_EVENTS_PER_SEC`, `SYNOLOGY_GLOBAL_EVENTS_PER_SEC` | `20`, `200` | Event caps per source address and for the sensor |
| `SYNOLOGY_HTTP_REDIRECT` | `false` | Redirect the HTTP login page to HTTPS, as a DSM with forced HTTPS does. Off by default: DSM serves the UI on port 5000. |

The Redis password is `REDIS_SENSOR_SYNOLOGY_PASSWORD`. See [Secrets](#secrets). The [sensor page](sensors/synology.md) describes what the sensor emulates and records.

## Demo data

| Variable | Default | Source | Description |
| --- | --- | --- | --- |
| `DEMO_DAYS` | `30` | `.env` | Number of days the demo data covers |
| `DEMO_SESSIONS` | `3000` | `.env` | Number of sessions the backfill creates |
| `DEMO_SEED` | `42` | `.env` | Random seed. The same seed gives the same data. |

See [Demo data](demo-data.md) for the command-line options that override these.

## Retention and disk guard

| Variable | Default | Description |
| --- | --- | --- |
| `RETENTION_DAYS` | `90` | Days to keep raw events (7 to 3650). Aggregates are kept forever. Read by the `migrate` service, which re-applies the policies on every run. See [Data retention](retention.md). |
| `DB_MAX_SIZE_GB` | `10` | Size ceiling of the database (at least 1). Above 90% the disk guard drops the oldest raw chunks down to 80%. Above 95% ingest keeps only payload previews. Read by `migrate` and `ingest`. |

## Blocklists and feeds (M16)

Details in [Defend](defend.md). Ingest scores indicators into blocklists when `BLOCKLIST_ENABLED=true`; the API serves a token-protected feed when `FEEDS_ENABLED=true`. Both are off by default.

| Variable | Default | Description |
| --- | --- | --- |
| `BLOCKLIST_ENABLED` | `false` | Score addresses, hosts, URLs and hashes into the blocklists (ingest, every 15 minutes) |
| `BLOCKLIST_WINDOW_DAYS` | `30` | How many days of sessions and indicators to score (1 to 365) |
| `BLOCKLIST_MAX_ROWS` | `20000` | Most entries kept, best score first (100 to 1,000,000) |
| `CONTACTS_SHARED_ASNS` | Google, Cloudflare, Microsoft, Akamai, Fastly, Meta, Apple | Comma-separated AS numbers whose addresses are dropped from VirusTotal-sourced probable-C2 contacts (read from the local ASN database, no lookup). Replaces the default list. ThreatFox C2 entries are never filtered by network. Pass it to the `ingest` service in `docker-compose.yml` to use it. |
| `BLOCKLIST_NEVER` | empty | Addresses, networks and names never listed (also read: `AUTH_TRUSTED_PROXIES`, `API_ALLOWED_HOSTS`, `INDICATORS_IGNORE`) |
| `FEEDS_ENABLED` | `false` | Serve `/feeds/*` with bearer tokens made in Settings. The only part of the API outside the dashboard login |

## Campaigns and ATT&CK (M15)

Details in [Architecture](ARCHITECTURE.md#analysis-workers-m15-to-m19). Both switches are off by default. Compose passes these variables to `ingest` and `api`.

| Variable | Default | Description |
| --- | --- | --- |
| `ATTACK_ENABLED` | `false` | Sync the MITRE ATT&CK catalogue every hour and label sessions with techniques |
| `CAMPAIGNS_ENABLED` | `false` | Cluster finished sessions into campaigns, every 5 minutes |
| `CAMPAIGN_MIN_SOURCES` | `2` | Distinct sources a shared key needs before it makes a campaign (2 to 100) |
| `CAMPAIGN_LINK_CAP` | `500` | Most sessions linked to one campaign (10 to 10,000) |
| `CAMPAIGNS_MAX_ROWS` | `50000` | Row ceiling of the campaign tables. The oldest, least seen rows go first (1,000 to 50 million) |

## Script library and LLM explainer (M17)

Details in [Architecture](ARCHITECTURE.md#analysis-workers-m15-to-m19). The explainer is off by default. When it is on, it sends the **normalised** command text of one script (addresses, host names and URLs are replaced by placeholders) to the Anthropic API, and nothing else. Set the key with `ANTHROPIC_API_KEY`. The API also accepts it as provider `anthropic` (`PUT /api/v1/settings/providers/anthropic`), which overrides the variable, but the Settings page does not show a card for it yet.

| Variable | Default | Description |
| --- | --- | --- |
| `SCRIPTS_ENABLED` | `false` | Fingerprint sessions with two or more commands into the script library, every 5 minutes |
| `SCRIPTS_MAX_ROWS` | `100000` | Row ceiling of the script tables (1,000 to 50 million) |
| `LLM_ENABLED` | `false` | Allow the optional LLM explanation. An administrator still has to ask for each one ("Explain now"). |
| `LLM_DAILY_QUOTA` | `50` | Calls to the model per UTC day, 0 to 10,000. Kept in the database, so a restart does not reset it. |
| `LLM_MONTHLY_TOKEN_CAP` | `2000000` | Tokens per UTC month, 0 to 1 billion. Kept in the database. |
| `LLM_MODEL` | `claude-haiku-5-5` | Model name: lower-case letters, digits, `-`, `.` and `_`, at most 64 characters |
| `ANTHROPIC_API_KEY` | empty | API key for the explainer. Needed only when `LLM_ENABLED=true`. |

## Alerts and weekly report (M18)

Details in [Architecture](ARCHITECTURE.md#analysis-workers-m15-to-m19). Alerts and the report are off by default. Discord and Teams targets are not set here. You add them in the dashboard (Alerts), where they are checked and stored encrypted. Every rule starts off, and you switch on each one yourself.

| Variable | Default | Description |
| --- | --- | --- |
| `ALERTS_ENABLED` | `false` | Evaluate the alert rules and deliver messages |
| `REPORTS_ENABLED` | `false` | Build the weekly report after each Monday 06:00 (site time) |
| `ALERTS_DASHBOARD_URL` | empty | Public `https` address of the dashboard, with no query string. Alert messages link to the matching page. Without it, messages have no links. |
| `SITE_TIMEZONE` | `UTC` | IANA time zone (for example `Europe/Zurich`) that decides when the week starts for the report |
| `SMTP_HOST` | empty | SMTP server for e-mail alerts. E-mail needs `SMTP_HOST` and `SMTP_FROM`. |
| `SMTP_PORT` | `587`, or `465` with `SMTP_SECURITY=ssl` | SMTP port (1 to 65535) |
| `SMTP_SECURITY` | `starttls` | `starttls` (usually port 587) or `ssl` (usually port 465). Plain text is not offered. The certificate is always checked. |
| `SMTP_USER` | empty | Login name. Leave empty for a server that needs no login. |
| `SMTP_FROM` | empty | Sender address of the alerts (a plain e-mail address) |
| `SMTP_PASSWORD` | empty | Login password. It can also be set in Settings, under provider `smtp`. |

Discord and Teams webhooks need no variable. They are stored as channels in the database. The outbound hosts are listed in [Architecture](ARCHITECTURE.md#outbound-hosts).

## Today and search (M19)

Today, global search, the glossary and the research-scanner switch need no variable. Research scanners are labelled by the network that owns them, and they are left out of lists unless a page asks for them (`include_benign`). The list of scanners is in `ingest/rules/scanners.yaml`.

## In `.env.example` but not used yet

These names are in the template. The code does not read them, so setting them has no effect today.

| Variable | Default | Milestone | Description |
| --- | --- | --- | --- |
| `FETCH_PAYLOADS` | `false` | not scheduled | If `true`, ingest fetches files from captured download URLs into quarantine. Not implemented. |
| `PAYLOAD_MAX_BYTES` | `10485760` | not scheduled | Maximum size of one fetched payload |
| `PAYLOAD_TIMEOUT_SECONDS` | `20` | not scheduled | Timeout for one payload fetch |

## Data sources and attribution

SuckerPot shows data from third parties. Keep these credits visible if you publish a screenshot or a page that shows the data.

| Data | Used when | Credit |
| --- | --- | --- |
| DB-IP Lite (country, city, ASN) | `GEOIP_PROVIDER` is `auto` without MaxMind keys, or `dbip` | IP geolocation data by DB-IP.com, CC BY 4.0, https://db-ip.com |
| MaxMind GeoLite2 | `MAXMIND_ACCOUNT_ID` and `MAXMIND_LICENSE_KEY` are set | This product includes GeoLite2 data created by MaxMind (https://www.maxmind.com) |
| AbuseIPDB, GreyNoise Community | Their API keys are set | Scores are read only. Respect each service's terms and daily quota. |

The API returns the credit text in `GET /api/v1/settings/enrichment` (`geoip.attribution`), and the dashboard shows it. The `.mmdb` files are downloaded by ingest at run time and are never committed to the repository, because their licences do not allow redistribution.
