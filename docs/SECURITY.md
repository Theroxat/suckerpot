# Security

SuckerPot is a honeypot. Its job is to be attacked. This page covers what it does to stay safe, what it never does, and what you must do when you deploy it.

```{admonition} Build status
:class: note

Milestone M1 builds the isolation layer: networks, container hardening, the Redis and database roles, the secrets policy, and the API exposure controls. The controls marked **planned** are not built yet. In M1 the API has **no login**, so the dashboard port must stay private.
```

## Deployment warning

- **The host is meant to be attacked.** Deploy SuckerPot only on an isolated machine or VM that you are ready to lose. Treat it as already compromised.
- **Never keep credentials that matter on the host.** No cloud keys, no SSH keys for other systems, no password manager exports, no personal files. Assume that anything on the host can be read by an attacker who breaks out of a container.
- **Keep the dashboard port private.** The default bind address is `127.0.0.1`, so the port is reachable only from the host. To reach it from another machine, use a reverse tunnel such as cloudflared, and filter the port upstream. See [Deployment](deployment.md).
- **Published Docker ports bypass ordinary host firewall rules.** Docker writes its own rules for published ports. A rule in the host `INPUT` chain does not stop traffic to a published port. Filter these ports upstream (router or hypervisor firewall) or in the `DOCKER-USER` chain.
- **Keep the admin SSH port separate.** The host's own SSH service must run on a port that no sensor or dashboard uses, and it must not be exposed to the internet.

## Threat model

| Threat | Control |
| --- | --- |
| An attacker runs code through a fake shell or a fake web app | Sensors never execute attacker input (planned, M2) |
| An attacker escapes a container | Non-root users, dropped capabilities, read-only file systems, no new privileges |
| An attacker reaches the database or the internet from a sensor | Sensors reach Redis only. Redis accepts only `XADD` from the sensor user. |
| An attacker uses a stolen queue credential | Each service has its own Redis user with the fewest commands it needs |
| An attacker uses the API to change data | The API connects as a read-only database role |
| An attacker reaches the internet from the API | Masquerading is off and the API resolves no external names. This is not a full block: host or hypervisor egress filtering is also required. See below. |
| An attacker floods the sensors or fills the disk | Stream length cap, Redis memory limit, size limits on events, connection caps (planned for the sensors), retention job (planned) |
| An attacker abuses the dashboard | Login, CSRF protection, rate-limited login, secure cookies (planned, M8). Until then, keep the port private. |
| The project is used to attack others | No offensive behaviour (see below) |
| Secrets leak into the public repo | Repo hygiene rules, `.gitignore`, secret scanning (see below) |

## Controls

### No execution of attacker input

These rules apply to the sensors, which are planned for M2 and later.

- The fake shell is pure emulation. It does not call `subprocess`, `os.system`, `eval` or `exec`, and it does not write files outside its own data path.
- Fake commands return canned or generated output from a fake file system.
- `wget`, `curl` and `tftp` are recorded as `download_attempt` events. They are never run and never fetched by the sensor.

### Downloads

These rules are planned. Payload fetching is not implemented.

- By default, only the download URL is recorded.
- Payload fetching is disabled by default (`FETCH_PAYLOADS=false`). When it is enabled, ingest fetches the file, not the sensors. The fetch has a size cap and a timeout.
- A fetched payload is stored in a quarantine volume under its sha256 name, with mode `0400`. It is never executed and never committed to the repo.

### Containers

These rules apply to every service in `docker-compose.yml`.

- Every service runs as a non-root user. Application services use UID and GID 10001. Redis and PostgreSQL use their image users.
- `read_only: true`, with `tmpfs` mounts where a service needs to write.
- `cap_drop: [ALL]`.
- `security_opt: [no-new-privileges:true]`.
- Memory, CPU and process limits on every service.
- A health check on every service.
- Sensors listen on high ports inside their containers. Compose maps the standard host ports to them, so no service needs extra capabilities to bind low ports.

### Network segmentation

| Network | Internet access | Used by | Notes |
| --- | --- | --- | --- |
| `sensors` | None (`internal: true`) | `redis`, the demo generator, sensors (planned) | Sensors reach Redis and nothing else |
| `backend` | None (`internal: true`) | `redis`, `db`, `migrate`, `ingest`, `api` | Storage and processing stay private |
| `egress` | Outbound | `ingest` only | Enrichment calls (planned, M4) |
| `dashboard` | Intended inbound only | `api` only | Masquerading is off. This does not block egress on its own. |

The planned M2 design for sensor traffic is described in [Architecture](ARCHITECTURE.md#planned-sensor-networking-m2).

#### Egress from the API

The API cannot reach the internet through Docker's normal NAT, and it cannot resolve external names through Docker's resolver. These are two layers, and neither is a full firewall.

Egress must also be filtered outside the containers. Check it from the owner side before you go live:

- The host or hypervisor firewall drops traffic from the dashboard network's address range to anything outside the host.
- The API container cannot open a connection to an external address, by IP or by name.

### Database access

- The owner role is used only by the database container and by the migration step.
- `suckerpot_ingest` can insert events and write sessions. It cannot read other tables, change the schema, or create roles.
- `suckerpot_api` can only read `events` and `sessions`.
- Both application roles have a statement timeout (30 s for ingest, 5 s for the API), so a slow query cannot hold the database.
- The role passwords come from `.env`. Migration 0002 sets them, and they are never written to files or logs.

### Secrets policy

- Every secret must be at least 24 characters long, and no two secrets may be equal. Redis checks its four passwords, and the migration step checks the three database passwords.
- The check refuses to start the service if the policy fails. The message names the variable, never its value.
- `SUCKERPOT_ALLOW_DEFAULT_SECRETS=1` turns the length and uniqueness checks off. It exists for CI and throwaway tests only. Never set it on a host that is reachable from the internet.

Generate each secret separately with `openssl rand -base64 32`.

### Abuse resistance

- Every event's `data` is capped at 16 KiB. A raw stream entry larger than 64 KiB is rejected before it is parsed.
- Redis has a memory limit of 192 MB with `noeviction`. When the stream is full, writes fail. Events are never silently evicted.
- The stream is capped at about 10,000 entries (`EVENTS_MAXLEN`). Ingest trims it after each acknowledged batch.
- Redis limits the size of a single command and the input buffer of each client.
- Ingest writes in bounded batches. A message that keeps failing is dead-lettered after 5 attempts.
- The live feed has a bounded queue per client, and at most 50 clients.
- Planned: connection caps per sensor and per source IP, timeouts on every network operation, and the retention job (raw events kept for 90 days, aggregates kept).

### API exposure

- The interactive documentation (`/docs`, `/redoc`, `/openapi.json`) is off by default. Turn it on only with `API_ENABLE_DOCS=true`, while developing.
- Every response has security headers. Pages carry a Content Security Policy that blocks scripts from other origins.
- The WebSocket feed rejects browser requests from an origin that is not the same host or in `API_ALLOWED_ORIGINS`.
- Path and query inputs are checked: session IDs use the same pattern as the event schema, IP addresses are normalised, and cursors are bounded.
- The API has no CORS policy, so other sites cannot read its responses in a browser.
- Planned (M8): dashboard login, rate limits on the API.

### Dashboard authentication

These controls are planned for M8. Until then, the dashboard has no login, so keep the port private.

- One admin account. The password is stored as an argon2 hash in `.env`.
- The session cookie is `httpOnly`, `Secure` and `SameSite`.
- CSRF protection on every state-changing request.
- Rate-limited login.
- The dashboard is designed to sit behind an access layer such as Cloudflare Access, but it must be safe without one.

### No offensive behaviour

SuckerPot does not:

- scan other hosts, or respond to scans with scans;
- hack back or run any active countermeasure;
- report IP addresses to AbuseIPDB or any other service without the owner's explicit approval.

### Realistic fingerprints

Fake services must look real to an attacker. Banners and versions are plausible and current. Hostnames are ordinary. The words "honeypot" and "suckerpot" never appear anywhere a client could see. This applies to the sensors (planned).

## Repo hygiene

This repository is public. Every commit is published, and it stays in the git history forever.

### Never committed

- `.env`, API keys, tokens, passwords and password hashes;
- private environment notes;
- private IP addresses, host names, admin ports, public IP addresses and network layouts;
- captured data: attacker IPs, credentials, sessions, payloads and database dumps;
- GeoLite2 `.mmdb` files (their licence does not allow redistribution);
- SSH host keys generated by the sensors;
- screenshots that show real attack data.

### Safeguards

| Safeguard | What it does |
| --- | --- |
| `.gitignore` | Keeps local secrets, captured data and generated files out of git |
| `.env.example` | Contains placeholders only. Copy it to `.env` and fill in your own values. |
| gitleaks pre-commit hook | Blocks commits that contain secrets. Install it with `scripts/install-hooks.sh`. |
| gitleaks in CI | Scans the full history on every push and pull request |
| Manual review | The staged diff is checked by hand before each commit |
| Documentation IP ranges | Examples use `192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24` only |

### If something sensitive is pushed

1. Stop pushing.
2. Rotate the secret immediately.
3. Remove the data from the git history. Deleting it in a new commit is not enough, because the old commit stays public.

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it privately through GitHub's private vulnerability reporting. Go to the **Security** tab of the repository and choose **Report a vulnerability**. Include:

- what you found and where;
- steps to reproduce it;
- the impact you expect.

Do not include real credentials, real attacker data or real IP addresses of your own systems in the report.
