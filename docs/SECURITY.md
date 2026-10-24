# Security

SuckerPot is a honeypot. Its job is to be attacked. This page covers what it does to stay safe, what it never does, and what you must do when you deploy it.

```{admonition} Build status
:class: note

**Built:** the isolation layer (networks, container hardening, Redis and database roles, the secrets policy), the API exposure controls, the host firewall template, and the SSH, RDP and Telnet sensors with their limits. The web sensor has the same kind of controls in its code but is not wired into Compose yet (it is under security review).

**Built:** dashboard login (M8). The security review passed.

**Planned:** retention (M8), payload fetching (not scheduled), and the terminal replay.

Keep the dashboard port private anyway. Login is one layer, not the only one.
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
| An attacker runs code through a fake shell or a fake web app | Sensors never execute attacker input |
| An attacker uses a compromised sensor to reach the host, the LAN or another sensor | Sensors have no outbound route, cannot talk to each other, and the host firewall drops new connections from their network |
| A terminal recording attacks the analyst's browser | The replay safety contract (see below) |
| An attacker escapes a container | Non-root users, dropped capabilities, read-only file systems, no new privileges |
| An attacker reaches the database or the internet from a sensor | Sensors reach Redis only. Redis accepts only `XADD` from the sensor user. |
| An attacker uses a stolen queue credential | Each service has its own Redis user with the fewest commands it needs. A sensor can write only to its own stream, and ingest checks the `sensor` field against the stream. |
| An attacker uses the API to change data | The API connects as a read-only database role |
| An attacker reaches the internet from the API | Masquerading is off and the API resolves no external names. This is not a full block: host or hypervisor egress filtering is also required. See below. |
| An attacker floods the sensors or fills the disk | Connection caps, timeouts, memory budgets and event rate limits in every sensor. Stream length cap and Redis memory limit. Size limits on events. Retention job (planned). |
| A sensor hangs and Docker does not restart it | A watchdog thread in each sensor exits the process when the event loop stalls |
| An attacker abuses the dashboard | Login with an argon2 hash, signed `HttpOnly` `Secure` `SameSite=Strict` cookies, CSRF protection, rate-limited login. Keep the port private as well. |
| The project is used to attack others | No offensive behaviour (see below) |
| Secrets leak into the public repo | Repo hygiene rules, `.gitignore`, secret scanning (see below) |

## Controls

### No execution of attacker input

These rules apply to every sensor.

- The fake shell is pure emulation. It does not call `subprocess`, `os.system`, `eval` or `exec`, and it does not write files outside its own data path. Tests read the sensor code to check this.
- Fake commands return canned or generated output from an in-memory fake file system. The file system has a size cap (1 MiB, 2000 nodes in the SSH sensor), and each connection gets its own copy.
- `wget`, `curl`, `tftp`, `ftpget` and `scp` are recorded as `download_attempt` events. They are never run and never fetched by the sensor.
- The web sensor analyses requests with byte searches over a bounded slice, with no regular expressions. URLs found in payloads are reported, never opened.
- The RDP sensor never completes CredSSP or NTLM, so it never receives a password-derived response. The only credential it records is the user name in the connection cookie.
- Sensors open no outbound connection at all.

### Downloads

Payload fetching is **not implemented**. The rules below are the contract for when it is.

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
| `ingress` (`sp-ingress`) | None. Masquerading off, inter-container communication off. | Every sensor | Attackers connect in. Sensors cannot reach each other or the internet. |
| `sensors-ssh`, `sensors-web`, ... | None (`internal: true`) | `redis` and one sensor each | A sensor reaches Redis and nothing else |
| `tools` | None (`internal: true`) | `redis`, the demo generator | The generator reaches Redis only |
| `backend` | None (`internal: true`) | `redis`, `db`, `migrate`, `ingest`, `api` | Storage and processing stay private |
| `egress` | Outbound | `ingest` only | GeoIP downloads and reputation lookups |
| `dashboard` (`sp-dashboard`) | Intended inbound only | `api` only | Masquerading is off. This does not block egress on its own. |

The design is explained in [Architecture](ARCHITECTURE.md#networks).

#### Egress from the API

The API cannot reach the internet through Docker's normal NAT, and it cannot resolve external names through Docker's resolver. These are two layers, and neither is a full firewall.

Egress must also be filtered outside the containers. Check it from the owner side before you go live:

- The [host firewall](deployment.md#host-firewall) is loaded. It drops new connections from `sp-ingress` and `sp-dashboard` to the host and through the host, and from every Docker network to the host's admin SSH port and the dashboard port.
- The API container cannot open a connection to an external address, by IP or by name.

#### The host firewall and the sensor network

A compromised sensor has no route to the internet (masquerading is off), but without a host rule it could still open connections to the host itself, for example to its admin SSH port, or to machines on your LAN through the host. The nftables table in `scripts/host/firewall.nft` blocks that, and it matches Docker networks by interface name, so it works whatever address pool Docker picks. It is installed with its own systemd unit, never with the stock `nftables` service, which would flush Docker's own rules.

#### Port guard

`scripts/check-ports.sh` runs before `just up`, `just config` and in CI. It refuses a layout where the dashboard sits on a classic service port, where two published ports collide, or where one equals the host's admin SSH port.

### Database access

- The owner role is used only by the database container and by the migration step.
- `suckerpot_ingest` can insert events and write sessions. It cannot read other tables, change the schema, or create roles.
- `suckerpot_api` can only read `events` and `sessions`.
- Both application roles have a statement timeout (30 s for ingest, 5 s for the API), so a slow query cannot hold the database.
- The role passwords come from `.env`. The `migrate` service sets them on every run as SCRAM-SHA-256 verifiers, so a rotation is one `docker compose run --rm migrate`, and the clear text never reaches the database logs.

### Secrets policy

- Every secret must be at least 24 characters long, and no two secrets may be equal. Redis checks all its passwords, and the migration step checks the three database passwords.
- The check refuses to start the service if the policy fails. The message names the variable, never its value.
- `SUCKERPOT_ALLOW_DEFAULT_SECRETS=1` turns the length and uniqueness checks off. It exists for CI and throwaway tests only. Never set it on a host that is reachable from the internet.

Generate each secret separately with `openssl rand -base64 32`.

### Abuse resistance

- Every event's `data` is capped at 16 KiB. A raw stream entry larger than 64 KiB is rejected before it is parsed. Sensors cut every attacker-controlled field before they build an event.
- Redis has a memory limit of 192 MB with `noeviction`. When the stream is full, writes fail. Events are never silently evicted.
- Each sensor stream is capped at about 10,000 entries (`EVENTS_MAXLEN`). Ingest trims each stream on its own after each acknowledged batch, and never past an entry that is still pending.
- Redis limits the size of a single command and the input buffer of each client.
- Ingest writes in bounded batches. A message that keeps failing is dead-lettered after 5 attempts.
- The live feed has a bounded queue per client, at most 50 clients in total and 5 per source address.
- Every sensor caps connections in total and per source address, sets a timeout on every read, bounds every buffer, keeps a memory budget, and rate-limits its own events with bounded in-process queues. See the page of each [sensor](sensors/index.md).
- Planned: the retention job (raw events kept for 90 days, aggregates kept).

### Watchdogs

Docker restarts a container that exits. It does **not** restart a container that is only *unhealthy*. A sensor stuck in a busy loop or a deadlock would sit there, silently dead, while the port stays open. Each sensor therefore runs a watchdog thread, independent of the event loop, that exits the process when the loop has not run for 10 seconds. `restart: unless-stopped` then brings the container back. Ingest does the opposite on purpose: when a database or Redis outage stops it, its heartbeat file goes stale and the health check fails, so the problem is visible.

### API exposure

- The interactive documentation (`/docs`, `/redoc`, `/openapi.json`) is off by default. Turn it on only with `API_ENABLE_DOCS=true`, while developing.
- Every response has security headers. Pages carry a Content Security Policy that blocks scripts from other origins.
- The WebSocket feed rejects browser requests from an origin that is not the same host or in `API_ALLOWED_ORIGINS`.
- Path and query inputs are checked: session IDs use the same pattern as the event schema, IP addresses are normalised, and cursors are bounded.
- The API has no CORS policy, so other sites cannot read its responses in a browser.
- Dashboard login guards every `/api/v1` path and the WebSocket (see below). Planned: rate limits on the rest of the API.

### Dashboard authentication

- One admin account. The password is stored as an argon2id hash in `.env` (`ADMIN_PASSWORD_HASH`), made with `python -m api.hashpw`. The password itself is never stored or logged.
- The session cookie is `__Host-sp_session`: `HttpOnly`, `Secure`, `SameSite=Strict`, no `Domain`. The `__Host-` prefix means the browser accepts it only over HTTPS for this exact host, so a sibling subdomain cannot plant it. (With `COOKIE_SECURE=false`, for local development only, the cookies have plain names and no `Secure` flag.)
- The session is a signed token with an expiry (12 hours by default). The signing key comes from `SESSION_SECRET` (at least 32 bytes), the password hash and a random value made at each API start. So changing the password, rotating the secret or restarting the API signs everybody out. Logout and a new login revoke the old session.
- CSRF protection by double submit: every unsafe request must echo the signed CSRF cookie in `X-CSRF-Token`, and the token is bound to the session. Login is checked against `Origin` or `Referer`: the full origin must be in `API_ALLOWED_ORIGINS` when that is set.
- Rate-limited login: 5 attempts per address (IPv6 per /64) and 30 overall per minute, a fixed delay on failure, and the hash is always verified, so timing does not reveal the account name. Argon2 runs one check at a time; with more than two waiting, logins get `429` at once, so a login flood cannot starve the API.
- Failed and successful logins are logged with the client address only. Nothing in the auth code logs a password, a hash or a cookie.
- A trusted-host check limits the `Host` header to `API_ALLOWED_HOSTS`, or the hosts of `API_ALLOWED_ORIGINS`, plus localhost. With both empty it allows any host and logs a warning, so set one in production.
- Client addresses for the login limit come from the connection. `CF-Connecting-IP` and `X-Forwarded-For` are read only for connections from `AUTH_TRUSTED_PROXIES`.
- A middleware guards every `/api/v1` path except `/api/v1/auth/*`. The live WebSocket checks the cookie in its handshake and rechecks it every 5 seconds.
- The API refuses to start with a missing or weak hash or secret.
- `API_AUTH_DISABLED=true` works only together with `SUCKERPOT_DEMO=1`, and only the test overlay `docker-compose.ci.yml` (`just up-test`) sets both. Never use it in production.
- The state (revocations, login counters, the per-boot key) is in memory, so the API must run as **one** worker.
- The dashboard is designed to sit behind an access layer such as Cloudflare Access as a second layer, but it must be safe without one.

### No offensive behaviour

SuckerPot does not:

- scan other hosts, or respond to scans with scans;
- hack back or run any active countermeasure;
- report IP addresses to AbuseIPDB or any other service without the owner's explicit approval.

### Realistic fingerprints

Fake services must look real to an attacker. Banners and versions are plausible and current. Hostnames are ordinary. The words "honeypot" and "suckerpot" never appear anywhere a client could see. This applies to the sensors (planned).

## Terminal replay safety contract

SSH and Telnet sessions are recorded as the bytes the attacker typed and the bytes sent back. Those bytes are attacker-controlled, and a terminal emulator interprets them. The replay player (xterm.js, planned for M5) must follow these rules:

1. **No clipboard addon.** A terminal can write to the clipboard with the OSC 52 sequence. Do not load the clipboard addon.
2. **No link opening.** Terminal links (OSC 8) must never open anything. Use a `linkHandler` that does nothing.
3. **Never wire input back.** Terminals answer some sequences (cursor position, device attributes) by sending data to the program. In a replay, `onData` and `onBinary` must not be connected to anything, so a recording cannot talk to the server or to the page.
4. **No image or sixel addons.**
5. **Text only.** Attacker strings (commands, URLs, user agents, banners) are rendered as text, never as HTML.
6. **Bounded replay.** The recording is already capped (12 KiB of frames in the SSH event), and the player must also cap the work it does per frame.

The player is a read-only display. It must not be possible for a recording to make the browser do anything beyond drawing text.

## How changes are reviewed

Every change that touches a sensor, networking, authentication, the Compose file or a Dockerfile gets a separate security review before it is merged. The review is read-only and checks the change against the rules on this page and the repo hygiene rules below. The reviewer reports findings and does not edit code. A finding is fixed and re-checked before the change is merged.

What the reviews have found so far, and what changed because of it:

| Review | Finding | Decision |
| --- | --- | --- |
| Foundations (M1), first pass | Unbounded stream, weak egress control, poison messages that block the queue, default credentials. The first pass failed. | A capped stream, the secrets policy, dead-lettering of bad entries and the egress controls above. The second pass passed. |
| Foundations (M1), follow-ups | Sensors would share a network, a Redis user and a stream. Containers could reach the host. | A fixed-name `ingress` network with no masquerade, one internal network, one Redis user and one stream per sensor, the sensor/stream check in ingest, and the host firewall table. |
| Foundations (M1), follow-ups | Ingest trimming and role passwords | A stable consumer name, trimming that never passes an entry still pending, and role passwords re-applied on every `migrate` run so they can be rotated. Idempotent replay after a crash is still open on the [roadmap](ROADMAP.md). |
| SSH sensor (M2) | A terminal replay could be attacked through escape sequences | The replay safety contract above |

Decisions that follow from these reviews:

- **No execution, no fetching, no outbound traffic from a sensor.** Everything a sensor knows about an attack comes from bytes it received.
- **Every allocation has a bound.** Buffers, queues, event sizes, file system sizes, line lengths and counters all have a fixed maximum, and the maximum is tested.
- **Per-connection and global limits.** One source cannot use more than its share, and all sources together cannot use more than the sensor's budget.
- **Drop, never block.** When a queue or Redis is full, the sensor drops the event and counts it. It never waits inside a connection handler.
- **Fail visibly.** A service that cannot do its job stops its heartbeat or exits, so the problem shows up in `docker compose ps` instead of in missing data.
- **Least privilege everywhere.** One Redis user per sensor, one database role per service, one network per job.

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
