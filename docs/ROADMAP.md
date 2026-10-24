# Roadmap

Each milestone ends with the Definition of Done from `CLAUDE.md` §8: all services healthy, tests/lint/typecheck green, security review passed when relevant, docs updated, this file ticked, an entry in `PROGRESS.md`, merged to `main` and pushed.

## Blocked — needs owner

- [x] Docker Engine + compose plugin installed on the VM (needs `sudo`).
- [x] Push access to GitHub (fine-grained token scoped to this repo only, Contents: read/write).
- [ ] Enable secret scanning and push protection in the GitHub repo settings.

## Host / owner actions before go-live (from the M1 security review)

- [ ] Host firewall (nftables, applied by the owner): drop NEW connections from Docker bridge ranges to the host's admin SSH port and the dashboard port.
- [ ] Block NEW outbound connections from the `dashboard` and `ingress` bridges (DOCKER-USER chain), and/or enable the hypervisor IP filter on the VM NIC.
- [ ] Admin SSH: key-only, password login disabled.
- [ ] Optional: `"userland-proxy": false` in the Docker daemon config.
- [ ] Dashboard port filtered upstream so only the reverse tunnel can reach it.

## M0 — Bootstrap

- [x] `.gitignore` created first; private context file verified ignored with `git check-ignore`.
- [x] `CLAUDE.md` and project subagents in `.claude/agents/`.
- [x] `docs/ROADMAP.md`, `docs/PROGRESS.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, skeleton `README.md`, MIT `LICENSE`, `.env.example` (placeholders only).
- [x] gitleaks pre-commit hook; GitHub Actions workflow running gitleaks, lint and tests.
- [x] Staged diff reviewed, `chore: bootstrap repository` committed and pushed.

**Acceptance:** CI is green on `main`; `gitleaks detect` finds nothing; no private data in the tree.

## M1 — Foundations

- [x] `docker-compose.yml` with `redis`, `db` (PostgreSQL + TimescaleDB), `ingest` and `api` skeletons.
- [x] Networks from §3: `sensors`, `backend` (`internal: true`), `egress`, `dashboard`.
- [x] Hardening from §5 on every service: non-root, `read_only` + tmpfs, `cap_drop: [ALL]`, `no-new-privileges`, memory/CPU/pids limits, healthchecks.
- [x] Redis with password and a sensor ACL user limited to `XADD` on the events stream.
- [x] Shared Event schema (Pydantic) in `sensors/common`, with tests.
- [x] DB migrations (Alembic): events hypertable, sessions table.
- [x] Ingest skeleton: consumes the stream, validates events, writes to the DB.
- [x] API skeleton: `/healthz`, a paginated sessions/events endpoint.
- [x] Demo data generator (`just demo`): realistic sessions across all 4 sensors over the last 30 days, documentation IP ranges only in examples.
- [x] `justfile` with `up`, `down`, `test`, `lint`, `demo`.
- [x] CI runs Python lint, typecheck and tests.

**Acceptance:** `docker compose up -d --build` → all services healthy; `just demo` fills the DB and the API returns sessions; dashboard port only on a non-sensor port; security review PASS; CI green.

## M2 — SSH sensor

- [ ] asyncssh on container port 2222, mapped from host 22.
- [ ] Accepts logins on a configurable set of weak credentials; records every attempt.
- [ ] Fake shell with a fake filesystem and common commands (`uname`, `cat /proc/cpuinfo`, `ls`, `cd`, `pwd`, `whoami`, `id`, `ps`, `w`, `free`, `history`, …).
- [ ] `wget` / `curl` / `tftp` recorded as `download_attempt`, never executed or fetched.
- [ ] Full session recording (timed I/O) for replay.
- [ ] Realistic banner and hostname; connection caps, timeouts, field size limits.
- [ ] Events land end to end in the DB.
- [ ] Sensor networking (from the M1 security review): an `ingress` bridge with a fixed name, `enable_ip_masquerade: "false"`, `enable_icc: "false"`; `dns: ["127.0.0.1"]` on every sensor; ports published on explicit IPv4 (no docker-proxy on `[::]`); one internal network, one Redis stream and one ACL user per sensor, with ingest checking the `sensor` field against the stream.
- [ ] Sensors drop and count events when Redis is unavailable, with bounded queues; per-IP event rate limit.
- [ ] M1 review follow-ups (before go-live): stable ingest consumer name + trim never past the oldest pending entry; role passwords re-applied on every `migrate` run (rotation); dead-letter only on data errors; strict WebSocket Origin comparison; strip Unicode format characters in summaries; `connect-src 'self'`; NUL-safe SPA paths; per-row error isolation in the live poller; per-IP WebSocket cap; explicit per-table grants.
- [ ] Ingest idempotency: no double counting when a batch is replayed after a crash between commit and ACK.

**Acceptance:** tests use a real SSH client against the container; no `subprocess`/`eval`/`exec` in sensor code; security review PASS.

> When M2 is done: remind the owner of the go-live checklist (see private environment notes).

## M3 — Design system + web shell

- [ ] Design tokens (dark default + light), type scale, spacing, radius, sensor colours, severity scale.
- [ ] Base components: Card, StatTile, TagBadge, EventRow, SessionStory, IPChip, CountryFlag, EmptyState, Skeleton.
- [ ] App layout and navigation for all pages from §4.
- [ ] Live event feed over WebSocket on demo data.
- [ ] `just screenshots`: Playwright at 1440 and 390, dark and light.

**Acceptance:** `ui-designer` approves the screenshots; WCAG AA contrast; web lint, typecheck and tests green.

## M4 — Enrichment and tagging

- [ ] GeoLite2 (needs a MaxMind licence key from the owner; degrade gracefully without it).
- [ ] ASN / org.
- [ ] AbuseIPDB and GreyNoise Community with a 24 h per-IP cache and enforced daily quotas.
- [ ] YAML rules engine in `ingest/rules/*.yaml` with first rules (`recon`, `mirai`, `crypto-miner`, `malware-drop`, `php2shell`).

**Acceptance:** enrichment works with and without API keys; quotas cannot be exceeded (tested); rules have unit tests.

## M5 — Core pages

- [ ] Overview: 4 KPIs, activity per sensor over time, top countries, insights.
- [ ] Attacks: filterable session list, one-line story per row, filters in the URL.
- [ ] Session detail: timeline, xterm.js terminal replay at real speed, IP panel.
- [ ] Attackers: profiles by IP and ASN.

**Acceptance:** pages load in under 1 s on demo data; lists virtualized and paginated server-side; `ui-designer` approval.

## M6 — More sensors

- [ ] Telnet with Mirai-style flows.
- [ ] Web: fake Apache + PHP 8.3.x (mod_php, unpatched), fake WordPress `wp-login.php` / `xmlrpc.php`, fake phpMyAdmin; `php2shell` tag on upload-progress abuse.
- [ ] RDP: low interaction, handshake + username capture.
- [ ] Optional: catch-all listener recording the first bytes on other ports.

**Acceptance:** each sensor tested with a real client; events end to end; security review PASS.

## M7 — Showcase

- [ ] Live page: 3D globe with attack arcs + live feed.
- [ ] Trends page: top usernames/passwords/commands/URLs, tags over time, day × hour heatmap, "new this week".
- [ ] Auto-written insights.
- [ ] Malware page: download URLs, hashes and VirusTotal links when payload fetching is enabled.

**Acceptance:** `ui-designer` approval on all pages; insights are correct on demo data (tested).

## M8 — Hardening and v0.1.0

- [ ] Dashboard auth: argon2 hash from `.env`, secure session cookie, CSRF, rate-limited login.
- [ ] Rate limits on the API.
- [ ] Retention job: raw events 90 days, aggregates forever.
- [ ] DB volume backup script.
- [ ] Full security review.
- [ ] README with demo-data screenshots.
- [ ] GitHub release `v0.1.0`.
- [ ] Remind the owner of the go-live checklist (dashboard firewall rule, `/logout`, token revocation, snapshot, then DMZ).

## Later (not part of the loop)

- Discord alerts on malware drops.
- Public read-only page through Cloudflare Tunnel, IPs masked.
- LLM-backed SSH shell.
- More sensors: Redis, MySQL, SMB, SIP.
