# Roadmap

Each milestone ends with the Definition of Done from `CLAUDE.md` §8: all services healthy, tests/lint/typecheck green, security review passed when relevant, docs updated, this file ticked, an entry in `PROGRESS.md`, merged to `main` and pushed.

## Blocked — needs owner

- [x] Docker Engine + compose plugin installed on the VM (needs `sudo`).
- [x] Push access to GitHub (fine-grained token scoped to this repo only, Contents: read/write).
- [ ] Enable secret scanning and push protection in the GitHub repo settings.
- [ ] Enable GitHub Pages (Source: GitHub Actions) and import the project on Read the Docs.
- [ ] Grow the VM disk (≥ 64 GB).
- [ ] Apply the host firewall (scripts/host/firewall.nft + suckerpot-firewall.service).

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

- [x] asyncssh on container port 2222, mapped from host 22.
- [x] Accepts logins on a configurable set of weak credentials; records every attempt.
- [x] Fake shell with a fake filesystem and common commands (`uname`, `cat /proc/cpuinfo`, `ls`, `cd`, `pwd`, `whoami`, `id`, `ps`, `w`, `free`, `history`, …).
- [x] `wget` / `curl` / `tftp` recorded as `download_attempt`, never executed or fetched.
- [x] Full session recording (timed I/O) for replay.
- [x] Realistic banner and hostname; connection caps, timeouts, field size limits.
- [x] Events land end to end in the DB.
- [x] Sensor networking (from the M1 security review): an `ingress` bridge with a fixed name, `enable_ip_masquerade: "false"`, `enable_icc: "false"`; `dns: ["127.0.0.1"]` on every sensor; ports published on explicit IPv4 (no docker-proxy on `[::]`); one internal network, one Redis stream and one ACL user per sensor, with ingest checking the `sensor` field against the stream.
- [x] Sensors drop and count events when Redis is unavailable, with bounded queues; per-IP event rate limit.
- [x] M1 review follow-ups (before go-live): stable ingest consumer name + trim never past the oldest pending entry; role passwords re-applied on every `migrate` run (rotation); dead-letter only on data errors; strict WebSocket Origin comparison; strip Unicode format characters in summaries; `connect-src 'self'`; NUL-safe SPA paths; per-row error isolation in the live poller; per-IP WebSocket cap; explicit per-table grants.
- [x] Ingest idempotency: no double counting when a batch is replayed after a crash between commit and ACK.

**Acceptance:** tests use a real SSH client against the container; no `subprocess`/`eval`/`exec` in sensor code; security review PASS.

> When M2 is done: remind the owner of the go-live checklist (see private environment notes).

## M3 — Design system + web shell

- [x] Design tokens (dark default + light), type scale, spacing, radius, sensor colours, severity scale.
- [x] Base components: Card, StatTile, TagBadge, EventRow, SessionStory, IPChip, CountryFlag, EmptyState, Skeleton.
- [x] App layout and navigation for all pages from §4.
- [x] Live event feed over WebSocket on demo data.
- [x] `just screenshots`: Playwright at 1440 and 390, dark and light.

**Acceptance:** `ui-designer` approves the screenshots; WCAG AA contrast; web lint, typecheck and tests green.

## M4 — Enrichment and tagging

- [x] GeoLite2 (needs a MaxMind licence key from the owner; degrade gracefully without it).
- [x] ASN / org.
- [x] AbuseIPDB and GreyNoise Community with a 24 h per-IP cache and enforced daily quotas.
- [x] YAML rules engine in `ingest/rules/*.yaml` with first rules (`recon`, `mirai`, `crypto-miner`, `malware-drop`, `php2shell`).

**Acceptance:** enrichment works with and without API keys; quotas cannot be exceeded (tested); rules have unit tests.

## M5 — Core pages

- [x] Overview: 4 KPIs, activity per sensor over time, top countries, insights.
- [x] Attacks: filterable session list, one-line story per row, filters in the URL.
- [x] Session detail: timeline, xterm.js terminal replay at real speed, IP panel.
- [x] Replay safety contract (from the M2 review): no Clipboard addon (OSC 52), a `linkHandler` that never opens links (OSC 8), `onData`/`onBinary` never wired to anything (query replies), no image/sixel addons, attacker strings rendered as text only.
- [x] Attackers: profiles by IP and ASN.

**Acceptance:** pages load in under 1 s on demo data; lists virtualized and paginated server-side; `ui-designer` approval.

## M6 — More sensors

- [x] Telnet with Mirai-style flows.
- [x] Web: fake Apache + PHP 8.3.x (mod_php, unpatched), fake WordPress `wp-login.php` / `xmlrpc.php`, fake phpMyAdmin; `php2shell` tag on upload-progress abuse.
- [x] RDP: low interaction, handshake + username capture.
- [x] Optional: catch-all listener recording the first bytes on other ports.

**Acceptance:** each sensor tested with a real client; events end to end; security review PASS.

## M7 — Showcase

- [x] Live page: 3D globe with attack arcs + live feed.
- [x] Trends page: top usernames/passwords/commands/URLs, tags over time, day × hour heatmap, "new this week".
- [x] Auto-written insights.
- [x] Malware page: download URLs, hashes and VirusTotal links when payload fetching is enabled.

**Acceptance:** `ui-designer` approval on all pages; insights are correct on demo data (tested).

## M8 — Hardening and v0.1.0

- [x] Dashboard auth: argon2 hash from `.env`, secure session cookie, CSRF, rate-limited login.
- [x] Rate limits on the API.
- [x] Retention job: raw events 90 days, aggregates forever.
- [x] DB volume backup script.
- [x] Full security review.
- [x] README with demo-data screenshots.
- [x] GitHub release `v0.1.0`.
- [ ] Remind the owner of the go-live checklist (dashboard firewall rule, `/logout`, token revocation, snapshot, then DMZ).

## M9 — Seven more sensors

- [ ] Redis (6379), Docker Engine API (2375), MySQL (3306), MSSQL (1433), Android ADB (5555), SMB (445), SIP (5060/udp + tcp).
- [ ] Contract lessons 16–18 on every sensor: wall-clock CPU budget per loop turn, pending output charged to the memory budget, per-IP event fairness.
- [ ] SIP: no UDP amplification (every reply ≤ its request, per-source and global reply caps).
- [ ] Ingest rules and tag severities for the new flags; per-IP brute-force tagging (`credential-stuffing`) and the `brute_force` insight.
- [ ] UI for 11 sensors (sensor families and colours); flat world map as the default Live view, with the 3D globe as an option.
- [ ] Compose integration, demo data for the new sensors, docs.

**Acceptance:** each sensor tested with real clients and nmap; security review PASS for each; all services healthy.

## M10 — RDP sensor, deeper

- [ ] CredSSP up to the NTLM challenge: record domain, user and workstation for every brute-force attempt, and check the NTLMv2 response against the configured weak passwords (nothing cracked).
- [ ] Optional "NLA disabled" mode: standard TLS security up to the Client Info PDU, recording the user name and the cleartext password the client sends.
- [ ] Client tool identification from JA3, CredSSP version and client OS version (nmap, hydra, ncrack, FreeRDP, mstsc, common brute-force bots), shown on the session page.
- [ ] Lessons 1–18 kept; security review PASS.

**Acceptance:** hydra/ncrack/FreeRDP against the sensor record user names, and weak passwords are recognised; security review PASS.

## M11 — Settings you can edit

- [ ] Enter, replace and remove enrichment API keys (AbuseIPDB, GreyNoise, MaxMind) from Settings, with no restart.
- [ ] Keys stored encrypted at rest (key from `.env`), write-only in the UI (only the last 4 characters shown), every change logged, CSRF and re-authentication required; `.env` values stay a supported fallback.
- [ ] Ingest picks up new keys within a minute; Settings shows where each key comes from (`.env` or Settings) and a "Test key" button that spends one quota call.

**Acceptance:** a key added in Settings turns the provider on without a restart; keys never leave the server in clear text; security review PASS.

## Later (not part of the loop)

- Discord alerts on malware drops.
- Public read-only page through Cloudflare Tunnel, IPs masked.
- LLM-backed SSH shell.
- RDP: a fake Windows logon screen that records keystrokes.
