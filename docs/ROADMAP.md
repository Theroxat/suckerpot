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

- [x] Redis (6379), Docker Engine API (2375), MySQL (3306), MSSQL (1433), Android ADB (5555), SMB (445), SIP (5060/udp + tcp).
- [x] Contract lessons 16–18 on every sensor: wall-clock CPU budget per loop turn, pending output charged to the memory budget, per-IP event fairness.
- [x] SIP: no UDP amplification (every reply ≤ its request, per-source and global reply caps).
- [x] Ingest rules and tag severities for the new flags; per-IP brute-force tagging (`credential-stuffing`) and the `brute_force` insight.
- [x] UI for 11 sensors (sensor families and colours); flat world map as the default Live view, with the 3D globe as an option.
- [x] Compose integration, demo data for the new sensors, docs.

**Acceptance:** each sensor tested with real clients and nmap; security review PASS for each; all services healthy.

## M10 — RDP sensor, deeper

- [x] CredSSP up to the NTLM challenge: record domain, user and workstation for every brute-force attempt, and check the NTLMv2 response against the configured weak passwords (nothing cracked).
- [x] Optional "NLA disabled" mode: standard TLS security up to the Client Info PDU, recording the user name and the cleartext password the client sends.
- [x] Client tool identification from JA3, CredSSP version and client OS version (nmap, hydra, ncrack, FreeRDP, mstsc, common brute-force bots), shown on the session page.
- [x] Lessons 1–18 kept; security review PASS.

**Acceptance:** hydra/ncrack/FreeRDP against the sensor record user names, and weak passwords are recognised; security review PASS.

## M11 — Settings you can edit

- [x] Enter, replace and remove enrichment API keys (AbuseIPDB, GreyNoise, MaxMind) from Settings, with no restart.
- [x] Keys stored encrypted at rest (key from `.env`), write-only in the UI (only the last 4 characters shown), every change logged, CSRF and re-authentication required; `.env` values stay a supported fallback.
- [x] Ingest picks up new keys within a minute; Settings shows where each key comes from (`.env` or Settings) and a "Test key" button that spends one quota call.

**Acceptance:** a key added in Settings turns the provider on without a restart; keys never leave the server in clear text; security review PASS.

## M12 — CVE watch

- [x] Ingest pulls new CVEs daily (CISA KEV, NVD, GitHub advisories) and ranks them by relevance to the services SuckerPot emulates.
- [x] A CVE page: recent relevant CVEs, and whether matching activity was already seen in our traffic.
- [ ] Trap proposals reviewed with the owner before anything is built. (The page only copies a trap-sheet template; the review itself is a conversation with the owner.)

**Acceptance:** the feed updates daily within its quotas; nothing is deployed automatically.

## M13 — Indicators and threat intelligence

- [x] Extract indicators (URLs, domains, IPs, hashes) from recorded events.
- [x] Enrich them with public threat-intelligence sources (quotas, caching, keys from Settings).
- [x] An Infrastructure view linking sources, indicators and malware families; export on demand.

**Acceptance:** passive only — nothing is executed, contacted beyond the intel APIs, or reported without the owner.

## M14 — Users and roles

- [x] Database users (`admin` and `viewer`) next to the `.env` owner account, which keeps working unchanged as the break-glass login.
- [x] Server-side roles with a default-deny check on every state-changing route, and a test that walks the route table.
- [x] Session versions: password change, reset, disable, role change, deletion and "Sign out everywhere" end the user's sessions at once.
- [x] Login hardening: per-username limit, lockout per source address with a high account-wide ceiling that spares known sources (admin can unlock), the owner never rate-limited by name, same argon2 work and same message for unknown names.
- [x] Password policy (12 to 256 characters, common-password list, not the username) and one-time temporary passwords with a forced change at first sign-in.
- [x] Settings > Users and Audit log for admins; a read-only shell for viewers; first-login "Set your password" screen; account menu with "Change password" and "Sign out".
- [x] Every admin action re-authenticates and writes an audit entry (kept one year).
- [x] Security and UI reviews.
- [x] Optional TOTP two-factor sign-in (future).

**Acceptance:** a colleague can be given read-only access and cannot change anything, by any request; disabling or resetting them ends their sessions at once; security review PASS.

## M15 — Campaigns and ATT&CK

- [x] One command normaliser (addresses, URLs, numbers and long blobs replaced by placeholders) shared by campaign clustering and the script library.
- [x] MITRE ATT&CK catalogue in `ingest/rules/attack/techniques.yaml`, synced hourly, and rules that tag each session with the techniques it used.
- [x] Campaign clustering of finished sessions by shared keys: script, exploit, credential list, payload host, file hash and malware family.
- [x] A campaign needs at least `CAMPAIGN_MIN_SOURCES` distinct sources, and one campaign links at most `CAMPAIGN_LINK_CAP` sessions.
- [x] Research scanners are never clustered.
- [x] Campaign pages with a plain-English story, and a Techniques page with a heatmap of ATT&CK techniques per day.
- [x] Campaign and ATT&CK endpoints in the API, open to both roles.

**Acceptance:** campaigns form from the demo data, a single source never makes one, and security review PASS after the fixes.

## M16 — Defend

- [x] Scored blocklists for addresses, host names, download URLs and file hashes, rebuilt every 15 minutes, with a plain-English reason for every point.
- [x] Scores count distinct source networks, so one attacker cannot fill a list by repeating an indicator.
- [x] A never-list: public resolvers, large SaaS and CDN domains, shared hosting names, reserved addresses, the owner's own addresses and `BLOCKLIST_NEVER`.
- [x] Overrides (always allow, always block) with a note, an optional expiry and an audit entry.
- [x] Exports for OPNsense and pfSense aliases, plain text and CSV; CSV cells are safe to open in a spreadsheet.
- [x] Opt-in token feed under `/feeds` (`FEEDS_ENABLED`): hashed tokens with limits, expiry and revocation.
- [x] Sigma and Suricata rules written from recorded behaviour, each marked "review before deploying".
- [x] "Your exposure" page: your own service inventory next to what the honeypot saw for the same kind of service.

**Acceptance:** the feed is off by default, blocklists stay off until enabled, and security review PASS after the fixes.

## M17 — Script library

- [x] Sessions that ran two or more commands are fingerprinted from their normalised command list. One row stands for one distinct script.
- [x] Script counters only grow, so they survive the deletion of old sessions.
- [x] Plain-English explanations from a declarative annotation base in `ingest/rules/annotations/*.yaml`, matched without regular expressions.
- [x] Optional LLM explainer (`LLM_ENABLED`, off by default) with a daily call quota and a monthly token cap. It sends only the normalised script text, and its answer is stored as text labelled "AI-generated, may be wrong".
- [x] Scripts list and script detail pages. Only an administrator can ask for an explanation ("Explain now").

**Acceptance:** with `LLM_ENABLED=false` nothing leaves the host, the explainer never executes or fetches what it reads, and security review PASS after the fixes.

## M18 — Alerts and weekly report

- [x] Alert channels: Discord and Microsoft Teams webhooks, and e-mail over TLS (STARTTLS or SMTPS). Targets are validated and encrypted at rest.
- [x] Alert rules for new campaigns, new download hosts, malware drops and watched CVEs. Every rule is off until it is switched on, and a rule never replays history.
- [x] A delivery outbox with rate limits and up to three attempts, a constant error code per failure, and a "send a test message" button.
- [x] Weekly report, built once a week after Monday 06:00 in `SITE_TIMEZONE`, with a one-page printable view and an optional alert.
- [x] Alerts never use research-scanner sessions or documentation addresses.

**Acceptance:** nothing is sent until a channel and a rule are both enabled, each channel type accepts a test message, and security review PASS after the fixes.

## M19 — Today, search and research scanners

- [x] Today home page: what changed in the last 24 hours, in plain English.
- [x] Global search for IP addresses, hashes, domains, CVEs and campaigns, from one box in the header.
- [x] Glossary of the terms used in the dashboard.
- [x] Known research scanners (`ingest/rules/scanners.yaml`) are labelled benign by the network that owns them, and left out of lists by default. The HTTP user agent never decides it.
- [x] Benign is an allowlist of harmless behaviour (connect, probe, plain GET, HEAD or OPTIONS). Any login, command, download, exploit or POST makes a session non-benign for good.
- [x] `include_benign` switch on the lists, so the scanners can be shown on request.

**Acceptance:** a research scanner never raises an alert, a session that does more than probe is never labelled benign, and security review PASS after the fixes.

## M20 — Synology NAS sensor and CVE watch fixes

- [x] Synology NAS sensor (`synology`): a DSM 7.2.1-69057 Update 11 look-alike on HTTP 5000 and HTTPS 5001, with the login page, the Web API (`SYNO.API.Info`, `SYNO.API.Auth` and the other APIs), logins always refused with DSM error codes, and every credential recorded.
- [x] Flags and tags for the C3RB3R campaign (CVE-2026-13639 and CVE-2026-13684): `synology-dsm`, `synology-exploit` and `c3rb3r`, mapped to ATT&CK T1190 and T1486. Downloads from DSM requests are recorded as `download_attempt`.
- [x] Compose: `sensor-synology`, network `sensors-synology`, volume `synology-sensor-data`, Redis user `sensor-synology` (`XADD` on `events:synology` only), port guard for 5000 and 5001, and the `.env.example` entries.
- [x] Migration `0017` adds `synology` to the inventory service list. The sensor belongs to the Web and APIs colour family, so the UI gets no new hue.
- [x] CVE watch: the NVD window is 60 days (was 30), read in one-day chunks, oldest first, with a page budget. A busy feed no longer loses CVEs silently at 10,000 results.
- [x] CVE watch: a run that stops early (quota or page budget) resumes from the last complete chunk. GitHub advisories are read in 7-day chunks.
- [x] CVE watch: a one-time start-up rewind refills a shallow history. Watched CVEs that are missing from the table are fetched by id from the NVD (at most 10 per run, once per id per 24 h).
- [x] `just test-integration` uses `docker-compose.it.yml`, so the throwaway project fits in Docker's default address pools next to the live stack.
- [x] Security review of the Synology sensor and of the Compose, port guard and migration changes: passed after fixes (TLS handshake-slot and handshake-rate exhaustion closed with per-IP caps and a full-ClientHello check, nginx error pages and asset sizes made realistic).
- [x] Full stack check: `docker compose up -d --build` with every service healthy, and the Synology ports reached from outside a test network.

**Acceptance:** a DSM client gets the DSM answers, every login attempt is recorded and refused, the forged-session and SCGI request shapes are tagged, the CVE watch fills 60 days without a silent gap, and the security review passes.

## Later (not part of the loop)

- Per-/24 or per-ASN daily cap on new campaigns, so one network cannot create many campaigns in a day.
- ATT&CK per-event mapping: compute the lower-case form of each event field once and share it between rules.
- Campaign clustering: commit per chunk instead of one transaction per cycle, so a long cycle does not hold locks.
- Payload analysis in quarantine: static checks on fetched files, without execution. To be framed with the owner before any design work.
- Provider keys: sealed-box (public-key) encryption so the API can store a key but never read it back, only ingest can.
- Public read-only page through Cloudflare Tunnel, IPs masked.
- LLM-backed SSH shell.
- RDP: a fake Windows logon screen that records keystrokes.
