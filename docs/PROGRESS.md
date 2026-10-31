# Progress log

Newest entries at the bottom. One entry per milestone or significant step: date, what was done, what is left.

## 2026-10-24 — M0 Bootstrap

- Created `.gitignore` first, then `CLAUDE.md`, project subagents in `.claude/agents/`, roadmap, architecture and security docs, README skeleton, MIT licence and `.env.example` (placeholders only).
- Added a gitleaks pre-commit hook (`scripts/install-hooks.sh`, custom rule for private IPv4 ranges) and a CI workflow (gitleaks over full history, Python/web lint and tests, compose config check).
- Left open: CI to be confirmed green on GitHub; secret scanning and push protection to be enabled in the repo settings by the owner.

## 2026-10-24 — M1 Foundations

- Shared Event schema and Redis publisher (`sensors/common`), demo generator (`scripts/demo`: ~3,000 realistic sessions over 30 days across SSH, Telnet, Web and RDP, plus a live mode).
- TimescaleDB schema with Alembic (events hypertable, sessions), least-privilege roles for ingest and the API with statement timeouts.
- Ingest: Redis Streams consumer, batched writes and session upserts, stream trimming after ACK, dead-lettering of poison messages.
- API: sessions, events and summary endpoints with keyset pagination; the live WebSocket feed and SPA serving (early M3 backend work) with security headers.
- Compose stack with four networks, Redis ACL users (admin, sensor, ingest, health), full container hardening and no added capabilities; justfile; CI with lint, typecheck, unit and integration tests and a full compose smoke test.
- Documentation site (Sphinx + MyST, Read the Docs config).
- Security review: first pass FAIL (unbounded stream, egress, poison messages, defaults), all fixed; second pass PASS. Remaining low/medium follow-ups are listed under M2.
- Verified: all services healthy, demo data end to end, WebSocket live feed, only the dashboard port published (loopback by default).

## 2026-10-25 — M2 to M7, most of M8

- Sensors: SSH (OpenSSH 9.6 fingerprint, emulated shell with fake filesystem, terminal replay), Telnet (BusyBox telnetd, Mirai flows), Web (Apache 2.4.58 + PHP 8.3 byte-identical error pages, WordPress/phpMyAdmin, PHP2Shell detection), RDP (Windows NLA, username capture). Each has its own ingress network without NAT, internal network to Redis, Redis user limited to XADD on its stream, watchdog, cgroup memory guard and per-connection/IP/global budgets.
- Security reviews: SSH 4 passes, Web 4 passes, Telnet 2, RDP 2, auth 1 — all PASS. No path executes attacker input.
- Pipeline: per-sensor streams, multi-stream ingest with never-trim-past-pending, enrichment (DB-IP Lite or MaxMind, AbuseIPDB/GreyNoise with quotas), regex-free YAML tagging, publisher byte backstop, retention (90 d raw, compression, continuous aggregates) and disk guard.
- API and UI: analytics, insights, trends, malware, settings, single-admin auth (argon2, CSRF, rate limits); pages Live (3D globe), Overview, Attacks, Session detail with safe terminal replay, Attackers, Trends, Malware, Settings, login; screenshot mode.
- Ops: backups, host firewall template, port guard, CI overlay, Sphinx docs, project page and offline demo for GitHub Pages.
- Left for v0.1.0: owner actions (firewall, disk, GitHub Pages/RTD/secret scanning), then the release.

## 2026-10-25 — M9 Seven more sensors

- Sensors: Redis 7.2 (6379), Docker Engine API 27.3 (2375), MySQL 8.0 (3306), SQL Server 2019/2022 with TLS inside PRELOGIN (1433), Android ADB TV box (5555), SMB2/3 with NTLM capture and SMB1 disabled (445), SIP/Asterisk over UDP and TCP (5060). Each tested with real clients (redis-cli, docker CLI, mysql/PyMySQL/hydra, impacket/sqlcmd, adb, smbclient, sipsak/SIPVicious) and nmap.
- New sensor contract lessons 16–18: wall-clock CPU budgets with per-IP buckets, pending output charged to the memory budget, per-IP event fairness with a priority path and a disconnect reserve. SIP never sends a reply larger than its request (measured amplification under 0.001 during a flood).
- Security reviews: Redis 2 passes, MySQL 2, MSSQL 3, ADB 2, Docker 2, SMB 2, SIP 2, compose and Redis ACLs 1 — all PASS. Every first-pass failure was a denial of service; no path executes attacker input, writes outside its data directory or opens outbound connections.
- Pipeline and UI: tags and severities for the new flags, per-IP brute-force tagging and insight, multi-sensor filters, readable scan summaries, demo data for eleven sensors; sensors grouped into four colour families; a flat world map is now the default Live view, with the globe as an option.
- Ops: memory limits sized from measured peaks, OOM and CPU priorities that protect db/redis/ingest, a shorter stream cap for the new sensors, port guard extended, conntrack sysctl and optional sensor slice templates.

## 2026-10-25 — M13 Indicators and threat intelligence

- Ingest extracts URLs, domains, IPs and file hashes from stored events (bounded scanning, no regular expressions; credentials stripped, private, documentation and own values dropped) into `indicators` and bounded `indicator_sessions` (migration 0009, retention aligned with raw events).
- Passive enrichment: URLhaus and ThreatFox (one abuse.ch Auth-Key) and VirusTotal for hashes only, at three fixed hosts, no redirects, byte caps, timeouts, persisted daily quotas (VirusTotal default 400) and a 24 h cache. Keys come from `.env` or Settings, like the other providers.
- API: indicators list, detail, a bounded infrastructure graph, and owner-triggered CSV and STIX 2.1 export.
- Web: an Infrastructure page (finding, flow diagram of addresses, indicators and families, list fallback on mobile, filterable table, detail panel, export buttons). Indicators are defanged text, never links.
- Open: migration 0009 follows 0007 (0008 reserved), to be re-chained at merge.

## 2026-10-25 — M11 Settings you can edit

- AbuseIPDB, GreyNoise and MaxMind keys can be set, replaced and removed from Settings. Keys are stored with AES-256-GCM (key derived from `SETTINGS_ENCRYPTION_KEY`, provider bound as associated data), shown only by their last four characters, and every change needs the admin password again; five wrong passwords end the session.
- Ingest reloads keys every 30 s without a restart; Settings shows where each key comes from (`.env` or Settings). "Test key" asks ingest for one quota-counted check, at most 10 per provider per day.
- Security review PASS; follow-ups fixed (MaxMind redirect, shared re-auth budget, test cap, no forced GeoIP re-download, weak or reused master keys refused). A sealed-box scheme so the API can only encrypt is listed for later.

## 2026-10-25 — M10 RDP sensor, deeper

- CredSSP now goes as far as the NTLM challenge: every brute-force attempt records domain, user, workstation and NTLM version (an 8-byte response preview only). Responses for a short list of public decoy accounts are verified against their known passwords, so weak-password attempts are recognised; nothing is ever cracked and no session is granted.
- Optional "NLA disabled" mode (off by default) runs the MCS/GCC sequence up to the Client Info PDU and records the cleartext credentials TLS-only clients send.
- Client tool identification (nmap, FreeRDP and the tools built on it, rdesktop, mstsc) from JA3, cookie, NTLM and GCC data, stored on the session and shown on the session page; new tags `bluekeep`, `weak-credentials` and `rdp-cleartext`.
- Security review: first pass FAIL (a busy loop in the optional MCS path, TLS slots without a per-IP cap), both fixed; second pass PASS in both modes. Contract lessons 16–18 now apply to RDP too.

## 2026-10-25 — M12 CVE watch

- Ingest: a daily job mirrors the CISA KEV catalogue, recent NVD CVEs (API 2.0, paced to the rate limit) and GitHub security advisories into a new `cve` table. Downloads are capped in size and time, never follow redirects and are validated item by item; every request spends a persisted daily quota, and a failing feed is retried after an hour without stopping the others. NVD and GitHub keys are optional and set from Settings like the other provider keys.
- Relevance: `ingest/rules/cve/relevance.yaml` maps the emulated services (Apache + PHP, WordPress, phpMyAdmin, OpenSSH, BusyBox telnetd, RDP, Redis, Docker, MySQL, SQL Server, ADB, SMB, Asterisk/SIP) to CPE vendors and keywords and gives each CVE a relevance (high, medium, none) and matched services. The same file links CVE ids to our tags so "seen in our traffic" counts real sessions. Non-KEV, non-relevant CVEs are pruned after 180 days.
- API: `GET /api/v1/cves` (keyset pagination, filters for relevance, KEV, severity, period and text, rank or date order), `GET /api/v1/cves/{id}` (with traffic counts) and `GET /api/v1/cves/sync` (feed status). The enrichment settings now report the NVD and GitHub keys.
- UI: a "CVE watch" page that opens with a plain-English finding, a ranked list with severity, KEV, relevance, matched services and traffic counts, a detail panel, a feed status card and a "Propose a trap" button that only copies a trap-sheet template. Settings gets NVD and GitHub key rows. Demo data (fictional `CVE-2099-*` ids) lives in the MSW mocks.
- Left open: the owner reviews trap proposals before anything is built; security and UI reviews.

## 2026-10-25 — M14 Users and roles

- Database users with the roles `admin` and `viewer`, next to the `.env` owner account, which still works exactly as before (always an admin, usable without the database, password only in `.env`). New tables `users` and `audit_log` (migration 0010); the API role manages `users` and appends to `audit_log`, ingest has no access to either. The audit log is pruned after a year by a database job.
- Roles are enforced on the server with a default-deny check attached to every `/api/v1` route when it is included: only sign in, sign out and changing one's own password are open to a viewer. `tests/test_authz.py` calls every state-changing route as a viewer from the OpenAPI route table. The live WebSocket works for both roles.
- Sessions now carry the account and a per-user session version, checked against the database on each request: password change or reset, disable, role change, deletion and "Sign out everywhere" end the user's sessions at once (the WebSocket within five seconds).
- Login hardening: per-username limit next to the per-address and global ones, per-source lockout that grows (5 wrong passwords lock one source for a minute, doubling up to 15) with a high account-wide ceiling that spares the user's known sources (admins can unlock), the owner never limited by name, global and per-name windows that count failures only, the same argon2 work and the same message for unknown names. Passwords: 12 to 256 characters, a bundled list of 1000 common passwords, not the username.
- Onboarding: an admin creates a user and sees a one-time temporary password (hash stored only); the person must choose their own password before any other route answers. Admin actions re-authenticate with the admin's own password (the M11 helper, now shared) and write an audit entry; provider key changes are audited too.
- Web: Settings > Users and Audit log for admins, a read-only shell for viewers (badge, no write controls), a Set your password screen, an account menu with Change password and Sign out, mock data with `?as=viewer` and `?as=first-login`.
- Left open: security and UI reviews; optional TOTP; the owner is never locked out by failures (rate limits still apply).

- Security review follow-up: structural route test, `system` actor and ids in audit details, WebSocket closes with 1013 after repeated session-check failures, THIRD_PARTY_NOTICES.md for the common-password list.

## 2026-10-25 — M15 to M19: campaigns, ATT&CK, Defend, scripts, alerts, Today

- **M15 Campaigns and ATT&CK.** A shared command normaliser, a bounded clustering job that groups finished sessions by shared keys (script, exploit, credential list, payload host, file hash, malware family), campaign pages with a plain-English story, an ATT&CK catalogue synced hourly and event rules that tag sessions with techniques, and a Techniques heatmap. Migration 0011.
- **M16 Defend.** Scored blocklists (addresses, hosts, URLs, hashes) with a reason for every point, a never-list for resolvers, big SaaS and CDN names and the owner's own addresses, overrides with audit entries, exports for OPNsense and pfSense aliases, plain text and CSV, an opt-in token feed under `/feeds` (off by default), Sigma and Suricata rules marked "review before deploying", and "Your exposure", an inventory compared with recorded attacks. Migration 0012. Documented in [Defend](defend.md).
- **M17 Script library.** Sessions with two or more commands are fingerprinted into scripts, explained by a declarative annotation base, with an optional LLM explainer (`LLM_ENABLED`, off by default) that sees only the normalised script text, under a daily call quota and a monthly token cap. Migration 0013.
- **M18 Alerts and weekly report.** Discord, Microsoft Teams and e-mail (TLS only) channels with validated, encrypted targets, four event alert rules and a weekly report rule, all off until switched on, a rate-limited outbox with a test button, and a weekly report with a printable view. Migration 0014.
- **M19 Today, search and research scanners.** A Today home page, a global search box, a glossary, and research scanners (for example known internet crawlers) labelled benign by the network that owns them. Benign is an allowlist of harmless behaviour, decided on what the session did, never on its user agent. Migration 0015.
- **Security reviews.** Each milestone went through a security review. The first pass of each one returned FAIL or findings, which were fixed. A second pass returned PASS.
- **Left open.** The campaign cap per network and ASN, commit per chunk in clustering, and payload analysis in quarantine (to be framed with the owner). See the [roadmap](ROADMAP.md) "Later" list. The M14 security and UI reviews are still unticked.

## 2026-10-27 — Simpler navigation and a story-style Today

- Navigation: 18 sidebar entries became 10 hubs with an underline tab strip above the page title, defined once in `web/src/app/nav.ts`. Detail pages light up their hub; the Styleguide shows only in dev builds; a new `/networks` route holds the ASN view.
- Today: rewritten around `GET /api/v1/story` (bounded queries on `sessions`, 3 s statement timeout, 30 s cache). A Sankey of origin, door and deepest stage reached, an hour strip that links to the matching sessions, and story cards whose plain sentences come from templates while attacker text stays in the technical details, clipped. The previous "what you can do" cards remain at the bottom.
- Attacks: new `stage`, `since` and `until` filters, so every number on Today opens the sessions behind it.
- Reviews: security review PASS (three low findings fixed: statement timeout on the stage filter, quoted hrefs, clipped org names); design review fixes applied (Sankey labels, stage colours, underline tabs, no duplicated navigation, attacker row width, hour strip key and ticks).

## 2026-10-30 — M20 Synology NAS sensor and CVE watch fixes

- **Synology sensor.** A twelfth sensor that looks like an unpatched Synology NAS on DSM 7.2.1 (Update 11). It serves the DSM login page and the Web API on HTTP 5000 and HTTPS 5001. Logins always fail with real DSM error codes, and the credentials are recorded. Nothing a client sends is run, written or fetched. Documented in [Synology](sensors/synology.md).
- **Tags for the C3RB3R campaign.** Forged session IDs and SCGI header injections (CVE-2026-13639 and CVE-2026-13684) are tagged `synology-exploit`, and ransomware indicators `c3rb3r`. Both are severe. DSM API calls are tagged `synology-dsm`. ATT&CK mapping: T1190 and T1486. Migration 0017 adds the sensor to the inventory.
- **Compose and ports.** `sensor-synology` with its own network, Redis user and volume, `SYNOLOGY_*` settings in `.env.example`, and 5000 and 5001 in the port guard.
- **CVE watch.** The NVD window is 60 days. It is read in one-day chunks, oldest first, with a page budget, so a busy feed no longer loses CVEs silently at 10,000 results. A partial run resumes from its last complete chunk. GitHub advisories are read in seven-day chunks. A one-time start-up rewind refills shallow history, and watched CVEs missing from the table are fetched by id.
- **Integration tests.** `just test-integration` uses `docker-compose.it.yml`, an overlay that keeps `redis` on the backend network only, so the throwaway project fits next to the live stack.
- **Closed on 2026-10-31.** Security review passed. Deployed: every service healthy, and the Synology ports receive internet traffic. An `INGEST_STREAMS` override written before M20 left out `events:synology`; ingest now logs a warning when the override omits a built-in sensor stream.
- **CI.** Python is pinned to 3.13 in the uv jobs. Two flaky tests are fixed: the Docker sensor no longer answers 409 to an unnamed create whose random name was taken, and the alert test fixtures retry a table reset picked as a deadlock victim.

## 2026-10-31 — M21 Anonymous egress, payload collection and static analysis

- **Anonymous egress.** A `vpn` service (WireGuard through gluetun, profile `egress`) is now the only container with a route to the internet. It has a kill switch, an HTTP proxy and a read-only control server. The old `egress` network is gone. `ingest` and the new `collector` reach the internet only through the proxy, using the shared `suckerpot_egress` package. An egress gate runs a self-check every 5 minutes (tunnel up, two echo services agree, the address matches gluetun's, is global and is in the allowed network) and pauses all lookups when it fails. Events are still stored. Without the profile every outbound feature stays idle.
- **Guardrails.** `just guardrails` is a static test of the compose files (networks, members, capabilities, DNS, proxy variables). `just egress-check` proves the isolation on the running stack, including a tunnel-down test. The host firewall (`scripts/host/firewall.nft`) gets rules for `sp-vpn`, `sp-egress` and `sp-samples`.
- **Collector and analyzer.** The collector fetches captured download URLs through the proxy with an SSRF validator, size, time, redirect and rate caps, and writes files to a quarantine volume under their sha256 name (mode 0400, never executed). The analyzer has no network. It identifies the type and architecture, hashes (sha256, sha1, md5, TLSH), extracts strings, runs YARA rules, deobfuscates shell scripts as text and extracts next-stage URLs and C2 addresses, in a resource-limited child process. Migration 0018 and two new database roles.
- **API and UI.** `/api/v1/samples`, the chain, an admin-only password-protected archive download, and `/api/v1/egress`. A Samples tab on Malware, a sample page and an Egress card in Settings.
- **Reviews.** Security review passed (egress, quarantine, parser safety on hostile files). UI review passed.
- **Not deployed.** The owner still has to add the VPN settings, apply the new host firewall rules and run `just egress-check`. See [Deployment](deployment.md#anonymous-egress-vpn). TFTP and FTP URLs are recorded but not fetched.
