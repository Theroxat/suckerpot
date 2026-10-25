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
