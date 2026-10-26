# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Docs

- A "Provider API keys" guide: what each optional key adds and how to get it, step by step.
- A Troubleshooting section in the deployment guide, and the upgrade command.
- Refreshed screenshots and a new README gallery for the three-space navigation.

## [0.2.0] - 2026-10-26

### Added

- Seven more sensors (M9): Redis, Docker Engine API, MySQL, Microsoft SQL Server, Android ADB, SMB and SIP (UDP and TCP), each with real-client tests, per-IP fairness for CPU, memory and events, and a security review. SIP never sends a reply larger than its request.
- Provider keys in Settings (M11): AbuseIPDB, GreyNoise and MaxMind keys stored encrypted (AES-256-GCM), write-only in the UI, with re-authentication and a "Test key" button.
- CVE watch (M12): daily CISA KEV, NVD and GitHub advisory feeds ranked by relevance to the emulated services, with "seen in our traffic" counts and a trap-proposal sheet.
- Indicators and threat intelligence (M13): URLs, domains, IPs and hashes extracted from events, enriched by URLhaus, ThreatFox and VirusTotal, shown on an Infrastructure page with CSV and STIX export. Passive only.
- Users and roles (M14): admin and read-only viewer accounts, one-time temporary passwords, per-source lockout and an audit log. The `.env` owner account stays the root of trust.
- Campaigns and MITRE ATT&CK (M15): sessions that share a script, payload host, hash, malware family, exploit or credential list are grouped into campaigns, with a Techniques heatmap. Off by default (`CAMPAIGNS_ENABLED`, `ATTACK_ENABLED`).
- Defend (M16): scored blocklists, overrides, exports for OPNsense and pfSense aliases, an opt-in token feed (`FEEDS_ENABLED`), Sigma and Suricata rules marked "review before deploying", and "Your exposure".
- Script library (M17): command scripts with plain-English explanations, and an optional LLM explainer (`LLM_ENABLED`, off by default) that sees only normalised script text.
- Alerts and reports (M18): Discord, Microsoft Teams and e-mail (TLS) channels, alert rules that are off until switched on, a test message button, and a weekly report with a printable view. Off by default (`ALERTS_ENABLED`, `REPORTS_ENABLED`).
- Today, search and research scanners (M19): a Today home page, a global search box, a glossary, and known research scanners labelled benign by network ownership.
- Migrations `0011` to `0015` add the campaign, ATT&CK, Defend, script, alert and search tables and columns.

- RDP sensor (M10): the NTLM challenge flow, so `nmap --script rdp-ntlm-info` returns the full Windows Server 2022 identity and logins arrive as `rdp-ntlm` events with the user name and domain.
- RDP decoy accounts (`RDP_ACCOUNTS`): a login with a decoy password is verified against the NTLM response and tagged `weak-credentials`. Nothing else is ever checked.
- Optional NLA-off mode (`RDP_NLA_MODE=optional`, off by default): records the cleartext user name and password from clients that skip NLA (`rdp-nla-off` events), tagged `rdp-cleartext`.
- RDP client tool identification (nmap, FreeRDP, rdesktop, ncrack, mstsc), stored on sessions as `client_tool` and shown on the session page.
- Tag `bluekeep` for RDP sessions that bind the `MS_T120` channel.
- RDP limit `RDP_MAX_TLS_PER_IP` (default 4), so a few addresses cannot hold every TLS slot.

### Changed

- Migration `0007` adds the nullable `sessions.client_tool` column.
- Live page: the 3D globe is replaced by a flat world map (Equal Earth) with per-country arcs for the last 15 minutes, a stats strip, a ticker of the newest events and rankings of addresses, countries and networks. `SITE_HOME_LAT`, `SITE_HOME_LON`, `SITE_HOME_LABEL` and `GET /api/v1/settings/site` are unchanged.

## [0.1.0] - 2026-10-25

### Added

- Bootstrap (M0) and foundations (M1): MIT licence, project rules, roadmap, architecture and security docs, a gitleaks pre-commit hook and CI; the shared event schema, a Redis Streams pipeline, a TimescaleDB schema with Alembic migrations, an ingest consumer and an API with a live WebSocket feed.
- Demo data generator (`just demo`): synthetic sessions across all four sensors with documentation IP ranges only, plus a live mode.
- SSH sensor: OpenSSH 9.6 fingerprint, configurable weak logins, an emulated shell on a fake filesystem, download recording without fetching, and timed session recording for replay.
- Telnet sensor: BusyBox telnetd look-alike with Mirai-style flows.
- Web sensor: byte-identical Apache 2.4.58 with PHP 8.3, fake WordPress and phpMyAdmin pages, and PHP2Shell (upload-progress) detection.
- RDP sensor: Windows Server look-alike with NLA and username capture.
- Enrichment: GeoIP and ASN from DB-IP Lite (no key) or MaxMind GeoLite2, optional AbuseIPDB and GreyNoise Community reputation with a 24 h cache and enforced daily quotas.
- Tagging: a declarative YAML rules engine without regular expressions (`recon`, `mirai`, `crypto-miner`, `malware-drop`, `php2shell`).
- Dashboard: Live (3D globe and event feed), Overview (KPIs and auto-written insights), Attacks, Session detail with terminal replay, Attackers, Trends, Malware (defanged URLs) and Settings, in dark and light on desktop and mobile; a design system; a screenshot mode (`?mask=1`); Playwright screenshots.
- Dashboard login: a single admin account with an argon2 password hash, CSRF protection and a rate-limited login.
- Retention and storage: raw events kept 90 days, aggregates forever, compression, a disk guard, and `just backup` / `just restore`.
- Hardened Docker Compose stack with a host firewall template in `scripts/host/`.
- Documentation site (Sphinx, Read the Docs) and a project page.
- Repository meta: README, `CONTRIBUTING.md`, `SECURITY.md`, issue and pull request templates, Dependabot and release-note configuration.

### Security

- No attacker input is ever executed: every sensor passed several rounds of adversarial security review (the web sensor's final review is pending).
- Isolation: four networks with an internal backend, one Redis ACL user per sensor limited to `XADD` on its own stream, least-privilege database roles, no outbound route for the API, non-root read-only containers with all capabilities dropped.
- The first review of the M1 stack found unbounded stream growth, egress, poison-message and default-credential issues; all were fixed and the second pass passed.

[Unreleased]: https://github.com/Theroxat/suckerpot/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Theroxat/suckerpot/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Theroxat/suckerpot/releases/tag/v0.1.0
