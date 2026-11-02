# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Installable Selfhostr (M28). Install with one command from a release tag: `./scripts/install.sh` (also `just install`). The installer checks the machine, asks a few questions, creates every secret on the host, writes `.env` (mode `0600`), creates the data volumes and starts the stack. It never overwrites `.env`, never adopts existing volumes and never looks up the public address. Guide: `docs/install.md`.
- Two install modes: signed release images (default) and a build from the checkout (`--source`).
- Sensor switches `SENSOR_<NAME>` (default `1`). Choose the sensors with `just sensors`, or change any allowed setting with `just set`. The port guard follows the selection.
- First-run setup in the dashboard (`/setup`, migration `0025`): welcome, sensors, ports, VPN, own address, abuse reports, alerts and a checklist. It can be skipped, finished later and opened again from Settings. Settings has a new "Sensors & ports" tab with the router port and the state of each sensor.
- Safe updates: `just update` takes a database dump first, records how to roll back and checks the health of the new version. An update that did not finish blocks the next one until `--force` or a rollback. `just rollback` restores the previous code, images and database after confirmation. Guide: `docs/updates.md`.
- Signed images: the release workflow publishes amd64 and arm64 images on version tags, signs them with cosign (keyless) and runs an install smoke test. `scripts/verify-images.sh` checks the signatures, and the installer and the updater refuse to run an image that does not verify (fail closed).
- Low-memory mode (`docker-compose.lowmem.yml`) for machines of about 2 GiB.
- The running version is shown in the dashboard. An optional daily update check (`UPDATE_CHECK_ENABLED`, off by default) asks GitHub through the VPN only, sends no version or identifier, and never installs anything.
- VPN idle mode: the egress profile starts before a WireGuard file is uploaded. The tunnel stays closed, with no route out, until a configuration is uploaded or passed to the installer.

### Changed

- `docs/deployment.md` "Upgrading" now points to `just update`. The old `git pull` and `docker compose up` steps are replaced.
- Abuse report wording is now optional (owner decision of 2026-11-01). Only the reply contact is required. An empty introduction, closing, note or signature is left out of every rendering (text, X-ARF, `.eml`), an empty subject template gives `Abuse report for <address>`, and an empty X-ARF user agent gives `Mozilla/5.0`. The `custom_intro_required` gate on marking a report reviewed is gone, and the report detail answers `missing` instead of `custom_intro`. The setup checklist item is green once the reply contact is set. The `default_wording` identity check still refuses text that equals wording published earlier.

## [0.5.0] - 2026-11-01

### Added

- Sending abuse reports (M25): a "To send" queue on the Abuse reports page opens each ready report in the mail app (the full text is copied to the clipboard), then marks it sent and moves on, with keyboard shortcuts. Free Proton addresses have no SMTP access, so this is the way to use them.
- Optional SMTP for reports, configured in Settings > Reporting > Sending (password encrypted and write-only, re-authentication, a preset for Proton paid plans with a custom domain). Three modes: off (the default: nothing is ever sent), send on click, and automatic after a waiting time with Cancel and a daily cap. Mail leaves only through the VPN, after a last identity check on the complete message (headers, envelope, EHLO name and every part); with the tunnel down nothing is sent. Delivery is at most once: a send whose outcome is unknown is never retried. Migration `0022`, `/api/v1/abuse/smtp`, `/api/v1/abuse/send-queue` and `/api/v1/abuse/reports/{id}/send`.

### Changed

- Alerts (email, Discord, Teams) now go through the identity check too: the honeypot's own addresses and terms are masked, and alerts pause until the owner's own address is confirmed in Settings > Reporting.
- The SMTP EHLO name of alert emails is the sender's domain, never the container's host name.

## [0.4.0] - 2026-11-01

### Added

- Guided tour (M24): a seven-step tour opens on each account's first login and can be replayed from the "Tour" button in the top bar. It explains daily reading, campaigns and tools, how payloads are fetched and analysed without ever being run, the VPN and its kill switch, abuse reports and alerts, each with a small flow diagram.
- Page help: a "?" next to every page title says what the page shows, where its data comes from and one useful action.
- Setup checklist: `GET /api/v1/setup/status` and a card in Settings > General (and the tour's last step) show, from the real state, what is done and what is left: sensor traffic, the outbound gate, the payload collector, report wording, your own address, abuse report drafts, alert channels and reputation keys.
- VPN tab: "Check now" asks the gate to re-check at once (`POST /api/v1/settings/vpn/check`, table `egress_check_requests`, migration `0021`) and "Reconnect" restarts the tunnel after asking for the password again (`POST /api/v1/settings/vpn/reconnect`, a marker file the `vpn` entrypoint watches).

### Changed

- While the egress gate is closed it re-checks every 20 seconds (for ten tries, then at the normal interval) instead of waiting the full interval, so lookups resume within a minute after a tunnel restart.

### Fixed

- Two flaky tests: the auth event-loop check and the collector table reset.

## [0.3.0] - 2026-11-01

### Changed

- `just test-integration` uses `docker-compose.it.yml`, an overlay that keeps `redis` on the backend network only, so the throwaway project fits in Docker's default address pools next to the live stack.
- The sidebar is grouped into ten entries. Related pages sit behind one entry with tabs: Attacks (Sessions, Attackers, Networks), Campaigns (Campaigns, Techniques), Tools (Scripts, Malware, Infrastructure), Trends (Activity, Patterns), Protection (Blocklists, Detections) and Exposure (Your exposure, CVE watch). Every old URL still works; `/attackers?view=asns` now redirects to `/networks`.
- Today is a visual story of the last 24 hours in plain words: a flow from country to service to how far each visit got, an hour-by-hour strip, and three to five stories of the day with their technical details one click away. Hard words have a short definition on hover.

### Added

- VPN configuration upload (M23): Settings > VPN takes the WireGuard `.conf` from your VPN provider, parses it strictly (no `PostUp` and the like, IP endpoint only, full tunnel) after asking for the password again, and writes it to the new `vpn-config` volume. The `vpn` service notices the new file and restarts on it; nothing leaves outside the tunnel during the switch, and the API gets no Docker socket. A new exit address stays blocked until the owner trusts the /24 the gate observed (table `egress_trusted_exits`, migration `0020`); an exit inside the honeypot's own addresses or in an AS listed in the new `EGRESS_DENY_ASNS` can never be trusted, and the exit's AS is shown next to it. `/api/v1/settings/vpn` endpoints, new guardrails.
- Anonymous reporting (M22): an ingest worker (`ABUSE_REPORTS_ENABLED`, off by default) finds abuse contacts over RDAP through the egress gate and prepares draft reports per recipient. The new `reporting/` package renders plain text, X-ARF v0.2, `.eml`, STIX 2.1 and MISP JSON and builds password-protected sample bundles. An identity guard checks every artefact before it is returned and fails closed. Learned self terms need the owner's confirmation. The package ships no wording: the owner writes it in Settings > Reporting. Nothing is ever sent by the stack. Migration `0019`, `/api/v1/abuse` endpoints, the Abuse reports page, Export for CERT, the sample bundle and the Reporting tab in Settings, `just abuse-guard-check` and the `ABUSE_*` settings.
- Anonymous egress (M21): a `vpn` service (WireGuard through gluetun, profile `egress`) with a kill switch and an HTTP proxy is the only container with a route to the internet. `ingest` and the new `collector` go through the proxy, an egress gate pauses outbound work when the tunnel or its exit address looks wrong, and the old `egress` network is removed. New `just guardrails` and `just egress-check`, new host firewall rules for `sp-vpn`, `sp-egress` and `sp-samples`.
- Payload collection and static analysis (M21): the `collector` service fetches captured download URLs through the VPN into a quarantine volume (SSRF validator, size, time and rate caps, never executed), and the network-less `analyzer` service identifies, hashes, scans with YARA, deobfuscates shell scripts and extracts C2 addresses in a limited child process. Migration `0018`, roles `suckerpot_collector` and `suckerpot_analyzer`, the `/api/v1/samples` and `/api/v1/egress` endpoints, a Samples tab, a sample page and an Egress card in Settings. `FETCH_PAYLOADS`, `PAYLOAD_MAX_BYTES` and `PAYLOAD_TIMEOUT_SECONDS` are replaced by `COLLECTOR_ENABLED` and the `COLLECTOR_*` and `QUARANTINE_*` settings.
- Synology NAS sensor (M20): a fake unpatched Synology NAS on DSM 7.2.1 (Update 11), with the DSM login page and Web API on HTTP 5000 and HTTPS 5001. Logins always fail with real DSM error codes and are recorded. Requests that match the forged-session and SCGI shapes of CVE-2026-13639 and CVE-2026-13684 are tagged `synology-exploit`, ransomware indicators of the C3RB3R campaign are tagged `c3rb3r`, and DSM API calls are tagged `synology-dsm`. Migration `0017` adds the sensor to the inventory.
- Probable C2 lookups ignore VirusTotal contacts in big shared networks (Google, Cloudflare, Microsoft, Akamai, Fastly, Meta, Apple, from the local ASN database) and CDN or update domains, and clean up already stored rows on start.
- Probable C2 addresses: for file hashes that VirusTotal or abuse.ch already know, ingest reads which addresses sandboxes saw the malware contact (VirusTotal relationships, ThreatFox `botnet_cc`), with the same fixed hosts, quotas and 24 h cache as the other intel lookups and no contact with the addresses. New table `indicator_contacts` (migration 0016), `GET /api/v1/indicators/c2`, and a blocklist reason "probable C2" (75 for ThreatFox, 40 for VirusTotal, capped at 45 when no sensor computed the hash and fewer than three networks dropped it).
- `GET /api/v1/story`, the plain-language summary behind Today.
- A `stage` filter on `GET /api/v1/sessions` and on the Attacks page (looked, guessed, got in, ran commands, tried to install, sent an exploit), plus `since` and `until` in the Attacks URL.

### Fixed

- The abuse, alerts and intel workers no longer wait up to an hour for their first run on a host that booted recently.
- CVE watch: the NVD window is 60 days (was 30) and is read in one-day chunks, oldest first, with a page budget, so a busy day no longer loses CVEs silently at the 10,000-result limit. A run that stops early resumes from its last complete chunk.
- CVE watch: GitHub advisories are read in seven-day chunks, oldest first. A one-time start-up rewind refills a shallow history, and watched CVEs that are missing from the table are fetched by id (at most 10 per run, once per id per 24 hours).

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

[Unreleased]: https://github.com/Theroxat/suckerpot/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/Theroxat/suckerpot/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/Theroxat/suckerpot/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Theroxat/suckerpot/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Theroxat/suckerpot/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Theroxat/suckerpot/releases/tag/v0.1.0
