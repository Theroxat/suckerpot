# SuckerPot

A self-hosted honeypot with a dashboard that makes internet attacks easy to read.

> **Status: early development.** Nothing here is ready to use yet. See [docs/ROADMAP.md](docs/ROADMAP.md) for what is done and what is planned.

## Features (planned)

- **Sensors** that look like real services:
  - SSH, with a fake shell and full session replay
  - Telnet, with Mirai-style flows
  - Web, with a fake Apache and PHP stack, a fake WordPress login and a fake phpMyAdmin
  - RDP, with handshake and username capture
- **Enrichment**: GeoIP, ASN, organisation, and reputation from AbuseIPDB and GreyNoise. Results are cached, and quotas are enforced.
- **Tagging**: a rules engine tags sessions, for example `recon`, `mirai`, `crypto-miner`, `malware-drop` and `php2shell`.
- **Dashboard** pages:
  - **Live**: a 3D globe with attack arcs and a live event feed
  - **Overview**: key numbers, activity per sensor, top countries and automatic insights
  - **Attacks**: a list of sessions, each with a one-line story
  - **Session detail**: a timeline, a terminal replay and an IP panel
  - **Attackers**: profiles by IP and by ASN
  - **Trends**: top usernames, passwords, commands and URLs, plus a day-by-hour heatmap
  - **Malware**: download URLs, hashes and VirusTotal links
  - **Settings**: sensor status, quotas and retention

## Screenshots

_Coming with the first release. Screenshots only ever use demo data (`just demo`), never real attack data._

## Quick start

Read [Getting started](docs/getting-started.md) first. It explains the requirements and the warnings. In short:

```bash
cp .env.example .env
# edit .env and replace every change-me value (openssl rand -base64 32)
docker compose up -d --build --wait
just demo
```

## Contributing

Install the git hooks before you commit:

```bash
scripts/install-hooks.sh
```

The gitleaks pre-commit hook blocks commits that contain secrets. Never commit `.env`, captured data or private infrastructure details. See [docs/SECURITY.md](docs/SECURITY.md) for the full rules.

## Warning

**Deploy SuckerPot only on an isolated host that you are ready to lose.** The sensors are built to be attacked. Never keep credentials or personal files on the host. Expose the dashboard only through a reverse tunnel, never directly on the internet.

## Documentation

Full documentation: <https://suckerpot.readthedocs.io/>

_The site goes live once the project is imported on Read the Docs. Until then, read the same pages in the `docs/` folder:_

- [Getting started](docs/getting-started.md): requirements, first run and warnings
- [Deployment](docs/deployment.md): go-live checklist for exposing the sensors
- [Demo data](docs/demo-data.md): what `just demo` generates
- [Configuration](docs/configuration.md): every environment variable
- [Architecture](docs/ARCHITECTURE.md): services, networks and data flow
- [Event schema](docs/event-schema.md): the shared event format
- [API](docs/api.md): REST endpoints
- [Security](docs/SECURITY.md): threat model, controls and how to report a vulnerability
- [Development](docs/development.md): repository layout, tools and commands

## License

MIT. See [LICENSE](LICENSE).
