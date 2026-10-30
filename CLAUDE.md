# SuckerPot

A self-hosted honeypot with a dashboard that makes internet attacks easy to read, understand and explore. Few sensors, built well, one beautiful UI. Everything runs in Docker Compose.

@ENVIRONMENT.local.md

> `ENVIRONMENT.local.md` is gitignored and holds the private infrastructure context. If it is missing, ask the owner before doing anything that touches networking or deployment.

## 1. Golden rules

1. **English everywhere**: code, comments, commit messages, docs, issues, PRs and every UI string. The owner writes to you in French: reply to him in French in chat, but nothing written to the repo is in French.
2. **The repo is PUBLIC.** Treat every commit as published to the whole world, forever. See §6.
3. **Docker Compose only.** Every component is a service in `docker-compose.yml`. Nothing runs directly on the host except Docker.
4. **You are an orchestrator.** See §2.
5. **Never weaken isolation.** See §5.
6. **Ship working increments.** Every milestone ends with all services healthy, tests green, docs updated and the work pushed.
7. **Ask the owner** when you need secrets or API keys, a Proxmox or ISP-box change, or an irreversible action (force-push, history rewrite, deleting data volumes), or when you are unsure whether something is safe to publish.

## 2. Orchestration model

The main session **plans, delegates, reviews, integrates and commits**. It does not write feature code itself. Exceptions: one-line fixes, config tweaks and merge conflicts.

### Workflow for each milestone

1. Read `docs/ROADMAP.md` and pick the next unchecked milestone.
2. Split it into tasks. Each task has a goal, the files it owns, the contracts it must respect (e.g. the shared Event schema), acceptance criteria and verification commands.
3. Dispatch subagents:
   - **Independent tasks run in parallel**: several Agent calls in a single message.
   - Parallel agents that write code use **worktree isolation**, or have strictly separate files (e.g. `sensors/ssh/` vs `web/`).
   - Every agent prompt is self-contained. Agents do not see this conversation.
4. Verify the results with the `qa-runner` agent: build, tests, lint, typecheck, and `docker compose up` health. When something fails, send it back to the agent that owns it (SendMessage) instead of rewriting it yourself.
5. Have `security-reviewer` check every change that touches sensors, networking, auth, the compose file or the Dockerfiles.
6. Review `git diff --staged` yourself (§6). Then commit, push, tick the roadmap and append an entry to `docs/PROGRESS.md`.

### Model selection

Pick the cheapest model that will do the job right.

| Model | Use it for |
| --- | --- |
| `haiku` | Codebase searches, reading files and docs, summarizing logs and test output, mechanical edits, boilerplate config, formatting docs, running checks and reporting results |
| `sonnet` | **The default for implementation**: sensors, ingest, API, React pages and components, tests, Dockerfiles |
| `opus` | Architecture and cross-cutting design, security reviews, tricky protocol emulation (SSH/RDP edge cases), hard debugging after a `sonnet` attempt failed, design-system and UX direction, the final review of a milestone |

Never start routine work on `opus`. If an agent fails twice on the same task, move it up one model.

### Project agents (`.claude/agents/`)

| Agent | Model | Scope |
| --- | --- | --- |
| `sensor-engineer` | sonnet | `sensors/**`: protocol emulation, fake shells, fake web apps |
| `backend-engineer` | sonnet | `ingest/**`, `api/**`, `db/**`: enrichment, tagging, REST and WebSocket |
| `frontend-engineer` | sonnet | `web/**`: pages and components. Uses the design system, never invents new styles |
| `ui-designer` | opus | Design system, layout, information hierarchy, visual QA from screenshots |
| `security-reviewer` | opus | Read-only review against §5 and §6. Reports findings, does not edit |
| `qa-runner` | haiku | Runs builds, tests, lint, compose health and Playwright screenshots, and reports |
| `docs-writer` | haiku | README, docs and changelog, in plain and clear English |

## 3. Architecture

```
Internet ──► ISP box (DMZ, all ports) ──► VM ──► 12 sensors ──► Redis Streams ──► ingest ──► PostgreSQL + TimescaleDB ──► API (FastAPI) ──► Web UI (React)
                                                                                                                            ▲
                                                                        cloudflared (another VM on the LAN) ────────────────┘
```

Full detail in `docs/ARCHITECTURE.md`; read it before touching compose, Redis ACLs or the ingest loop.

| Service | Network(s) | Notes |
| --- | --- | --- |
| `sensor-{ssh,telnet,adb,web,docker,synology,redis,mysql,mssql,rdp,smb,sip}` | `ingress` (`sp-ingress`) + its own `sensors-<name>` | The only services published to the internet. `sp-ingress` has masquerading and inter-container traffic off; `sensors-<name>` is internal and links that one sensor to Redis. One Redis ACL user per sensor, limited to `XADD events:<name>` |
| `redis` | every `sensors-<name>`, `tools`, `backend` | One stream per sensor (`events:<name>`), AOF on `redis-data` |
| `migrate` | `backend` | Runs Alembic as the DB owner and (re)sets the `suckerpot_ingest` / `suckerpot_api` role passwords on every run |
| `ingest` | `backend`, `egress` | Enrichment, tagging and the analysis workers. The only service with outbound internet |
| `db` | `backend` | PostgreSQL + TimescaleDB, on a named volume |
| `api` | `backend`, `dashboard` (`sp-dashboard`) | FastAPI: REST + WebSocket, also serves the built web UI |
| `demo` (profile `tools`) | `tools` | Demo generator; reaches Redis only |

- `backend`, `tools` and every `sensors-<name>` network are `internal: true`. The host firewall (`scripts/host/`) matches `sp-ingress` and `sp-dashboard` by bridge name.
- The dashboard is published on ONE port only (set in `.env`), never on a sensor port or 22222. `scripts/check-ports.sh` enforces this and runs before `just up` / `just config`.

### Pipeline invariants (break these and data is lost or forged)

- Sensors build an `Event` (`sensors/common/suckerpot_common/models.py`) and publish through its `publisher.py`, which drops (never buffers) when Redis is unavailable.
- Ingest is a **single** consumer (group `ingest`) over all streams. It drops events whose `sensor` field does not match the stream suffix, acknowledges only **after** the DB commit, then `XTRIM MINID` per stream. Never run two ingest instances.
- Each service uses its own DB role: `suckerpot_api` cannot write events/sessions; only `migrate` changes the schema (`db/migrations`, models in `db/suckerpot_db`).
- Tagging rules are YAML in `ingest/rules/` (`shell`, `web`, `services`, `session`, `scanners`, plus `attack/`, `cve/`, `annotations/` subfolders). Prefer adding a rule over adding code.
- Ingest background workers (campaigns, blocklist, scripts, LLM explainer, alerts, reports, ATT&CK) are each off until their `*_ENABLED` flag is `true`.

### Shared Event schema (`sensors/common`, a Pydantic model)

| Field | Content |
| --- | --- |
| `ts` | Timestamp, UTC |
| `sensor` | Which sensor produced the event |
| `session_id` | Groups all events of one connection |
| `src_ip`, `src_port`, `dst_port` | Source and target |
| `type` | One of: `connect`, `login_attempt`, `command`, `http_request`, `download_attempt`, `disconnect`, `scan` |
| `data` | Raw details, as JSON |

Ingest adds: `country`, `city`, `asn`, `org`, `abuse_score`, `known_scanner`, `tags[]`.

A **session** is the unit the UI tells as a story. **Tags** come from a declarative rules engine (`ingest/rules/*.yaml`): URL patterns, typical commands, user-agents, CVE signatures (e.g. `php2shell`, `mirai`, `crypto-miner`, `malware-drop`, `recon`).

### Stack

| Layer | Choice |
| --- | --- |
| Sensors | Python 3.13, asyncio, asyncssh (SSH), raw asyncio (Telnet, RDP), Starlette (web) |
| Ingest and API | FastAPI, SQLAlchemy 2 / asyncpg, Alembic |
| Queue | Redis Streams |
| Database | PostgreSQL 16+ with TimescaleDB (hypertables + continuous aggregates for trends) |
| Enrichment | MaxMind GeoLite2 (local), AbuseIPDB (free tier: 1,000 checks/day), GreyNoise Community (free tier: about 50/day). Results cached per IP for 24 h, quotas enforced |
| Web UI | React + Vite + TypeScript (strict), Tailwind, shadcn/ui, Recharts / Tremor, globe.gl, xterm.js, TanStack Query + Table |
| Python tooling | uv, ruff, mypy, pytest |
| Web tooling | pnpm, eslint, prettier, vitest, Playwright |
| Task runner | `justfile` (`just up`, `just test`, `just lint`, `just demo`, `just screenshots`) |

## 4. UI/UX — the most important part of this project

The owner chose to build SuckerPot because existing honeypot UIs, T-Pot and Kibana first among them, are cluttered and hard to read. **The UI is the product.** The bar is a polished, modern SaaS dashboard, not an admin panel.

### Process

1. **Build the design system first**, before any page: colour tokens (dark default, plus light), type scale, spacing, radius, one colour per sensor, a severity scale, and base components (Card, StatTile, TagBadge, EventRow, SessionStory, IPChip, CountryFlag, EmptyState, Skeleton).
2. Use the **`frontend-design` skill** for visual direction, and the **shadcn MCP** to install components. Never hand-roll what shadcn provides.
3. **Build against demo data**: `just demo` generates realistic fake attacks, so the UI never waits for real traffic. README screenshots must only ever use demo data.
4. **Check visually**: after every UI change, `qa-runner` takes Playwright screenshots (desktop 1440 and mobile 390, dark and light), and `ui-designer` reviews them and sends fixes until the result is clean.

### Principles

- **A sentence before a chart.** Each card opens with a plain-English finding ("PHP exploit attempts tripled since Tuesday"), then shows the chart that proves it.
- **Colour means something.** One hue per sensor (SSH, Telnet, Web, RDP). Red only for severe events: malware dropped, exploit payload sent. No decorative gradients.
- **Everything is clickable.** An IP, a country, an ASN, a username, a password, a tag or a URL opens the matching filtered view. Filters live in the URL, so every view can be shared.
- **Calm real-time.** New events slide into feeds and counters animate softly. Nothing flashes or jumps.
- **Generous whitespace**, clear hierarchy and readable numbers (tabular figures, thousands separators). Times are stored in UTC and shown in the browser's time zone.
- **Fast.** Lists are virtualized, queries are paginated server-side, and pages load in under 1 s on demo data.
- **Accessible.** WCAG AA contrast, keyboard navigation, no meaning carried by colour alone.

### Pages

The core pages are below. Later milestones added Today, Campaigns, Techniques, Scripts, Infrastructure, Blocklists, Detections, Exposure, CVEs, Alerts and Report (`web/src/pages/`, described in `docs/ui.md`). Design tokens and base components are documented in `web/DESIGN.md`.

1. **Live**: a 3D globe with attack arcs landing on Switzerland, next to a live event feed. The "wow" screen to leave running.
2. **Overview**: 4 KPIs (attacks in 24 h, unique IPs, sessions with commands, malware attempts), activity per sensor over time, top countries, and 3 auto-written insights.
3. **Attacks**: the list of sessions, filterable by sensor, country, tag and period. Each row is a one-line story, e.g. "45.x.x.x (Netherlands, DigitalOcean) tried 37 SSH passwords, then ran a crypto-miner".
4. **Session detail**: the attack timeline; for SSH and Telnet, an xterm.js **terminal replay** at real speed; an IP panel (reputation, other visits).
5. **Attackers**: profiles by IP and by ASN: first and last seen, sensors targeted, AbuseIPDB score, known scanner or not.
6. **Trends**: top usernames, passwords, commands and URLs, tags over time, a day × hour heatmap, and "new this week" (never seen before).
7. **Malware**: recorded download URLs and, if payload fetching is enabled, hashes with VirusTotal links.
8. **Settings**: sensor status, enrichment quotas, retention.

## 5. Security and isolation (non-negotiable)

- **Sensors never execute attacker input.** The fake shell is pure emulation: no `subprocess`, `os.system`, `eval` or `exec`, and no file write outside its own data path. Fake commands return canned or generated output from a fake filesystem.
- **Downloads.** By default, only record the URL. Payload fetching (`FETCH_PAYLOADS=false` by default), when enabled, is done by ingest, not by the sensors: size cap, timeout, stored in a quarantine volume under its sha256 name, mode 0400, never executed, never committed.
- **Containers.** Non-root user, `read_only: true` with tmpfs where needed, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, memory, CPU and pids limits, healthchecks. Sensors listen on high ports inside the container, and compose maps host 22 → container 2222, etc., so no capability is needed.
- **Abuse resistance.** Cap concurrent connections per sensor and per IP, set timeouts everywhere, and limit the size of every captured field. A retention job keeps raw events for 90 days and aggregates forever. Make sure disk usage cannot explode.
- **Never** bind host port 22222 (admin SSH) from any service. The dashboard port is never one of the sensor ports.
- **Dashboard auth.** One admin account, with an argon2 password hash taken from `.env`. httpOnly + Secure + SameSite session cookie, CSRF protection, rate-limited login. Assume it also sits behind Cloudflare Access.
- **No offensive behaviour.** No counter-scans, no hacking back, and no automatic reporting to AbuseIPDB without the owner's explicit approval.
- **Fake services must look real.** Plausible banners and versions (e.g. an OpenSSH banner from a recent Ubuntu, a fake hostname such as `srv-web01`, never "honeypot" or "suckerpot" anywhere a client could see it).

## 6. Public repo hygiene

**Never commit:**
- `.env`, API keys, tokens, passwords or password hashes;
- `ENVIRONMENT.local.md`;
- the owner's private IPs, hostnames, admin ports, public IP or network layout;
- captured data: attacker IPs, credentials, sessions, payloads, DB dumps;
- GeoLite2 `.mmdb` files (licence);
- SSH host keys generated by sensors;
- screenshots containing real attack data.

**Safeguards:**
- `.gitignore`, and a `.env.example` with placeholders only;
- a gitleaks pre-commit hook, plus gitleaks in CI;
- before every commit, the orchestrator reads `git diff --staged` and checks it against the list above;
- in docs and examples, use the documentation IP ranges `192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24`, never real addresses.

**If something sensitive was pushed:** stop, tell the owner immediately, and rotate the secret. Deleting it in a new commit is NOT enough, because it stays in the git history.

## 7. Repo conventions

```
suckerpot/
├── docker-compose.yml
├── justfile
├── .env.example
├── sensors/           # common/ (Event schema) + one dir per sensor
├── ingest/            # consumer, enrichment, rules/*.yaml
├── api/               # FastAPI app, also serves web/dist
├── web/               # React app
├── db/                # migrations
├── scripts/demo/      # demo data generator
└── docs/              # ROADMAP, PROGRESS, ARCHITECTURE, SECURITY
```

### Commands

Python, Node and Playwright never run on the host: every `just` recipe runs inside a pinned container (uv image per Python package, Node image for `web/`). Full list: `just` or `docs/development.md`.

| Command | What it does |
| --- | --- |
| `just up` / `just down` / `just logs ingest api` | Stack lifecycle (`up` waits for healthy) |
| `just up-test` | Stack with dashboard auth OFF (`docker-compose.ci.yml`); needed by `ssh-test`, `telnet-test`, `rdp-test`, `http-test` |
| `just check` | `lint` + `typecheck` (mypy strict) + `test` + `web-build` |
| `just test` | Unit tests of every Python package (`-m 'not integration'`) then vitest |
| `just test-integration` | `-m integration` tests in `db`, `ingest`, `api`, against a throwaway compose project (never the live volumes) using the `docker-compose.it.yml` overlay. Needs every `REDIS_SENSOR_*_PASSWORD` set (≥ 24 chars) |
| `just web-dev` / `just screenshots` | Vite on mock data (`VITE_MOCK=1`, `web/src/mocks`) / Playwright 1440+390, dark+light, into `web/screenshots` |
| `just demo --sessions 200 --days 3` | Push demo events into Redis |

The package list for Python recipes is the `packages` variable in the `justfile`; a new package must be added there and to the CI `python` job.

Run a single Python test (adapt `-w`):

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" -v suckerpot-uv-cache:/cache -w /work/sensors/ssh \
  -e HOME=/tmp -e UV_CACHE_DIR=/cache -e UV_LINK_MODE=copy -e UV_PROJECT_ENVIRONMENT=/tmp/venv \
  ghcr.io/astral-sh/uv:0.8.24-python3.13-bookworm-slim uv run pytest -q tests/test_shell.py -k some_name
```

Run a single web test: `just _web "pnpm exec vitest run src/pages/today.test.tsx"`.

Every sensor has `tests/test_static.py`, which scans the sensor's own source and fails on `subprocess`/`eval`/`exec`, outbound sockets and writes outside its data path: §5 is enforced by tests, keep them passing rather than editing them.

### Conventions

- **Commits**: Conventional Commits (`feat(ssh): ...`, `fix(web): ...`). Small and focused.
- **Branches**: one `feat/<milestone>` branch per milestone, fast-forward merged into `main` once the Definition of Done is met, then pushed.
- **Docker images**: every service has a multi-stage Dockerfile with pinned base image versions and a healthcheck.
- **Configuration**: everything through environment variables, documented in `.env.example`.

## 8. Definition of Done (each milestone)

- [ ] `docker compose up -d --build`: all services healthy.
- [ ] Tests, lint and typecheck green (Python and web).
- [ ] For UI work: screenshots reviewed by `ui-designer`, desktop and mobile, dark and light.
- [ ] `security-reviewer` passed, if sensors, networking, auth or compose changed.
- [ ] Docs updated, `docs/ROADMAP.md` ticked, entry appended to `docs/PROGRESS.md`.
- [ ] Staged diff reviewed for §6, merged to `main` and pushed.
