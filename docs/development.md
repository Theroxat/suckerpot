# Development

This page is for people who change the code. It explains the repository layout, the tools and how to run them. The tools run inside containers, so the host needs only Docker and `just`.

## Ground rules

- **English everywhere.** Code, comments, commit messages, docs and UI strings.
- **The repository is public.** Never commit `.env`, captured data, screenshots of real attacks, private IP addresses or host names. Use the documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) in examples.
- **Docker Compose only.** Every component is a service in `docker-compose.yml`.
- **Read the [Security](SECURITY.md) page** before you change a sensor, the network layout or a Dockerfile.

## Set up

1. Install Docker with the Compose plugin, and `just`.
2. Install the git hooks, once:

   ```bash
   scripts/install-hooks.sh
   ```

   The script installs `pre-commit` if it can, and falls back to a plain git hook. Both run `gitleaks` before each commit and block commits that contain secrets. The fallback installs a pinned `gitleaks` binary in `~/.local/bin`.

3. Create your `.env`, as described in [Getting started](getting-started.md).

## Common commands

All commands are `just` recipes. Run `just` with no arguments to list them.

| Recipe | What it does |
| --- | --- |
| `just up` | Build the images and start the stack. Waits until everything is healthy. |
| `just down` | Stop the stack. Data volumes are kept. |
| `just logs [service ...]` | Follow the logs. For example, `just logs ingest api`. |
| `just ps` | Show the state of the services |
| `just config` | Check that `docker-compose.yml` is valid |
| `just demo [args]` | Generate demo data. For example, `just demo --sessions 200 --days 3`. |
| `just demo-live` | Keep sending demo traffic until you press Ctrl+C |
| `just psql` | Open a `psql` shell as the database owner, inside the database container. Use it for maintenance only. |
| `just lint` | Run `ruff check` and `ruff format --check` on every Python package |
| `just fmt` | Fix and format the Python code with `ruff` |
| `just typecheck` | Run `mypy` (strict) on every Python package |
| `just test` | Run the unit tests of every Python package. Integration tests are skipped. |
| `just test-integration` | Run the integration tests against a database and Redis. It uses its own throwaway compose project (`<project>-it`) and removes its volumes afterwards, so your real data is never touched. |

`just lint`, `just typecheck` and `just test` run in the pinned `uv` image. The virtual environments live inside the container, and the `uv` download cache lives in a Docker volume. Nothing is written to the repository.

## Repository layout

```
suckerpot/
├── docker-compose.yml      # all services, networks and volumes
├── justfile                # task runner
├── .env.example            # configuration template (placeholders only)
├── redis/                  # Redis image and the ACL entrypoint
├── sensors/
│   └── common/             # suckerpot-common: the shared Event schema
├── ingest/                 # suckerpot-ingest: consumer and writer
├── api/                    # suckerpot-api: FastAPI app
├── db/                     # suckerpot-db: SQLAlchemy models and Alembic migrations
├── scripts/
│   ├── demo/               # suckerpot-demo: demo data generator
│   └── install-hooks.sh    # git hooks (gitleaks)
└── docs/                   # this documentation site
```

Sensors other than `common` (SSH, Telnet, Web and RDP) are planned.

## Python packages

Each package has its own `pyproject.toml` and a committed `uv.lock`. The code targets Python 3.13. The tools are `uv`, `ruff` (line length 100), `mypy` (strict) and `pytest`.

| Directory | Distribution name | Import name | Purpose |
| --- | --- | --- | --- |
| `sensors/common` | `suckerpot-common` | `suckerpot_common` | Event model, stream helpers, Redis publisher |
| `scripts/demo` | `suckerpot-demo` | `demo` | Demo data generator |
| `db` | `suckerpot-db` | `suckerpot_db` | Models and migrations |
| `ingest` | `suckerpot-ingest` | `ingest` | Redis consumer, validation and database writes |
| `api` | `suckerpot-api` | `api` | REST API |

Packages depend on each other by path. For example, `ingest` depends on `suckerpot-common` and `suckerpot-db`.

## Docker images

Every service image is built from a multi-stage Dockerfile:

- A pinned Python base image (`python:3.13.x-slim-bookworm`).
- The `uv` binary copied from a pinned `uv` image.
- A final stage with a non-root user, no build tools and `PYTHONDONTWRITEBYTECODE=1`.
- A health check.

Build contexts are the repository root for the Python services, so that path dependencies resolve.

## Commits and branches

- Use [Conventional Commits](https://www.conventionalcommits.org/): `feat(ingest): ...`, `fix(api): ...`, `docs: ...`, `chore: ...`.
- Keep commits small and focused.
- Work on a branch per milestone (`feat/m1`, and so on). Merge it into `main` when the milestone is done.

## Continuous integration

The GitHub Actions workflows run on every push and pull request to `main`:

| Workflow | Checks |
| --- | --- |
| `ci.yml`, job `gitleaks` | Scans the full git history with `gitleaks` |
| `ci.yml`, job `python` | Lint, type check and unit tests of each Python package |
| `ci.yml`, job `web` | Lint, type check and tests of the web app, when `web/` exists |
| `ci.yml`, job `python-integration` | Integration tests against a real database and Redis |
| `ci.yml`, job `compose` | Builds the stack, checks the API health endpoint, runs the demo, and waits until ingest has stored sessions |
| `docs.yml` | Builds this documentation site with warnings treated as errors |

The `compose` job is the only place where the placeholder secrets are allowed. It sets `SUCKERPOT_ALLOW_DEFAULT_SECRETS=1` in a throwaway `.env`. Never copy that setting to a real host.

Read the Docs builds the site from `.readthedocs.yaml`, using the same pinned requirements.

## Building these docs locally

The docs use Sphinx with MyST Markdown. The versions are pinned in `docs/requirements.txt`. Build them in a container, so nothing is installed on the host:

```bash
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD:/work" -w /work python:3.13-slim \
  sh -c 'pip install --quiet --user -r docs/requirements.txt && python -m sphinx -W --keep-going -b html docs /tmp/docs-html'
```

The build must finish with no warnings. The output goes to `/tmp` inside the container, so the repository stays clean.

## Before you commit

1. Run `just lint`, `just typecheck` and `just test`.
2. Read `git diff --staged`. Look for secrets, private addresses, host names and captured data.
3. Commit with a Conventional Commit message.
