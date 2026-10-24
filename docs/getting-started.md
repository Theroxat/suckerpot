# Getting started

This page shows how to run SuckerPot on a single host with Docker Compose. It also covers the warnings you must read first.

## Read this first

```{warning}
**SuckerPot is designed to be attacked.** Once its ports face the internet, bots will probe it within minutes. Expect constant scans, login attempts and exploit traffic.

- Use a **dedicated machine or VM** that you are ready to lose. Do not reuse a machine that holds other work.
- **Never keep credentials that matter on the host.** No cloud keys, no SSH keys for other systems, no password manager exports and no personal files.
- **Do not run SuckerPot on a machine that you also use for development.** Development tools often keep tokens in plain files.
- **Do not expose the dashboard directly to the internet.** Reach it through a reverse tunnel. See [Deployment](deployment.md).
```

## Requirements

| Requirement | Notes |
| --- | --- |
| A Linux host, such as a VM | Dedicated and isolated (see the warning above) |
| Docker Engine | With the Compose plugin (`docker compose version` must work) |
| `just` | Optional, but recommended. It wraps the common commands. |
| About 4 GB of RAM | The database and the Python services need the memory. Smaller hosts may swap. |

No Python, Node.js or database has to be installed on the host. Everything runs in containers.

## 1. Get the code

```bash
git clone https://github.com/<your-account>/suckerpot.git
cd suckerpot
```

Use the URL of your own fork or of the project repository.

## 2. Create your `.env` file

Copy the template and edit it:

```bash
cp .env.example .env
```

Every `change-me` value must be replaced. Each secret must be at least 24 characters, and no two secrets may be equal. Generate each one separately:

```bash
openssl rand -base64 32
```

Also set the dashboard login: `SESSION_SECRET` (at least 32 bytes) and `ADMIN_PASSWORD_HASH` (make it with `docker compose run --rm api python -m api.hashpw`, and put it in `.env` in single quotes). See [Deployment](deployment.md#dashboard-login).

The stack refuses to start with a short or repeated secret, and the error names the variable (never its value). Do not commit `.env` to git. The full list of variables is in [Configuration](configuration.md).

```{note}
Passwords and secrets are read by the containers at start-up. If you change one later, restart the stack with `docker compose up -d`.
```

## 3. Start the stack

```bash
docker compose up -d --build --wait
```

`--wait` returns when every service is running and healthy. The first build takes a few minutes.

With `just`, the same command is:

```bash
just up
```

To check the state of the services:

```bash
docker compose ps
```

## 4. Load demo data

The database is empty on the first start. Load demo data so the dashboard has something to show:

```bash
just demo
```

This generates synthetic attacks for the last 30 days. See [Demo data](demo-data.md) for the options.

```{warning}
Demo data is fake. Do not mix it with real captures. To start clean, stop the stack and delete the database volume. Deleting a volume removes all its data.
```

## 5. Open the dashboard

The dashboard port is set by `DASHBOARD_PORT` in `.env` (8443 in the template). By default it binds to `127.0.0.1`, so only the host itself can reach it. From the host:

```bash
curl -s http://127.0.0.1:8443/healthz
```

The `/healthz` path returns `{"status": "ok", "db": "ok"}` when the API can reach the database. The live feed is at `/api/v1/live` (WebSocket). See [API](api.md).

The dashboard itself is served on the same port once the web app is built (`just web-build` creates `web/dist`). See [Dashboard](ui.md) for the pages. The dashboard has a login (M8): set `ADMIN_PASSWORD_HASH` and `SESSION_SECRET` first, as described in [Deployment](deployment.md#dashboard-login). `just up` refuses to start without them. For a throwaway local trial, `just up-test` starts the stack with the login off (it uses `docker-compose.ci.yml`). Never use that on a host that other people can reach. To sign in over plain HTTP on your own machine, set `COOKIE_SECURE=false`.

```{note}
The API documentation pages (`/docs`) are off by default. To turn them on while you develop, set `API_ENABLE_DOCS=true` and restart the stack. Keep them off on any host that is reachable from outside.
```

## Stop and clean up

| Command | Effect |
| --- | --- |
| `just down` or `docker compose down` | Stops the containers. Data volumes are kept. |
| `docker compose down -v` | Stops the containers **and deletes all data volumes**. This cannot be undone. |

## Next steps

- [Deployment](deployment.md): the go-live checklist, the host firewall and secret rotation.
- [Sensors](sensors/index.md): what each fake service does and records.
- [Dashboard](ui.md): the pages and the screenshot mode.
- [Configuration](configuration.md): every setting.
- [Architecture](ARCHITECTURE.md): how the services fit together.
