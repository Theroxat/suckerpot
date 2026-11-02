# Selfhostr network hub: operator guide

The hub is the server of the Selfhostr network. It takes the daily batches from member systems, confirms the targets that enough independent sensors agree on, sends abuse reports for them, and publishes the network's figures. It is a separate deployment. It lives in `hub/`, with its own `docker-compose.yml`, its own database and its own migrations.

This guide is for the person who runs a hub. For what members see and share, read [The Selfhostr network](../docs/network.md). For the wire format, read [Network protocol](../docs/network-protocol.md). The design and its review are in [M29](../docs/design/m29.md).

Every example uses placeholders. The public name is `hub.example.org`, and addresses come from the documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).

## Where to run the hub

Run the hub on its own host, not on a member's connection.

- **Never on a home line.** A member's home address must never be the hub's address, and must never be the address that sends abuse reports. A home line also changes IP addresses and goes down often.
- **Not on a sensor host.** Keep the hub off any machine that runs a sensor or a member's dashboard.
- **A machine you can dedicate.** A small virtual server in a data centre is the usual choice.

The host needs:

| Need | Why |
| --- | --- |
| A public IPv4 address (IPv6 if you can) | Members connect to it. Caddy also needs it for the certificate |
| Inbound TCP 80 and 443 | Let's Encrypt validation and the HTTPS API |
| A DNS record for `HUB_DOMAIN` that points at the host | Caddy gets its certificate for this name |
| Outbound access | RDAP (to find abuse contacts), the report mailbox (SMTP over TLS), and the optional lookup sources |
| Docker with Compose | Everything runs in containers |
| 2 GB of RAM or more, and 2 vCPUs | The compose file sets a memory limit on each service |

The hub's address becomes public the first time a member joins. Treat the host as public from day one.

## Architecture

| Service | Networks | What it does |
| --- | --- | --- |
| `caddy` | `hub-edge`, `hub-public` | Terminates TLS for `HUB_DOMAIN`, proxies `/v1/*` only, writes no logs |
| `hub-api` | `hub-edge`, `hub-internal` | The signed API (FastAPI and uvicorn), no access log |
| `hub-worker` | `hub-internal`, `hub-out` | Hourly consensus, takedown votes, reputation, statistics, retention, reports. The only service with outbound traffic |
| `hub-db` | `hub-internal` | PostgreSQL 17, with connection and statement logging off |
| `hub-migrate` | `hub-internal` | One-shot: runs the migrations and sets the three database role passwords |
| `hub-admin` | `hub-internal` | Operator CLI, in the `tools` profile. Run it with `docker compose run --rm hub-admin ...` |
| `hub-backup` | `hub-internal` | Daily `pg_dump`, seven kept |

`hub-edge` and `hub-internal` are internal networks. Only Caddy has a port on the host, and only the worker reaches the outside.

Three database roles keep the parts apart. `hub_api` can write nodes, nonces, challenges and observations. `hub_worker` can do everything except change the schema. The migration owner is used only by `hub-migrate`.

## First deployment

1. Create the two external volumes. Their names are `<HUB_VOLUME_PREFIX>_db-data` and `<HUB_VOLUME_PREFIX>_backups`. For example, with the prefix `hubprod`:

   ```bash
   docker volume create hubprod_db-data
   docker volume create hubprod_backups
   ```

   The volumes are external on purpose. Compose cannot delete them, and `docker compose down -v` does not touch them.

2. Create the environment file from the template, and fill in every empty value. Use 24 or more characters for each password, all different, with letters, digits, `-` and `_` only.

   ```bash
   cd hub
   cp .env.example .env
   ```

3. Make the signing key. The key is an Ed25519 seed in a file that only the hub can read. Keep the directory and the file out of Git.

   ```bash
   mkdir -p secrets
   sudo chown 10001 secrets
   sudo chmod 700 secrets
   docker compose run --rm hub-admin gen-signing-key --out /keys/hub_signing_key
   docker compose run --rm hub-admin show-public-key --key-file /keys/hub_signing_key
   ```

   The second command prints `hub_key=...`. This is the public key. Publish it to members as `NETWORK_HUB_KEY`, together with `NETWORK_HUB_URL=https://hub.example.org`, through a channel you control.

4. Start the stack and wait for the health checks:

   ```bash
   docker compose up -d --build
   docker compose ps
   ```

   `hub-migrate` runs first, applies the migrations and sets the role passwords. Then `hub-api`, `hub-worker` and `caddy` start. Caddy gets its certificate on the first request.

5. Check the API from a machine outside the hub:

   ```bash
   curl -s https://hub.example.org/v1/info
   ```

   The answer lists `protocols`, `hub_key`, `pow`, `limits`, `thresholds` and `today`. The `hub_key` must match the key you printed in step 3.

### Upgrades

Pull the new code, then run `docker compose up -d --build` from `hub/`. Migrations run again on their own. The worker runs one copy only. Keep it that way.

## Configuration

Set these in `hub/.env`. The defaults are the values in the code, and in `.env.example` where the template sets them.

### Secrets and identity

| Variable | Default | Meaning |
| --- | --- | --- |
| `HUB_DOMAIN` | none (required) | Public name of the hub. Members use it as `NETWORK_HUB_URL` |
| `HUB_VOLUME_PREFIX` | none (required) | Prefix of the two external volumes |
| `HUB_DB_PASSWORD` | none (required) | Database owner. Used by `hub-db`, `hub-migrate` and `hub-backup` |
| `HUB_API_DB_PASSWORD` | none (required) | Role `hub_api` |
| `HUB_WORKER_DB_PASSWORD` | none (required) | Role `hub_worker` |
| `HUB_SIGNING_KEY_PATH` | `./secrets/hub_signing_key` | Host path of the signing key file, mounted as a Docker secret |
| `HUB_SIGNING_KEY_DIR` | `./secrets` | Host directory that `hub-admin` writes the key into. It must be the directory of `HUB_SIGNING_KEY_PATH` |

The signing key is never read from the environment. Only its file path is.

### Enrolment and proof of work

| Variable | Default | Meaning |
| --- | --- | --- |
| `HUB_POW_DIFFICULTY` | `27` | Base difficulty in bits, from 0 to 40 |
| `HUB_ENROL_SOFT_CAP` | `3` | Challenges one address prefix may draw in 10 minutes before the price rises |
| `HUB_ENROL_STEP` | `3` | Further challenges per extra bit above the soft cap |
| `HUB_ENROL_HARD_CAP` | `5000` | Enrolments per UTC day in total. More are refused with `enrolment_closed` |
| `HUB_CHALLENGES_PER_PREFIX` | `20` | Challenges one address prefix may request per 10 minutes |

The price is per address prefix. An IPv4 address is its own prefix. An IPv6 address counts as its /64. A flood from one prefix raises that prefix's price only. See the protocol page for the full rule.

### Consensus

| Variable | Default | Meaning |
| --- | --- | --- |
| `HUB_MIN_NODES` | `5` | Eligible nodes that must see a value before it is confirmed. Also the number of nodes that must fetch a dropper |
| `HUB_MIN_WEIGHT` | `3.0` | Total reputation of those nodes. A node counts at most 1.0 |
| `HUB_NODE_MIN_AGE_DAYS` | `14` | Days a node must be enrolled before its sightings count |
| `HUB_NODE_MIN_ACTIVE_DAYS` | `7` | Days with data in the last 14 that a node needs to count, from 0 to 14 |
| `HUB_MIN_REPUTATION` | `0.3` | Lowest reputation that counts |
| `HUB_WINDOW_DAYS` | `7` | Days of sightings that one consensus run looks at, from 1 to 14 |
| `HUB_COHORT_MAX_SHARE` | `0.5` | Most of the nodes one enrolment week may supply |
| `HUB_OBS_RETENTION_DAYS` | `14` | Days to keep per-node observations, from 1 to 60 |

Lower the thresholds only on a test hub. A smaller `HUB_MIN_NODES` makes the network easier to poison.

### Reports

| Variable | Default | Meaning |
| --- | --- | --- |
| `HUB_REPORT_MODE` | `review` | `review`: an operator approves each report. `auto`: sent after the hold, when the rules below allow it. `off`: nothing is queued |
| `HUB_REPORT_HOLD_HOURS` | `24` | Hours a queued report waits before an automatic approval (`auto` mode) |
| `HUB_AUTO_MIN_COHORTS` | `5` | Independent enrolment weeks among eligible nodes before `auto` mode may approve anything |
| `HUB_REPORT_DAILY_CAP` | `100` | Reports sent per day, all recipients together |
| `HUB_REPORT_TEMPLATE_FILE` | empty | Path of a file on the hub host with the wording. Empty means facts only |
| `HUB_REPORT_REPLY_TO` | empty | Reply address written into the reports |
| `HUB_SMTP_HOST`, `HUB_SMTP_PORT` | empty, `587` | The project's report mailbox |
| `HUB_SMTP_USER`, `HUB_SMTP_PASSWORD` | empty | Login for that mailbox. The password is never logged |
| `HUB_SMTP_FROM` | empty | Sender address |
| `HUB_SMTP_STARTTLS` | `true` | Upgrade the connection with STARTTLS |

Keep the wording out of Git. Put it in a file on the host and point `HUB_REPORT_TEMPLATE_FILE` at it.

### Corroboration

| Variable | Default | Meaning |
| --- | --- | --- |
| `HUB_ABUSEIPDB_KEY` | empty | Optional. Lets the hub check an address with AbuseIPDB. About 900 checks a day, cached for 24 hours |
| `HUB_GREYNOISE_KEY` | empty | Optional. Lets the hub check an address with GreyNoise. About 40 checks a day, cached for 24 hours |

Without a key, a source is off. Addresses then need 10 nodes instead of 5. The lookup sends only public attacker addresses to the source. No node data is sent.

### Limits and worker

| Variable | Default | Meaning |
| --- | --- | --- |
| `HUB_RATE_UNSIGNED_PER_MIN` | `10` | Unsigned requests per address, per minute |
| `HUB_RATE_UNSIGNED_PER_DAY` | `100` | Unsigned requests per address, per day |
| `HUB_RATE_SIGNED_PER_HOUR` | `60` | Signed requests per node, per hour |
| `HUB_REVEALS_PER_DAY` | `2000` | Reveals per node, per day |
| `HUB_NEW_VALUES_PER_DAY` | `20000` | New values per node and day. More are dropped and counted as `cap` |
| `HUB_WORKER_INTERVAL_S` | `3600` | Seconds between worker cycles, at least 5 |

### Test overlay only

| Variable | Default | Meaning |
| --- | --- | --- |
| `HUB_ALLOW_DOCUMENTATION` | off | Accepts documentation address ranges. Never set it on a real hub |
| `HUB_TRUST_PROXY` | set to `1` by compose on `hub-api` | Reads the client address from the forwarding header that Caddy sets. Used only for the in-memory rate limits |

Every variable `hub/hub/config.py` reads is passed through by `hub/docker-compose.yml` with the same default, except the few that compose sets itself (database URLs, signing key path, proxy trust) or that exist only for tests; `hub/tests/test_compose_env.py` fails if one is missing.

## Privacy: what is and is not logged

The hub is designed so that no client IP address is stored or logged.

| Layer | What it does |
| --- | --- |
| Caddy | Log output is discarded globally, and per site. No access log |
| `hub-api` | uvicorn runs with `--no-access-log --no-server-header`, and the log level is `warning` |
| Application | A logging filter rewrites any record that contains an IPv4 or IPv6 address, a node key or a long hex string |
| Rate limits | Kept in memory only, keyed by an HMAC of the address with a random key that changes every day |
| Database | No IP column in any table. `log_connections`, `log_disconnections` and `log_statement` are off |
| Tests | `hub/tests/test_privacy.py` checks these rules, including the Caddyfile and the uvicorn command |

What the operator must still take care of:

- **The host.** The hub cannot control the host's own logs. SSH logs, firewall logs and the Docker daemon's logs can show addresses. Keep them off, or keep them private and short-lived.
- **Your own changes.** Do not add access logs, request logging or a debug mode to the containers. Do not put a client address in a table, a file or a report. The privacy tests will catch some of this, not all.
- **The reverse proxy in front.** If you put a second proxy or a CDN in front of Caddy, its logs are outside this design. Use Caddy alone, or make sure the front proxy also logs nothing.
- **Backups.** A dump holds node keys and observations, but no client addresses. See [Backups](#backups).

## Reports

### What a report contains

A report covers a group of targets. It goes to one recipient, usually an abuse desk for the address's network, and it contains:

- the day range of the evidence;
- the services and the kind of activity;
- behaviour tags and malware families;
- the number of sensors, as a range (5 to 9, 10 to 24, 25 or more) and the number of countries, shown only from three countries up;
- for a download, the SHA-256 and the link, once the link is confirmed;
- for a command server, the address or domain, the port and the family.

A report never contains a node id, a pseudonym, a fingerprint, a node's address, or an exact count. It is sent as plain text and as X-ARF. Headers are neutral: no project name, and no mailer name.

### What gets reported

- An address with a severe activity (a login that worked, a command, a download or an exploit) from enough nodes, or with 100 or more login attempts from enough nodes.
- A link or a file-hosting domain that at least two nodes fetched, once the link is confirmed.
- A command server that is confirmed. Command servers are always reported by hand.

Scans and connections alone are never reported. A target that has been reported is not reported again. A target that came back after a takedown can be reported again, but only when its earlier report is more than 30 days old.

### The flow

1. Each worker cycle (hourly) queues reports for reportable targets, one per recipient and kind. A recipient gets at most one new report per kind every 7 days. A failed report is retried after a day.
2. In `review` mode (the default), the queued report waits.
3. In `auto` mode, the report is approved once the hold is over. Auto mode stays closed until `HUB_AUTO_MIN_COHORTS` independent enrolment weeks exist. It never approves a command-server report.
4. Approved reports are sent. At most one mail per recipient per day, and at most `HUB_REPORT_DAILY_CAP` in total. A failed send blocks that recipient for a day.

### The operator's review

In `review` mode, review each report before you approve it. The CLI runs in the `hub-admin` container:

```bash
docker compose run --rm hub-admin reports list --state queued
docker compose run --rm hub-admin reports show 42
docker compose run --rm hub-admin reports approve 42
docker compose run --rm hub-admin reports cancel 42
```

Before you approve, check:

- **The targets.** Is each address really an attacker, and not a shared service? A public resolver, a large CDN or a package mirror should be on the never-list (`never add`), not in a report.
- **The timing.** Does the day range make sense? A single odd day can be a probe from a member. Ask whether the evidence would also fit a test from your own network.
- **The recipient.** Is the abuse contact the one for that network? The hub gets it from RDAP.
- **Command servers.** Check the dropper that named the server. A command server that only one file vouches for is a weak case.
- **The wording.** The facts must match the evidence. If the wording is empty, the report states the facts only.

Cancel a report when you are not sure. A cancelled report blocks the same target for 30 days, so cancel only what you are willing to leave alone.

### Reports in auto mode

Use `auto` only after you have run `review` for a while and trust the consensus. Keep the hold at least 24 hours, so that you can cancel. Watch the report count. Switch back to `review` if a bad pattern shows up. Command servers still wait for you.

### Abuse handling

When a desk replies, or a member or someone else reports a mistake:

- `target dispute <id> --note "..."` marks the target disputed, and lowers the reputation of the nodes that supported it. Use it when a report was wrong.
- `never add <value> --kind ip|domain|sha256 --note "..."` puts a value on the never-list. The hub stops confirming it, and recheck disputes any confirmed target that matches.
- `node suspend <fingerprint>` (and `unsuspend`) stops a node's data from counting. The node is not told.

Each CLI action that changes state writes an entry to `hub_audit`, with the actor and the action. The audit holds no node data.

## Operator CLI

```bash
docker compose run --rm hub-admin <command>
```

| Command | What it does |
| --- | --- |
| `gen-signing-key --out /keys/hub_signing_key` | Makes the signing key. Refuses to overwrite unless `--force` is given. The file is mode 0400 |
| `show-public-key --key-file /keys/hub_signing_key` | Prints `hub_key=...` |
| `reports list [--state queued\|approved\|sent\|failed\|cancelled]` | Lists reports |
| `reports show <id>` | Shows a report's text and targets |
| `reports approve <id>` | Approves a queued report. It is sent by the next worker cycle |
| `reports cancel <id>` | Cancels a report |
| `target dispute <id> --note "..."` | Disputes a target |
| `never add <value> [--kind ip\|domain\|sha256] [--note "..."]` | Adds a value to the never-list |
| `never remove <value>` | Removes a value from the never-list |
| `never list` | Lists the never-list |
| `node suspend <fingerprint>` / `node unsuspend <fingerprint>` | Suspends or restores a node |
| `stats` | Prints the figures |

There is no web admin. The CLI keeps the attack surface small.

## What the worker does

Each cycle runs these steps. A failing step is logged by type and does not stop the others.

1. Seeds the built-in never-list (public resolvers, large CDN and SaaS domains, update servers, package registries).
2. Runs consensus over the window, confirming or keeping candidates.
3. Reads the takedown votes.
4. Re-checks the never-list against confirmed targets.
5. Expires targets that nobody has seen for 30 days.
6. Once a day: reputation, weekly member statistics and the network summary.
7. Runs retention.
8. Queues, approves and sends reports, if the mode allows it.
9. Writes a heartbeat. The container health check fails when the heartbeat is older than three cycles.

Takedown votes come from members' local re-checks. Members do not send those yet in this release, so no target moves to `taken_down` for now. See [Takedown checks](../docs/network.md#takedown-checks).

## Retention

| Data | Kept for |
| --- | --- |
| Per-node observations | `HUB_OBS_RETENTION_DAYS` (14) |
| Batch markers | 14 days |
| Nonces and enrolment challenges | Until they expire (10 minutes) |
| Contributor links | Until the target is resolved, or 30 days |
| Takedown votes | 30 days |
| Weekly member statistics | 8 weeks |
| Candidate targets that nobody saw again | 14 days |
| Expired targets | 180 days after their last update |
| Recipient log (report counts per day) | 90 days |
| Reports sent, failed or cancelled | 365 days |
| Nodes with no request for 30 days | Deleted, with everything linked to them |

## Backups

The `hub-backup` service runs `pg_dump` once a day, in custom format. It keeps the seven newest dumps in the `<HUB_VOLUME_PREFIX>_backups` volume. The health check is healthy while a dump is less than 26 hours old.

A dump holds the node public keys, pseudonyms, countries that members showed, enrolment days, the last 14 days of observations, the report texts and the audit log. Treat the volume as sensitive:

- keep it on a private disk, and do not copy it to shared storage unless it is encrypted;
- do not put dumps in a bug report or a chat;
- delete old dumps when you no longer need them.

### Restoring

The repository has no restore script for the hub yet. A restore is manual:

1. Stop the services that write: `docker compose stop hub-api hub-worker`.
2. Restore the dump into `hub-db`, with `pg_restore --clean --if-exists` into the `hub` database, as the database owner.
3. Run `docker compose run --rm hub-migrate` to check the schema and the role passwords.
4. Start the stopped services again.

Be aware of two things. First, a dump older than a node's leave brings that node back into the database. Its key can no longer sign anything, because the node wiped its key, and the node is removed after 30 days of silence. Second, a restore loses everything written after the dump was taken.

### The signing key

Back up the signing key file separately, in a private and encrypted place. Do not store it in the same volume as the dumps. Without it, the hub cannot sign answers under the published key.

If the key is lost, make a new one with `gen-signing-key`, publish the new `hub_key`, and tell members to update `NETWORK_HUB_KEY`. Their node keys stay valid, so they do not need to join again.

If the key leaks, an attacker can sign fake answers that members would accept. Make a new key at once, publish it through a channel you trust, and ask members to update. Treat every answer signed in the time between as suspect.

## Health and monitoring

| Check | Healthy when |
| --- | --- |
| `hub-api` | `GET /healthz` on `127.0.0.1:8080` returns 200 |
| `hub-worker` | `python -m hub.worker --health`: the last heartbeat is less than three cycles old |
| `hub-db` | `pg_isready` answers |
| `hub-backup` | A dump is less than 26 hours old |
| `caddy` | Port 443 accepts connections |

Watch the queued reports and the figures from `stats`. A growing queue that nobody reviews is a risk: it stops the reports, or it leaves a target unreported for a long time.

## Tests

| Command | What it runs |
| --- | --- |
| `just test` | The unit tests of the hub (`-m 'not integration'`), with the other Python packages |
| `just hub-integration` | The integration tests against a throwaway PostgreSQL (`hub/docker-compose.test.yml`), with documentation ranges allowed, and an end-to-end flow: synthetic nodes enrolled with a low difficulty, aged, a worker run, reveals, rechecks, and a leave |

The integration run uses its own project name and its own volumes, and removes them at the end.

## Limits of this release

- No web admin. Everything is done through the CLI.
- No restore script yet (see [Restoring](#restoring)).
- Takedown votes are not sent by members yet, so no target becomes `taken_down`.
- Command-server reports are always reviewed by hand. The hub never connects to a target itself. A confirmed target is a judgement by consensus, not a proof.
