# API

The API is a FastAPI application. It reads the database and returns JSON. It also serves a live WebSocket feed, and the web UI once one is built. The API has no Redis access and cannot change data: it connects as the read-only role `suckerpot_api`.

```{admonition} Build status
:class: note

**Built:** sessions, events, summary, enrichment settings, the analytics endpoints (M5), insights, trends, malware and site settings (M7), the live WebSocket feed, and dashboard authentication (M8, security review passed).

**Planned:** API rate limits beyond the login limits.
```

## Base URL

Every example below uses the dashboard port on the host. With the default `DASHBOARD_PORT=8443`, and with the default bind address `127.0.0.1`, run the examples on the host itself:

```text
http://127.0.0.1:8443
```

## Authentication

Every `/api/v1` path needs a session, except `/api/v1/auth/*`. `/healthz` and the static web app stay public. There are two kinds of account: the owner from `.env`, and users with the role `admin` or `viewer` (see [Users and roles](configuration.md#users-and-roles)). A viewer can call every `GET` that an admin can, except the user and audit endpoints, and nothing that changes data: any other method needs an admin, unless it is sign in, sign out or changing one's own password, and the API answers `403` with `{"code": "admin_required"}`.

### Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/auth/login` | Body `{"username": "...", "password": "..."}`. Returns `204` and sets the cookies. `401` for wrong credentials, `403` for a cross-origin request, `429` with `Retry-After` when rate limited. |
| `POST` | `/api/v1/auth/logout` | Revokes the session and clears the cookie. Needs the CSRF token. Returns `204`. |
| `GET` | `/api/v1/auth/me` | Who is signed in: `username`, `display_name`, `role`, `is_owner`, `must_change_password`, `read_only` and `last_login_at` (the sign-in before this one). `401` otherwise. The web app uses it to decide what to show. |
| `POST` | `/api/v1/auth/password` | Body `{"current_password": "...", "new_password": "..."}`. Changes the signed-in user's own password and keeps this browser signed in; every other session of the user ends. `403` with `reauth_failed` for a wrong current password, `422` with `weak_password` for a rejected new one, `403` with `owner_password_in_env` for the owner. Allowed while `must_change_password` is true. |
| `GET` | `/api/v1/auth/csrf` | `{"token": "..."}` and sets the CSRF cookie. |

### Cookies

| Cookie | Flags | Content |
| --- | --- | --- |
| `__Host-sp_session` | `HttpOnly`, `Secure`, `SameSite=Strict`, path `/`, no `Domain` | A signed token with an expiry (`SESSION_TTL_HOURS`, default 12). No server-side session table. |
| `__Host-sp_csrf` | Readable by JavaScript, `Secure`, `SameSite=Strict`, path `/` | A signed anti-CSRF token, bound to the session |

The `__Host-` prefix makes the browser refuse the cookie unless it is `Secure`, set over HTTPS, for the exact host and without a `Domain`. That stops a sibling subdomain from planting or overwriting it. The prefix exists only when `COOKIE_SECURE=true` (the default). With `COOKIE_SECURE=false` the cookies are named `sp_session` and `sp_csrf` and lose the `Secure` flag. Use that **only for local development over plain HTTP**. In production the dashboard must be served over HTTPS (for example by the tunnel).

The session signing key is derived from `SESSION_SECRET`, the password hash **and a random value created at each API start**. So changing the password signs everybody out, and so does **every restart of the API** (including `docker compose up -d api` after a config change and a container restart). Logging out puts the session into a small in-memory revocation list, and logging in again revokes the previous session.

### CSRF protection (double submit)

Every `POST`, `PUT`, `PATCH` and `DELETE` must send the value of the CSRF cookie in an `X-CSRF-Token` header. The server checks that the two match and that the token carries a valid signature **for the current session**, so a cookie planted by another site, or a token from another session, is refused (`403`). Login is the one exception, because there is no session yet. It requires an `Origin` (or `Referer`) check:

- When `API_ALLOWED_ORIGINS` is set, the **full origin** (scheme, host and port, such as `https://dash.example.com`) must be in the list.
- When it is empty, the origin's host must equal the request's `Host` header, and the scheme is ignored.

A `401` means "sign in". A `403` means "bad or missing CSRF token", or a login from an origin that is not allowed. Call `GET /api/v1/auth/csrf` once and send the token on every unsafe request.

### Rate limits and costs

Login attempts are counted per client address and for the whole server, over a sliding 60 seconds: `LOGIN_RATE` (default 5) per address and `LOGIN_RATE_GLOBAL` (default 30) overall. IPv6 addresses are counted per `/64`, because one subscriber owns a whole `/64`. Beyond the limit the answer is `429` with a `Retry-After` header. A wrong password also costs a short fixed delay.

The password hash is always checked, whether or not the user name exists, so timing does not reveal the account name. Argon2 is expensive on purpose, so the API checks **one hash at a time**. When more than two checks are already waiting, further logins get `429` with `Retry-After` at once. A flood of login attempts can therefore slow down sign-in, but not the rest of the API.

Failed and successful logins are logged with the client address only. A submitted user name, password, hash or cookie is never logged.

### Client address behind a proxy

Behind a reverse proxy, every request seems to come from the proxy. Set `AUTH_TRUSTED_PROXIES` to the proxy's addresses as a comma-separated list of CIDR ranges. The API then reads `CF-Connecting-IP`, or else the rightmost `X-Forwarded-For` entry that is not itself a trusted proxy, **but only** when the connection comes from one of those addresses. From anyone else the headers are ignored, so nobody can fake their address. With the default (empty), the headers are never read.

### Allowed hosts

The API answers only to host names it expects (a "trusted host" check), which blocks Host-header tricks. `API_ALLOWED_HOSTS` (comma-separated host names) sets the list. Without it, the hosts of `API_ALLOWED_ORIGINS` are used. `localhost` and `127.0.0.1` are always allowed. When both variables are empty the API **allows any host and logs a warning**. In production, set one of them, for example to the tunnel's host name.

### WebSocket

The live WebSocket checks the session cookie in its handshake. Without a valid session the connection is closed with code `1008`. While it is open, the server rechecks the session every 5 seconds and closes with `1008` when it has expired or been revoked. The browser sends the cookie on its own for a same-site WebSocket.

### Single worker

The revocation list, the per-boot signing key and the login counters live in the memory of one process. Run the API with **one** uvicorn worker (the image's default command does). With several workers, a logged-out session could still work on another worker, and the login limits would multiply.

### Setting it up

1. Generate the password hash. The command prompts twice without echo and prints the hash:

   ```bash
   docker compose run --rm api python -m api.hashpw
   ```

2. Put it in `.env`, in **single quotes**. An argon2 hash contains `$` characters, which Compose would otherwise try to expand as variables:

   ```text
   ADMIN_PASSWORD_HASH='$argon2id$v=19$m=65536,t=3,p=4$...'
   ```

3. Set `SESSION_SECRET` to at least 32 random bytes (`openssl rand -base64 48`).
4. Start the stack. The API refuses to start when the hash or the secret is missing or weak.

See [Configuration](configuration.md#dashboard-authentication) for every variable.

## Interactive documentation

The OpenAPI pages are **off by default**. To turn them on while you develop, set `API_ENABLE_DOCS=true` in `.env` and restart the API. Then the following paths are served:

| Path | Content |
| --- | --- |
| `/docs` | Swagger UI |
| `/redoc` | ReDoc |
| `/openapi.json` | Raw OpenAPI schema |

These pages are generated from the code, so they match the running version. Use them for the exact field list. Turn them off again before you expose the port.

## Conventions

- Times are ISO 8601 in UTC, for example `2026-10-24T18:02:11Z`.
- Session lists use **keyset pagination**. Each list response has `items` and `next_cursor`. Pass `next_cursor` back as `cursor` to get the next page. When `next_cursor` is `null`, there are no more items.
- The cursor is opaque. Do not build it yourself. An invalid cursor returns `400`.
- `limit` must be between 1 and 200.
- Session IDs match `^[A-Za-z0-9_-]{1,64}$`. Other values are rejected.
- IP address filters are normalised. An invalid address returns `422`.
- Errors use the FastAPI shape: `{"detail": "..."}`.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz` | Health check. Checks the database. |
| `GET` | `/api/v1/events/recent` | The newest events, newest first |
| `GET` | `/api/v1/sessions` | List sessions, newest first |
| `GET` | `/api/v1/sessions/{session_id}` | One session |
| `GET` | `/api/v1/sessions/{session_id}/events` | Events of one session, oldest first |
| `GET` | `/api/v1/stats/summary` | Totals for the last 24 hours |
| `GET` | `/api/v1/settings/system` | Sensor status, retention policy, disk guard state and database size. See [System settings](#get-apiv1settingssystem). |
| `GET` | `/api/v1/settings/enrichment` | GeoIP database status and reputation quotas. See [Enrichment status](#get-apiv1settingsenrichment). |
| `PUT` | `/api/v1/settings/providers/{provider}` | Set or replace an enrichment API key. See [Provider keys](#provider-keys). |
| `DELETE` | `/api/v1/settings/providers/{provider}` | Remove a key set in Settings. See [Provider keys](#provider-keys). |
| `POST` | `/api/v1/settings/providers/{provider}/test` | Ask ingest to test the key with one real call. See [Provider keys](#provider-keys). |
| `WebSocket` | `/api/v1/live` | Live feed of new events and statistics. See [Live feed](#live-feed). |

### `GET /healthz`

Returns `200` when the API can reach the database. Returns `503` when it cannot. Docker uses this endpoint for the container health check.

```json
{
  "status": "ok",
  "db": "ok"
}
```

When the database is unreachable, the response has status `503` and this body:

```json
{
  "status": "degraded",
  "db": "error"
}
```

### `GET /api/v1/events/recent`

The newest events, newest first. This is the REST version of the WebSocket backfill. It returns the live view of an event, without the raw `data` object.

| Query parameter | Default | Meaning |
| --- | --- | --- |
| `limit` | `50` | Number of events, 1 to 200 |

Example request:

```bash
curl -s "http://127.0.0.1:8443/api/v1/events/recent?limit=2"
```

Example response (fake values, documentation addresses only):

```json
{
  "items": [
    {
      "id": 1842,
      "ts": "2026-10-24T18:02:14Z",
      "sensor": "ssh",
      "session_id": "k3J9x2_a7Qe",
      "type": "login_attempt",
      "src_ip": "198.51.100.23",
      "src_port": 51422,
      "dst_port": 22,
      "summary": "login root/123456 failed",
      "country": null,
      "city": null,
      "asn": null,
      "org": null,
      "abuse_score": null,
      "known_scanner": null,
      "tags": []
    },
    {
      "id": 1841,
      "ts": "2026-10-24T18:02:11Z",
      "sensor": "ssh",
      "session_id": "k3J9x2_a7Qe",
      "type": "connect",
      "src_ip": "198.51.100.23",
      "src_port": 51422,
      "dst_port": 22,
      "summary": "connected",
      "country": null,
      "city": null,
      "asn": null,
      "org": null,
      "abuse_score": null,
      "known_scanner": null,
      "tags": []
    }
  ]
}
```

`summary` is a one-line description built by the API. Attacker-controlled text is cleaned (control characters are replaced) and shortened.

### `GET /api/v1/sessions`

Lists sessions, newest first. Order: `started_at` descending, then `session_id`.

| Query parameter | Default | Meaning |
| --- | --- | --- |
| `limit` | `50` | Items per page, 1 to 200 |
| `cursor` | none | Cursor from the previous page |
| `sensor` | none | Only sessions from one sensor: `ssh`, `telnet`, `adb`, `web`, `docker`, `redis`, `mysql`, `mssql`, `rdp`, `smb` or `sip`. Repeat the parameter or separate names with commas for several sensors. |
| `src_ip` | none | Only sessions from one source address |
| `tag` | none | Only sessions that carry this tag. Lower-case letters, digits and `-`, up to 32 characters (for example `crypto-miner`). |
| `country` | none | Only sessions from this country. Two letters (ISO 3166-1), case-insensitive. |
| `asn` | none | Only sessions from this autonomous system number (an integer) |
| `since` | none | Only sessions that started at or after this time (ISO 8601, with a time zone) |
| `until` | none | Only sessions that started before this time |

Example request:

```bash
curl -s "http://127.0.0.1:8443/api/v1/sessions?sensor=ssh&limit=2"
```

Example response (values are fake, and use documentation addresses):

```json
{
  "items": [
    {
      "session_id": "k3J9x2_a7Qe",
      "sensor": "ssh",
      "src_ip": "198.51.100.23",
      "src_port": 51422,
      "dst_port": 22,
      "started_at": "2026-10-24T18:02:11Z",
      "ended_at": "2026-10-24T18:02:19Z",
      "last_event_at": "2026-10-24T18:02:19Z",
      "event_count": 4,
      "login_attempts": 3,
      "login_success": false,
      "commands": 0,
      "downloads": 0,
      "http_requests": 0,
      "country": null,
      "city": null,
      "asn": null,
      "org": null,
      "abuse_score": null,
      "known_scanner": null,
      "client_tool": null,
      "tags": []
    },
    {
      "session_id": "Q8mW1-zT4bA",
      "sensor": "ssh",
      "src_ip": "203.0.113.77",
      "src_port": 40018,
      "dst_port": 22,
      "started_at": "2026-10-24T17:48:03Z",
      "ended_at": "2026-10-24T17:49:40Z",
      "last_event_at": "2026-10-24T17:49:40Z",
      "event_count": 12,
      "login_attempts": 1,
      "login_success": true,
      "commands": 6,
      "downloads": 1,
      "http_requests": 0,
      "country": null,
      "city": null,
      "asn": null,
      "org": null,
      "abuse_score": null,
      "known_scanner": null,
      "client_tool": null,
      "tags": []
    }
  ],
  "next_cursor": "WyIyMDI2LTEwLTI0VDE3OjQ4OjAzKzAwOjAwIiwiUThtVzEtelQ0YkEiXQ"
}
```

The cursor in the example is opaque and only shows the format. Do not decode or edit it.

The enrichment fields (`country`, `city`, `asn`, `org`, `abuse_score`, `known_scanner`) are `null` and `tags` is empty until ingest has enriched the session. Enrichment and tagging run in ingest (M4). Ingest has to download a GeoIP database first, so right after a first start the fields stay `null` for a short while. Sessions that were stored before enrichment was running are not enriched afterwards.

`client_tool` is a best-effort guess at the client software of an RDP session (see [RDP sensor](sensors/rdp.md#client-tool-identification)). It is `null` for every other sensor, and for RDP when the guess is `unknown`.

Filters combine with AND. `since` and `until` need a time zone (`2026-10-24T00:00:00Z`). An invalid value returns `422`.

### `GET /api/v1/sessions/{session_id}`

Returns one session, with the same fields as a list item. Returns `404` when the session does not exist.

```json
{
  "detail": "session not found"
}
```

### `GET /api/v1/sessions/{session_id}/events`

Returns the events of one session, oldest first. Order: `ts` ascending, then `id`.

| Query parameter | Default | Meaning |
| --- | --- | --- |
| `limit` | `100` | Items per page, 1 to 200 |
| `cursor` | none | Cursor from the previous page |

Example response:

```json
{
  "items": [
    {
      "id": 1841,
      "ts": "2026-10-24T18:02:11Z",
      "sensor": "ssh",
      "session_id": "k3J9x2_a7Qe",
      "type": "connect",
      "src_ip": "198.51.100.23",
      "src_port": 51422,
      "dst_port": 22,
      "data": {
        "client_version": "SSH-2.0-libssh_0.9.6"
      },
      "country": null,
      "city": null,
      "asn": null,
      "org": null,
      "abuse_score": null,
      "known_scanner": null,
      "tags": []
    },
    {
      "id": 1842,
      "ts": "2026-10-24T18:02:14Z",
      "sensor": "ssh",
      "session_id": "k3J9x2_a7Qe",
      "type": "login_attempt",
      "src_ip": "198.51.100.23",
      "src_port": 51422,
      "dst_port": 22,
      "data": {
        "username": "root",
        "password": "123456",
        "success": false,
        "method": "password"
      },
      "country": null,
      "city": null,
      "asn": null,
      "org": null,
      "abuse_score": null,
      "known_scanner": null,
      "tags": []
    }
  ],
  "next_cursor": null
}
```

The `data` object follows the recommended keys in [Event schema](event-schema.md). An event `cursor` is bounded: an id outside 0 to 2^63-1 returns `400`.

### `GET /api/v1/stats/summary`

Totals for the last 24 hours (`window_hours` is `24`). The `by_sensor` object has one entry per sensor that has data.

Example response (fake values):

```json
{
  "window_hours": 24,
  "events": 18342,
  "sessions": 1260,
  "unique_ips": 417,
  "sessions_with_commands": 88,
  "download_attempts": 14,
  "by_sensor": {
    "rdp": {"events": 1204, "sessions": 150},
    "redis": {"events": 412, "sessions": 38},
    "ssh": {"events": 12010, "sessions": 910},
    "telnet": {"events": 3580, "sessions": 280},
    "web": {"events": 1548, "sessions": 120}
  }
}
```

### `GET /api/v1/settings/system`

Read-only data for the Settings page. Every block becomes `null` or empty when its source is not available, so a partly migrated database never breaks the page.

| Field | Content |
| --- | --- |
| `sensors` | One entry per sensor: `sensor`, `last_event_at`, `events_last_hour` and `status`: `active` (an event in the last 15 minutes), `quiet` (in the last 24 hours) or `silent` |
| `retention` | `raw_days` (when raw events are dropped), `compression_after_days`, and the names of the `aggregates` that are kept forever |
| `disk_guard` | The state written by the disk guard job (see [Data retention](retention.md#disk-guard)), or `null` |
| `ingest_disk` | The state ingest reports for its own payload trimming, or `null` |
| `database` | `size_bytes` and `max_bytes` (from `DB_MAX_SIZE_GB`) |

### `GET /api/v1/settings/enrichment`

The status of the enrichment providers and today's quota use. It never returns an API key. The Settings page will use it.

```json
{
  "geoip": {
    "provider": "dbip",
    "available": true,
    "files": {
      "city": {"file": "dbip-city-lite.mmdb", "bytes": 131072000, "updated_at": "2026-10-01T03:00:00Z", "age_days": 23.6}
    },
    "last_error": null,
    "refresh_days": 30,
    "attribution": "IP geolocation by DB-IP.com (https://db-ip.com), CC BY 4.0"
  },
  "abuseipdb": {
    "configured": true, "source": "settings", "last4": "a1b2", "updated_at": "2026-10-25T09:00:00Z",
    "secret_error": null, "pending_apply": false,
    "test": {"ok": true, "error": null, "checked_at": "2026-10-25T09:01:00Z"},
    "test_pending": false, "test_requested_at": "2026-10-25T09:00:50Z",
    "daily_quota": 1000, "used_today": 12, "disabled": null, "paused": false, "last_error": null
  },
  "greynoise": {"configured": false, "source": null, "last4": null, "updated_at": null, "secret_error": null,
                "pending_apply": false, "test": null, "test_pending": false, "test_requested_at": null,
                "daily_quota": null, "used_today": 0, "disabled": null, "paused": false, "last_error": null},
  "maxmind": {"configured": false, "source": null, "last4": null, "updated_at": null, "secret_error": null,
              "pending_apply": false, "test": null, "test_pending": false, "test_requested_at": null},
  "key_editing": {"enabled": true, "reason": null},
  "reported_at": null
}
```

For each provider, `source` is `env` (the key comes from `.env`), `settings` (set on the Settings page) or `null` (no key). `last4` and `updated_at` are set only for keys saved in Settings. `secret_error` is `cannot_decrypt` or `no_encryption_key` when a saved key cannot be used; ingest then falls back to the `.env` key. `pending_apply` is true for the few seconds before ingest picks up a change. `test` is the last "Test key" result (`error` is one of `no_key`, `quota_exhausted`, `auth`, `rate_limited`, `error`). `key_editing.enabled` is false when `SETTINGS_ENCRYPTION_KEY` is not set, with the reason in `reason`.

`provider` is `maxmind`, `dbip`, `off`, or `unknown` when ingest has not reported yet. The attribution text must be shown wherever DB-IP data is displayed.

### Users and audit log (administrators)

Every request below needs an administrator and, when it changes something, the administrator's own password in the body (`password`), the same re-authentication as the provider keys. Each change writes an audit entry. A user who must still choose a password gets `403` with `password_change_required` from every other endpoint.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/users` | `owner` (read-only), `items` (users by id) and `next_cursor`. Query: `limit` (1 to 200, default 50), `cursor`. |
| `POST` | `/api/v1/users` | Body `username`, `display_name`, `role`, `password`. `201` with the `user` and a one-time `temporary_password` (`Cache-Control: no-store`). `409` with `username_taken` (also for the owner's name). |
| `PATCH` | `/api/v1/users/{id}` | Body `role`, `disabled` or `display_name` (at least one) and `password`. A role change or a disable ends the user's sessions. |
| `POST` | `/api/v1/users/{id}/reset-password` | Body `password`. Returns a new `temporary_password`, ends the user's sessions and makes them choose a password again. |
| `POST` | `/api/v1/users/{id}/unlock` | Body `password`. Clears the lock after repeated wrong passwords. |
| `POST` | `/api/v1/users/{id}/revoke-sessions` | Body `password`. Ends every session of the user. `204`. |
| `DELETE` | `/api/v1/users/{id}` | Body `password`. `204`. |
| `GET` | `/api/v1/audit` | Newest first. Query: `actor` (exact name, any case), `action` (a name such as `user.create`, or a prefix such as `user.`), `limit` (1 to 200, default 50), `cursor`. |

An administrator cannot disable, demote, reset or delete their own account (`409`, `self_action`). Audit actions: `auth.login`, `user.create`, `user.role`, `user.disable`, `user.enable`, `user.rename`, `user.reset_password`, `user.unlock`, `user.locked`, `user.revoke_sessions`, `user.delete`, `password.change`, `provider_key.set`, `provider_key.remove`, `provider_key.test`.

### Provider keys

`provider` is `abuseipdb`, `greynoise` or `maxmind`. A key is never returned by any endpoint.

| Request | Body | Answer |
| --- | --- | --- |
| `PUT` | `{"key": "...", "password": "<admin password>"}`, plus `"account_id": "<digits>"` for `maxmind` | `200` with `provider`, `source`, `last4`, `updated_at` |
| `DELETE` | `{"password": "<admin password>"}` | `204` |
| `POST .../test` | none | `202` with `requested_at`. Poll `GET /api/v1/settings/enrichment` for `test`. |

Changes need the session cookie, the `X-CSRF-Token` header, a same-origin request and the admin password again. Errors carry a `code`: `editing_disabled` (`503`, no `SETTINGS_ENCRYPTION_KEY`), `invalid_key` (`422`, wrong length or characters), `reauth_failed` (`403`, wrong password), `origin` (`403`), `rate_limited` (`429`, shared with the login limit), `no_key` (`409`), `cooldown` (`429`, one test per 20 seconds), `daily_cap` (`429`, 10 tests per provider per day) and `session_revoked` (`401`, five wrong passwords in a row). A `422` never repeats the submitted values.

## Analytics endpoints

```{admonition} Status
:class: note

Implemented (M5). Check `/openapi.json` (with `API_ENABLE_DOCS=true`) for the exact fields of your version.
```

All analytics endpoints are read-only, run as the `suckerpot_api` role with the 5 second statement timeout, and use TimescaleDB `time_bucket` queries. Lists are paginated or capped (`limit` at most 200). Times are ISO 8601 UTC.

Common optional filters: `since` and `until` (with a time zone; the default window is the last 24 hours for stats, with 30 days as the maximum) and `sensor` (any of the eleven sensor names: `ssh`, `telnet`, `adb`, `web`, `docker`, `redis`, `mysql`, `mssql`, `rdp`, `smb`, `sip`).

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/stats/timeseries` | Events and sessions per time bucket and sensor. `bucket` is `5m`, `1h` or `1d`. Empty buckets are filled with zeros. At most 500 points. |
| `GET` | `/api/v1/stats/top` | The most frequent values of one `field`: `country`, `asn`, `org`, `username`, `password`, `command`, `url`, `user_agent`, `tag` or `src_ip`. Returns `value`, `count`, `share`, `first_seen` and `last_seen`. `limit` defaults to 10. |
| `GET` | `/api/v1/stats/heatmap` | 168 cells (day of week, Monday is 0, by hour, in UTC) with an event count each |
| `GET` | `/api/v1/attackers` | Attacker profiles, one per source address. Sort by `last_seen`, `sessions`, `events` or `first_seen`. Filters: `country`, `asn`, `sensor`, `tag`, `q` (address prefix). Cursor pagination. |
| `GET` | `/api/v1/attackers/{ip}` | One profile, with the 20 most recent sessions, the top usernames and commands, and a 30-day timeline |
| `GET` | `/api/v1/asns` | Networks, sorted by `sessions`, `ips` or `events`: `asn`, `org`, `country`, `ips`, `sessions`, `events`, `last_seen` |

An attacker profile has: `ip`, `first_seen`, `last_seen`, `sessions`, `events`, `sensors`, `login_attempts`, `login_success`, `commands`, `downloads`, `country`, `city`, `asn`, `org`, `abuse_score`, `known_scanner` and `tags`.

Example, a top list (fake values):

```json
{
  "field": "username",
  "total": 1280,
  "items": [
    {"value": "root", "count": 540, "share": 0.42, "first_seen": "2026-10-01T02:11:00Z", "last_seen": "2026-10-24T17:58:00Z"}
  ]
}
```

The target is under 300 ms per endpoint on the default demo data set (about 3,000 sessions and 25,000 events).

## Insights, trends and malware (M7)

All of these are read-only and need a session.

### `GET /api/v1/insights`

Up to three short findings, written by fixed rules (no language model). Each is one plain sentence plus the numbers behind it and a link to the filtered dashboard view.

| Query parameter | Default | Meaning |
| --- | --- | --- |
| `since`, `until` | the last 7 days | The window to describe, with a time zone. At most 30 days. The previous period of the same length is the comparison. |

```json
{
  "generated_at": "2026-10-24T18:05:00Z",
  "items": [
    {
      "id": "surge-tag-php2shell",
      "kind": "surge",
      "severity": "severe",
      "sentence": "PHP2Shell exploit attempts tripled since Tuesday (312 vs 104).",
      "evidence": {"metric": "sessions_by_tag", "current": 312, "previous": 104, "ratio": 3.0},
      "link": "/attacks?tag=php2shell&since=2026-10-20T00:00:00Z&until=2026-10-24T18:05:00Z"
    }
  ]
}
```

`kind` is `surge`, `new_value`, `campaign`, `exploit`, `success` or `geo_shift`. `severity` is `info`, `notice`, `warning` or `severe`.

**The rules.** A rule produces a finding only when the volume is large enough, so a quiet host never says "tripled (3 vs 1)". Candidates are ranked by severity first, then by size, and the top three are returned. All times are UTC, so "since Tuesday" and "midnight" are UTC days.

| Kind | Fires when | Wording |
| --- | --- | --- |
| `exploit` | A session tagged `php2shell` or `malware-drop` appears for the first time, with none in the 90 days before | "PHP2Shell exploit attempts appeared for the first time: 12 sessions in the last 7 days, none in the 90 days before." Severity `severe`. |
| `surge` | Sessions for a tag or a sensor: at least 20 now, at least 5 before, and at least 1.5 times the previous period | "<Label> tripled / doubled / up 4.2x / up 40% since <day> (current vs previous)." |
| `success` | Sessions with a successful login: at least 5 now, at least 2 before, and at least twice the previous period | "Successful logins doubled since yesterday (12 vs 5)." Severity `warning`. |
| `campaign` | At least 50 sessions in total, and one network (ASN) has 40% or more of them, or one address has 30% or more | "AS64496 (Example Net) accounts for 62% of all sessions in the last 7 days (620 of 1,000)." |
| `geo_shift` | At least 50 sessions in both periods, and a country with at least 20 sessions, 20% or more of the traffic, and at least double its previous share | "Sessions from NL rose from 8% to 25% of all traffic in the last 7 days." |
| `new_value` | A username, command, URL or ASN never seen in the 90 days before, seen at least 10 times | "A command never seen before showed up 14 times in the last 7 days: ..." Attacker-controlled text has control characters removed and is cut to 60 characters. |

### `GET /api/v1/trends/new`

Values that appeared in the window and **not** in the 90 days before it.

| Query parameter | Default | Meaning |
| --- | --- | --- |
| `field` | required | `username`, `password`, `command`, `url`, `asn` or `user_agent` |
| `days` | `7` | Window length, 1 to 30 days, ending now |
| `limit` | `50` | 1 to 200 |

Returns `{"field": "...", "items": [{"value": "...", "count": 14, "first_seen": "..."}]}`, most frequent first.

### `GET /api/v1/trends/tags`

Sessions per tag over time, for the "tags over time" chart.

| Query parameter | Default | Meaning |
| --- | --- | --- |
| `bucket` | `1d` | `5m`, `1h` or `1d` |
| `since`, `until` | the last 7 days | Window, at most 30 days and 500 buckets |

Returns `series` (the eight most frequent tags, plus `other` when there are more), and `points`, one per bucket, each with a `ts` and a count per series entry. Empty buckets are zero.

## Indicators and infrastructure (M13)

Read-only and passive: nothing is fetched from an indicator. Values come both raw (`value`) and defanged (`defanged`, such as `hxxp://files[.]host[.]tld/a.sh`).

| Endpoint | What it returns |
| --- | --- |
| `GET /api/v1/indicators` | Keyset-paginated list (`cursor`, `limit` 1 to 200). Filters: `type` (`url`, `domain`, `ip`, `hash`), `role` (`download_host`, `contacted_host`, `hash`), `known` (true or false), `family`, `since`, `hours` (seen in the last N hours, 1 to 2160, the graph's window), `q` (literal substring). IPv6 values are defanged too (`2001[:]db8[:][:]1`). Each item has sightings, sessions, distinct source addresses, sensors and the intel verdict (`checked`, `known`, `family`). |
| `GET /api/v1/indicators/{id}` | One indicator with the intel answers (source, family, threat type, tags, first reported, reference link), recent sessions, source addresses and indicators seen in the same sessions. |
| `GET /api/v1/infrastructure/graph` | Nodes and edges linking source addresses, indicators (hosts and hashes) and malware families for the last `hours` (1 to 2160, default 168), with a `summary` and `truncated`. At most 300 nodes. |
| `GET /api/v1/indicators/export` | A download of up to 5,000 indicators matching the same filters, as `format=csv` or `format=stix` (a STIX 2.1 bundle of `indicator` objects). |

### `GET /api/v1/malware`

Download URLs recorded from `download_attempt` events, one row per URL, most recently seen first. **Nothing is fetched.**

| Query parameter | Default | Meaning |
| --- | --- | --- |
| `limit` | `50` | 1 to 200 |
| `cursor` | none | From the previous page |
| `tool` | none | Only URLs seen with this tool (`wget`, `curl`, `tftp`, ...) |
| `q` | none | Case-insensitive text search in the URL |

Each item has `url` (cut to 512 characters), `host`, `first_seen`, `last_seen`, `attempts`, `sessions`, `ips`, `tools`, `sensors`, and `sha256`, `size` and `virustotal_url`. The last three are `null` until payload fetching exists, which is off and not implemented.

### `GET /api/v1/malware/detail`

`?url=<the exact URL>`. Returns the same item plus up to 20 recent sessions that used the URL. `404` when the URL is unknown. The URL is a query parameter, not a path part, so it needs no special escaping rules.

```{important}
The API returns URLs exactly as the attacker sent them. They are dangerous strings. The dashboard shows them **defanged** (`hxxp://example[.]com/x.sh`), renders them as text and never as links. Do the same in any tool you build on this API.
```

### `GET /api/v1/settings/site`

The home point of the Live map, where the attack arcs land, as a country-level point.

```json
{"home": {"lat": 46.8, "lon": 8.2, "label": "Switzerland"}}
```

It comes from `SITE_HOME_LAT`, `SITE_HOME_LON` and `SITE_HOME_LABEL`. The values are rounded to one decimal place (about 11 km) on purpose, so the public page never shows an exact location. Do not put the real address of the host in them.

## Live feed

`/api/v1/live` is a WebSocket. It pushes new events as they are stored, so a page does not need to poll.

### How it works

- The API checks the database for new events about once per second. It does not read Redis.
- On connect, the client receives a backfill of the 50 newest events, then the latest statistics.
- Each new event is sent once to every client, oldest first.
- Statistics are sent every 5 seconds.
- Each client has a queue of 200 messages. A slow client loses its oldest messages and is told how many were lost.
- The hub accepts at most 50 clients in total and 5 per source address. A connection beyond either limit is closed with code `1013`.
- A client that is slow to receive is dropped after a send timeout of 10 seconds.
- Reconnect politely: the dashboard backs off exponentially and falls back to polling `/api/v1/events/recent`. See [Dashboard](ui.md#the-live-feed).

### Messages

All messages are JSON text frames from the server.

| `kind` | Payload | When |
| --- | --- | --- |
| `backfill` | `events`: list of live events, newest first | Once, right after connecting |
| `stats` | `stats`: window of 60 seconds, with totals and `by_sensor` | After the backfill, then every 5 seconds |
| `event` | `event`: one live event | For each new event, oldest first |
| `dropped` | `count`: messages skipped for this client | When the client was too slow |
| `pong` | none | Reply to a client text frame `ping` |

A live event has the same fields as an item of `/api/v1/events/recent`.

Example `event` message:

```json
{
  "kind": "event",
  "event": {
    "id": 1843,
    "ts": "2026-10-24T18:02:16Z",
    "sensor": "web",
    "session_id": "Lr4pD0c_9Ks",
    "type": "http_request",
    "src_ip": "192.0.2.45",
    "src_port": 38812,
    "dst_port": 80,
    "summary": "GET /wp-login.php → 200",
    "country": null,
    "city": null,
    "asn": null,
    "org": null,
    "abuse_score": null,
    "known_scanner": null,
    "tags": []
  }
}
```

### Origin check

- A client with no `Origin` header (a script or a command-line tool) is accepted.
- A browser must send an `Origin` that matches the `Host` header, or a host listed in `API_ALLOWED_ORIGINS`. Otherwise the connection is closed with `1008`.
- The handshake needs a valid session cookie (see [Authentication](#authentication)). Without it the connection is closed with `1008`, and a session that ends while the socket is open closes it with `1008` too.

### Close codes

| Code | Meaning |
| --- | --- |
| `1000` | Normal close, for example the client left |
| `1001` | The server is shutting down |
| `1008` | The origin is not allowed, there is no valid session, or the session ended |
| `1011` | Internal error on the server |
| `1013` | Too many clients connected (in total or from one address), or the session cannot be checked (database unavailable) |

## Not built yet

| Feature | Milestone |
| --- | --- |
| API rate limits beyond the login limits | M8 |
