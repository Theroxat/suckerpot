# API

The API is a FastAPI application. It reads the database and returns JSON. It also serves a live WebSocket feed, and the web UI once one is built. The API has no Redis access and cannot change data: it connects as the read-only role `suckerpot_api`.

```{admonition} Build status
:class: note

The REST endpoints and the live feed are built in M1. Dashboard login and rate limits are **planned** (M8). Until then the API is open to anyone who can reach the dashboard port. Keep that port behind the reverse tunnel described in [Deployment](deployment.md).
```

## Base URL

Every example below uses the dashboard port on the host. With the default `DASHBOARD_PORT=8443`, and with the default bind address `127.0.0.1`, run the examples on the host itself:

```text
http://127.0.0.1:8443
```

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
| `sensor` | none | Only sessions from one sensor: `ssh`, `telnet`, `web` or `rdp` |
| `src_ip` | none | Only sessions from one source address |
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
      "tags": []
    }
  ],
  "next_cursor": "WyIyMDI2LTEwLTI0VDE3OjQ4OjAzKzAwOjAwIiwiUThtVzEtelQ0YkEiXQ"
}
```

The cursor in the example is opaque and only shows the format. Do not decode or edit it.

In M1, the enrichment fields (`country`, `city`, `asn`, `org`, `abuse_score`, `known_scanner`) are `null` and `tags` is empty. Enrichment and tagging arrive in M4.

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
    "ssh": {"events": 12010, "sessions": 910},
    "telnet": {"events": 3580, "sessions": 280},
    "web": {"events": 1548, "sessions": 120}
  }
}
```

## Live feed

`/api/v1/live` is a WebSocket. It pushes new events as they are stored, so a page does not need to poll.

### How it works

- The API checks the database for new events about once per second. It does not read Redis.
- On connect, the client receives a backfill of the 50 newest events, then the latest statistics.
- Each new event is sent once to every client, oldest first.
- Statistics are sent every 5 seconds.
- Each client has a queue of 200 messages. A slow client loses its oldest messages and is told how many were lost.
- The hub accepts at most 50 clients. The connection to client number 51 is closed with code `1013`.

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

### Close codes

| Code | Meaning |
| --- | --- |
| `1000` | Normal close, for example the client left |
| `1001` | The server is shutting down |
| `1008` | The origin is not allowed |
| `1011` | Internal error on the server |
| `1013` | Too many clients connected |

## What is not in M1

| Feature | Milestone |
| --- | --- |
| Dashboard login, session cookie and rate limits | M8 |
| Filters on `tag`, `country`, `asn` and `period` | M4 and M5 |
| Attacker endpoints (profiles by IP and ASN) | M5 |
| Trends and malware endpoints | M7 |
| The web UI served from `WEB_DIST_DIR` | M3 and later |
