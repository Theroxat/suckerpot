# Synology sensor

A low-interaction honeypot that looks like an internet-exposed Synology NAS running DSM
7.2.1-69057 Update 11, one update below the fix of Synology-SA-26:13. It serves the DSM login
page and the Web API on HTTP (5000) and HTTPS (5001), records everything precisely and never
accepts a login, executes, writes or fetches anything.

Why: a ransomware campaign (C3RB3R, a Cerber variant: files renamed `*.L0CK3D`, ransom note
`read-me3.txt`) hits exposed DSM through CVE-2026-13639 (insufficient entropy in the login
logic, CWE-331) and CVE-2026-13684 (improper output encoding in SCGI, CWE-116). The exploit
details are not public, so the sensor cannot match an exact exploit. It looks like a real
vulnerable DSM and tags request shapes that fit those weakness classes.

Run with `python -m synology_sensor`. Container ports: **5000** (HTTP) and **5001** (HTTPS).

## What is served

| route | answer |
| --- | --- |
| `GET /`, `/webman/index.cgi`, `/index.html` | DSM 7 login shell: `<title>` is the per-install host name, `SYNO.SDS.Session` globals with version and build, asset paths |
| `/webman/favicon.ico`, `/webman/resources/*`, `/synoSDSjslib/*`, `/scripts/*`, `/webman/modules/*` | tiny stub assets (icon, one-line JS or CSS, 1x1 PNG) |
| `GET /webapi/query.cgi?api=SYNO.API.Info&method=query&version=1&query=all` | fixed JSON map of 62 APIs (`path`, `minVersion`, `maxVersion`), 4.9 KB; `query=a,b` returns the subset |
| any `/webapi/*.cgi` (also the `/webapi/____entry.cgi` form), GET or POST | `api`, `method`, `version` read from the query string, a form, multipart or JSON body. `SYNO.API.Auth` `login` always fails, `SYNO.API.Encryption` `getinfo` returns a key, `logout` succeeds, every other known API answers `{"error":{"code":119},"success":false}` (SID not found) |
| `/webman/login.cgi` | the older login endpoint, always `error_cantlogin` |
| `/webman/info.cgi`, `/webman/get_status.cgi` | tiny version JSON |
| anything else | nginx's `404` page; other methods than GET, HEAD, POST get `405` |

Login error codes: `400` wrong account or password, `401` account disabled (`guest`), `402`
permission denied (system accounts such as `sshd`), `403` / `404` 2-step verification required /
failed (about one account name in eleven, stable per name, never `admin` or `root`), `407` IP
blocked (12 failures from one IP in 5 minutes). Other errors: `101` missing parameter, `102`
unknown API, `103` unknown method, `104` unsupported version. Responses carry `Server: nginx`
and the header set of DSM's nginx. Plain HTTP on the HTTPS port gets nginx's "The plain HTTP
request was sent to HTTPS port" `400`. `SYNOLOGY_HTTP_REDIRECT=true` makes port 5000 redirect the
login page to HTTPS (off by default, DSM serves the UI on 5000).

Identity (host name such as `DS920plus`, `NAS01`, `DiskStation`; model; serial) comes from a
random secret in `/data/profile.json` (mode 0600). TLS: an RSA 2048 certificate generated on
first start in `/data/tls`, subject `C=TW, L=Taipei, O=Synology Inc., CN=synology`, issuer
`CN=Synology Inc. CA`, ten years, like the factory certificate. TLS 1.2 and 1.3.

## Events

Stream from `EVENTS_STREAM` (`events:synology`), `sensor` = `synology`, `dst_port` = the public
port of the listener that accepted the connection. One session per TCP connection.

| type | when | `data` keys |
| --- | --- | --- |
| `connect` | connection accepted | `tls`, `sni`, `handshake`, `tls_version`, `cipher` |
| `http_request` | every request | `method`, `path`, `query`, `http_version`, `host`, `sni`, `tls`, `user_agent`, `headers` (32 at most), `body_len`, `body_preview`, `body_binary`, `body_sha256`, `body_truncated`, `api`, `api_method`, `api_version`, `params` (24 at most, passwords left out), `flags`, `cve` (only with `sid_forge` or `scgi_injection`), `status`, `route`, `dsm_version`, `upload_names` |
| `login_attempt` | `SYNO.API.Auth` `login`, `/webman/login.cgi` | `username`, `password` (the `__cIpHeRtExT` blob when the client encrypts), `otp_present`, `success` (always false), `api`, `path`, `api_version`, `encrypted`, `error_code`, `session` |
| `download_attempt` | a URL in any parameter of a `/webapi/` or `/webman/` request | `url`, `tool` (`download_station` / `dsm_api`), `source` (`dsm_api`), `param`, `api` |
| `scan` | non-HTTP bytes, incomplete request, failed TLS handshake, refused connections | `kind` (`non_http`, `incomplete_request`, `tls_handshake_failed`, `rate_limited`, `events_suppressed`) |
| `disconnect` | connection closed | `duration_s`, `reason`, `requests`, `login_attempts`, `downloads`, `bytes_out`, `tls`, `sni`, `flags`, `statuses`, `suppressed`, `repeats` |

### Flags (`data.flags` of `http_request`)

| flag | set when |
| --- | --- |
| `dsm_api` | the path starts with `/webapi/` |
| `dsm_login` | `SYNO.API.Auth` `login` (or `/webman/login.cgi` with credentials) |
| `dsm_version_probe` | `SYNO.API.Info`, `SYNO.DSM.Info`, `SYNO.Core.System`, `SYNO.Core.Desktop.Initdata`, `/webman/info.cgi`, `/webman/get_status.cgi` |
| `sid_forge` | a `_sid` / `sid` / `SynoToken` parameter, an `X-SYNO-TOKEN` header or an `id` / `sid` / `_sid` / `SynoToken` cookie (the sensor never issues one), or a login with an account and no password at all |
| `scgi_injection` | in the path, a parameter name or value, or a header value: CR, LF, NUL or another control byte; a surviving `%0d`, `%0a` or `%00` (double encoding); SCGI / CGI variable names (`CONTENT_LENGTH`, `SCGI`, `REQUEST_URI`, ...); header-like text (`Content-Length:`, `Set-Cookie:`, `X-Accel-Redirect:`, ...); `<digits>:` netstring framing followed by SCGI content |
| `file_write` | FileStation Upload, Rename, Delete, CopyMove, Compress, Extract or CreateFolder (any method but status / stop / list), `SYNO.Core.TaskScheduler` create / set / run / delete / save, `SYNO.Core.Package` Installation / Uninstallation |
| `ransom_indicator` | `.L0CK3D` or `read-me3.txt` in the path, query, a parameter, a header, a multipart file name or the body |
| `no_user_agent`, `oversized_body` | no User-Agent header; the body was cut (more than 128 KB kept, or more than the 4 MB read limit) |
| `plain_http_on_tls`, `incomplete_body` | plain HTTP on port 5001; the body did not arrive |

`cve` is `["CVE-2026-13639", "CVE-2026-13684"]` exactly when `sid_forge` or `scgi_injection` is
set. `file_write` and `ransom_indicator` alone do not add it.

## Limits

Global 200 connections (HTTP and HTTPS together), 8 per IP, 5 new connections per second per IP
(burst 20), 20 requests per second per IP (burst 100, then `503` and close), all checked before
any work. TLS: no handshake slot is taken until the whole ClientHello record (at most 16 KiB) has
arrived (2 s), then at most 64 handshakes in flight sensor-wide and 3 per source IP, handshake rate 1 per second per IP (burst 5) and 40 per second sensor-wide
(plus a small reserved share for IPs that have hardly handshaken recently), 4 s handshake timeout, none while the memory guard refuses. Request line 8190 bytes, head 16 KB and 64 headers, then
`431`. Body: read and hashed up to 4 MB, only the first 128 KB are kept and parsed. Parameters:
64 per request, 4096 characters looked at per value, 4 URLs. Head within 15 s, body reads 10 s each
with a 500 B/s floor after 5 s and 45 s in total, keep-alive 15 s, 100 requests and 180 s per
connection, 10 s write timeout. Kernel socket buffers 64 KB, `TCP_USER_TIMEOUT` 30 s. Answers are
fixed documents (largest 4.9 KB), so a client that pipelines requests and never reads cannot grow
memory. No regular expressions anywhere (ReDoS).

Per-IP state: only the login-failure counter (2048 IPs, least recently seen out first). Nothing
per session beyond the connection itself.

Events and CPU: the same machinery as the Docker sensor (per-session, per-IP and sensor-wide
buckets, a priority queue for logins, downloads, exploit-shaped requests, connects and
disconnects, per-IP byte buckets, a periodic `events_suppressed` summary, a CPU budget per
connection, per IP and sensor-wide). Every field is capped before the event is built, so no
event reaches the 16 KB limit. Connections from 127.0.0.1 (the healthcheck) are never refused and
never reported.

Memory: a byte budget (80 MB) charged per connection (96 KB, plus 224 KB for TLS) and per body in
flight, plus a cgroup guard: above 70 % of the limit new connections are refused, above 85 % the
connections holding the most are aborted. The event-loop watchdog exits the process (code 70) if
the loop stalls for 10 s. Measured in the hardened container: about 37 MB idle.

## Environment variables

| variable | default | meaning |
| --- | --- | --- |
| `REDIS_HOST`, `REDIS_PORT`, `REDIS_USER`, `REDIS_PASSWORD`, `EVENTS_STREAM`, `EVENTS_MAXLEN`, `EVENTS_MAX_BYTES_PER_SEC`, `EVENTS_MAX_BYTES_BURST` | see `suckerpot_common` | publisher (`EVENTS_STREAM=events:synology`) |
| `SYNOLOGY_HTTP_PORT` / `SYNOLOGY_HTTPS_PORT` | `5000` / `5001` | container ports |
| `SYNOLOGY_HTTP_PUBLIC_PORT` / `SYNOLOGY_HTTPS_PUBLIC_PORT` | the container ports | reported as `dst_port`, used in redirects |
| `SYNOLOGY_HTTP_REDIRECT` | `false` | redirect the HTTP login page to HTTPS |
| `SYNOLOGY_DATA_DIR` | `/data` | profile secret and TLS material (volume) |
| `SYNOLOGY_MAX_CONNECTIONS` / `SYNOLOGY_MAX_PER_IP` | `200` / `8` | caps |
| `SYNOLOGY_CONN_RATE` / `SYNOLOGY_CONN_BURST` | `5` / `20` | new connections per IP |
| `SYNOLOGY_MEMORY_BUDGET_MB` | `80` | connection and body byte budget |
| `SYNOLOGY_MEMORY_LIMIT_MB` | `160` | guard limit when the cgroup has none (keep equal to `mem_limit`) |
| `SYNOLOGY_EVENTS_PER_SEC` / `SYNOLOGY_GLOBAL_EVENTS_PER_SEC` | `20` / `200` | |

## Design notes

* Hand written HTTP, as for the other HTTP sensors: a framework would normalise or reject
  malformed requests in ways that identify it, and the SCGI-shaped abuse needs the raw bytes.
* Nothing is executed: `tests/test_static.py` walks the AST and fails on `subprocess`, `eval`,
  `exec`, `compile`, `pickle`, `re`, `importlib`, file writes outside `profile.py` and `tls.py`
  (both below the data directory) and outbound network clients. Downloads are recorded as
  `download_attempt` events only. The sensor has no outbound code.
* Uploads are never stored: multipart bodies are parsed in memory (bounded) for field and file
  names, then dropped.

## Compose block

```yaml
  sensor-synology:
    build:
      context: .
      dockerfile: sensors/synology/Dockerfile
    image: suckerpot-sensor-synology:latest
    restart: unless-stopped
    networks: [ingress, sensors-synology]
    dns: ["127.0.0.1"]
    ports:
      - "0.0.0.0:${SYNOLOGY_HTTP_HOST_PORT:-5000}:5000"
      - "0.0.0.0:${SYNOLOGY_HTTPS_HOST_PORT:-5001}:5001"
    environment:
      REDIS_HOST: redis
      REDIS_USER: sensor-synology
      REDIS_PASSWORD: ${REDIS_SENSOR_SYNOLOGY_PASSWORD:?set REDIS_SENSOR_SYNOLOGY_PASSWORD}
      EVENTS_STREAM: events:synology
      SYNOLOGY_HTTP_PUBLIC_PORT: ${SYNOLOGY_HTTP_HOST_PORT:-5000}
      SYNOLOGY_HTTPS_PUBLIC_PORT: ${SYNOLOGY_HTTPS_HOST_PORT:-5001}
    volumes:
      - synology-sensor-data:/data
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001
    user: "10001:10001"
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    mem_limit: 160m
    memswap_limit: 160m
    cpus: 0.5
    pids_limit: 128
    healthcheck:
      test: ["CMD", "python", "-m", "synology_sensor.healthcheck"]
      interval: 15s
      timeout: 5s
      retries: 3
      start_period: 15s
```

Also needed (orchestrator): a `sensors-synology` network with `internal: true` that `redis`
joins, the `synology-sensor-data` volume, a Redis ACL user `sensor-synology` limited to `XADD` on
`events:synology`, and the host port variables in `.env.example`. Neither 5000 nor 5001 may be
the dashboard port. The data volume must be writable by uid 10001 (the Dockerfile creates
`/data` with that owner).

## Development

```
uv sync
uv run ruff check && uv run ruff format --check && uv run mypy . && uv run pytest
```
