# SIP sensor

A small PBX endpoint that only observes. It answers on UDP 5060 (and optionally TCP 5060) like an
Asterisk server and records SIP scanners: OPTIONS sweeps, REGISTER brute force and INVITE
toll-fraud attempts. Run with `python -m sip_sensor`. It listens on container port 5060; compose
maps the host port `SIP_HOST_PORT` to it, and no capability is needed.

**Nothing is executed, established, fetched or relayed.** There is no call, no dialog, no SDP
answer and no RTP: an INVITE never gets a `200 OK`. The sensor never opens an outbound
connection (UDP replies go back to the datagram's sender only) and the only file it writes is
its profile secret under `SENSOR_DATA_DIR`. `tests/test_static.py` enforces this with an AST
scan (no `eval`/`exec`/`compile`/`subprocess`/`pickle`/`importlib`, no regular expressions, no
outbound sockets, exactly one `sendto`, no file writes elsewhere).

## Anti-reflection (top priority)

UDP source addresses are spoofable, so a UDP service that answers is a candidate reflector.
Every one of these holds before a single reply byte leaves the sensor:

1. **A reply is never larger than the datagram that triggered it.** The reply is built from the
   request's own mandatory headers (Via, From, To, Call-ID, CSeq) plus optional ones (`received` / `rport` on the top Via, Server,
   Allow, Supported, Accept, Contact, Content-Length) that are added one by one only while the total stays
   within the request size. If even the mandatory part does not fit (for example a challenge
   header that would not fit), the sensor stays silent. A final check in `ReplyGate.permit`
   rejects any reply bigger than its request. Amplification factor: **at most 1.0 by
   construction**; measured below.
2. **Responses are never answered**, ACK gets no reply, unparseable input gets no reply. Two
   reflectors cannot ping-pong.
3. **No reply to implausible sources:** private (RFC 1918, CGNAT), loopback-from-outside,
   link-local, multicast, broadcast, unspecified, reserved, documentation and other non-global
   ranges, port 0, and the addresses listed in `SENSOR_SIP_OWN_IPS`. (127.0.0.1 is answered: it
   never leaves the container and the healthcheck uses it.) `SENSOR_SIP_ALLOW_PRIVATE=true`
   lifts the private-range rule for lab tests only.
4. **Per-source reply bucket:** 2 replies/s, burst 5. **Global caps:** 100 replies/s (burst
   200) and 32 KiB/s of reply bytes (burst 64 KiB), all sources together.
5. **Work bounds before parsing:** datagrams above 4096 bytes are dropped unread; per-source
   (50/s, burst 100) and global (3000/s) packet buckets protect the CPU.
6. **Events are aggregated per source IP**, so a flood is a few events, not a stream.

Measured (`tests/test_reflection.py`, run with `-s` to print it): over 4000 requests of every
shape (OPTIONS, REGISTER, INVITE, BYE, CANCEL, SUBSCRIBE, MESSAGE, unknown methods; minimal and
typical sizes; with and without bodies; compact header forms), with all rate limits switched
off so that the size rule alone is tested: 2705 replies, 1,146,143 bytes in, 810,926 bytes
out, **amplification factor 0.708, worst single reply 0.993** (also run on the live path with real
UDP sockets: a 300-datagram burst gets at most a dozen replies). With the limits on, 20,000
packets from 20,000 spoofed sources produce at most `200 + 100 * seconds` replies, and the
reply bytes are below 10 % of the bytes received.

## What it does

- **Parser.** Written by hand with `str` / `bytes` operations only. Bounds: 4096 bytes per
  message, 64 headers, 1024 bytes per header line, 512 bytes for the start line, 8 Via headers
  echoed, `Content-Length` at most 4096 and at most 6 digits, 256 bytes of body kept, at most
  24 digest parameters of 256 bytes. Compact header names (`v`, `f`, `t`, `i`, `m`, `l`, ...)
  and folded lines are understood. Timing tests feed pathological 4 KB inputs.
- **OPTIONS** gets `200 OK` with `Allow`, `Supported` and `Server: Asterisk PBX 20.x.y`.
- **REGISTER** gets `401 Unauthorized` with a Digest challenge (realm `asterisk`, 8-hex-digit
  nonce like chan_sip: stateless, `HMAC(secret, source IP, 120 s time bucket)` truncated, valid
  in its bucket and the next one). A REGISTER that carries `Authorization` is a `login_attempt`: username, realm,
  URI, algorithm and the first 8 characters of the digest response. Nothing is ever cracked.
  Because the cleartext of a few configured weak credentials is known
  (`SENSOR_SIP_WEAK_CREDENTIALS`, default `100:100,1000:1000,admin:admin`), a correct digest
  with a valid nonce for one of them gets a stateless `200 OK` (and the clear-text password is
  recorded). Nothing is registered or remembered, so this only keeps brute-forcers going to the
  next stage, the INVITE.
- **INVITE** records From, To, the Request-URI and the dialled number. Without credentials or
  with wrong ones: `407 Proxy Authentication Required` with a fresh challenge (what chan_sip
  does with `alwaysauthreject=yes`: the same answer for unknown users and wrong passwords;
  REGISTER likewise gets `401`, INVITE gets `407`, as chan_sip uses Proxy-Authenticate for
  INVITE). With a weak credential: `486 Busy Here`. Real chan_sip finishes with `403` after
  three failed attempts on one dialog; the sensor is stateless and never does. Never a `200 OK`, never SDP, never RTP.
  `Proxy-Authorization` is recorded as a `login_attempt` as well.
- **CANCEL / BYE** `481`; known methods without support (SUBSCRIBE, NOTIFY, MESSAGE, REFER,
  INFO, PUBLISH, UPDATE, PRACK) `405` with `Allow`; anything else `501`.
- **TCP** (`SENSOR_SIP_TCP=true`, default) frames messages by `Content-Length` with the same
  bounds, deadlines (15 s to the first message, 30 s idle, 120 s total, 5 s per write), at most
  200 messages and 256 KiB per connection, 100 connections and 5 per IP; a peer that does not
  read is aborted. TCP replies need no size cap (the source cannot be spoofed) but go through
  the same message handler.

### Fingerprint

- `nmap -sU -sV -p 5060` reports `sip  Asterisk PBX (Status: 200 OK)` or similar for the
  OPTIONS probe; the version string of the `Server` / `User-Agent` header is derived from the
  deployment secret (Asterisk 16.28 to 18.24 (the chan_sip era; Asterisk 20 answers with PJSIP, whose replies differ)) unless `SENSOR_SIP_USER_AGENT` is set (for
  example `FPBX-16.0.40(18.20.0)`).
- SIPVicious `svmap` lists it as `Asterisk PBX x.y.z`; `svwar` enumerates nothing special (every
  REGISTER is challenged, like Asterisk with `alwaysauthreject=yes`); `svcrack` finds the
  configured weak passwords. `sipsak` works unmodified.
- The reply `Content-Length: 0`, `Allow` and `Supported` headers follow Asterisk 20; in
  small datagrams some optional headers are missing (see above). Nothing mentions the sensor.

## Events

All events use the shared `suckerpot_common.Event` model; `dst_port` is `SIP_PUBLIC_PORT`. A
*session* is one source IP: it opens with the first message and ends after `SENSOR_SIP_SESSION_IDLE`
(30 s) of silence or 300 s in all. UDP and TCP traffic of one IP share the session. No events are
emitted for 127.0.0.1 / ::1 (the container healthcheck).

| type | data |
| --- | --- |
| `connect` | `transport`, `protocol`, `source_verified` |
| `login_attempt` | `username`, `password` (only a configured weak password that matched, else `null`), `success`, `method` (`REGISTER` / `INVITE`), `realm`, `uri`, `algorithm`, `response_preview` (8 characters), `from`, `user_agent`, `transport`, `response_code`, `flags` |
| `command` | INVITE only: `input` (request line), `to`, `from`, `dialled`, `user_agent`, `transport`, `response_code`, `output_preview`, `body_preview`, `flags` |
| `scan` | `kind` = `options_scan` / `sip_probe` (first low-value message of a session: OPTIONS, REGISTER without credentials, unknown methods, responses; `method`, `input`, `request_uri`, `to`, `from`, `user_agent`, `response_code`, `flags`) / `sip_malformed` (`reason`, `size`, `preview`) / `sip_summary` (at session end: `messages`, `aggregated`, `methods`, `user_agents`, `targets` (users probed or dialled), `flags`, `window_s`) / `rate_limited` and `rate_limited_aggregate` (sources that did not get a session: `suppressed_packets`) |
| `disconnect` | `duration_s`, `reason` (`idle`, `max_session`, `shutdown`, `memory_pressure`), `messages`, `bytes_in`, `replies`, `silent` (requests not answered), `methods`, `flags`, `transports`, `suppressed_events` |

Every event of a session carries `source_verified`: `true` when the source address is proven
not spoofed (it returned a valid IP-bound nonce, or connected over TCP), `false` otherwise. Verified
sources get their own session-admission lane (20 sessions/s, up to the full 5000), unverified ones
share 50/s and 80 % of the slots, so a spoofed flood cannot lock real attackers out.

`flags` (ingest rules key on them): `register`, `invite`, `options_scan`, `toll_fraud` (the
dialled number starts with `+`, `00` or `011` and has at least 7 to 9 digits), `scanner_ua`
(User-Agent of SIPVicious `friendly-scanner`, `sipcli`, `sundayddr`, `iWar`, `sipsak`, ...),
`injection_attempt` (`${jndi`, `<?php`, shell metacharacters in URI or headers), `response`,
`unknown_method`.

## Limits and abuse resistance

- **Events.** At most 200 ordinary, 300 priority and 60 disconnect events/s per sensor; a
  session gets 200 high-value events (`login_attempt`, INVITE `command`), 1 immediate low-value
  `scan`, then only counts. New sessions: 50/s globally, 5 burst plus 0.1/s per IP, 5000 open
  at once; the rest are counted and reported every 60 s as `rate_limited`. Every string in an
  event is cut to 2048 characters with `truncate_data`.
- **Memory.** Per-source structures are small and bounded (10,000 tracked IPs per bucket
  table, 5000 sessions). A guard reads the cgroup `memory.current` (minus page cache) every
  second: above 70 % of `memory.max` new datagrams and connections are dropped, above 85 % TCP
  connections are aborted and sessions are closed. Without cgroup v2 the process RSS against
  `SENSOR_MEMORY_LIMIT` is used.
- **Watchdog.** A thread exits the process (code 70) if the event loop stalls for 10 s, so
  `restart: unless-stopped` recovers it.
- **Identity.** `/data/profile_secret` (mode 0600, generated once) seeds the Asterisk version
  and the nonces. Persist the `sip-sensor-data` volume so they stay stable.

### Fairness and bounded work

- **CPU.** The wall-clock time spent on each datagram or TCP message is charged to a per-source
  CPU bucket (`SENSOR_SIP_CPU_PER_IP`, default 5 % of a core) and a global one
  (`SENSOR_SIP_CPU_GLOBAL`, 60 %); a source over budget is dropped before parsing, and TCP
  handles one message per loop turn. Test: two sources flooding 4 KB, 60-header requests with
  digests keep the event loop lag below 1 s and a third source is still answered.
- **Output memory.** UDP replies are size-checked before they are built, are skipped when the
  socket's write buffer exceeds 64 KiB, and TCP replies are awaited with `drain()` (5 s, then
  `abort()`) before the next message is read, so pending output per connection is one reply.
  The memory guard is also consulted on every new datagram and connection. Test: 100 TCP
  connections over 25 source addresses that never read keep all write buffers below 64 KiB.
- **Event fairness.** Every event passes a per-source-IP event bucket and byte budget before
  the global one, so a flooding source cannot use up the shared budget. `connect`,
  `disconnect`, `login_attempt` and INVITE `command` events have their own queue that is always
  drained first; scans and summaries wait behind them. Test: a flooding IP and a victim IP, all
  victim events arrive.

## Configuration

| variable | default | meaning |
| --- | --- | --- |
| `SENSOR_PORT` | 5060 | container listen port (UDP and TCP) |
| `SIP_PUBLIC_PORT` | 5060 | `dst_port` in events |
| `SENSOR_SIP_TCP` | true | also listen on TCP |
| `SENSOR_SIP_USER_AGENT` | derived | `Server` / UA string, e.g. `FPBX-16.0.40(18.20.0)` |
| `SENSOR_SIP_REALM` | asterisk | Digest realm |
| `SENSOR_SIP_WEAK_CREDENTIALS` | `100:100,1000:1000,admin:admin` | `user:password` pairs that get a 200 on REGISTER (empty to disable) |
| `SENSOR_SIP_OWN_IPS` | empty | addresses that are never answered |
| `SENSOR_SIP_ALLOW_PRIVATE` | false | answer private sources (lab only) |
| `SENSOR_SIP_REPLY_PER_IP_RATE` / `_BURST` | 2 / 5 | replies per source |
| `SENSOR_SIP_REPLY_GLOBAL_RATE` / `_BURST` | 100 / 200 | replies, all sources |
| `SENSOR_SIP_REPLY_BYTES_RATE` / `_BURST` | 32768 / 65536 | reply bytes, all sources |
| `SENSOR_SIP_PPS_PER_IP` / `SENSOR_SIP_PPS_GLOBAL` | 50 / 3000 | packets processed per second |
| `SENSOR_SIP_SESSION_IDLE` | 30 | seconds of silence that end a session |
| `SENSOR_MAX_CONNECTIONS` / `SENSOR_MAX_PER_IP` | 100 / 5 | TCP caps |
| `SENSOR_FIRST_DATA_TIMEOUT` / `SENSOR_IDLE_TIMEOUT` / `SENSOR_MAX_SESSION` | 15 / 30 / 120 | TCP deadlines (s) |
| `SENSOR_GLOBAL_EVENTS_PER_SEC` / `SENSOR_PRIORITY_EVENTS_PER_SEC` | 200 / 300 | event budgets |
| `SENSOR_MEMORY_LIMIT` | 268435456 | used when the cgroup reports no limit |
| `SENSOR_DATA_DIR` | /data | profile secret |
| `REDIS_HOST` `REDIS_PORT` `REDIS_USER` `REDIS_PASSWORD` `EVENTS_STREAM` `EVENTS_MAXLEN` | | event publisher |

## Compose service

```yaml
  sensor-sip:
    build:
      context: .
      dockerfile: sensors/sip/Dockerfile
    image: suckerpot/sensor-sip:dev
    restart: unless-stopped
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=16m
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    user: "10001:10001"
    mem_limit: 256m
    memswap_limit: 256m
    cpus: 0.5
    pids_limit: 128
    dns: ["127.0.0.1"]
    networks:
      - ingress
      - sensors-sip
    ports:
      - "0.0.0.0:${SIP_HOST_PORT:-5060}:5060/udp"
      - "0.0.0.0:${SIP_HOST_PORT:-5060}:5060/tcp"
    environment:
      SENSOR_PORT: "5060"
      SENSOR_SIP_OWN_IPS: ${SIP_OWN_IPS:-}
      SIP_PUBLIC_PORT: ${SIP_PUBLIC_PORT:-5060}
      REDIS_HOST: redis
      REDIS_USER: sensor-sip
      REDIS_PASSWORD: ${REDIS_SENSOR_SIP_PASSWORD:?set REDIS_SENSOR_SIP_PASSWORD}
      EVENTS_STREAM: events:sip
    volumes:
      - sip-sensor-data:/data
    healthcheck:
      test: ["CMD", "python", "-m", "sip_sensor.healthcheck"]
      interval: 15s
      timeout: 5s
      retries: 3
      start_period: 20s
```

Also needed in the compose file: network `sensors-sip` (`internal: true`, shared with `redis`),
volume `sip-sensor-data`, and a Redis ACL user `sensor-sip` limited to XADD on `events:sip`
with `REDIS_SENSOR_SIP_PASSWORD` in `.env.example`. If the TCP listener is not wanted, drop the
`/tcp` port line and set `SENSOR_SIP_TCP=false`.

The sensor must see the real source address of each datagram, otherwise the per-source limits and
the source checks would act on the proxy. Docker's NAT (iptables) path keeps the source address
for published UDP ports; with the userland proxy (`docker-proxy`) the source seen by the container
is the proxy's, so do not enable the proxy for this port. `SIP_OWN_IPS` is an optional
comma-separated list of the host's own addresses that must never be answered (empty by default).

## Development

```
uv sync
uv run ruff check && uv run ruff format --check && uv run mypy . && uv run python -m pytest
sg docker -c "sh sensors/sip/tests/blackbox.sh"   # from the repo root: sipsak, SIPVicious, nmap
```
