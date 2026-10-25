# SuckerPot SMB sensor

A low-interaction, defensive honeypot that looks like a Windows Server 2019/2022 SMB file
service on port 445. It parses the NetBIOS framing and SMB headers, answers `NEGOTIATE` and
`SESSION_SETUP` the way a modern Windows server does, records what clients send, and closes.

It is an **observation sink only**. It never grants a session, never verifies or cracks a
credential, never reproduces or simulates any vulnerable behaviour, never executes anything,
and never makes an outbound connection. Downloads or payloads are not fetched — nothing in SMB
is fetched at all.

## What it does

1. **NetBIOS session framing.** Each message is a 4-byte header (type + 3-byte big-endian
   length) followed by the SMB payload. The length is capped (`SMB_MAX_PDU_BYTES`, default
   128 KiB), reads are bounded and deadline-driven, and partial reads across TCP segments are
   reassembled with a single deadline. Keepalives are ignored; other NetBIOS control messages
   are recorded and the connection is closed.
2. **SMB2/3 (default).** `NEGOTIATE` is answered like a modern Windows server: the highest
   dialect the client offers up to **3.1.1**, a per-deployment `ServerGuid`, Windows
   capabilities (DFS; plus leasing and multi-credit from 2.1; plus encryption on 3.0 / 3.0.2
   only when the client offers it), `MaxTransact/Read/Write = 8 MiB`, the current system time,
   signing **enabled but not required**, and for 3.1.1 the pre-auth-integrity (SHA-512)
   context plus an encryption context only when the client sent one. For `SESSION_SETUP` the sensor speaks just enough NTLMSSP to
   send a realistic **CHALLENGE**: its flags are computed from the client's NEGOTIATE flags
   (as Windows does), and its target-info AV pairs carry the NetBIOS / DNS computer, domain and
   tree names derived from the profile secret, plus a current timestamp. From the client's **AUTHENTICATE** it
   records only the domain, user name, workstation, the negotiated flags and a short
   length + an 8-byte preview of the LM/NT response blobs (empty when a blob is absent) and
   whether it is NTLMv1 or v2 — never the full blobs — and it always answers
   `STATUS_LOGON_FAILURE`. `LOGOFF` gets `STATUS_USER_SESSION_DELETED`; any other SMB2 command
   is answered with an error (`STATUS_ACCESS_DENIED` / `STATUS_USER_SESSION_DELETED`) and
   recorded as a `scan`. A source over its CPU budget gets `STATUS_INSUFFICIENT_RESOURCES`
   and the connection is closed.
3. **Legacy SMB1.** Like a modern Windows server, the sensor answers an SMB1 `NEGOTIATE`
   according to the dialects offered, and nothing more:
   - `SMB 2.???` offered → the SMB2 "switch to SMB2" response (wildcard dialect `0x02FF`);
     the client then sends a fresh SMB2 `NEGOTIATE`;
   - only `SMB 2.002` offered → a real SMB2 2.0.2 `NEGOTIATE` response;
   - SMB1 dialects only → recorded, then the connection is reset (Windows with SMB1
     disabled).
   Any further SMB1 traffic is recorded as a `scan` (bounded hex preview, the SMB1 command byte
   and a best-effort command name, the `smbv1` flag) and the connection is closed. The sensor
   never implements SMB1 command processing, Trans2/NT_TRANSACT handlers or any
   exploit-specific logic — old traffic is opaque bytes to be logged, not interpreted.
   `SMB_SMB1_MODE=reset` resets on every SMB1 negotiate.
4. **Anything else** (not valid SMB framing/signature) is recorded as a `scan` with a hex
   preview and a protocol guess, then the connection is closed.

## Events

All events use the shared `Event` schema and are emitted via a bounded in-process queue drained
by background workers (a handler never waits on Redis). `dst_port` is the public port.

| Type | When | Key `data` fields |
|---|---|---|
| `connect` | new connection accepted | `transport` |
| `login_attempt` | NTLM AUTHENTICATE received | `username`, `password` (always `null`), `success` (always `false`), `method` (`"ntlm"`), `domain`, `workstation`, `ntlm_flags`, `ntlm_version`, `lm_response_len`, `nt_response_len`, `lm_response_preview`, `nt_response_preview` (≤ 8 bytes, hex), `session_key_len`, `anonymous`, `flags` |
| `scan` | SMB1 traffic, unexpected SMB2 command, non-SMB bytes, NetBIOS control, oversized/malformed PDU, or rate-limited connections | `kind`, `protocol_guess`, `payload_preview` (hex), `payload_ascii`, `bytes_received`, `flags`, plus kind-specific keys (`smb1_dialects`, `smb1_outcome`, `smb1_command_name`, `smb2_command`, `netbios_type`, …) |
| `disconnect` | connection closed | `duration_s`, `reason`, `stage`, `bytes_in`, `bytes_out`, `pdus`, `dialect`, `offered_dialects`, `flags`, `events_suppressed` (per-session quota), `events_dropped` (rate budgets) |

Tag hints in `data.flags` (ingest rules key on them): `ntlm`, `smbv1`, `null_session`,
`compound_request`. The sensor deliberately does **not** emit `eternalblue` / `ms17_010` tags
itself — detecting those is left to ingest's declarative rules, which can key on the recorded
`smb1_command_name` / `payload_preview`. See *Deviations* below.

`scan` kinds: `smb1_negotiate`, `smb1_command`, `unexpected_command`, `session_setup_non_ntlm`,
`session_setup_unexpected_ntlm`, `ntlm_authenticate_unparsed`, `non_smb`, `netbios_control`,
`oversized_pdu`, `malformed_smb2`, `rate_limited`, `rate_limited_aggregate`.

## Fingerprint

Measured against a throwaway image mapped host `445 → 4450` (as in production):

- `nmap -sV`: **`microsoft-ds?`** — nmap's `SMBProgNeg` probe offers SMB1 dialects only, so it
  gets a reset, exactly like Windows Server 2019/2022 with SMB1 disabled.
- `nmap --script smb-protocols` → dialects **2.0.2, 2.1, 3.0, 3.0.2, 3.1.1**.
- `nmap --script smb2-security-mode` → **"3.1.1: Message signing enabled but not required"**.
- `nmap --script smb2-capabilities` → 2.0.2: DFS; 2.1 to 3.1.1: DFS, Leasing, Multi-credit.
- `nmap --script smb2-time` → current date, `start_date: N/A` (as on Windows).
- `smb-os-discovery` / `smb-security-mode` (SMB1-only scripts) print nothing, as on a host
  with SMB1 disabled.
- `smbclient -m SMB3` with a user (list shares, connect `C$`), `-N` (null session) and
  `-m SMB2_02` → `NT_STATUS_LOGON_FAILURE`, with the user name / domain / workstation recorded
  (`null_session` flagged for the anonymous attempt); `-m NT1` → connection reset
  (`NT_STATUS_CONNECTION_DISCONNECTED`).

No attacker-visible string reveals the honeypot: there are no library names, and the host /
domain / DNS names and the `ServerGuid` are derived from a random per-deployment secret in
`/data` (never documentation or TEST-NET ranges).

## Isolation and limits

- No code execution of any kind (enforced by an AST static test), no file writes outside
  `/data`, no outbound connections, no payload fetching.
- Global connection cap (`SMB_MAX_CONNECTIONS`, 200) and per-IP cap (`SMB_MAX_PER_IP`, 10);
  idle connections are evicted under pressure. Over-cap connections are slow-rejected.
- Timeouts everywhere (first-data, idle, per-PDU read, hard session cap).
- Per-connection byte budget and a global `SMB_MAX_BUFFERED` budget; `SMB_MAX_PDUS` per
  connection; every captured field is truncated.
- Per-connection event quotas with an aggregated "suppressed" count, a global event rate cap,
  and a separate priority bucket so `connect` / `login_attempt` / `disconnect` survive a flood.
- **Event fairness (per-IP):** connection admission, priority events and ordinary events each
  go through a per-IP token bucket *before* the shared one, and every shared bucket keeps a
  reserve that only light sources (those with most of their own budget left) may spend; the
  tail of the queue is reserved for priority events. One or many flooding IPs therefore cannot
  cost a quiet victim IP its credentials or session boundaries (12 flooding IPs: every victim
  event still arrives). Dropped events are counted in the session's `disconnect`.
- **CPU fairness (per-IP):** every expensive response (3.1.1 negotiate, NTLM challenge) spends a
  per-IP CPU token; a source over budget is cut (`cpu_rate_limited`). The PDU loop yields on
  every turn, so no mix of sources and connections can monopolise the event loop.
- **Reply memory:** responses are drained before the next PDU is built, every pending byte is
  charged to the global memory budget until it drains, per-connection output is capped, and the
  memory guard is sampled on admission as well as periodically.
- A cgroup memory guard (reads `memory.current`): refuses new connections above 70 % and aborts
  the heaviest connections above 85 %.
- An event-loop watchdog exits the process if the loop stalls > 10 s, so `restart:
  unless-stopped` recovers (Docker does not restart a merely-unhealthy container).
- Sockets get `SO_SNDBUF`/`SO_RCVBUF ≈ 32 KiB`, `TCP_USER_TIMEOUT ≈ 30 s`, and are aborted
  (not just closed) on write failure or memory pressure, so a non-reading peer cannot pin
  memory.

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `REDIS_HOST` / `REDIS_PORT` | — / `6379` | Redis Streams endpoint |
| `REDIS_USER` / `REDIS_PASSWORD` | — | ACL user `sensor-smb` (XADD only) |
| `EVENTS_STREAM` | `events` | Stream name (compose sets `events:smb`) |
| `EVENTS_MAXLEN` | `10000` | Approx. stream cap |
| `SMB_PORT` | `4450` | Container listen port |
| `SMB_PUBLIC_PORT` | `445` | Public port reported as `dst_port` |
| `SMB_HOSTNAME` | *(derived)* | Override the NetBIOS computer name (1–15 chars) |
| `SMB_DOMAIN` | *(derived)* | Override the NetBIOS domain / workgroup |
| `SMB_DATA_DIR` | `/data` | Where the profile secret is stored |
| `SMB_SMB1_MODE` | `steer` | `steer` (switch to SMB2, then record) or `reset` (record, drop) |
| `SMB_MAX_CONNECTIONS` | `200` | Global connection cap |
| `SMB_MAX_PER_IP` | `10` | Per-IP connection cap |
| `SMB_FIRST_DATA_TIMEOUT` | `10` | Seconds to wait for the first bytes |
| `SMB_IDLE_TIMEOUT` | `20` | Seconds to wait for the next PDU |
| `SMB_READ_TIMEOUT` | `10` | Seconds to finish one PDU already started |
| `SMB_MAX_SESSION` | `60` | Hard cap on one connection (seconds) |
| `SMB_MAX_PDU_BYTES` | `131072` | Max single NetBIOS message |
| `SMB_MAX_SESSION_INPUT` | `262144` | Max bytes read per connection |
| `SMB_MAX_PDUS` | `64` | Max PDUs handled per connection |
| `SMB_MAX_BUFFERED` | `33554432` | Global budget for parser buffers + pending output (bytes) |
| `SMB_MAX_PENDING_OUTPUT` | `131072` | Max output queued on one connection before it is cut |
| `SMB_MEMORY_LIMIT` | `268435456` | Fallback limit when the cgroup reports none |
| `SMB_CPU_PER_SEC_PER_IP` | `80` | Expensive responses (negotiate/NTLM) per source |
| `SMB_CPU_BURST_PER_IP` | `320` | Burst for the per-IP CPU bucket |
| `SMB_SESSIONS_PER_SEC_PER_IP` | `2` | Recorded connections per source (burst ×15) |
| `SMB_GLOBAL_SESSIONS_PER_SEC` | `50` | Recorded connections overall (burst ×2) |
| `SMB_GLOBAL_EVENTS_PER_SEC` | `200` | Global event emit cap |
| `SMB_PER_IP_EVENTS_PER_SEC` | `20` | Non-priority events per source, before the queue |
| `SMB_PER_IP_EVENTS_BURST` | `60` | Burst for the per-IP event bucket |
| `SMB_PRIORITY_EVENTS_PER_SEC` | `80` | Priority (connect/login/disconnect) emit cap |
| `SMB_PER_IP_PRIORITY_PER_SEC` | `10` | Priority events per source, before the shared cap |
| `SMB_PER_IP_PRIORITY_BURST` | `30` | Burst for the per-IP priority bucket |
| `SMB_SESSION_EVENT_QUOTA` | `24` | Events one connection may emit |

## Compose service block

The orchestrator merges this into `docker-compose.yml`. It uses the house hardening style:
`ingress` + internal `sensors-smb` networks, `dns: ["127.0.0.1"]`, `mem_limit` =
`memswap_limit`, `cpus 0.5`, `pids_limit 128`, read-only root fs with tmpfs `/tmp`.

```yaml
  sensor-smb:
    build:
      context: .
      dockerfile: sensors/smb/Dockerfile
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    user: "10001:10001"
    environment:
      REDIS_HOST: redis
      REDIS_PORT: "6379"
      REDIS_USER: sensor-smb
      REDIS_PASSWORD: ${REDIS_SENSOR_SMB_PASSWORD:?REDIS_SENSOR_SMB_PASSWORD must be set in .env}
      EVENTS_STREAM: events:smb
      EVENTS_MAXLEN: ${EVENTS_MAXLEN:-10000}
      SMB_PORT: "4450"
      SMB_PUBLIC_PORT: ${SMB_HOST_PORT:-445}
      SMB_HOSTNAME: ${SMB_HOSTNAME:-}
      SMB_DOMAIN: ${SMB_DOMAIN:-}
      SMB_DATA_DIR: /data
      SMB_SMB1_MODE: ${SMB_SMB1_MODE:-steer}
      SMB_MAX_CONNECTIONS: ${SMB_MAX_CONNECTIONS:-200}
      SMB_MAX_PER_IP: ${SMB_MAX_PER_IP:-10}
    # Explicit IPv4 so Docker does not also publish on [::]. No capability needed.
    ports:
      - "0.0.0.0:${SMB_HOST_PORT:-445}:4450"
    # Docker's embedded DNS still resolves service names; external names fail.
    dns: ["127.0.0.1"]
    # ingress: inbound only. sensors-smb: internal link to Redis.
    networks: [ingress, sensors-smb]
    volumes:
      # Profile secret (NetBIOS/DNS names, ServerGuid), generated on first start. Never committed.
      - smb-data:/data
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001
    mem_limit: 256m
    memswap_limit: 256m
    cpus: 0.5
    pids_limit: 128
    restart: unless-stopped
```

The matching top-level additions: network `sensors-smb` (`internal: true`), volume `smb-data`,
a Redis ACL user `sensor-smb` limited to `XADD` on `events:smb`, and `REDIS_SENSOR_SMB_PASSWORD`
in `.env`.

## Tests

- Unit: framing, NTLM challenge build / AUTHENTICATE parse (malformed, truncated, oversized,
  timing-bounded), SPNEGO/DER, negotiate response + dialect selection, identity derivation.
- Protocol: the real listener over real sockets (negotiate, full NTLM exchange, null session,
  SMB1 steer, non-SMB scan, unexpected command, caps/timeouts, memory guard).
- `test_static.py`: an AST guard proving no code-execution / process-spawning primitives, no
  writes outside `/data`, no network clients, and no giveaway strings.
- Real clients from throwaway containers: `smbclient -m SMB3` (list shares / connect → logon
  failure, recorded user name) and `nmap -sV` / `--script smb-protocols,smb2-security-mode`.

Gates: `ruff check`, `ruff format --check`, `mypy --strict`, `pytest`.

## Deviations

- **No self-asserted exploit tags.** The sensor tags `smbv1` and records the SMB1 command byte
  and name, but it does not itself emit `eternalblue` / `ms17_010`. Those are exploit-specific
  interpretations; per the contract ("old traffic is opaque bytes to be logged, not
  interpreted") they are left to ingest's declarative rules, which can match on the recorded
  `smb1_command_name` and `payload_preview`.
- **Null sessions are refused.** Many Windows servers accept an anonymous NTLM logon and only
  deny the following tree connect; the sensor never grants any session, so `smbclient -N`
  sees `NT_STATUS_LOGON_FAILURE` instead. The attempt is still recorded (`null_session`).
- **Compound requests** (`NextCommand ≠ 0`) are flagged (`compound_request`) and only the first
  command is acted on; the sensor does not implement SMB2 compounding.
```
