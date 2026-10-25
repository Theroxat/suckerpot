# RDP sensor

A low-interaction Remote Desktop listener that answers the RDP connection handshake like a
Windows Server 2022 host, plays the CredSSP (NLA) NTLM exchange up to the logon decision, and —
when NLA is disabled — runs the MCS/GCC connect sequence far enough to capture the cleartext
credentials from the Client Info PDU. It never grants a session, never executes anything and
never opens an outbound connection. Run with `python -m rdp_sensor`. It listens on container
port 3389; compose maps the host port `RDP_HOST_PORT` to it, and no capability is needed.

## What it does

1. **First bytes.** It waits for the client to send data (`RDP_FIRST_DATA_TIMEOUT`). If the
   data is not a TPKT (HTTP, a bare TLS ClientHello, an SSH banner, SMB, random bytes), the
   sensor emits a `scan` event with a hex preview, an ASCII preview and a protocol guess, then
   closes without answering, as Windows does. A bare TLS ClientHello is also fingerprinted
   (JA3, SNI, ALPN).
2. **X.224 Connection Request.** TPKT and X.224 are parsed by hand with strict length checks.
   A `Cookie: mstshash=<name>` line produces a `login_attempt` (method `rdp-cookie`, no
   password); a request without one produces a `scan` (`kind = rdp_negotiation`).
3. **Connection Confirm**, built as Windows builds it (source reference `0x1234`, response
   flags `0x1F`):
   - HYBRID_EX or HYBRID offered → that protocol is selected (CredSSP / NLA path);
   - only standard RDP security offered → `RDP_NEG_FAILURE` `HYBRID_REQUIRED_BY_SERVER`;
   - in **NLA-disabled mode** (`SENSOR_RDP_NLA_MODE=optional`) a client that offers
     `PROTOCOL_SSL` and no CredSSP gets SSL selected (standard-security path over TLS);
   - no negotiation request (a legacy client) → a bare confirm, then the next PDU is read,
     previewed and checked for `MS_T120` (BlueKeep), then the connection is dropped.
4. **CredSSP / NLA path (HYBRID / HYBRID_EX).** The sensor completes the TLS handshake with its
   per-deployment certificate, then plays the server side of one NTLM exchange carried in
   CredSSP `TSRequest` tokens:
   - it reads the client's NTLM **NEGOTIATE**;
   - it answers with a realistic NTLM **CHALLENGE**: the NegotiateFlags are derived from the
     client's, and the target-info AV pairs carry the deployment's NetBIOS and DNS computer and
     domain names, the DNS tree name and a current timestamp, so `nmap --script rdp-ntlm-info`
     sees a domain-joined Windows Server 2022;
   - it reads the client's NTLM **AUTHENTICATE** and records a `login_attempt` (method
     `rdp-ntlm`) with the domain, user name, workstation, NTLM version (v1/v2), and the NT
     response length plus an 8-byte preview — **never the full response blob, never any
     cracking**;
   - **only** when the user/password pair is one of the configured decoy accounts
     (`SENSOR_RDP_ACCOUNTS`), it verifies the NTLMv2 / NTLMv1 response against the known
     cleartext (the server challenge is known) and records `password` and `success = true`;
     otherwise `password` is null;
   - it always ends with a CredSSP `errorCode` of `STATUS_LOGON_FAILURE` (`0xC000006D`) and
     closes, exactly like a real host refusing the logon. No session is ever granted.
5. **NLA-disabled path (SSL selected).** After TLS, the sensor runs the MCS/GCC sequence
   (Connect Initial → Connect Response, Erect Domain, Attach User → Confirm, Channel Joins →
   Confirms) up to the **Client Info PDU**, records the cleartext domain, user name, password,
   alternate shell and working directory, and the GCC client build / name / keyboard layout,
   then sends a plausible MCS teardown and closes. Standard RDP (RC4) encryption is **not**
   implemented: a client offering only standard RDP security always gets
   `HYBRID_REQUIRED_BY_SERVER`.

The fake identity lives under `RDP_DATA_DIR` (a volume) and is created on first start, each
file at mode 0600: a 32-byte `profile_secret`; the NetBIOS host name (e.g. `WIN-7QK2M0D9XRA` or
`SRV-RDS03`, override with `RDP_HOSTNAME`); a NetBIOS domain and a private DNS domain
(e.g. `OFFICE` / `office.local`), all derived from the secret, never from public data; and
`rdp_cert.pem` / `rdp_key.pem`, a self-signed certificate made like the one Windows creates for
Remote Desktop (RSA 2048, SHA-256, CN = host name, 182-day lifetime, Server Authentication
EKU). Nothing is ever executed, fetched or written outside `RDP_DATA_DIR`; `tests/test_static.py`
checks this with an AST scan.

## Events

All events use the shared `suckerpot_common.Event` model. `dst_port` is `RDP_PUBLIC_PORT`. No
events are emitted for connections from 127.0.0.1 or ::1 (the container healthcheck).

| type | data |
| --- | --- |
| `connect` | (empty) |
| `login_attempt` (`rdp-cookie`) | `username`, `password` (null), `success` (false), `method`, `client_tool`, `requested_protocols`, `requested_protocols_raw`, `neg_request`, `neg_flags`, `routing_token`, `other_cookie`, `correlation_id`, `notes`, `negotiation`, `raw_preview` |
| `login_attempt` (`rdp-ntlm`) | `username`, `password` (cleartext only on a decoy match, else null), `success`, `method`, `client_tool`, `domain`, `workstation`, `ntlm_version` (`v1`/`v2`), `ntlm_flags`, `nt_response_len`, `nt_response_preview` (8 bytes hex), `anonymous` |
| `login_attempt` (`rdp-nla-off`) | `username`, `password` (cleartext, bounded), `success` (false), `method`, `client_tool`, `domain`, `alternate_shell`, `working_dir` |
| `scan` | `kind` = `rdp_negotiation` / `non_rdp` / `malformed_rdp` / `mcs_malformed` / `credssp_malformed` / `credssp_authenticate_unparsed` / `rate_limited` / `rate_limited_aggregate`; for `non_rdp`/`malformed_rdp`: `protocol_guess`, `payload_preview`, `payload_ascii`, `bytes_received`, `error`, `client_hello`; for `rate_limited`: `suppressed_connections`, `window_s` |
| `disconnect` | `duration_s`, `reason`, `stage`, `bytes_in`, `bytes_out`, `flags`, `client_tool`; when they apply: `negotiation`, `username`, `client_hello`, `tls` (`version`, `cipher`), `tls_error`, `credssp` (`version`, `ntlm_negotiate` {`flags`, `os_version`}), `ntlm` (the AUTHENTICATE fields), `weak_password_match`, `client_info`, `gcc` (`client_build`, `client_name`, `keyboard_layout`, `rdp_version`, `channels`), `followup_preview`, `ms_t120`, `after_confirm_preview`, `events_suppressed`, `events_dropped` |

**Flags** (for the ingest rules engine, in `disconnect.data.flags`): `rdp_ntlm` (an NTLM
exchange happened), `rdp_nla_off` (standard-security MCS path taken), `weak_password_match` (a
decoy password was confirmed), `bluekeep_probe` (the `MS_T120` channel appeared), `null_session`
(anonymous NTLM).

`negotiation` is one of `HYBRID`, `HYBRID_EX`, `SSL`, `HYBRID_REQUIRED_BY_SERVER`, `legacy`.

`disconnect.reason` includes: `no_data`, `non_rdp`, `malformed_rdp`, `negotiation_failure`,
`nla_required`, `client_closed_after_confirm`, `tls_error`, `tls_rate_limited`, `tls_busy`,
`cpu_rate_limited`, `credssp_no_negotiate`, `credssp_no_authenticate`, `credssp_malformed`,
`credssp_logon_failure`,
`client_info_captured`, `mcs_closed`, `mcs_malformed`, `mcs_max_pdus`, `evicted`,
`memory_pressure`, `timeout`, `client_closed`, `client_reset`, `input_limit`, `buffered_limit`,
`output_limit`, `max_session`, `server_closed`, `error`, `shutdown`.

## Client tool identification

`client_tool` is a best-effort guess combining the signals the handshake already produced; it is
never authoritative. The table below is built from captures of real tools run against the sensor
in throwaway containers (FreeRDP 2.x, nmap 7.94, hydra 9.5, ncrack 0.7, rdesktop 1.9).

| tool | how it is recognised |
| --- | --- |
| `nmap` | `mstshash` cookie `nmap`; or JA3 `24b17abb1c18a4c5eb806eb218774f32`; or a CredSSP challenge read with no cookie (rdp-ntlm-info / rdp-enum-encryption) |
| `ncrack` | `mstshash` cookie `NCRACK_USER` |
| `FreeRDP` | TLS JA3 `a3afc2c46ba4a7d7fbe1cfb7a3031c2f`; or a GCC client name containing `freerdp`. **hydra** and **ncrack**'s CredSSP brute-forcing are built on libfreerdp and present as FreeRDP at the per-connection level — their brute-force *pattern* (many short sessions) is tagged by ingest, not here |
| `rdesktop` | TLS JA3 `b19598fb776b9d0e9d2f428f249858c7`; or a GCC client name containing `rdesktop` |
| `mstsc` | GCC clientBuild 2600 / 6002 / 7601; or an NTLM NEGOTIATE OS version `10.0.x` with a cookie |
| `unknown` | nothing matched |

The lookup tables live in `rdp_sensor/fingerprint.py`; `tests/test_fingerprint.py` pins the
captured signatures. Add a new capture to both when a new tool is characterised.

### Limits and rate limiting

- **Connections**: at most `RDP_MAX_CONNECTIONS` overall and `RDP_MAX_PER_IP` per source. At the
  global cap the oldest connection that has not sent anything is evicted; otherwise a new
  connection is slow-refused (first bytes read, random 0.2–1 s delay, then abort) so an
  accept-and-close is not an easy fingerprint. At most 64 are refused this way at once.
- **TLS** is the expensive step: a per-source bucket (`RDP_TLS_PER_SEC_PER_IP`, burst
  `RDP_TLS_BURST_PER_IP`) must allow it and one of `RDP_MAX_TLS_HANDSHAKES` global slots must be
  free, otherwise the connection closes right after the confirm. Each live TLS session is
  charged a fixed budget to the process memory accounting.
- **CPU (lesson 16)**: NTLM crypto and each MCS PDU spend a per-source CPU token
  (`RDP_CPU_PER_SEC_PER_IP`, burst `RDP_CPU_BURST_PER_IP`); over budget, the connection is
  closed with `cpu_rate_limited`. Every TLS / CredSSP / MCS loop yields to the event loop and
  checks a wall-clock deadline, so no mix of IPs and connections can block the loop.
- **Memory (lessons 15/17)**: pending output is charged to a global byte budget
  (`RDP_MAX_BUFFERED`), per-connection output is capped (`RDP_MAX_PENDING_OUTPUT`), and a
  process memory guard reads the cgroup once a second — above 70 % it refuses new connections,
  above 85 % it aborts the connections holding the most memory. 200 non-reading connections over
  25 source IPs held the container at ≈ 28 % of its 128 MiB limit in a load test.
- **Events (lesson 18)**: a per-IP token bucket precedes every shared budget, and the shared
  budgets keep a reserve that heavy sources cannot spend, so flooding IPs cannot starve a quiet
  victim. Important events (`connect`, `login_attempt`, `disconnect`) use a separate priority
  budget; `disconnect` is never charged per-IP so a session boundary always gets out. A single
  connection's events are capped by `RDP_SESSION_EVENT_QUOTA`. Unrecorded connections behave
  identically on the wire and are summarised once per minute per IP (`kind = rate_limited`).
- **Deadlines**: first data, each PDU and the TLS handshake (`RDP_HANDSHAKE_TIMEOUT`), the
  CredSSP TSRequests (`RDP_CREDSSP_TIMEOUT`), the whole MCS sequence (`RDP_MCS_TIMEOUT`), and a
  hard cap on the connection (`RDP_MAX_SESSION`). A watchdog thread exits the process if the
  loop stalls > 10 s, so `restart: unless-stopped` recovers it.
- **Buffers**: at most 96 KiB read from one client across all stages; the Connection Request is
  ≤ 260 bytes, a buffered PDU ≤ 8 KiB, a TLS record ≤ 18 KiB, a TSRequest ≤ 16 KiB, decrypted
  MCS plaintext ≤ 32 KiB; previews ≤ 256 bytes; event strings ≤ 1 KiB (`truncate_data`).

## Fidelity notes (nmap 7.94, FreeRDP 2)

- `nmap -sV`: `3389/tcp open ms-wbt-server Microsoft Terminal Services`, `Service Info: OS:
  Windows`.
- `nmap --script rdp-enum-encryption`: `CredSSP (NLA): SUCCESS`, `CredSSP with Early User Auth:
  SUCCESS`.
- `nmap --script rdp-ntlm-info` now returns the full identity, e.g. `NetBIOS_Computer_Name:
  SRV-RDS01`, `DNS_Domain_Name: office.local`, `Product_Version: 10.0.20348` (Windows Server
  2022), with a consistent `System_Time`.
- `xfreerdp /u:administrator /p:P@ssw0rd /sec:nla +auth-only`: the client authenticates with
  NTLMv2; the sensor confirms the decoy password and refuses the logon with
  `SPNEGO received NTSTATUS: STATUS_LOGON_FAILURE [0xC000006D]`, like a real server.
- `xfreerdp /sec:tls` against a sensor in `optional` mode drives the MCS sequence to the Client
  Info PDU; the sensor records the cleartext user name and password, then tears the session
  down.
- TLS is OpenSSL with a Schannel-like cipher order (ECDHE-RSA-AES256-GCM first), session tickets
  off. The JA3S and TLS extension order still differ from Schannel's.

## Environment variables

| variable | default | meaning |
| --- | --- | --- |
| `REDIS_HOST`, `REDIS_PORT`, `REDIS_USER`, `REDIS_PASSWORD`, `EVENTS_STREAM`, `EVENTS_MAXLEN` | see `suckerpot_common` | Redis stream publisher |
| `RDP_PORT` / `RDP_PUBLIC_PORT` | `3389` / `3389` | listen port / port reported as `dst_port` |
| `RDP_HOSTNAME` | derived | NetBIOS name in the certificate CN and NTLM target info |
| `RDP_DATA_DIR` | `/data` | profile secret, certificate and key (volume) |
| `RDP_ENABLE_TLS` | `true` | complete TLS after selecting CredSSP / SSL |
| `SENSOR_RDP_NLA_MODE` | `required` | `required` (CredSSP only) or `optional` (also accept `PROTOCOL_SSL` and run MCS to the Client Info PDU) |
| `SENSOR_RDP_ACCOUNTS` | `administrator:P@ssw0rd,administrator:123456,admin:admin` | decoy `user:password` pairs whose NTLM response is verified against the known cleartext |
| `RDP_MAX_CONNECTIONS` / `RDP_MAX_PER_IP` | `200` / `8` | connection caps |
| `RDP_FIRST_DATA_TIMEOUT` | `8` | seconds to wait for the first bytes |
| `RDP_HANDSHAKE_TIMEOUT` | `10` | seconds per PDU and for the TLS handshake |
| `RDP_CREDSSP_TIMEOUT` | `10` | seconds to wait for each CredSSP TSRequest |
| `RDP_MCS_TIMEOUT` | `15` | seconds for the whole MCS sequence (NLA-off path) |
| `RDP_MAX_MCS_PDUS` | `24` | MCS PDUs handled on one NLA-off connection |
| `RDP_MAX_SESSION` | `60` | hard cap on one connection, in seconds |
| `RDP_TLS_PER_SEC_PER_IP` / `RDP_TLS_BURST_PER_IP` | `5` / `20` | TLS handshakes started per source |
| `RDP_MAX_TLS_HANDSHAKES` | `32` | TLS handshakes + CredSSP/MCS reads in progress at once |
| `RDP_MAX_TLS_PER_IP` | `4` | concurrent TLS handshakes allowed from a single source (so a few IPs cannot hold every global slot) |
| `RDP_CPU_PER_SEC_PER_IP` / `RDP_CPU_BURST_PER_IP` | `60` / `240` | expensive steps (NTLM crypto / MCS PDUs) per source |
| `RDP_MEMORY_LIMIT` | `128 MiB` | fallback used only when the cgroup reports no limit |
| `RDP_MAX_BUFFERED` / `RDP_MAX_PENDING_OUTPUT` | `24 MiB` / `64 KiB` | global buffer budget / per-connection output cap |
| `RDP_SESSION_EVENT_QUOTA` | `16` | events emitted by one connection |
| `RDP_SESSIONS_PER_SEC_PER_IP` / `RDP_GLOBAL_SESSIONS_PER_SEC` | `2` / `50` | recorded connections per source / overall |
| `RDP_GLOBAL_EVENTS_PER_SEC` / `RDP_PRIORITY_EVENTS_PER_SEC` | `200` / `80` | global event / priority-event caps |
| `RDP_PER_IP_EVENTS_PER_SEC` / `RDP_PER_IP_EVENTS_BURST` | `20` / `60` | non-priority events per source |
| `RDP_PER_IP_PRIORITY_PER_SEC` / `RDP_PER_IP_PRIORITY_BURST` | `10` / `30` | priority events per source |

## Compose service

```yaml
  sensor-rdp:
    build:
      context: .
      dockerfile: sensors/rdp/Dockerfile
    <<: *hardening
    user: "10001:10001"
    environment:
      REDIS_HOST: redis
      REDIS_PORT: "6379"
      REDIS_USER: sensor-rdp
      REDIS_PASSWORD: ${REDIS_SENSOR_RDP_PASSWORD:?REDIS_SENSOR_RDP_PASSWORD must be set in .env}
      EVENTS_STREAM: events:rdp
      EVENTS_MAXLEN: ${EVENTS_MAXLEN:-10000}
      RDP_PORT: "3389"
      RDP_PUBLIC_PORT: ${RDP_HOST_PORT:-3389}
      RDP_HOSTNAME: ${RDP_HOSTNAME:-}
      RDP_DATA_DIR: /data
      SENSOR_RDP_NLA_MODE: ${RDP_NLA_MODE:-required}
      SENSOR_RDP_ACCOUNTS: ${RDP_ACCOUNTS:-administrator:P@ssw0rd,administrator:123456,admin:admin}
      RDP_MAX_TLS_PER_IP: ${RDP_MAX_TLS_PER_IP:-4}
      RDP_MAX_CONNECTIONS: ${RDP_MAX_CONNECTIONS:-200}
      RDP_MAX_PER_IP: ${RDP_MAX_PER_IP:-8}
    # Explicit IPv4 so Docker does not also publish on [::]. No capability needed.
    ports:
      - "0.0.0.0:${RDP_HOST_PORT:-3389}:3389"
    dns: ["127.0.0.1"]
    networks: [ingress, sensors-rdp]
    volumes:
      - rdp-data:/data
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001
    mem_limit: 128m
    memswap_limit: 128m
    cpus: 0.5
    pids_limit: 128
    restart: unless-stopped
```

The orchestrator also adds the `rdp-data` volume, the `sensors-rdp` network (`internal: true`),
a `sensor-rdp` Redis ACL user limited to XADD on `events:rdp`, and `REDIS_SENSOR_RDP_PASSWORD`
(plus optional `RDP_HOSTNAME`, `SENSOR_RDP_NLA_MODE`, `SENSOR_RDP_ACCOUNTS`) in `.env.example`.

## Development

```
uv sync
uv run ruff check && uv run ruff format --check && uv run mypy . && uv run python -m pytest
sg docker -c "sh sensors/rdp/tests/blackbox.sh"   # real nmap + FreeRDP clients in containers
```
