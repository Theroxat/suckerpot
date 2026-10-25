# RDP sensor

```{admonition} Status
:class: note

Built (M6, deepened in M10) and wired into Compose as `sensor-rdp`, with the stream `events:rdp`, the internal network `sensors-rdp`, the Redis user `sensor-rdp`, the secret `REDIS_SENSOR_RDP_PASSWORD` and the volume `rdp-data`.
```

## What it emulates

A low-interaction Remote Desktop listener. It answers the RDP handshake like a Windows Server 2022 host, plays the Network Level Authentication (NLA) exchange up to the logon decision, and records what the client sends. It never grants a session, never runs anything and never opens an outbound connection. It listens on container port 3389.

1. **First bytes.** It waits for the client to send data. If the data is not TPKT (HTTP, a bare TLS ClientHello, an SSH banner, SMB, random bytes), it emits a `scan` event with a hex preview, an ASCII preview and a protocol guess, then closes the connection without answering, as Windows does. A bare TLS ClientHello is fingerprinted (JA3, SNI, ALPN).
2. **X.224 Connection Request.** TPKT and X.224 are parsed by hand with strict length checks. A `Cookie: mstshash=<name>` line produces a `login_attempt` (method `rdp-cookie`, no password). A request without one produces a `scan` (`kind = rdp_negotiation`).
3. **Connection Confirm**, built the way Windows builds it:
   - the client offers HYBRID_EX or HYBRID (CredSSP): that protocol is selected;
   - the client offers only standard RDP security: a `HYBRID_REQUIRED_BY_SERVER` failure, then close;
   - the client offers `PROTOCOL_SSL` and no CredSSP: with `SENSOR_RDP_NLA_MODE=required` (the default) the same failure; with `optional` SSL is selected (see [NLA-off mode](#nla-off-mode-optional));
   - no negotiation request (a legacy client): a bare confirm. The sensor reads the next PDU, records a preview and checks whether the `MS_T120` channel appears (BlueKeep scanners use it), then closes.
4. **TLS and CredSSP (NLA).** After the TLS handshake, with the sensor's own certificate, the sensor plays the server side of one NTLM exchange, carried in CredSSP `TSRequest` tokens:
   - it reads the client's NTLM **NEGOTIATE** and records the version and OS fields;
   - it answers with a realistic NTLM **CHALLENGE**. The flags follow the client's. The target information carries the deployment's NetBIOS and DNS names for the computer and the domain, the DNS tree name and a current timestamp. A tool such as `nmap --script rdp-ntlm-info` therefore sees a domain-joined Windows Server 2022;
   - it reads the client's NTLM **AUTHENTICATE** and records a `login_attempt` (method `rdp-ntlm`) with the domain, user name, workstation, NTLM version, flags and a short preview of the response;
   - it checks the password only for a **decoy account** (see [Decoy accounts](#decoy-accounts)). For any other pair the password is not known, so it is recorded as null;
   - it always ends with the CredSSP error `STATUS_LOGON_FAILURE` (`0xC000006D`) and closes, like a real host that refuses the logon. No session is ever granted.

```{important}
The sensor never stores or uses the full NTLM response. It keeps the response length and an 8-byte preview. It never tries to crack a password. The only check it runs is "does this response match the decoy password for this user?", and only for the decoy pairs in its configuration.
```

## NLA-off mode (optional)

Some clients do not use NLA. They offer only `PROTOCOL_SSL`, and the connection is protected by TLS alone, so the password crosses the TLS tunnel in the Client Info PDU. This is the only way to see those passwords.

With `SENSOR_RDP_NLA_MODE=optional` (Compose: `RDP_NLA_MODE=optional` in `.env`), the sensor does the following for a client that offers SSL and no CredSSP:

1. selects `PROTOCOL_SSL` in the Connection Confirm and completes TLS;
2. runs the MCS / GCC connect sequence (Connect Initial and Response, Erect Domain, Attach User, Channel Joins) up to the **Client Info PDU**;
3. records the cleartext domain, user name, password, alternate shell and working directory, and the GCC client build, client name and keyboard layout, as a `login_attempt` (method `rdp-nla-off`);
4. sends a plausible MCS teardown and closes.

Standard RDP encryption (RC4) is **not** implemented. A client that offers only standard RDP security always gets `HYBRID_REQUIRED_BY_SERVER`, in both modes.

The default is `required`. In that mode the sensor never reads a password from a client that skips NLA. See [Security](../SECURITY.md#credentials-the-sensors-record) for the reasons.

## Decoy accounts

`SENSOR_RDP_ACCOUNTS` (Compose: `RDP_ACCOUNTS` in `.env`) is a list of `user:password` pairs, separated by commas. The default is:

```text
administrator:P@ssw0rd,administrator:123456,admin:admin
```

These pairs are **decoys**. They are public, because they are in this repository by design. They are not real credentials, and no real host uses them. Their only job is to show whether an attacker guessed a common password:

- A pair in the list is checked against the NTLM response. If the response matches, the sensor records the password, sets `success` to `true` and adds the `weak_password_match` flag. The logon is still refused. The check uses the server challenge that the sensor sent, so it is a verification, not a search.
- A user name that is not in the list, or a wrong password for a listed user, produces no password at all.
- Nothing is guessed from the response. A pair that is not configured is never tested.

Set your own pairs in `.env` if you want other passwords to be verified. Keep the list short. Each pair costs one NTLM check per login attempt.

## What it records

All events use the shared `suckerpot_common.Event` model. `dst_port` is `RDP_PUBLIC_PORT`. No events are emitted for connections from 127.0.0.1 or ::1 (the container health check).

| Event `type` | Method or kind | `data` keys |
| --- | --- | --- |
| `connect` | | (empty) |
| `login_attempt` | `rdp-cookie` | `username`, `password` (always null), `success` (false), `method`, `client_tool`, `requested_protocols`, `requested_protocols_raw`, `neg_request`, `neg_flags`, `routing_token`, `other_cookie`, `correlation_id`, `notes`, `negotiation`, `raw_preview` |
| `login_attempt` | `rdp-ntlm` | `username`, `password` (cleartext only for a decoy match, else null), `success`, `method`, `client_tool`, `domain`, `workstation`, `ntlm_version` (`v1` or `v2`), `ntlm_flags`, `nt_response_len`, `nt_response_preview` (8 bytes, hex), `anonymous` |
| `login_attempt` | `rdp-nla-off` | `username`, `password` (cleartext, length-limited), `success` (false), `method`, `client_tool`, `domain`, `alternate_shell`, `working_dir` |
| `scan` | | `kind` = `rdp_negotiation`, `non_rdp`, `malformed_rdp`, `mcs_malformed`, `credssp_malformed`, `credssp_authenticate_unparsed`, `rate_limited` or `rate_limited_aggregate`. Depending on the kind: `protocol_guess`, `payload_preview`, `payload_ascii`, `bytes_received`, `error`, `client_hello`, `suppressed_connections`, `window_s` |
| `disconnect` | | `duration_s`, `reason`, `stage`, `bytes_in`, `bytes_out`, `flags`, `client_tool`. When they apply: `negotiation`, `username`, `client_hello`, `tls` (`version`, `cipher`), `tls_error`, `credssp` (`version`, `ntlm_negotiate` with `flags` and `os_version`), `ntlm` (the AUTHENTICATE fields), `weak_password_match`, `client_info`, `gcc` (`client_build`, `client_name`, `keyboard_layout`, `rdp_version`, `channels`), `followup_preview`, `ms_t120`, `after_confirm_preview`, `events_suppressed`, `events_dropped` |

`negotiation` is one of `HYBRID`, `HYBRID_EX`, `SSL`, `HYBRID_REQUIRED_BY_SERVER` or `legacy`.

### Flags

The sensor puts flags in `disconnect.data.flags`. The ingest rules read them.

| Flag | Meaning | Tag |
| --- | --- | --- |
| `rdp_ntlm` | An NTLM exchange happened | |
| `rdp_nla_off` | The standard-security MCS path was taken (NLA-off mode) | `rdp-cleartext` |
| `weak_password_match` | A decoy password was confirmed | `weak-credentials` |
| `bluekeep_probe` | The `MS_T120` channel appeared | `bluekeep` |
| `null_session` | An anonymous NTLM logon (empty user and password) | |

### Disconnect reasons

`disconnect.reason` includes: `no_data`, `non_rdp`, `malformed_rdp`, `negotiation_failure`, `nla_required`, `client_closed_after_confirm`, `tls_error`, `tls_rate_limited`, `tls_busy`, `cpu_rate_limited`, `credssp_no_negotiate`, `credssp_no_authenticate`, `credssp_malformed`, `credssp_logon_failure`, `client_info_captured`, `mcs_closed`, `mcs_malformed`, `mcs_max_pdus`, `evicted`, `memory_pressure`, `timeout`, `client_closed`, `client_reset`, `input_limit`, `buffered_limit`, `output_limit`, `max_session`, `server_closed`, `error` and `shutdown`.

## Client tool identification

`client_tool` is a best-effort guess. It combines the signals the handshake already gave the sensor, and it is never authoritative. The guess is put on every RDP login and on `disconnect`. The table is built from captures of real tools run against the sensor in throwaway containers (FreeRDP 2.x, nmap 7.94, hydra 9.5, ncrack 0.7, rdesktop 1.9).

| Tool | How it is recognised |
| --- | --- |
| `nmap` | `mstshash` cookie `nmap`; or TLS JA3 `24b17abb1c18a4c5eb806eb218774f32`; or a CredSSP challenge read with no cookie (`rdp-ntlm-info`, `rdp-enum-encryption`) |
| `ncrack` | `mstshash` cookie `NCRACK_USER` |
| `FreeRDP` | TLS JA3 `a3afc2c46ba4a7d7fbe1cfb7a3031c2f`; or a GCC client name containing `freerdp`. hydra and ncrack's CredSSP brute-forcing use libfreerdp, so they show up as FreeRDP for one connection. Their pattern (many short sessions) is tagged by ingest, not here. |
| `rdesktop` | TLS JA3 `b19598fb776b9d0e9d2f428f249858c7`; or a GCC client name containing `rdesktop` |
| `mstsc` | GCC client build 2600, 6002 or 7601; or an NTLM NEGOTIATE OS version `10.0.x` with a cookie |
| `unknown` | Nothing matched |

The lookup tables live in `sensors/rdp/rdp_sensor/fingerprint.py`. `sensors/rdp/tests/test_fingerprint.py` pins the captured signatures. When you characterise a new tool, add the capture to both.

Ingest stores the guess on the session as `sessions.client_tool`. Only the RDP sensor's guess is stored, and `unknown` is stored as null. The session page shows it as **Client**. See [Event schema](../event-schema.md#session-fields).

## Limits and abuse resistance

- **Connections.** At most `RDP_MAX_CONNECTIONS` overall and `RDP_MAX_PER_IP` per source. At the global cap, the oldest connection that has not sent anything is evicted. Otherwise a new connection is slow-refused: its first bytes are read, then the sensor waits a random 0.2 to 1 s and aborts. An immediate close would be an easy fingerprint. At most 64 connections are refused this way at once.
- **TLS is the expensive step.** A per-source bucket (`RDP_TLS_PER_SEC_PER_IP`, burst `RDP_TLS_BURST_PER_IP`) must allow it. One of the `RDP_MAX_TLS_HANDSHAKES` global slots must be free, and no more than `RDP_MAX_TLS_PER_IP` may come from one source. Otherwise the connection closes right after the confirm. This stops a few addresses from holding every slot.
- **CPU.** NTLM crypto and each MCS PDU spend a per-source CPU token (`RDP_CPU_PER_SEC_PER_IP`, burst `RDP_CPU_BURST_PER_IP`). Over budget, the connection closes with `cpu_rate_limited`. Every TLS, CredSSP and MCS loop yields to the event loop and checks a wall-clock deadline.
- **Memory.** Pending output is charged to a global byte budget (`RDP_MAX_BUFFERED`), and each connection's output is capped (`RDP_MAX_PENDING_OUTPUT`). A memory guard reads the cgroup limit once a second. Above 70 % it refuses new connections. Above 85 % it closes the connections that use the most memory.
- **Events.** A per-IP token bucket comes before every shared budget, and the shared budgets keep a reserve that heavy sources cannot use. `connect`, `login_attempt` and `disconnect` use a priority budget. `disconnect` is not charged per IP, so every session end gets out. One connection emits at most `RDP_SESSION_EVENT_QUOTA` events. Connections that are not recorded behave the same on the wire and are summarised once a minute per IP (`kind = rate_limited`).
- **Deadlines.** First data, each PDU and the TLS handshake (`RDP_HANDSHAKE_TIMEOUT`), each CredSSP TSRequest (`RDP_CREDSSP_TIMEOUT`), the whole MCS sequence (`RDP_MCS_TIMEOUT`), and a hard cap on one connection (`RDP_MAX_SESSION`). A watchdog thread exits the process if the event loop stalls for more than 10 s, so `restart: unless-stopped` recovers it.
- **Buffers.** At most 96 KiB is read from one client across all stages. The Connection Request is at most 260 bytes, a buffered PDU 8 KiB, a TLS record 18 KiB, a TSRequest 16 KiB and decrypted MCS data 32 KiB. Previews are 256 bytes at most and event strings 1 KiB.
- **Errors.** Any exception in a handler closes the connection quietly. A `disconnect` with `reason = error` is still emitted, and no error text is sent to the client.
- **Nothing outside its data path.** Nothing is executed or fetched, and nothing is written outside `RDP_DATA_DIR`. A test reads the code to check this.

## Configuration

See [Configuration](../configuration.md#rdp-sensor) for the full table. The most useful variables are:

| Variable in `.env` | Sensor variable | Default | Meaning |
| --- | --- | --- | --- |
| `RDP_NLA_MODE` | `SENSOR_RDP_NLA_MODE` | `required` | `required` or `optional` (see [NLA-off mode](#nla-off-mode-optional)) |
| `RDP_ACCOUNTS` | `SENSOR_RDP_ACCOUNTS` | the decoy list above | Decoy `user:password` pairs |
| `RDP_MAX_TLS_PER_IP` | `RDP_MAX_TLS_PER_IP` | `4` | TLS handshakes allowed from one source at a time |
| `RDP_HOST_PORT` | (Compose only) | `3389` | Host port |
| `RDP_HOSTNAME` | `RDP_HOSTNAME` | derived | NetBIOS name in the certificate (1 to 15 characters) |
| `RDP_MAX_CONNECTIONS`, `RDP_MAX_PER_IP` | same | `200`, `8` | Connection caps |

Compose maps the `.env` names to the sensor names. An unknown value for `SENSOR_RDP_NLA_MODE` stops the sensor at start-up, so a typo is noticed at once.

## Fingerprint notes

The fake identity lives under `RDP_DATA_DIR` (a volume), created on first start with every file at mode 0600: a random `profile_secret`, a host name derived from it (a Windows install-time name such as `WIN-7QK2M0D9XRA`, or a hand-picked style such as `SRV-RDS03`), a NetBIOS domain and a private DNS domain derived from the same secret, and a self-signed certificate made like the one Windows creates for Remote Desktop (RSA 2048, SHA-256, 182 days, `CN=<host name>`). The certificate is renewed 7 days before it expires.

What a scanner sees:

- `nmap -sV` reports `ms-wbt-server Microsoft Terminal Services`, and `Service Info: OS: Windows`.
- `rdp-enum-encryption` reports CredSSP (NLA) and CredSSP with Early User Auth as supported. Native RDP and SSL are refused with `HYBRID_REQUIRED_BY_SERVER` in the default mode.
- `rdp-ntlm-info` returns the full identity: NetBIOS computer name, DNS domain name, `Product_Version` 10.0.20348 (Windows Server 2022) and a consistent system time.
- A FreeRDP client with `/sec:nla` authenticates with NTLMv2. The sensor confirms a decoy password if it matches, and refuses the logon with `STATUS_LOGON_FAILURE`, like a real server.
- A FreeRDP client with `/sec:tls` against a sensor in `optional` mode reaches the Client Info PDU. The sensor records the user name and password, then tears the session down.
- TLS is OpenSSL with a Schannel-like cipher order (ECDHE-RSA-AES256-GCM first), with session tickets off. TLS 1.2 and 1.3 are accepted. The JA3S hash and the TLS extension order still differ from Schannel's.
