# RDP sensor

A low-interaction Remote Desktop listener: it answers the RDP connection handshake like a
Windows Server 2022 host that requires Network Level Authentication, records the user name
from the `mstshash` cookie, and closes the connection when real authentication would start.
Run with `python -m rdp_sensor`. It listens on container port 3389. Compose maps the host port
`RDP_HOST_PORT` to it, and no capability is needed.

## What it does

1. **First bytes.** It waits for the client to send data (`RDP_FIRST_DATA_TIMEOUT`). If the
   data is not a TPKT (HTTP, a bare TLS ClientHello, an SSH banner, SMB, random bytes), the
   sensor emits a `scan` event with a hex preview, an ASCII preview and a protocol guess,
   then closes the connection without answering, as Windows does. A bare TLS ClientHello
   also gets fingerprinted (JA3, SNI, ALPN).
2. **X.224 Connection Request.** TPKT and X.224 are parsed by hand with strict length
   checks: the TPKT length must match the X.224 length indicator, the request is at most
   260 bytes, and the `RDP_NEG_REQ` and `RDP_NEG_CORRELATION_INFO` lengths are checked. A
   framing error produces a `scan` event (`kind = malformed_rdp`, `error = <reason>`). With a
   `Cookie: mstshash=<name>` line, it emits a `login_attempt` (method `rdp-cookie`, no
   password). Without one, it emits a `scan` (`kind = rdp_negotiation`). Both events carry
   the requested protocols, the routing token (`Cookie: msts=`), the correlation id and a hex
   preview of the request.
3. **Connection Confirm**, built as Windows builds it (source reference `0x1234`, response
   flags `0x1F`):
   - the client offers HYBRID_EX: HYBRID_EX is selected (`03 00 00 13 0e d0 00 00 12 34 00 02 1f 08 00 08 00 00 00`);
   - the client offers HYBRID (CredSSP): HYBRID is selected;
   - the client offers only standard RDP, SSL or RDSTLS: `RDP_NEG_FAILURE`
     `HYBRID_REQUIRED_BY_SERVER`, then close;
   - there is no negotiation request (a legacy client): a bare confirm. The sensor then reads
     the client's next PDU (usually MCS Connect Initial), records a preview and whether the
     `MS_T120` channel appears (BlueKeep scanners use it), then closes.
4. **TLS (CredSSP).** When HYBRID or HYBRID_EX is selected and `RDP_ENABLE_TLS=true`, the
   sensor completes the TLS handshake with its own certificate. It reads the client's first
   CredSSP `TSRequest`, records the CredSSP version and the NTLM NEGOTIATE details (flags,
   client OS version, and the domain and workstation names if the client sent them), then
   sends a TLS close_notify and closes. **CredSSP and NTLM authentication are not
   implemented.** The server never sends an NTLM challenge, so the client never sends a
   response derived from its password. The only credential the sensor ever records is the
   `mstshash` user name.

The fake identity lives under `RDP_DATA_DIR` (a volume) and is created on first start, with
every file at mode 0600:

- `profile_secret`: 32 random bytes in hex;
- the host name: derived from that secret, either a Windows install-time name such as
  `WIN-7QK2M0D9XRA` or a hand-picked style such as `SRV-RDS03`. Set `RDP_HOSTNAME` to
  override it;
- `rdp_cert.pem` and `rdp_key.pem`: a self-signed certificate made like the one Windows
  creates for Remote Desktop: RSA 2048, SHA-256, subject and issuer `CN=<host name>`, valid
  for 182 days, the Server Authentication EKU, and key usage Key Encipherment and Data
  Encipherment. On first creation its start date is set a few days to four months in the
  past. It is renewed 7 days before it expires, and again whenever the host name changes.

Nothing is ever executed, fetched or written outside `RDP_DATA_DIR`. The sensor never opens
outbound connections. `tests/test_static.py` checks all of this.

## Events

All events use the shared `suckerpot_common.Event` model. `dst_port` is `RDP_PUBLIC_PORT`.
No events are emitted for connections from 127.0.0.1 or ::1 (the container healthcheck).

| type | data |
| --- | --- |
| `connect` | (empty) |
| `login_attempt` | `username`, `password` (always null), `success` (false), `method` = `rdp-cookie`, `requested_protocols` (names), `requested_protocols_raw`, `neg_request`, `neg_flags`, `routing_token`, `other_cookie`, `correlation_id`, `notes`, `negotiation`, `raw_preview` (hex, 256 bytes max) |
| `scan` | `kind` = `rdp_negotiation` (same keys as `login_attempt` without the credential keys) / `non_rdp` / `malformed_rdp` / `rate_limited` / `rate_limited_aggregate`; for `non_rdp` and `malformed_rdp`: `protocol_guess`, `payload_preview` (hex, 256 bytes max), `payload_ascii`, `bytes_received`, `error`, `client_hello` (`ja3`, `ja3_hash`, `sni`, `alpn`, `supported_versions`, `cipher_count`); for `rate_limited`: `suppressed_connections`, `window_s` |
| `disconnect` | `duration_s`, `reason`, `stage`, `bytes_in`, `bytes_out`; when they apply: `negotiation`, `username`, `client_hello`, `tls` (`version`, `cipher`), `tls_error`, `credssp` (`bytes`, `version`, `ntlm_negotiate` {`flags`, `os_version`, `domain`, `workstation`} or `preview`), `followup_preview`, `ms_t120`, `after_confirm_preview` |

`protocol_guess` is one of: `http`, `tls`, `sslv2`, `ssh`, `tpkt`, `smb`, `socks4`, `socks5`,
`redis`, `text-command`, `asn1-ber`, `newline`, `text`, `unknown`, `empty`.

`negotiation` is one of: `HYBRID`, `HYBRID_EX`, `HYBRID_REQUIRED_BY_SERVER`, `legacy`.

`disconnect.reason` is one of:

| reason | meaning |
| --- | --- |
| `no_data` | the client sent nothing |
| `non_rdp` | the client sent non-RDP traffic |
| `malformed_rdp` | the Connection Request was malformed |
| `negotiation_failure` | the client did not offer CredSSP |
| `nla_required` | a legacy client was dropped |
| `credssp_not_supported` | the normal end for a real client |
| `client_closed_after_confirm` | nmap and many scanners end here |
| `tls_error` | the TLS handshake failed (or exceeded 64 rounds) |
| `tls_rate_limited` | CredSSP was selected, but this source started too many TLS handshakes; closed right after the confirm |
| `tls_busy` | no global TLS slot freed up within 2 s; closed right after the confirm |
| `evicted` | an idle connection (no bytes sent yet) was closed to make room at the global cap |
| `too_many_rounds` | the CredSSP read loop hit its iteration bound |
| `timeout` | a read deadline passed |
| `client_closed` | the client closed the connection |
| `client_reset` | the client reset the connection |
| `input_limit` | the client sent more than the input cap |
| `max_session` | the connection hit the time cap |
| `server_closed` | the sensor closed the connection |
| `error` | an internal error, caught and logged |
| `shutdown` | the sensor was stopping |

### Limits and rate limiting

- Connections: at most `RDP_MAX_CONNECTIONS` overall and `RDP_MAX_PER_IP` per source. At
  the global cap, the oldest connection that has not sent anything yet is evicted to make
  room for the new one. When no connection is idle, or the per-source cap is hit, the new
  connection is refused like this: the sensor reads its first bytes (2 s at most), waits a
  random 0.2 to 1 s, then closes. An instant accept-and-close would be easy to fingerprint.
  At most 64 connections are refused this way at the same time; beyond that they are
  closed at once.
- TLS is the expensive step. Before a handshake starts, a per-source bucket
  (`RDP_TLS_PER_SEC_PER_IP`, burst `RDP_TLS_BURST_PER_IP`) must allow it and the sensor must
  get one of `RDP_MAX_TLS_HANDSHAKES` global slots. Otherwise it closes right after the
  Connection Confirm.
- Event loop: every TLS and CredSSP loop yields to the event loop, checks its deadline on
  each pass and stops after 64 passes. A clean close_notify ends the stream. As a last
  resort, a watchdog thread exits the process when the event loop stalls for more than
  10 s, so compose restarts the container (`restart: unless-stopped` does not restart a
  container that is only unhealthy).
- Deadlines: first data, then each PDU and the TLS handshake (`RDP_HANDSHAKE_TIMEOUT`), the
  first TSRequest (`RDP_CREDSSP_TIMEOUT`), and a hard cap on the whole connection
  (`RDP_MAX_SESSION`).
- Buffers: at most 64 KiB is read from one client, all stages together. The Connection
  Request is at most 260 bytes, a buffered PDU at most 8 KiB, a TLS record at most 18 KiB
  and the TSRequest plaintext at most 16 KiB. Previews are capped at 256 bytes and strings in
  events at 1 KiB (`truncate_data`). With 200 parallel hostile connections, the container
  peaked at about 50 MiB in a flood test (`docker stats`).
- Events: a connection produces at most three events, so rate limiting happens once per
  connection. Each new connection is recorded only if both the per-source bucket
  (`RDP_SESSIONS_PER_SEC_PER_IP`, burst 15 times that) and the global bucket
  (`RDP_GLOBAL_SESSIONS_PER_SEC`, burst 2 times that) allow it. Connections that are not
  recorded get exactly the same bytes on the wire. They are counted per IP, and every 60 s
  the sensor emits one aggregated `scan` event (`kind = rate_limited`) per IP, for the 100
  IPs with the most unrecorded connections. The rest are reported in one `scan` event
  (`kind = rate_limited_aggregate`, `src_ip` `0.0.0.0`, with `suppressed_connections` and
  `source_ips`). Counters are reset after each flush. Two global buckets act as a second
  safety net: one for events (`RDP_GLOBAL_EVENTS_PER_SEC`) and one for `disconnect` events
  (`RDP_DISCONNECT_EVENTS_PER_SEC`). Events go through a bounded in-process queue, so handlers never wait for Redis.
- Errors: any exception in a handler is caught. The connection is closed quietly, a
  `disconnect` event with `reason = error` is still emitted, and no error text is ever sent
  to the client.

## Fidelity notes (nmap 7.98, FreeRDP 2)

- `nmap -sV`: `3389/tcp open ms-wbt-server Microsoft Terminal Services`,
  `Service Info: OS: Windows`.
- `rdp-enum-encryption`: `CredSSP (NLA): SUCCESS`, `CredSSP with Early User Auth: SUCCESS`.
  Native RDP and SSL are refused with `HYBRID_REQUIRED_BY_SERVER`.
- `rdp-ntlm-info` returns nothing, because no NTLM CHALLENGE is ever sent. A real Windows
  host would reveal its NetBIOS and DNS names and its OS build here. This is the most
  visible difference from a real server, and a deliberate one: this is a low-interaction
  sensor.
- `xfreerdp /u:administrator /cert:ignore +auth-only`: the sensor records
  `username = administrator`. The client fails with `ERRCONNECT_CONNECT_TRANSPORT_FAILED`
  after the TLS handshake, much like a server that drops the connection during CredSSP.
- TLS is OpenSSL with a cipher order like Schannel's (ECDHE-RSA-AES256-GCM first), and
  TLS 1.2 and 1.3 are both accepted. Session tickets are off (`OP_NO_TICKET`), so the sensor
  keeps no resumption state. The key exchange groups are set to X25519, P-256 and P-384
  only on Python versions that have `SSLContext.set_groups`; on Python 3.13 OpenSSL's
  default list is used. The JA3S and TLS extension order still differ from
  Schannel's.

## Environment variables

| variable | default | meaning |
| --- | --- | --- |
| `REDIS_HOST`, `REDIS_PORT`, `REDIS_USER`, `REDIS_PASSWORD`, `EVENTS_STREAM`, `EVENTS_MAXLEN` | see `suckerpot_common` | Redis stream publisher |
| `RDP_PORT` | `3389` | listen port inside the container |
| `RDP_PUBLIC_PORT` | `3389` | port reported as `dst_port` |
| `RDP_HOSTNAME` | derived | NetBIOS name used in the certificate CN (1 to 15 characters) |
| `RDP_DATA_DIR` | `/data` | profile secret, certificate and key (volume) |
| `RDP_ENABLE_TLS` | `true` | complete the TLS handshake after selecting CredSSP |
| `RDP_MAX_CONNECTIONS` / `RDP_MAX_PER_IP` | `200` / `8` | connection caps |
| `RDP_FIRST_DATA_TIMEOUT` | `8` | seconds to wait for the first bytes |
| `RDP_HANDSHAKE_TIMEOUT` | `10` | seconds per PDU and for the TLS handshake |
| `RDP_CREDSSP_TIMEOUT` | `10` | seconds to wait for the first TSRequest |
| `RDP_MAX_SESSION` | `60` | hard cap on one connection, in seconds |
| `RDP_SESSIONS_PER_SEC_PER_IP` | `2` | recorded connections per source per second (burst 15 times that) |
| `RDP_GLOBAL_SESSIONS_PER_SEC` | `50` | recorded connections per second overall (burst 2 times that) |
| `RDP_GLOBAL_EVENTS_PER_SEC` | `200` | global event cap (all types except `disconnect`) |
| `RDP_DISCONNECT_EVENTS_PER_SEC` | `60` | global cap on `disconnect` events (burst 2 times that) |
| `RDP_TLS_PER_SEC_PER_IP` / `RDP_TLS_BURST_PER_IP` | `5` / `20` | TLS handshakes started per source |
| `RDP_MAX_TLS_HANDSHAKES` | `32` | TLS handshakes and CredSSP reads in progress at the same time |

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
      RDP_MAX_CONNECTIONS: ${RDP_MAX_CONNECTIONS:-200}
      RDP_MAX_PER_IP: ${RDP_MAX_PER_IP:-8}
    # Explicit IPv4 so Docker does not also publish on [::]. No capability needed.
    ports:
      - "0.0.0.0:${RDP_HOST_PORT:-3389}:3389"
    # Docker's embedded DNS still resolves service names; external names fail.
    dns: ["127.0.0.1"]
    # ingress: inbound only. sensors-rdp: internal link to Redis.
    networks: [ingress, sensors-rdp]
    volumes:
      # Profile secret and RDP certificate, generated on first start. Never committed.
      - rdp-data:/data
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001
    mem_limit: 128m
    memswap_limit: 128m
    cpus: 0.5
    pids_limit: 128
    restart: unless-stopped
```

The orchestrator also has to add the `rdp-data` volume, the `sensors-rdp` network
(`internal: true`), a `sensor-rdp` Redis ACL user limited to XADD on `events:rdp`, and
`REDIS_SENSOR_RDP_PASSWORD` (plus an optional `RDP_HOSTNAME`) in `.env.example`.

## Development

```
uv sync
uv run ruff check && uv run ruff format --check && uv run mypy . && uv run python -m pytest
sg docker -c "sh sensors/rdp/tests/blackbox.sh"   # from the repo root: real nmap + FreeRDP clients
```
