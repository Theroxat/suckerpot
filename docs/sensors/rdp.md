# RDP sensor

```{admonition} Status
:class: note

Built (M6) and wired into Compose as `sensor-rdp`, with the stream `events:rdp`, the internal network `sensors-rdp`, the Redis user `sensor-rdp`, the secret `REDIS_SENSOR_RDP_PASSWORD` and the volume `rdp-data`.
```

## What it emulates

A low-interaction Remote Desktop listener. It answers the RDP handshake like a Windows Server 2022 host that requires Network Level Authentication (NLA), records the user name from the `mstshash` cookie, and closes the connection when real authentication would start. It listens on container port 3389.

1. **First bytes.** It waits for the client to send data. If the data is not TPKT (HTTP, a bare TLS ClientHello, an SSH banner, SMB, random bytes), it emits a `scan` event with a hex preview, an ASCII preview and a protocol guess, then closes the connection without answering, as Windows does. A bare TLS ClientHello is fingerprinted (JA3, SNI, ALPN).
2. **X.224 Connection Request.** TPKT and X.224 are parsed by hand with strict length checks. A framing error produces a `scan` event. With a `Cookie: mstshash=<name>` line the sensor emits a `login_attempt` (method `rdp-cookie`, no password). Without a cookie it emits a `scan` (`kind = rdp_negotiation`).
3. **Connection Confirm**, built as Windows builds it:
   - the client offers HYBRID_EX: HYBRID_EX is selected;
   - the client offers HYBRID (CredSSP): HYBRID is selected;
   - the client offers only standard RDP, SSL or RDSTLS: a `HYBRID_REQUIRED_BY_SERVER` failure, then close;
   - no negotiation request (a legacy client): a bare confirm. The sensor reads the next PDU, records a preview and whether the `MS_T120` channel appears (BlueKeep scanners use it), then closes.
4. **TLS (CredSSP).** When HYBRID or HYBRID_EX is selected and `RDP_ENABLE_TLS=true`, the sensor completes the TLS handshake with its own certificate. It reads the client's first CredSSP `TSRequest`, records the CredSSP version and the NTLM NEGOTIATE details, sends a TLS `close_notify` and closes.

```{important}
CredSSP and NTLM authentication are **not implemented**. The server never sends an NTLM challenge, so a client never sends a response derived from a password. The only credential the sensor ever records is the `mstshash` user name.
```

## What it records

| Event `type` | `data` keys |
| --- | --- |
| `connect` | (empty) |
| `login_attempt` | `username`, `password` (always null), `success` (false), `method` = `rdp-cookie`, `requested_protocols`, `requested_protocols_raw`, `neg_request`, `neg_flags`, `routing_token`, `other_cookie`, `correlation_id`, `notes`, `negotiation`, `raw_preview` (hex, 256 bytes at most) |
| `scan` | `kind` = `rdp_negotiation`, `non_rdp`, `malformed_rdp`, `rate_limited` or `rate_limited_aggregate`. Depending on the kind: `protocol_guess`, `payload_preview`, `payload_ascii`, `bytes_received`, `error`, `client_hello` (`ja3`, `ja3_hash`, `sni`, `alpn`, `supported_versions`, `cipher_count`), `suppressed_connections`, `window_s`. |
| `disconnect` | `duration_s`, `reason`, `stage`, `bytes_in`, `bytes_out`. When they apply: `negotiation`, `username`, `client_hello`, `tls` (`version`, `cipher`), `tls_error`, `credssp` (`bytes`, `version`, `ntlm_negotiate`), `followup_preview`, `ms_t120`, `after_confirm_preview`. |

`negotiation` is `HYBRID`, `HYBRID_EX`, `HYBRID_REQUIRED_BY_SERVER` or `legacy`.

The `disconnect.reason` values include `no_data`, `non_rdp`, `malformed_rdp`, `negotiation_failure`, `nla_required`, `credssp_not_supported` (the normal end for a real client), `client_closed_after_confirm` (where `nmap` and many scanners stop), `tls_error`, `tls_rate_limited`, `tls_busy`, `evicted`, `too_many_rounds`, `timeout`, `client_closed`, `client_reset`, `input_limit`, `max_session`, `server_closed`, `error` and `shutdown`.

## Limits and abuse resistance

- **Connections.** At most `RDP_MAX_CONNECTIONS` overall and `RDP_MAX_PER_IP` per source. At the global cap, the oldest connection that has not sent anything yet is evicted. A refused connection is not closed at once (that would be easy to fingerprint): the sensor reads its first bytes (2 s at most), waits a random 0.2 to 1 s, then closes. At most 64 connections are held in this state at once.
- **TLS is the expensive step.** A per-source bucket (`RDP_TLS_PER_SEC_PER_IP`, burst `RDP_TLS_BURST_PER_IP`) and one of `RDP_MAX_TLS_HANDSHAKES` global slots must be free. Otherwise the sensor closes right after the Connection Confirm.
- **Event loop.** Every TLS and CredSSP loop yields to the event loop, checks its deadline on each pass and stops after 64 passes. A watchdog thread exits the process if the loop stalls for more than 10 s, so Compose restarts the container.
- **Deadlines.** First data, each PDU and the TLS handshake, the first `TSRequest`, and a hard cap on the whole connection (`RDP_MAX_SESSION`).
- **Buffers.** At most 64 KiB is read from one client. The Connection Request is at most 260 bytes, a buffered PDU 8 KiB, a TLS record 18 KiB and the `TSRequest` plaintext 16 KiB. Previews are 256 bytes at most and strings in events 1 KiB. In a flood test with 200 parallel hostile connections, the container peaked at about 50 MiB.
- **Events.** A connection produces at most three events. Each new connection is recorded only if both the per-source bucket and the global bucket allow it. Unrecorded connections get exactly the same bytes on the wire, are counted per IP, and are reported every 60 s in aggregated `scan` events (`rate_limited` for the 100 busiest IPs, `rate_limited_aggregate` for the rest). Two more global buckets cap all events and `disconnect` events. Events go through a bounded in-process queue, so handlers never wait for Redis.
- **Errors.** Any exception in a handler is caught. The connection is closed quietly, a `disconnect` with `reason = error` is still emitted, and no error text is ever sent to the client.
- **Nothing outside its data path.** Nothing is executed or fetched, and nothing is written outside `RDP_DATA_DIR`. A test checks this by reading the code.

## Configuration

See [Configuration](../configuration.md#rdp-sensor) for the full table.

| Variable | Default | Meaning |
| --- | --- | --- |
| `RDP_HOST_PORT` | `3389` | Host port (Compose only) |
| `RDP_HOSTNAME` | derived | NetBIOS name used in the certificate (1 to 15 characters) |
| `RDP_ENABLE_TLS` | `true` | Complete the TLS handshake after selecting CredSSP |
| `RDP_MAX_CONNECTIONS`, `RDP_MAX_PER_IP` | `200`, `8` | Connection caps |

## Fingerprint notes

The fake identity lives under `RDP_DATA_DIR` (a volume), created on first start with every file at mode 0600: a random `profile_secret`, a host name derived from it (a Windows install-time name such as `WIN-7QK2M0D9XRA`, or a hand-picked style such as `SRV-RDS03`), and a self-signed certificate made like the one Windows creates for Remote Desktop (RSA 2048, SHA-256, 182 days, `CN=<host name>`). The certificate is renewed 7 days before it expires.

What a scanner sees:

- `nmap -sV` reports `ms-wbt-server Microsoft Terminal Services` on Windows.
- `rdp-enum-encryption` reports CredSSP (NLA) and CredSSP with Early User Auth as supported. Native RDP and SSL are refused with `HYBRID_REQUIRED_BY_SERVER`.
- `rdp-ntlm-info` returns **nothing**, because no NTLM challenge is ever sent. A real Windows host would reveal its NetBIOS name, DNS name and OS build here. This is the most visible difference from a real server, and a deliberate one.
- A FreeRDP client records the user name and then fails after the TLS handshake, much like a server that drops the connection during CredSSP.
- The TLS cipher order resembles Schannel's, and TLS 1.2 and 1.3 are accepted. The JA3S hash and the TLS extension order still differ from Schannel's.
