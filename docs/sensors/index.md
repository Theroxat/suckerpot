# Sensors

Sensors are the fake services that face the internet. Each one speaks just enough of a protocol to look real, records what the attacker does, and publishes it as [events](../event-schema.md). A sensor never runs attacker input and never makes an outbound connection.

| Sensor | Fake service | Host port (default) | Stream | Status |
| --- | --- | --- | --- | --- |
| [SSH](ssh.md) | OpenSSH 9.6 on Ubuntu, with an emulated shell | 22 | `events:ssh` | Built (M2). Wired into Compose. |
| [Web](web.md) | Apache 2.4 with PHP 8.3 (unpatched), WordPress and phpMyAdmin | 80 and 443 | `events:web` | In progress (M6). Code exists, **not yet in Compose** (under security review). |
| [RDP](rdp.md) | Windows Server 2022 with NLA, handshake only | 3389 | `events:rdp` | Built (M6). Wired into Compose. |
| [Telnet](telnet.md) | BusyBox-style DVR or router login | 23 | `events:telnet` | Built (M6). Wired into Compose. |

## Rules every sensor follows

- **No execution.** No `subprocess`, `os.system`, `eval` or `exec` on attacker input. Fake commands return canned or generated output.
- **No fetching.** A download command only records the URL. Fetching, when it exists, is done by ingest and is off by default.
- **No outbound traffic.** A sensor sits on `sp-ingress` (inbound only) and on its own internal network to reach Redis. See [Architecture](../ARCHITECTURE.md#networks).
- **Bounded everything.** Connection caps (total and per source IP), timeouts on every read, a size cap on every captured field, a memory budget, and bounded queues.
- **A watchdog.** Docker does not restart a container that is only *unhealthy*. Each sensor runs a watchdog thread that exits the process when the event loop stalls, so `restart: unless-stopped` brings it back.
- **Drop, never block.** When Redis refuses a write, the event is dropped and counted. A sensor never waits for Redis inside a connection handler.
- **Its own stream and Redis user.** A sensor can only `XADD` to its own stream. Ingest checks that the `sensor` field of every event matches the stream.
- **Realistic identity.** Plausible banners and host names. The words "honeypot" and "suckerpot" never appear anywhere a client could see.
- **No events from the health check.** Connections from loopback (the container health check) produce no events.

```{toctree}
:maxdepth: 1
:hidden:

ssh
web
rdp
telnet
```
