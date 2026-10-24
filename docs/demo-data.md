# Demo data

`just demo` fills SuckerPot with synthetic attack data. Use it to try the pipeline and the dashboard, to develop against it, and to make screenshots.

The demo data is fake. The generator never contacts real attackers and never sends traffic to the internet. It publishes events to Redis the same way a sensor does, so the rest of the pipeline is tested too.

## Run it

```bash
just demo
```

This runs the `demo` service from `docker-compose.yml`, which is in the `tools` profile. It is not started by `docker compose up`. It connects to Redis as the `sensor` user, so it uses the same permissions as a real sensor.

You can also run it without `just`:

```bash
docker compose --profile tools run --rm demo
```

Arguments after `just demo` go to the generator:

```bash
just demo --days 3 --sessions 200 --seed 7
```

## What it generates

The generator first creates a **backfill**: sessions spread over the last `--days` days. Then, with `--live`, it keeps sending new sessions. Each session is a short story made of events. The four sensors are covered:

| Sensor | Session types in the generator | Example story |
| --- | --- | --- |
| SSH | Password guessing, successful login with reconnaissance, persistence attempts, a miner install | Tried a list of passwords, then logged in and ran a miner |
| Telnet | Single logins, and botnet waves that arrive together | Part of a coordinated wave of weak-password attempts |
| Web | Generic HTTP scanning, WordPress login probes, and PHP upload probes | Looked for admin pages, then tried an exploit |
| RDP | Connection probes with one username | Opened a session and tried one username |

Some SSH sessions come from one campaign: a single source tries many passwords. The mix, the timing and the source addresses aim to look realistic, with busy hours, quiet nights and a few repeat visitors.

The generator uses only the documentation address ranges (`192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24`). Nothing is captured from the internet.

```{note}
In M1, the real sensors do not exist yet. The generator sends the events directly, as the `sensor` Redis user. The event shape is the same as the one the sensors will send. See [Event schema](event-schema.md).
```

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `--days N` | `DEMO_DAYS` (30) | Spread the backfill over the last N days. Must be at least 1. |
| `--sessions N` | `DEMO_SESSIONS` (3000) | Number of backfill sessions |
| `--seed N` | `DEMO_SEED` (42) | Random seed. The same seed gives the same data. |
| `--now ISO` | current time | The time to treat as "now", for reproducible output, for example `2026-10-24T12:00:00Z` |
| `--live` | off | After the backfill, keep sending new sessions until you stop it with Ctrl+C. Use `just demo-live` for this. |
| `--live-only` | off | Skip the backfill and send new sessions only |
| `--live-min S` | `1.0` | Minimum seconds between live sessions |
| `--live-max S` | `8.0` | Maximum seconds between live sessions |
| `--live-speed X` | `1.0` | Time compression for the events of one live session |
| `--dry-run` | off | Print the events as JSON lines on standard output, and send nothing to Redis |

Defaults come from `.env`. Command-line options override them.

```bash
# Print 2 days of events as JSON lines, without touching Redis
docker compose --profile tools run --rm demo --days 2 --sessions 50 --dry-run
```

## Running it twice

Each run adds data. To start from scratch, stop the stack and delete the database volume with `docker compose down -v`. This deletes all data, real or fake.

## Screenshots use demo data only

Every screenshot in the README and in these docs comes from demo data. Never take a screenshot of a real capture. Real attack data contains attacker addresses, credentials and payloads, and the repository is public.
