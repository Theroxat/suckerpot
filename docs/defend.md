# Defend: blocklists, detection rules and your exposure

The Defend pages turn what the honeypot saw into things you can use at work: lists to load into a firewall, rules to load into a SIEM or an intrusion detection system, and a short checklist per attack type. Everything here is built from data already in the database. Nothing is scanned, resolved or contacted, and nothing is reported to anyone.

## Blocklists

Ingest scores every source address, host name, download URL and file hash seen in the last `BLOCKLIST_WINDOW_DAYS` days (default 30) and stores the result in `blocklist_entries`. It runs every 15 minutes and is off by default: set `BLOCKLIST_ENABLED=true`.

A score runs from 0 to 100. Each point has a reason, shown in plain English on the page: brute-forcing, a login that worked, commands run, malware dropped, an exploit attempt, a bad AbuseIPDB score, several sensors hit, part of a campaign, and so on. Mass scanners that did no harm are capped at 35. Entries below 10 are not listed. At most `BLOCKLIST_MAX_ROWS` entries are kept (default 20,000), best score first.

Never listed, whatever the score:

- private, loopback, link-local, multicast and other reserved addresses (so your own network cannot end up on a list);
- shared hosting names such as `github.com` or `pastebin.com` (attackers download tools from them, and so do you);
- research scanners, unless you ask for them.

### Overrides

An administrator can always allow or always block a value, with a note and an optional expiry. Allowed values leave every list at once; blocked values join at score 100. Overrides are audited.

### Exports

Download from the Blocklists page, or `GET /api/v1/defend/export` while signed in:

| Format | Content | Use it for |
| --- | --- | --- |
| `alias` | IP addresses, one per line, nothing else | OPNsense and pfSense "URL Table (IPs)" aliases |
| `txt` | One value per line (any kind) | Proxies, DNS filters, EDR import lists |
| `csv` | Every column, with a header | Spreadsheets and reports |

Every value is validated again when it is written out. In CSV, a cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return gets a leading apostrophe, and control characters are removed, so opening a file in a spreadsheet cannot run a formula. Demo entries are left out unless you ask for them.

### The subscription feed (optional)

A firewall cannot sign in to the dashboard, so there is an optional feed. It is **off by default**: set `FEEDS_ENABLED=true` and restart the API. It is the only part of the app that works without the dashboard login.

- Create a token in Settings, Feeds (administrators, password asked again). The token has 256 random bits and is shown once; only its hash is stored. It can carry limits (kinds, minimum score, research scanners or not) and an expiry, and it can be revoked at any time.
- Fetch `https://<dashboard>/feeds/<token>/ip.txt` (also `domain`, `url`, `hash`, and `.csv`). This form exists for tools that can only fetch a URL, so treat the URL like a password. Tools that can send a header should use `GET /feeds/ip.txt` with `Authorization: Bearer <token>`.
- Requests are rate limited per client address and per token. Wrong tokens count against the client address. Every refusal is a plain `404`, so a probe learns nothing. The API keeps no access log.
- If the dashboard is behind Cloudflare Access, add a bypass policy for `/feeds/*`, or the firewall will be turned away.

## Detections

The Detections page writes Sigma rules (for log search) and Suricata rules (for network inspection) from what the honeypot recorded: request paths that attackers used, shell commands typed in tagged sessions, and the hosts, download URLs and file hashes with a high score.

**Every rule says "review before deploying", and so does every export.** The rules come from decoy traffic, not from your network. They can match harmless activity. Run them as searches or in alert-only mode first.

Captured strings are untrusted. A string must be printable ASCII to be used at all, it is cut to a fixed length, and it only ever appears inside one quoted value: single-quoted in Sigma, and in Suricata every character outside a short safe set is written as `|hex|` bytes, so it cannot end the option or add one. Titles and messages are built from fixed text, never from captures. Suricata ids are in the local range 4100000 to 4999999.

Below the rules, "Check this at your company" lists, for each behaviour the honeypot actually saw, what the attackers do, where to look in your own logs and what to change.

## Your exposure

Type in the services you run (name, kind of service, product, version, whether it is reachable from the internet). The page puts each one next to what the honeypot recorded for the same kind of service: attacks, sources, how many went as far as running commands, the trend against the previous period, and the known exploited vulnerabilities the CVE watch matched. Services that are attacked here but are not in your inventory are listed too, as a prompt to check.

The inventory is free text that is stored and shown. It is only compared with our own data.

## API

| Route | Who | What |
| --- | --- | --- |
| `GET /api/v1/defend/summary` | both roles | Totals per kind, top reasons, feed status |
| `GET /api/v1/defend/blocklist` | both roles | Scored entries, paginated |
| `GET /api/v1/defend/export` | both roles | Download a list |
| `GET /api/v1/defend/overrides` | both roles | Overrides, paginated |
| `POST /api/v1/defend/overrides`, `DELETE .../{id}` | admin | Allow or block a value |
| `GET /api/v1/defend/feed-tokens` | admin | Tokens (hint only, never the token) |
| `POST /api/v1/defend/feed-tokens` | admin, password again | Create a token |
| `POST /api/v1/defend/feed-tokens/{id}/revoke` | admin | Revoke a token |
| `GET /api/v1/defend/detections` and `/export` | both roles | Generated rules |
| `GET /api/v1/defend/guidance` | both roles | What to check at your company |
| `GET /api/v1/defend/inventory` | both roles | The inventory, paginated |
| `POST`, `PATCH`, `DELETE /api/v1/defend/inventory` | admin | Change the inventory |
| `GET /api/v1/defend/exposure` | both roles | Inventory against attacks |
| `GET /feeds/{token}/{kind}.{txt,csv}`, `GET /feeds/{kind}.{txt,csv}` | token | The subscription feed (opt in) |

## Settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `BLOCKLIST_ENABLED` | `false` | Score indicators into blocklists (ingest) |
| `BLOCKLIST_WINDOW_DAYS` | `30` | How far back to look |
| `BLOCKLIST_MAX_ROWS` | `20000` | Most entries kept |
| `FEEDS_ENABLED` | `false` | Serve the token-protected feed (API) |
