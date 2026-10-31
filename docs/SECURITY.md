# Security

SuckerPot is a honeypot. Its job is to be attacked. This page covers what it does to stay safe, what it never does, and what you must do when you deploy it.

```{admonition} Build status
:class: note

**Built:** the isolation layer (networks, container hardening, Redis and database roles, the secrets policy), the API exposure controls, the host firewall template, and the SSH, RDP and Telnet sensors with their limits. The web sensor is wired into Compose and is under security review.

**Built in M9:** seven more sensors (ADB, Docker API, Redis, MySQL, MSSQL, SMB and SIP), each with its own Redis user, network and stream. Their review status is on the [roadmap](ROADMAP.md).

**Built in M20:** the Synology NAS sensor (a DSM 7.2.1 look-alike on HTTP 5000 and HTTPS 5001), with its own network, Redis user and stream, the same limits and the same no-execution rules.

**Built:** dashboard login (M8). The security review passed.

**Built:** retention (90 days raw, aggregates kept) and the database disk guard. See [Data retention](retention.md).

**Planned:** payload fetching (not scheduled), and the terminal replay.

Keep the dashboard port private anyway. Login is one layer, not the only one.
```

## Deployment warning

- **The host is meant to be attacked.** Deploy SuckerPot only on an isolated machine or VM that you are ready to lose. Treat it as already compromised.
- **Never keep credentials that matter on the host.** No cloud keys, no SSH keys for other systems, no password manager exports, no personal files. Assume that anything on the host can be read by an attacker who breaks out of a container.
- **Keep the dashboard port private.** The default bind address is `127.0.0.1`, so the port is reachable only from the host. To reach it from another machine, use a reverse tunnel such as cloudflared, and filter the port upstream. See [Deployment](deployment.md).
- **Published Docker ports bypass ordinary host firewall rules.** Docker writes its own rules for published ports. A rule in the host `INPUT` chain does not stop traffic to a published port. Filter these ports upstream (router or hypervisor firewall) or in the `DOCKER-USER` chain.
- **Keep the admin SSH port separate.** The host's own SSH service must run on a port that no sensor or dashboard uses, and it must not be exposed to the internet.

## Threat model

| Threat | Control |
| --- | --- |
| An attacker runs code through a fake shell or a fake web app | Sensors never execute attacker input |
| An attacker uses a compromised sensor to reach the host, the LAN or another sensor | Sensors have no outbound route, cannot talk to each other, and the host firewall drops new connections from their network |
| A terminal recording attacks the analyst's browser | The replay safety contract (see below) |
| An attacker escapes a container | Non-root users, dropped capabilities, read-only file systems, no new privileges |
| An attacker reaches the database or the internet from a sensor | Sensors reach Redis only. Redis accepts only `XADD` from the sensor user. |
| An attacker uses a stolen queue credential | Each service has its own Redis user with the fewest commands it needs. A sensor can write only to its own stream, and ingest checks the `sensor` field against the stream. |
| An attacker uses the API to change data | The API connects as a database role that is read-only, except for the encrypted provider keys it manages (see [Provider keys set in Settings](#provider-keys-set-in-settings)) |
| An attacker reaches the internet from the API | Masquerading is off and the API resolves no external names. This is not a full block: host or hypervisor egress filtering is also required. See below. |
| An attacker floods the sensors or fills the disk | Connection caps, timeouts, memory budgets and event rate limits in every sensor. Stream length cap and Redis memory limit. Size limits on events. Retention and a database size guard. |
| A sensor hangs and Docker does not restart it | A watchdog thread in each sensor exits the process when the event loop stalls |
| An attacker abuses the dashboard | Login with an argon2 hash, signed `HttpOnly` `Secure` `SameSite=Strict` cookies, CSRF protection, rate-limited login. Keep the port private as well. |
| The project is used to attack others | No offensive behaviour (see below) |
| Someone gets a copy of the database (backup, dump, stolen volume) | Provider keys in it are encrypted with AES-256-GCM. The encryption key lives only in `.env` (`SETTINGS_ENCRYPTION_KEY`). A dump alone reveals nothing. |
| Someone steals an admin session (cookie) | They can see where each key comes from and its last four characters, and trigger key tests, capped at 10 per provider per day with a 20 second cooldown. They cannot change or remove a key without the admin password, and five wrong passwords in a row revoke the session. |
| Secrets leak into the public repo | Repo hygiene rules, `.gitignore`, secret scanning (see below) |

## Controls

### No execution of attacker input

These rules apply to every sensor.

- The fake shell is pure emulation. It does not call `subprocess`, `os.system`, `eval` or `exec`, and it does not write files outside its own data path. Tests read the sensor code to check this.
- Fake commands return canned or generated output from an in-memory fake file system. The file system has a size cap (1 MiB, 2000 nodes in the SSH sensor), and each connection gets its own copy.
- `wget`, `curl`, `tftp`, `ftpget` and `scp` are recorded as `download_attempt` events. They are never run and never fetched by the sensor.
- The web sensor analyses requests with byte searches over a bounded slice, with no regular expressions. URLs found in payloads are reported, never opened.
- The RDP sensor runs the NTLM exchange only as far as the logon decision, then refuses the logon. It never grants a session and never cracks a password. Its only password check is against the decoy accounts (see below).
- Sensors open no outbound connection at all.

### Credentials the sensors record

Attackers send credentials to the sensors, so the sensors record some of them. These are the rules.

- **Decoy accounts are public by design.** The RDP sensor's default decoy pairs (`SENSOR_RDP_ACCOUNTS`) are in this repository and in the sensor's documentation. They are fake, no real host uses them, and they exist so that a login with a common password can be shown as a weak-credential match. Anyone can read them, and that is fine.
- **Decoys are verified, never cracked.** For an NTLM login, the sensor checks only the pairs it was configured with, against the response and the server challenge it sent. It never tries a list of passwords and never derives a password from the response. Any other pair is recorded without a password.
- **Cleartext from TLS-only clients is opt-in.** A client that does not use NLA sends its password inside TLS. The RDP sensor reads that password only when the owner sets `RDP_NLA_MODE=optional`. The default, `required`, accepts NLA clients only, so it never reads a password from a TLS-only client. Turn the optional mode on only when you accept that real passwords typed into such clients will be stored in the database. Those passwords are length-limited, like every captured field, and they are then subject to the retention rules in [Retention](retention.md).
- **Stored passwords are data, not secrets to reuse.** They are stored as the attacker sent them, in the event `data` field, and shown to the owner in the dashboard. Treat the database with the same care as any other capture.
- **Nothing from the decoy list is ever a real secret.** Do not put a real password in `RDP_ACCOUNTS`. The sensor treats each pair as public.

### Downloads

Payload fetching is done by the `collector` (M21), and only when `COLLECTOR_ENABLED=true`. The rules below apply.

- By default, only the download URL is recorded.
- Payload fetching is off by default (`COLLECTOR_ENABLED=false`). When it is on, the `collector` service fetches the file, never a sensor and never ingest. See [Anonymous egress](#anonymous-egress-m21).
- A fetched payload is stored in the quarantine volume under its sha256 name, with mode `0400`. It is never executed and never committed to the repo.

### Containers

These rules apply to every service in `docker-compose.yml`.

- Every service runs as a non-root user. Application services use UID and GID 10001. Redis and PostgreSQL use their image users.
- `read_only: true`, with `tmpfs` mounts where a service needs to write.
- `cap_drop: [ALL]`.
- `security_opt: [no-new-privileges:true]`.
- Memory, CPU and process limits on every service.
- A health check on every service.
- Sensors listen on high ports inside their containers. Compose maps the standard host ports to them, so no service needs extra capabilities to bind low ports.

### Network segmentation

| Network | Internet access | Used by | Notes |
| --- | --- | --- | --- |
| `ingress` (`sp-ingress`) | None. Masquerading off, inter-container communication off. | Every sensor | Attackers connect in. Sensors cannot reach each other or the internet. |
| `sensors-ssh`, `sensors-web`, ... | None (`internal: true`) | `redis` and one sensor each | A sensor reaches Redis and nothing else |
| `tools` | None (`internal: true`) | `redis`, the demo generator | The generator reaches Redis only |
| `backend` | None (`internal: true`) | `redis`, `db`, `migrate`, `ingest`, `api` | Storage and processing stay private |
| `vpn-uplink` (`sp-vpn`) | Outbound, only through the WireGuard tunnel | `vpn` only | The one route to the internet |
| `egress-proxy` (`sp-egress`) | None (`internal: true`) | `vpn`, `ingest`, `collector` | The HTTP proxy and control server of `vpn` |
| `samples` (`sp-samples`) | None (`internal: true`) | `db`, `collector`, `analyzer` | Keeps the file handling away from Redis and the API |
| `dashboard` (`sp-dashboard`) | Intended inbound only | `api` only | Masquerading is off. This does not block egress on its own. |

The design is explained in [Architecture](ARCHITECTURE.md#networks).

#### Egress from the API

The API cannot reach the internet through Docker's normal NAT, and it cannot resolve external names through Docker's resolver. These are two layers, and neither is a full firewall.

Egress must also be filtered outside the containers. Check it from the owner side before you go live:

- The [host firewall](deployment.md#host-firewall) is loaded. It drops new connections from `sp-ingress` and `sp-dashboard` to the host and through the host, and from every Docker network to the host's admin SSH port and the dashboard port.
- The API container cannot open a connection to an external address, by IP or by name.

#### The host firewall and the sensor network

A compromised sensor has no route to the internet (masquerading is off), but without a host rule it could still open connections to the host itself, for example to its admin SSH port, or to machines on your LAN through the host. The nftables table in `scripts/host/firewall.nft` blocks that, and it matches Docker networks by interface name, so it works whatever address pool Docker picks. It is installed with its own systemd unit, never with the stock `nftables` service, which would flush Docker's own rules.

#### Anonymous egress (M21)

The aim: no outbound connection made by the stack ever comes from the home address.

- **One route out.** Only `vpn` (gluetun, WireGuard) has an internet route. A static test (`just guardrails`, part of `just test`) loads `docker-compose.yml` and its overlays and fails if another service joins a network with a route out, if `ingest`, `collector` or `analyzer` lack `dns: 127.0.0.1`, if any service other than `vpn` gets `cap_add`, `devices`, `privileged` or a `network_mode`, if the `egress-proxy` members change, or if any `HTTP_PROXY`-style variable appears.
- **Kill switch.** gluetun's firewall starts before the tunnel and allows only the tunnel and the WireGuard packets to one endpoint. The [host firewall](deployment.md#host-firewall) drops everything else from `sp-vpn` (new connections other than UDP to the endpoint, the LAN, IPv6, TCP) and every new connection from `sp-vpn`, `sp-egress` and `sp-samples` to the host. With the tunnel down, nothing leaves.
- **Proxy only.** `ingest` and `collector` use one client factory that sends host names to the proxy. External DNS does not resolve in those containers. A static test scans their code and fails on any other way to open a socket (`httpx.AsyncClient(` outside the factory, `socket`, `smtplib`, `urllib.request`, `requests`, `aiohttp`, `getaddrinfo`). SMTP goes through an HTTP `CONNECT` tunnel.
- **The gate.** No outbound work starts unless the last self-check passed (every `EGRESS_CHECK_INTERVAL_S`, 300 s by default). It checks that the tunnel is running, that two independent echo services agree on the public address, that it equals the address gluetun reports, that it is a global address and that it is inside `EGRESS_ALLOWED_CIDRS` (default: the /24 of the endpoint). Otherwise it stays closed with a constant reason code and lookups wait without spending quota. Events keep being stored. It is a positive check: it never needs to learn the home address.
- **Least privilege for `vpn`.** It is the only container with `NET_ADMIN` and `/dev/net/tun`, still `cap_drop: [ALL]`, `no-new-privileges`, read-only root, no published port, image pinned by digest. Its control server answers only two read routes (tunnel status, public address), so a compromised client cannot stop or reconfigure the tunnel. The proxy needs a password (at least 24 characters) and runs in stealth mode (no `Via` or `X-Forwarded-For`).
- **Known limit.** The proxy runs inside `vpn`, so a CONNECT to `vpn`'s own address is a local connection that gluetun's firewall cannot filter. A client holding the proxy password could read the two open control routes. The collector's validator refuses every private literal and the control server denies everything else, so `egress-check` reports this as a NOTE, not a failure.
- **Exit range.** Providers often exit on a different network from the endpoint, so the default allow-list (the endpoint /24) can keep the gate closed. Set `EGRESS_ALLOWED_CIDRS` to the observed exit range (Settings > Egress shows it to admins). A closed gate is the safe failure.
- **Check it live.** `just egress-check` tries direct TCP and UDP to public resolvers from `ingest`, `collector` and `analyzer`, name resolution, CONNECT to the bridge gateway, a name that resolves to loopback, and takes the tunnel down and back up. It prints PASS or FAIL per line and never prints the exit address.

#### The collector and SSRF

The collector is the one component whose destination is chosen by an attacker (the URL in a captured command). Its rules:

- **URL validator**, run before the first request and on every redirect hop (redirects are followed by hand, 3 at most). Only `http` and `https`, no user-info. An IP literal must be in canonical form (decimal, octal, hex and short forms are refused) and global: not private, loopback, link-local, multicast, reserved, documentation or carrier-grade NAT, not the VPN's own addresses, not anything in `COLLECTOR_DENY_CIDRS`. A name needs at least two labels, valid IDNA, and must not be `localhost` or end in `.local`, `.internal`, `.lan`, `.arpa` and similar, or be one of the deployment's own host names.
- **Three more layers** behind the validator: gluetun's DNS rebinding protection drops private answers, the host firewall allows nothing from `sp-vpn` but WireGuard, and `vpn` shares networks only with its two clients.
- **Caps.** 16 MiB (`COLLECTOR_MAX_BYTES`) counted on the bytes streamed, never on `Content-Length`; 10 s connect and 60 s total; 2 concurrent fetches and one per host; 10 s between requests to one host; 60 fetches an hour and 500 a day. No decompression, no cookies, no `Referer`. The client identity is a generic `Wget` or `curl` string, never the project name.
- **No body is kept on failure.** Every attempt is recorded with a constant outcome code.

#### Quarantine

- The `quarantine` volume is written only by `collector`. `analyzer` and `api` mount it read-only.
- A file is written to a temporary name, hashed while streaming, aborted if it passes the size cap, set to mode `0400`, then moved to `ab/cd/<sha256>`. No extension, no execute bit. A static test forbids `chmod` with an `x` bit and any `exec` or `spawn` call on a quarantine path.
- Total size is capped (`QUARANTINE_MAX_MB`, 2,048). At the cap the collector stops fetching and keeps recording URLs. A file is deleted `QUARANTINE_RETENTION_DAYS` (90) after it was last seen; its row and analysis stay.
- Nothing is ever served raw. An administrator can download a sample only as an AES-256 zip with the conventional password `infected`, after typing their password again, at most 10 times an hour, with an audit log entry.
- Nothing from the quarantine, and no file named after a sha256, may be committed.

#### Parser safety

The analyzer treats every file as hostile. It has no network and no Redis. Parsing happens in a child process with `RLIMIT_AS` 384 MB (`ANALYZER_MEMORY_MB`), `RLIMIT_CPU`, a zero file-size limit and 16 open files, a 60 s wall-clock timeout (`ANALYZER_TIMEOUT_S`) after which the child is killed, and a 2 MiB output cap. The parent validates the child's JSON against a model, so a confused child cannot write arbitrary rows. File types and architectures are read with small bounds-checked header parsers, not libmagic. YARA runs with a scan timeout. Archives are identified but not extracted, and packed files are never unpacked. Shell deobfuscation is plain text rewriting: no `eval`, no command substitution, at most 5 passes and 256 KiB of output. Tests feed truncated headers, huge counts, random 16 MiB buffers, deeply nested base64 and self-expanding variables, and no real malware is committed.

#### Port guard

`scripts/check-ports.sh` runs before `just up`, `just config` and in CI. It refuses a layout where the dashboard sits on a classic service port, where two published ports collide, or where one equals the host's admin SSH port.

### Database access

- The owner role is used only by the database container and by the migration step.
- `suckerpot_ingest` can insert events and write sessions. It cannot read other tables, change the schema, or create roles.
- `suckerpot_api` can only read the event, session and enrichment tables. It can also read and write the encrypted provider keys (`provider_secrets`), queue key tests (`provider_test_requests`) and manage the dashboard `users` table, and it can append to and read `audit_log`. Nothing else.
- `suckerpot_ingest` has no access to `users` and `audit_log`.
- `suckerpot_ingest` can read `provider_secrets` (to use the keys) but never write it.
- Both application roles have a statement timeout (30 s for ingest, 5 s for the API), so a slow query cannot hold the database.
- The role passwords come from `.env`. The `migrate` service sets them on every run as SCRAM-SHA-256 verifiers, so a rotation is one `docker compose run --rm migrate`, and the clear text never reaches the database logs.

### CVE feeds (ingest egress)

The CVE watch job adds three outbound destinations, all fixed in code and all reached by `ingest` only: `www.cisa.gov` (KEV catalogue), `services.nvd.nist.gov` (NVD API 2.0) and `api.github.com` (security advisories). They are read-only `GET` requests that send nothing but the query itself.

- **Bounded.** Redirects are not followed, every response is streamed with a hard byte cap (8 MB for KEV and NVD, 4 MB for GitHub) and a 60 s deadline, and the number of pages per run is capped. A run that reaches the cap stops at a complete chunk (one day for NVD, seven days for GitHub) and resumes there on the next run.
- **Untrusted input.** Feeds are validated item by item. An invalid item is skipped, text fields are length-capped and stripped of control characters, only `http` and `https` links are kept, and the UI renders everything as text.
- **Quotas.** Each request spends a persisted daily quota, so a bug or a restart loop cannot hammer a public API. A feed that fails is retried after an hour.
- **Optional keys.** The GitHub token must be a fine-grained token with access to public repositories only and no permissions, never a push or personal token.
- **Generic request identity.** Requests send a generic user agent without the project name.
- **Optional keys (details).** `NVD_API_KEY` and `GITHUB_ADVISORY_TOKEN` only raise rate limits. They follow the rules of the next section, travel in a request header (never in a URL) and are never logged.
- **Least privilege.** The ingest role may read, insert, update and delete rows of `cve` (retention), and write `cve_sync_state`. The API role may only read them. The tables hold public data, no captured data.
- **No automation.** The CVE page can copy a trap-sheet template for the owner to review. Nothing is built, configured or deployed from it.

(probable-c2-addresses)=

### Indicators and threat intelligence (passive by design)

Ingest extracts URLs, hosts and file hashes from events it already stored, and asks public intel services about them. The design rules:

- **Nothing is contacted.** An indicator host is never fetched, resolved, pinged or scanned. The only outbound requests go to three fixed API hosts: `urlhaus-api.abuse.ch`, `threatfox-api.abuse.ch` and `www.virustotal.com`. The code refuses any other host, never follows a redirect, reads at most 256 KiB of an answer and times out after 8 s. VirusTotal is asked about file hashes only.
- **Only the indicator value is sent**, with the API key. No session, source address, sensor name or other event data. Private, loopback, documentation and example values are never sent (they are cached as "not checked").
- **Bounded parsing.** Indicators are found with `find`, slicing and `ipaddress`, with no regular expressions. Every string, token and result count is capped, so hostile input cannot make extraction slow or large. URLs lose their credentials and fragment and are capped at 512 characters.
- **Quotas and cache.** Each provider has a persisted daily quota. Answers are cached for 24 hours, and an unknown answer for an indicator only one address used for a week. A rejected key disables the provider, and a rate limit pauses it.
- **Text, never links.** The API returns values raw and defanged (`hxxp://host[.]tld/x`). The dashboard shows only the defanged form and never renders an indicator as a link. Reference links come from a fixed allow-list of the intel services, built by the server and checked again in the browser.

- **Probable C2 addresses.** For a file hash that VirusTotal or abuse.ch already recognise, ingest also reads which addresses public sandboxes saw that malware contact: VirusTotal's `relationships/contacted_ips` and `relationships/contacted_domains` (descriptor-only answers, 20 each, one quota unit per request, same key) and ThreatFox's `search_hash` answer (entries of type `botnet_cc` only). These are the same three fixed hosts, the same body cap, backoff and persisted quotas as every other lookup, and a separate persisted counter per provider (`virustotal:contacts`, `abusech:contacts`) capped at 30 % of its daily quota; every request also counts against the provider's real daily quota, so the total never exceeds it. When VirusTotal answers 404 for the addresses call, the domains call is skipped. Only hashes that are worth the quota are asked about: sensor-computed hashes, or hashes dropped from at least three independent source networks (/24 for IPv4, /48 for IPv6), because a hash typed in a command can be planted by a single attacker; one source address gets at most 20 contact lookups a day. Only the hash is sent. The addresses are strings from an answer: ingest never fetches, resolves or connects to them. **High** confidence is a ThreatFox `botnet_cc` entry. **Medium** is a VirusTotal sandbox contact that is a public address outside big shared networks (Google, Cloudflare, Microsoft, Akamai, Fastly, Meta and Apple AS numbers, checked in the local ASN database and never over the network; `CONTACTS_SHARED_ASNS` replaces the list; ThreatFox entries are never filtered this way) and outside the never-block list (resolvers, big SaaS and CDN names, `BLOCKLIST_NEVER`, `INDICATORS_IGNORE`); private, reserved and documentation ranges are dropped, and so is everything else. CDN and update domain suffixes (for example `gvt1.com`, `1e100.net`, `msftncsi.com`) are in the shared-name list. On start, stored rows that no longer pass these filters are deleted. Every field is validated and length-capped, at most 40 rows are kept per hash, and the lookup is cached for 24 hours. With `BLOCKLIST_ENABLED=true`, high addresses score 75 and medium ones 40 (below the default feed threshold of 50) under the reason "contacted by malware dropped here (probable C2)", but never above 45 unless one of the hashes is sensor-computed or came from three independent networks. A probable-C2 entry never clears or sets the research-scanner (benign) flag of the same address; the best score wins and the reasons are merged. Nothing is reported or blocked automatically.
- **Export is manual.** CSV and STIX 2.1 downloads happen only when the owner clicks them (up to 5,000 indicators, CSV cells defused against spreadsheet formulas). Nothing is shared or reported automatically.
- **Egress allow-list.** For firewalls: ingest needs HTTPS to the three hosts above, on top of the GeoIP and reputation hosts.
- **Retention and size.** Indicators, links and cached answers expire with the raw events (`RETENTION_DAYS`). `INDICATORS_MAX_ROWS` (default 500,000) is a hard ceiling enforced by the hourly job, which drops the least sighted, oldest single-source indicators first and halves the ceiling while the database disk guard is trimming. Ingest writes no indicators at all when it is in degraded mode.
- **Your own names are not indicators.** Referer, Origin and `X-Forwarded-*` values, and any URL on the event's own Host or SNI, are skipped. The hosts in `API_ALLOWED_HOSTS` and `API_ALLOWED_ORIGINS` are ignored automatically. Set `INDICATORS_IGNORE` (names, addresses and CIDR blocks) to your public IP before you go live. The ignore list is applied again when looking up, and stored indicators that now match are marked "not checked".
- **IPv6 tricks.** Zone ids are refused. Addresses that hide an IPv4 address (mapped, NAT64, Teredo, 6to4) are unwrapped and checked as IPv4. Local-use NAT64 is dropped.
- **Quota fairness.** One source address cannot spend the quota: candidates are ranked by distinct source addresses, a single address gets at most 20 lookups a day, unknown single-source indicators are not asked about again for a week, 30 % of every quota is kept for indicators several addresses used, a URL is only asked about once its host is known to be listed, and a hash goes to the intel services only when a sensor computed it or two addresses showed it.
- **Demo data.** Demo events carry `demo: true`. Indicators taken only from them keep documentation values but are marked and never sent anywhere.

### Provider keys set in Settings

The admin can enter the AbuseIPDB, GreyNoise, MaxMind, NVD and GitHub keys on the Settings page instead of in `.env`.

- **Write-only.** A key is never sent back to the browser. The page and the API show only where the key comes from (`.env` or Settings), its last four characters and when it changed.
- **Encrypted at rest.** The key is encrypted with AES-256-GCM before it reaches the database. The data key is derived with HKDF-SHA256 from `SETTINGS_ENCRYPTION_KEY` (at least 32 random bytes, base64). The provider name is bound to the ciphertext, so a row cannot be moved to another provider, and any change to the stored bytes is detected when ingest decrypts them.
- **What an attacker needs.** A database dump alone does not reveal the keys. Someone who has both the database and `.env` does, and so does anyone who can run code in the `api` or `ingest` containers. Treat `SETTINGS_ENCRYPTION_KEY` like the other secrets in `.env`. If you lose or change it, the saved keys cannot be read again and you enter them again. Without it, editing is disabled and the keys in `.env` keep working.
- **Who can change them.** Setting, replacing or removing a key needs the session cookie, the CSRF token, a same-origin request and the admin password again (checked with argon2). Every attempt is charged to the same global window as the login (plus a separate per-address window), so re-authentication cannot be used to guess the password around the login limit. Five wrong passwords in a row revoke the session.
- **Audit.** Every change writes a line to the API log with the provider, the action, the time and the account. It never contains the key or the password.
- **No key in an error.** Validation errors do not echo the submitted values. Keys are checked for length and printable ASCII, and are never written to a log line, an exception message or a status row.
- **Test cap.** "Test key" spends provider quota, so it is limited to 10 per provider per day and one per 20 seconds, enforced in a single database statement.
- **Key quality.** `SETTINGS_ENCRYPTION_KEY` must decode to at least 32 bytes with at least 16 distinct byte values, and must differ from `SESSION_SECRET` and every `*_PASSWORD` variable. Otherwise editing is disabled.
- **Least privilege.** The API role may write `provider_secrets`. The ingest role may only read it. The API still has no internet access: "Test key" leaves a request in the database, and ingest makes the one real call and spends one unit of the provider's daily quota.

### Secrets policy

- Every secret must be at least 24 characters long, and no two secrets may be equal. Redis checks all its passwords, and the migration step checks the three database passwords.
- The check refuses to start the service if the policy fails. The message names the variable, never its value.
- `SUCKERPOT_ALLOW_DEFAULT_SECRETS=1` turns the length and uniqueness checks off. It exists for CI and throwaway tests only. Never set it on a host that is reachable from the internet.

Generate each secret separately with `openssl rand -base64 32`.

### Abuse resistance

- Every event's `data` is capped at 16 KiB. A raw stream entry larger than 64 KiB is rejected before it is parsed. Sensors cut every attacker-controlled field before they build an event.
- Redis has a memory limit of 192 MB with `noeviction`. When the stream is full, writes fail. Events are never silently evicted.
- Each sensor stream is capped at about 10,000 entries (`EVENTS_MAXLEN`), or about 3,000 for the seven M9 sensors and the Synology sensor (`EVENTS_MAXLEN_LOW`). Ingest trims each stream on its own after each acknowledged batch, and never past an entry that is still pending.
- The host's connection-tracking table is sized and timed by the optional `scripts/host/sysctl-suckerpot.conf`. Without it, a flood of short connections can make the kernel drop new connections for every service, including the admin SSH port. See [Host safeguards](deployment.md#host-safeguards).
- Redis limits the size of a single command and the input buffer of each client.
- Ingest writes in bounded batches. A message that keeps failing is dead-lettered after 5 attempts.
- The live feed has a bounded queue per client, at most 50 clients in total and 5 per source address.
- Every sensor caps connections in total and per source address, sets a timeout on every read, bounds every buffer, keeps a memory budget, and rate-limits its own events with bounded in-process queues. See the page of each [sensor](sensors/index.md).
- Retention: raw events are dropped after `RETENTION_DAYS` (90) and compressed after 7 days. Aggregates are kept. A **disk guard** job runs every 5 minutes: above 90% of `DB_MAX_SIZE_GB` (default 10) it drops the oldest raw chunks until the size is below 80%, never touching the last 4 days or the aggregates. Above 95%, ingest stops storing payload previews. The state is shown on the Settings page. See [Data retention](retention.md).

### Watchdogs

Docker restarts a container that exits. It does **not** restart a container that is only *unhealthy*. A sensor stuck in a busy loop or a deadlock would sit there, silently dead, while the port stays open. Each sensor therefore runs a watchdog thread, independent of the event loop, that exits the process when the loop has not run for 10 seconds. `restart: unless-stopped` then brings the container back. Ingest does the opposite on purpose: when a database or Redis outage stops it, its heartbeat file goes stale and the health check fails, so the problem is visible.

### API exposure

- The interactive documentation (`/docs`, `/redoc`, `/openapi.json`) is off by default. Turn it on only with `API_ENABLE_DOCS=true`, while developing.
- Every response has security headers. Pages carry a Content Security Policy that blocks scripts from other origins.
- The WebSocket feed rejects browser requests from an origin that is not the same host or in `API_ALLOWED_ORIGINS`.
- Path and query inputs are checked: session IDs use the same pattern as the event schema, IP addresses are normalised, and cursors are bounded.
- The API has no CORS policy, so other sites cannot read its responses in a browser.
- Dashboard login guards every `/api/v1` path and the WebSocket (see below). Planned: rate limits on the rest of the API.

### Dashboard authentication

- The **owner** account (`ADMIN_USERNAME`) has its argon2id hash in `.env` (`ADMIN_PASSWORD_HASH`), made with `python -m api.hashpw`. It is always an administrator, works when the database is down, and cannot be disabled, demoted or deleted from the UI. Other accounts are database users with the role `admin` or `viewer` (see below). No password is ever stored in clear or logged.
- The session cookie is `__Host-sp_session`: `HttpOnly`, `Secure`, `SameSite=Strict`, no `Domain`. The `__Host-` prefix means the browser accepts it only over HTTPS for this exact host, so a sibling subdomain cannot plant it. (With `COOKIE_SECURE=false`, for local development only, the cookies have plain names and no `Secure` flag.)
- The session is a signed token `v2.<subject>.<version>.<issued>.<expires>.<nonce>.<signature>` with an expiry (12 hours by default). The subject is the owner or `u<id>`; the version is the user's `session_version`. The signing key comes from `SESSION_SECRET` (at least 32 bytes), the owner password hash and a random value made at each API start. So changing the owner password, rotating the secret or restarting the API signs everybody out. Logout and a new login revoke the old session.
- CSRF protection by double submit: every unsafe request must echo the signed CSRF cookie in `X-CSRF-Token`, and the token is bound to the session. Login is checked against `Origin` or `Referer`: the full origin must be in `API_ALLOWED_ORIGINS` when that is set.
- Rate-limited login: 5 attempts per address (IPv6 per /64) and 30 overall per minute, a fixed delay on failure, and the hash is always verified, so timing does not reveal the account name. Argon2 runs one check at a time; with more than two waiting, logins get `429` at once, so a login flood cannot starve the API.
- Failed and successful logins are logged with the client address only. Nothing in the auth code logs a password, a hash or a cookie.
- A trusted-host check limits the `Host` header to `API_ALLOWED_HOSTS`, or the hosts of `API_ALLOWED_ORIGINS`, plus localhost. With both empty it allows any host and logs a warning, so set one in production.
- Client addresses for the login limit come from the connection. `CF-Connecting-IP` and `X-Forwarded-For` are read only for connections from `AUTH_TRUSTED_PROXIES`.
- A middleware guards every `/api/v1` path except `/api/v1/auth/*`. The live WebSocket checks the cookie in its handshake and rechecks it every 5 seconds.
- The API refuses to start with a missing or weak hash or secret.
- `API_AUTH_DISABLED=true` works only together with `SUCKERPOT_DEMO=1`, and only the test overlay `docker-compose.ci.yml` (`just up-test`) sets both. Never use it in production.
- The state (revocations, login counters, the per-boot key) is in memory, so the API must run as **one** worker.
- The dashboard is designed to sit behind an access layer such as Cloudflare Access as a second layer, but it must be safe without one.

#### Users, roles and the audit log (M14)

- **Roles.** `admin` can do everything. `viewer` can read everything an admin can read (including exports and the live feed) and change nothing; the user list and the audit log are for admins only.
- **Default deny.** `authorize` (`api/api/authz.py`) is attached to every `/api/v1` HTTP route when a router is included: any method other than `GET`, `HEAD` and `OPTIONS` needs an admin unless the endpoint is explicitly marked `@allow_any_role` (sign in, sign out, change one's own password). A new write route is therefore admin-only without anyone remembering to say so. `tests/test_authz.py` reads the route table from the OpenAPI schema and calls every state-changing route as a viewer, so a route that escapes the rule fails the build; admin-only reads use `require_admin` and are listed in the same test. The server is the only enforcement: the web UI also hides controls, but that is a courtesy.
- **Immediate revocation.** The middleware resolves the account from the database on every request. A user's `session_version` is bumped by a password change or reset, a disable, a role change, "Sign out everywhere" and, because the row is gone, a deletion. A session whose version no longer matches is refused on its next request and its live WebSocket is closed within five seconds. The cost is one primary-key lookup per request.
- **Lockout, by source.** A lock must not become a way to shut a user out, so wrong passwords are tracked per account **and source address** (IPv6 by /64): five from one source lock that source for that account for a minute, doubling with each repeat up to 15 minutes; a correct sign-in clears the history. A second, much higher account-wide ceiling (50 wrong passwords in total) answers distributed guessing, and it applies only to sources that never signed in as that user: the API remembers the 8 most recent source networks of each user (`users.known_sources`), and failures from elsewhere never lock those out. While locked, the right password fails with the same generic message; an admin can unlock at once, which also clears the per-source locks. The account-wide lock is recorded in the audit log by `system`. The per-source state is in memory (like the rate limits), so a restart forgets it. The owner is never locked by failures, so an attacker cannot lock out the break-glass account.
- **Rate limits.** Logins are limited per address, per username (`LOGIN_RATE_USER`) and globally (`LOGIN_RATE_GLOBAL`). Only the per-address window counts every attempt; the per-username and global windows count **wrong passwords only**, so successful sign-ins (for example everyone arriving through the tunnel's one address) never use them up. The owner's name has no per-username window (per-address, global and argon2 limits still apply). Re-authentication and password-change attempts have their own windows, separate from login.
- **Equal argon2 cost and generic messages.** An unknown username costs the same argon2 verification (against a dummy hash) as a known one or the owner, and every path makes one lookup and one write (a no-op for unknown names), so the remaining difference is a database round trip, far below the hash. Every failure answers `401 Invalid credentials`, whether the name is unknown, the password wrong, the account disabled or locked, or the database unavailable (the owner can still sign in then).
- **Passwords.** 12 to 256 characters; not in the bundled list of 1000 very common passwords (the NCSC 100k list, Open Government Licence v3.0, long entries only; see the header of `api/api/data/common-passwords.txt`) also with digits or symbols added; not containing the username. Hashing uses the same argon2id defaults as the owner hash, under the same one-at-a-time limit. A temporary password has about 114 bits, is returned once with `Cache-Control: no-store`, and only its hash is stored.
- **Onboarding.** A new or reset account has `must_change_password`: the middleware answers `403 password_change_required` to everything except `/api/v1/auth/*`, and the WebSocket refuses it. Changing the password needs the current (temporary) one and rotates the session.
- **Re-authentication and audit.** Every user-management request needs the acting admin's own password (the M11 helper: same rate limit, five wrong passwords end the session) and writes an `audit_log` row in the same transaction. Entries hold names, roles and flags, never a password, hash, cookie or token (`details` is limited to 2 KiB by a database constraint). Names can be reused after a deletion, so `details` also carries `actor_id` (a user id, `owner` or `system`) and `target_id`. Failed logins of unknown names are not recorded, to keep the table from growing under attack; a lock is. Entries are deleted after one year by a database job.
- **Database grants.** `suckerpot_api` may select, insert, update and delete `users`, and select and insert `audit_log` (no update, delete or truncate). `suckerpot_ingest` has no privilege on either table. The grant test is in `api/tests/test_users_integration.py`.
- **Self-protection.** An admin cannot disable, demote, reset or delete their own account.
- **Admins can act on other admins.** Any administrator can reset, disable or delete another administrator (never the owner, which is not a row). All of it is audited, and the owner account in `.env` is the root of trust: it can always sign in and fix things.
- **Live socket and the database.** The WebSocket rechecks the session every 5 seconds; after 6 failed checks in a row (database down) it closes with `1013` rather than keep streaming to a session it cannot vouch for.
- **Not built:** two-factor sign-in (TOTP) and password-history rules.

### SIP anti-reflection

UDP source addresses can be forged. A UDP service that answers every request can be used to flood a victim with replies. The SIP sensor follows these rules, and each one holds before a reply byte leaves the sensor:

1. **A reply is never larger than the request that caused it.** The reply is built from the mandatory headers (Via, From, To, Call-ID, CSeq). Optional headers are added one at a time, and only while the total stays within the request size. If the mandatory part does not fit, the sensor stays silent. A last check rejects any reply that is bigger than its request.
2. **Responses, ACKs and unparseable input get no reply.** Two reflectors cannot answer each other.
3. **No reply to implausible sources.** Private, shared (CGNAT), loopback, link-local, multicast, broadcast, unspecified, reserved and documentation addresses get no reply, and neither does port 0 or an address listed in `SENSOR_SIP_OWN_IPS`.
4. **Reply caps.** Per source: 2 replies per second, burst 5. For all sources together: 100 replies per second (burst 200) and 32 KiB of reply bytes per second (burst 64 KiB).
5. **Work bounds before parsing.** Datagrams over 4096 bytes are dropped unread. Packets are capped per source (50 per second) and in total (3000 per second).
6. **Events are aggregated per source address,** so a flood produces a few events, not a stream.

The sensor's test suite (`sensors/sip/tests/test_reflection.py`) measures the result. Over 4000 requests of every shape, with the rate limits off so that the size rule alone is tested, the amplification factor is 0.708, and the largest single reply is 0.993 of its request. With the limits on, 20,000 packets from 20,000 spoofed sources give at most `200 + 100 × seconds` replies.

### No offensive behaviour

SuckerPot does not:

- scan other hosts, or respond to scans with scans;
- hack back or run any active countermeasure;
- report IP addresses to AbuseIPDB or any other service without the owner's explicit approval.

### Realistic fingerprints

Fake services must look real to an attacker. Banners and versions are plausible and current. Hostnames are ordinary. The words "honeypot" and "suckerpot" never appear anywhere a client could see. This applies to every sensor.

## Defend: feeds, exports and generated rules (M16)

The Defend pages turn recorded data into lists and rules (see [Defend](defend.md)). The rules for that code:

- **The feed is opt-in and the only route outside the login.** `FEEDS_ENABLED` is `false` by default. When it is on, `/feeds/*` is the only part of the API that does not need the dashboard session, and a test (`test_authz.py`) fails if any other route appears outside `/api/v1`. The feed is read-only (GET only).
- **Tokens.** 256 random bits, shown once, stored only as a sha256 hash (the table also keeps the first six characters to tell tokens apart). A token can be revoked at once or given an expiry, and limits which kinds, which minimum score and whether research scanners are served. Creating one needs an administrator and the account password again; the audit log records it without the token.
- **Probing.** Requests are rate limited per client address and per token; wrong tokens count against the client address; every refusal (unknown, revoked, expired, wrong kind, disabled feeds) is the same plain `404`. A token in a URL can end up in a firewall's or a proxy's logs, so the API writes no access log and the docs say to treat that URL like a password. The header form avoids the problem for tools that support it.
- **Database grants.** Ingest has no access to `feed_tokens`. The API can read, insert and update it, not delete.
- **Lists never contain your own network.** Private, loopback, link-local, multicast and reserved addresses and shared hosting names are refused when ingest scores them, when an override is set and again when a list is written. Every value is re-validated at export time.
- **Captured strings are untrusted.** CSV cells are defused against formula injection. Rule generators accept printable ASCII only, cut it to a fixed length, quote it (Sigma) or hex-escape it (Suricata), and never put it in a title or message. Every generated rule and export is marked "review before deploying".
- **Poisoning.** Text typed by an attacker can name any host (for example a public resolver). Indicators score by distinct source networks and stay below the default feed threshold without confirmation; public resolvers, big SaaS/CDN domains and the owner's never-list (`BLOCKLIST_NEVER`, trusted proxies, allowed hosts, ignore list) are never listed. Sigma wildcards in captured text are escaped.
- **Nothing is contacted.** The exposure inventory is only compared with our own data. No list is pushed anywhere and nothing is reported to AbuseIPDB or anyone else.

## Terminal replay safety contract

SSH and Telnet sessions are recorded as the bytes the attacker typed and the bytes sent back. Those bytes are attacker-controlled, and a terminal emulator interprets them. The replay player (xterm.js, planned for M5) must follow these rules:

1. **No clipboard addon.** A terminal can write to the clipboard with the OSC 52 sequence. Do not load the clipboard addon.
2. **No link opening.** Terminal links (OSC 8) must never open anything. Use a `linkHandler` that does nothing.
3. **Never wire input back.** Terminals answer some sequences (cursor position, device attributes) by sending data to the program. In a replay, `onData` and `onBinary` must not be connected to anything, so a recording cannot talk to the server or to the page.
4. **No image or sixel addons.**
5. **Text only.** Attacker strings (commands, URLs, user agents, banners) are rendered as text, never as HTML.
6. **Bounded replay.** The recording is already capped (12 KiB of frames in the SSH event), and the player must also cap the work it does per frame.

The player is a read-only display. It must not be possible for a recording to make the browser do anything beyond drawing text.

## How changes are reviewed

Every change that touches a sensor, networking, authentication, the Compose file or a Dockerfile gets a separate security review before it is merged. The review is read-only and checks the change against the rules on this page and the repo hygiene rules below. The reviewer reports findings and does not edit code. A finding is fixed and re-checked before the change is merged.

Review outcomes so far:

| Area | Passes | Outcome |
| --- | --- | --- |
| Foundations (M1: networks, Redis, database, ingest, API) | 2 | The first pass failed (unbounded stream, weak egress control, poison messages that block the queue, default credentials). All were fixed and the second pass passed. Follow-ups: per-sensor networks, users and streams, the sensor/stream check, the host firewall, stable trimming, rotatable role passwords. Idempotent replay after a crash is still open on the [roadmap](ROADMAP.md). |
| SSH sensor | 4 | Passed on the fourth pass. The passes found resource problems under hostile load, not code execution: unbounded input, expensive decryption of tiny packets, one address starving the shell CPU, memory growth, and event volume. They led to flow-controlled channels, inbound metering, a fair CPU scheduler, a cgroup memory guard, byte budgets for events and collapsed repeats. |
| Telnet sensor | 2 | Pass 1 **failed**: pipelined heavy command lines starved the event loop (the watchdog then restarted the container in a loop), the fake `/etc/shadow` used constant hashes (a fingerprint), the memory budget could be used up to make the sensor drop other sessions, and option negotiation was chattier than BusyBox. Fixed with a shared fair CPU budget, per-device generated hashes, sessions kept open with a "Cannot allocate memory" error instead of being dropped when the memory budget is full and the exact BusyBox opener. Pass 2 passed. |
| RDP sensor | 2 | Pass 1 **failed**: a TLS `close_notify` made the read return empty data, which sent the read loop into a 100% CPU busy loop (a one-packet denial of service), TLS handshakes were not throttled, and slow clients could use up all handshake slots. Fixed with an explicit end-of-stream check, per-source and global handshake limits, short deadlines and eviction of idle connections. Pass 2 passed. |
| Dashboard authentication | 1 | Passed on the first pass. The medium findings were fixed: argon2 concurrency could exhaust memory (one check at a time now), CSRF bound to the session, `__Host-` cookies, trusted hosts, a per-boot signing key, IPv6 rate limiting per /64, trusted proxy CIDRs, and a stricter redirect target check in the web app. |
| Synology sensor (M20) | passed | Two passes. Fixed: per-IP and sensor-wide caps on TLS handshakes in flight and per second, a full ClientHello required before a handshake slot is taken, an exact nginx plain-HTTP-on-HTTPS-port page, consistent `text/html`, and per-path asset sizes. PoCs against a hardened container kept legitimate HTTPS working. |
| Anonymous egress, collector, analyzer and quarantine (M21) | passed | Reviewed for the VPN service and kill switch, the egress gate, the SSRF validator, the quarantine and the parser limits on hostile files. The rules it checked are listed in the section above. |
| Web sensor | in progress | Pass 1 found response amplification that could exhaust memory. Pass 2 found lingering transports under reconnect churn. Pass 3 found the per-connection cost of TLS. Fixes are ongoing, and the sensor is not in Compose until it passes. |
| Terminal replay (planned) | | The [safety contract](#terminal-replay-safety-contract) is a requirement for it. |

Lessons that every new sensor and service must follow:

- **Bounded allocations.** Every buffer, queue, string, file system and counter has a fixed maximum, and the size of a result is computed or capped before it is built, not cut afterwards.
- **Yield on every iteration.** A loop that handles attacker input checks its deadline and yields to the event loop on each pass, and stops after a fixed number of passes.
- **Watchdogs.** Docker does not restart an unhealthy container, so a sensor kills itself when its event loop stalls.
- **Budgets at three levels.** Per connection, per source address and global, for connections, input bytes, shell CPU, memory and events. Fairness between source addresses, so one address cannot starve the rest.
- **Abort stuck transports.** A peer that does not read, or does not acknowledge, is cut off (write timeouts, `TCP_USER_TIMEOUT`, small send buffers) instead of keeping buffers alive.
- **Measure the cost.** Expensive steps (a TLS handshake, a password hash, a decryption) get their own rate limit and concurrency cap, based on measured cost rather than a guess.
- **Look at the real memory.** A cgroup memory guard compares the container's actual use with its limit and sheds load before the kernel kills the process.
- **Budget the event bytes, not only the count.** Over budget, an event loses its bulk first and is dropped last. A shared publisher backstop covers every sensor.
- **Guard the disk.** Retention drops old raw data, a size-based guard drops the oldest chunks when the database nears its ceiling, ingest keeps only previews above 95%, streams are capped, and backups refuse to run without enough free space. Disk use cannot explode.
- **Drop, never block.** When a queue or Redis is full, the sensor drops the event and counts it. It never waits inside a connection handler.
- **Fail visibly.** A service that cannot do its job stops its heartbeat or exits, so the problem shows in `docker compose ps` instead of in missing data.
- **Least privilege everywhere.** One Redis user per sensor, one database role per service, one network per job.
- **No execution, no fetching, no outbound traffic from a sensor.** Everything a sensor knows about an attack comes from bytes it received.

### Lessons 16 to 18 (added in M9)

These three lessons apply to every sensor. They came from the review of the M9 sensors, where hostile load found the limits of the earlier design.

16. **Wall-clock CPU budget per loop turn, per source address.** Work that can be expensive (a parse, a glob, an NTLM answer, a TLS handshake) is timed and charged to a budget for the source address and another for the whole sensor. A loop turn stops when its time slice is used up. A source that uses its own budget waits or is cut, and other sources keep their service. Each sensor measures its own cost: the MSSQL sensor charges the measured CPU time of each message, the SMB sensor spends a CPU token per expensive answer, and the Redis and Docker sensors have buckets for work per connection, per source and for the sensor.
17. **Pending output is memory.** Bytes that wait to be sent count against the memory budget until they leave the sensor. Output per connection is capped. A peer that does not read is aborted (write timeout, `TCP_USER_TIMEOUT`, small socket buffers) instead of pinning buffers. The memory guard is also checked when a new connection is admitted, not only once a second.
18. **Per-source event fairness with a priority path.** Each source address has its own event buckets, counted in events and in bytes, in front of the shared queue. Shared buckets keep a reserve that only light sources can use. Connection, login and disconnect events take a priority path, so a flood from some addresses cannot hide the events of others. Dropped events are counted and reported in the session's `disconnect` event.

## Repo hygiene

This repository is public. Every commit is published, and it stays in the git history forever.

### Never committed

- `.env`, API keys, tokens, passwords and password hashes;
- private environment notes;
- private IP addresses, host names, admin ports, public IP addresses and network layouts;
- captured data: attacker IPs, credentials, sessions, payloads and database dumps;
- GeoLite2 `.mmdb` files (their licence does not allow redistribution);
- SSH host keys generated by the sensors;
- screenshots that show real attack data.

### Safeguards

| Safeguard | What it does |
| --- | --- |
| `.gitignore` | Keeps local secrets, captured data and generated files out of git |
| `.env.example` | Contains placeholders only. Copy it to `.env` and fill in your own values. |
| gitleaks pre-commit hook | Blocks commits that contain secrets. Install it with `scripts/install-hooks.sh`. |
| gitleaks in CI | Scans the full history on every push and pull request |
| Manual review | The staged diff is checked by hand before each commit |
| Documentation IP ranges | Examples use `192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24` only |

### If something sensitive is pushed

1. Stop pushing.
2. Rotate the secret immediately.
3. Remove the data from the git history. Deleting it in a new commit is not enough, because the old commit stays public.

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it privately through GitHub's private vulnerability reporting. Go to the **Security** tab of the repository and choose **Report a vulnerability**. Include:

- what you found and where;
- steps to reproduce it;
- the impact you expect.

Do not include real credentials, real attacker data or real IP addresses of your own systems in the report.
