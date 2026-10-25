# Deployment

This page is the checklist for putting SuckerPot on the internet. Follow the steps in order. Do not skip the firewall, the snapshot or the verification.

Read [Getting started](getting-started.md) first, and the [Security](SECURITY.md) page for the threat model.

```{admonition} Build status
:class: note

All eleven sensors are in `docker-compose.yml`: the SSH, Telnet, ADB, web, Docker API, Redis, MySQL, MSSQL, RDP, SMB and SIP sensors. The web sensor is still under security review. The seven M9 sensors are new: check them before you forward their ports. The dashboard has a login (M8). Keep it behind the tunnel and the upstream filter described below anyway: login is one layer, not the only one.
```

## Principles

- **Only the sensor ports face the internet.** Every other port stays private.
- **The dashboard is reached through a reverse tunnel.** The tunnel (for example cloudflared) connects from a machine you control to the dashboard port. The dashboard port is never open to everyone.
- **The host's own admin SSH runs on a port that no sensor uses.** It is never exposed to the internet.
- **Filters work upstream of the host.** Docker publishes ports in its own firewall rules, so a host `INPUT` rule does not protect a published port. Filter at the router or hypervisor, or in the `DOCKER-USER` chain.
- **Containers must not reach the host or the LAN.** The host firewall below enforces that.
- **A broken setup must fail closed.** Test the rules before you open the router.

## Go-live checklist

Do these in order. Tick each item only after you have checked it.

1. [ ] The host is a dedicated VM or machine (see the warning in [Getting started](getting-started.md)), with Docker and the Compose plugin up to date.
2. [ ] Generate fresh secrets (see [Secrets](#secrets)), the dashboard `SESSION_SECRET` and the [admin password hash](#dashboard-login) included. No `change-me` is left in `.env`.
3. [ ] Log out of any AI coding assistant, IDE sync and cloud CLI on the host. Revoke or rotate any git or API token that was used on the host. Check that no key sits in a file that other users can read.
4. [ ] Move the host's admin SSH to a port that no sensor or dashboard uses. Allow it only from your management network.
5. [ ] Run the [port guard](#port-guard) (`just ports`).
6. [ ] Install and verify the [host firewall](#host-firewall).
7. [ ] Set [`DASHBOARD_BIND`](#dashboard-bind-and-upstream-filtering) and filter the dashboard port upstream.
8. [ ] Set [`API_ALLOWED_ORIGINS`](#behind-a-tls-terminating-tunnel) if the tunnel terminates TLS.
9. [ ] Set [`INDICATORS_IGNORE`](configuration.md) to your public IP (or CIDR block) and the host names you answer to, so your own addresses are never recorded as attack infrastructure. `API_ALLOWED_HOSTS` and `API_ALLOWED_ORIGINS` are added automatically.
10. [ ] Keep `API_ENABLE_DOCS=false`.
11. [ ] Start the stack and check it: `just up`, then `docker compose ps`. Run `just ssh-test`.
12. [ ] Take a [snapshot](#snapshot).
13. [ ] [Forward the ports](#forward-the-ports).
14. [ ] [Verify from outside](#verify-from-outside).

## Secrets

Every secret must be at least 24 characters long, and no two may be equal. The stack refuses to start otherwise, and names the variable (never its value).

Generate each one separately:

```bash
openssl rand -base64 32
```

| Secret | Purpose |
| --- | --- |
| `POSTGRES_PASSWORD` | Database owner. Schema changes only. |
| `POSTGRES_INGEST_PASSWORD` | Role `suckerpot_ingest` |
| `POSTGRES_API_PASSWORD` | Role `suckerpot_api` (read-only) |
| `REDIS_PASSWORD` | Redis `admin` user (operators only) |
| `REDIS_HEALTH_PASSWORD` | Redis `health` user |
| `REDIS_INGEST_PASSWORD` | Redis `ingest` user |
| `REDIS_SENSOR_SSH_PASSWORD` | Redis `sensor-ssh` user |
| `REDIS_SENSOR_RDP_PASSWORD` | Redis `sensor-rdp` user |
| `REDIS_SENSOR_TELNET_PASSWORD` | Redis `sensor-telnet` user |
| `REDIS_SENSOR_WEB_PASSWORD` | Redis `sensor-web` user |
| `REDIS_SENSOR_REDIS_PASSWORD` | Redis `sensor-redis` user |
| `REDIS_SENSOR_DOCKER_PASSWORD` | Redis `sensor-docker` user |
| `REDIS_SENSOR_MYSQL_PASSWORD` | Redis `sensor-mysql` user |
| `REDIS_SENSOR_MSSQL_PASSWORD` | Redis `sensor-mssql` user |
| `REDIS_SENSOR_ADB_PASSWORD` | Redis `sensor-adb` user |
| `REDIS_SENSOR_SMB_PASSWORD` | Redis `sensor-smb` user |
| `REDIS_SENSOR_SIP_PASSWORD` | Redis `sensor-sip` user |
| `REDIS_DEMO_PASSWORD` | Redis `demo` user |

Keep `.env` readable by the owner only (`chmod 600 .env`). Never commit it. `SUCKERPOT_ALLOW_DEFAULT_SECRETS=1` turns the checks off. It exists for CI only. Never set it on a real host.

### Rotating secrets

Rotate every secret before the first exposure, after any suspected leak, and from time to time. Passwords are read at container start, so each change needs a restart. Take a [snapshot](#snapshot) or a database dump first.

**Redis passwords** (`REDIS_*`):

1. Edit the values in `.env`.
2. Recreate everything that talks to Redis. Redis rewrites its ACL file on every start.

   ```bash
   docker compose up -d --force-recreate redis ingest sensor-ssh sensor-telnet sensor-adb sensor-web sensor-docker sensor-redis sensor-mysql sensor-mssql sensor-rdp sensor-smb sensor-sip
   ```

   Leave out any sensor you do not run. Events published while Redis restarts are dropped and counted, never buffered without limit.

**Ingest and API database passwords** (`POSTGRES_INGEST_PASSWORD`, `POSTGRES_API_PASSWORD`):

1. Edit the values in `.env`.
2. Run the migration step. It sets both role passwords on every run, from the environment, as SCRAM verifiers, so the clear text never reaches the database logs.

   ```bash
   docker compose run --rm migrate
   ```

3. Recreate the services that use the roles:

   ```bash
   docker compose up -d --force-recreate ingest api
   ```

**Database owner password** (`POSTGRES_PASSWORD`). This one is different: the database container only reads the variable when it first creates the data directory, so editing `.env` does not change the password inside the database. Change it in the database first, then in `.env`:

1. Open a `psql` shell as the owner and set the new password. `\password` hashes it on the client, so it is not written to the logs or to the shell history.

   ```bash
   just psql
   ```

   ```text
   suckerpot=# \password suckerpot
   ```

   Use the owner name from `POSTGRES_USER` if you changed it.
2. Put the same value in `.env` as `POSTGRES_PASSWORD`.
3. Check that the migration step still works: `docker compose run --rm migrate`.

If you edit `.env` first, `migrate` cannot log in and the stack will not start. Fix it by running `\password` with the old value in place.

## Dashboard login

The dashboard has one admin account. Set it up before the first start:

1. Make the password hash. It prompts twice without echo:

   ```bash
   docker compose run --rm api python -m api.hashpw
   ```

2. Put the result in `.env` in **single quotes**, because it contains `$`: `ADMIN_PASSWORD_HASH='$argon2id$...'`. Set `ADMIN_USERNAME` if you do not want `admin`.
3. Set `SESSION_SECRET` to at least 32 random bytes: `openssl rand -base64 48`.
4. Start the stack. `just up` (and `docker compose up`) refuse to start at all while `ADMIN_PASSWORD_HASH` or `SESSION_SECRET` is missing from `.env`, and the API refuses a weak hash or secret.

To change the password, make a new hash and put it in `.env`, then run `docker compose up -d api`. Changing the hash signs every session out. Rotating `SESSION_SECRET` does the same, and so does every restart of the API: the signing key includes a random value created at each start, so you sign in again after each restart. The login is limited to 5 attempts per address and 30 in total per minute, and only one password check runs at a time. The API must run as a single worker (the default).

Set `API_ALLOWED_HOSTS` (or `API_ALLOWED_ORIGINS`) to the host name you publish. With both empty the API accepts any `Host` header and logs a warning.

`API_AUTH_DISABLED=true` turns authentication off, but only together with `SUCKERPOT_DEMO=1`, and only the test overlay `docker-compose.ci.yml` (`just up-test`) sets both. The normal `docker-compose.yml` does not. Never run the test overlay on a host that other people can reach.

See [API](api.md#authentication) for the cookie and CSRF details.

## Port guard

`scripts/check-ports.sh` (`just ports`) refuses a port layout that would expose the wrong thing. It runs automatically before `just up` and `just config`, and in CI. It fails when:

- `DASHBOARD_PORT` is 22, 23, 80, 443 or 3389;
- two of `DASHBOARD_PORT` and the `*_HOST_PORT` variables are equal;
- one of them equals `ADMIN_SSH_PORT`, the optional variable in `.env` that holds the port of the host's own admin SSH daemon;
- a value is not a number between 1 and 65535.

The dashboard port must never be a sensor port. The script refuses the five classic service ports listed above. It also compares the dashboard port with every `*_HOST_PORT`, defaults included, and fails on a clash. Keep the dashboard on a port that no sensor uses. The default, 8443, is safe.

Set `ADMIN_SSH_PORT` in `.env`. It is used only by this script. If you start the stack with plain `docker compose up`, run `just ports` yourself first.

## Host firewall

Docker's network settings remove the containers' route to the internet, but they do not stop a compromised container from opening connections to the host itself (for example its admin SSH port) or to other machines on your LAN. The nftables table in `scripts/host/firewall.nft` closes that gap. The same text is in `scripts/host/README.md`.

`firewall.nft` is a template with no address from any real network. It matches Docker networks by interface name, not by address, so it does not depend on the address pools Docker picks.

### What each rule does

| Rule | Effect |
| --- | --- |
| `input`, from `sp-ingress` and `sp-dashboard` | Containers on the sensor network and the dashboard network cannot open **new** connections to the host. |
| `input`, from `docker0`, `br-*` and `sp-*`, to `protected_ports` | No container on any Docker network can reach the host's admin SSH port or the dashboard port. |
| `forward`, from `sp-ingress` and `sp-dashboard` | These containers cannot start new connections through the host: no LAN scanning, no outbound traffic, no traffic between sensors. Replies to inbound connections still go out. |

Nothing here affects traffic from the internet to the published sensor ports. Loopback and established connections are always accepted. Docker's own rules are left alone: the table only adds drops, at a priority ahead of Docker's chains.

### Before you apply it

1. Copy the template to its permanent place, and edit the **installed copy**, never the tracked file. Your admin port must not end up in git.
2. Set `ADMIN_SSH_PORT` to the port of your host's admin SSH daemon. The file ships with `CHANGE_ME` on purpose and will not load until you change it.
3. Check that `DASHBOARD_PORT` matches your `.env`.
4. Keep a second way into the machine (a hypervisor console) the first time.

### Install it with the dedicated systemd unit

```bash
sudo install -m 0600 scripts/host/firewall.nft /etc/suckerpot-firewall.nft
sudo editor /etc/suckerpot-firewall.nft        # set ADMIN_SSH_PORT (and DASHBOARD_PORT)
sudo nft -c -f /etc/suckerpot-firewall.nft     # syntax check, changes nothing
sudo install -m 0644 scripts/host/suckerpot-firewall.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now suckerpot-firewall.service
```

The unit loads only the `suckerpot_host` table, after `docker.service` has started. It refuses to start while the file still contains `CHANGE_ME`, and it checks the syntax before it loads anything. Loading is idempotent: the file deletes and re-creates its own table.

```{warning}
Do **not** use the stock `nftables` service for this. On Debian and Ubuntu, `/etc/nftables.conf` starts with `flush ruleset`. Starting that service on a running host wipes Docker's own rules (NAT and published ports) until Docker restarts. The dedicated unit only touches its own table, so it never does that.
```

### Verify

1. After starting the stack, list the table. Counters on the `drop` rules stay at 0 in normal operation.

   ```bash
   sudo nft list table inet suckerpot_host
   ```

   An error means the firewall is not active. Check this after every reboot.
2. From inside a sensor, a new connection to the host must fail. Replace the placeholders: the gateway is the `.1` address of the `sp-ingress` subnet.

   ```bash
   docker run --rm --network container:<sensor-container> busybox nc -w2 -zv <gateway> <admin-ssh-port>
   ```

   It must time out, and the `input` drop counter must go up.
3. From the internet, or from another machine, the sensor ports must still answer.
4. The host listens on each sensor port for IPv4 only. `ss -tlnp | grep ':22 '` shows `0.0.0.0:22` and no `[::]:22`.

### Roll back

```bash
sudo systemctl disable --now suckerpot-firewall.service
```

or, for the running session only, `sudo nft delete table inet suckerpot_host`. To remove it for good:

```bash
sudo rm /etc/systemd/system/suckerpot-firewall.service /etc/suckerpot-firewall.nft
sudo systemctl daemon-reload
```

Without the table, a compromised sensor can reach the host's admin SSH port. Do not forward ports while it is off.

## Host safeguards

Two optional or recommended host settings protect the host from floods. The repository never applies them for you. Run them yourself, as the host owner.

### Connection tracking (recommended)

The kernel keeps a table of open connections. Scans and floods (many short TCP connections, spoofed UDP to SIP) can fill it. When it is full, the kernel drops **new** connections for every service on the host, including your admin SSH port. The file `scripts/host/sysctl-suckerpot.conf` raises the table size and shortens the timeouts of half-open and UDP entries. Install it with:

```bash
sudo install -m 0644 <repo>/scripts/host/sysctl-suckerpot.conf /etc/sysctl.d/90-suckerpot.conf
sudo sysctl --system
sysctl net.netfilter.nf_conntrack_max      # verify
```

Replace `<repo>` with the path of your clone, for example the folder where you ran `git clone`. The `sysctl --system` command reloads all sysctl files, so it applies the other files in `/etc/sysctl.d/` too.

### Aggregate cap for the sensors (optional)

Each container already has its own limits in `docker-compose.yml`. The optional file `scripts/host/suckerpot-sensors.slice` caps their **sum**, so that a flood on every sensor at once cannot starve Redis, the database, ingest or the API. It sets a memory ceiling of 1536 MB, no swap and a CPU quota of 120 %. Nothing uses it by default.

1. Check the Docker cgroup driver. The slice only works with the `systemd` driver: `docker info | grep -i 'cgroup driver'`. If the driver is `cgroupfs`, skip this section.
2. Install the slice unit and reload systemd:

   ```bash
   sudo install -m 0644 <repo>/scripts/host/suckerpot-sensors.slice /etc/systemd/system/
   sudo systemctl daemon-reload
   ```

3. In `docker-compose.yml`, add `cgroup_parent: suckerpot-sensors.slice` to each `sensor-*` service, then recreate the sensors. Only the host owner should make this change.

### Optional SIP rate limit in the firewall

The firewall template has a commented-out rule that rate-limits new SIP flows on UDP 5060 before they reach the sensor. Read the comment in `scripts/host/firewall.nft` before you enable it. Keep it off until you have measured your normal SIP traffic.

## Dashboard bind and upstream filtering

`DASHBOARD_BIND` is the host address the dashboard port binds to.

| Setup | `DASHBOARD_BIND` | Filter |
| --- | --- | --- |
| The tunnel runs on the same host | `127.0.0.1` (default) | None needed. The port is reachable from the host only. |
| The tunnel runs on another machine | The host's LAN address | Filter the port **upstream**: accept it only from the tunnel's address, drop everything else. |

A host `INPUT` rule is not enough, because Docker publishes the port in its own rules. Filter at the router or hypervisor firewall, or in the `DOCKER-USER` chain. Example rules, with documentation addresses only:

| Rule | Source | Port | Action |
| --- | --- | --- | --- |
| 1 | `198.51.100.10` (tunnel machine) | 8443/tcp | Accept |
| 2 | any | 8443/tcp | Drop |

Test from a machine that is not the tunnel machine: the dashboard port must not answer.

This matters most if you forward **all** ports to the host (a DMZ). A DMZ also forwards the dashboard port. Put the upstream filter in place first.

## Behind a TLS-terminating tunnel

A tunnel such as cloudflared usually terminates TLS and forwards plain HTTP to the dashboard port. The browser then loads the page from `https://dash.example.com` while the API sees a plain-HTTP request with another `Host`. The live WebSocket checks the `Origin` header against the request's host, so it would be refused (close code `1008`), and the dashboard would fall back to polling.

Fix it by listing the public origin in `.env`:

```text
API_ALLOWED_ORIGINS=https://dash.example.com
```

Use full origins (scheme and host, no path), comma-separated. Then restart the API: `docker compose up -d api`. Same-host origins are always accepted, so local use keeps working.

Also set the tunnel's own access policy (for example Cloudflare Access) in front of the dashboard, as a second layer in front of the dashboard login. If you give a colleague an account (Settings > Users), **add their email address to the Cloudflare Access policy as well**, or they never reach the sign-in page.

Keep `COOKIE_SECURE=true` (the default). The browser talks HTTPS to the tunnel, so the `__Host-` cookies work, even though the tunnel talks plain HTTP to the API. Production must be served over HTTPS. `COOKIE_SECURE=false` (plain cookie names, no `Secure` flag) is for local development over HTTP only. Without the full origin in `API_ALLOWED_ORIGINS`, **login fails with 403** and the live feed is refused, so set it before you try to sign in. Also set `API_ALLOWED_HOSTS` to the tunnel's host name, or the API accepts any `Host`.

Set `AUTH_TRUSTED_PROXIES` to the CIDR range of the machine that runs the tunnel. Then the API takes the client address from the tunnel's `CF-Connecting-IP` header, but only for requests that really come from that range. Without it, every login attempt appears to come from the tunnel, and the per-address login limit becomes one limit for everybody.

## Backups

A snapshot protects the whole machine. A database dump is smaller, can be kept off the machine, and can be restored on a fresh install.

```bash
just backup
```

`scripts/backup-db.sh` writes a custom-format dump (TimescaleDB data included) to `./backups`, with mode 0600 in a 0700 folder. The database credentials come from the container and are never printed.

| Variable | Default | Meaning |
| --- | --- | --- |
| `BACKUP_DIR` | `./backups` | Where dumps go. The folder is ignored by git. |
| `BACKUP_KEEP` | `7` | How many dumps to keep. Older ones are deleted. |

The script refuses to run when the free disk space is less than twice the size of the last dump (or 1 GiB when there is no previous dump).

To restore:

```bash
just restore backups/suckerpot-20261024T020000Z.dump
```

This **replaces the whole database**. The script asks you to type `restore`, stops ingest and the API, recreates the database, restores the dump, runs the migrations (which re-apply the role grants) and starts ingest and the API again. Sensors keep running during a restore: their events wait in Redis and are ingested afterwards.

For a daily backup, use the systemd timer example in `scripts/host/README.md` ("Daily database backup"): a oneshot service that runs `backup-db.sh` as a user who can run Docker, and a timer that starts it once a day.

```{warning}
Dumps contain captured attack data: attacker addresses, credentials and payload fragments. Keep them private. Never commit them, never put them in a public place, and copy them off the machine only to storage that you control.
```

## Snapshot

Take a snapshot of the VM, or a full image of the machine, in a clean state **after** the stack works and **before** the first exposure. If the host is compromised, you can restore a clean state in minutes. Name it clearly, for example `clean-before-internet`. Update it when you change the setup.

## Forward the ports

Forward the sensor ports to the host, then verify each one. Forward only the ports of sensors that are actually running. Each row is one host port. The variable is the one in `.env` that sets it.

| Sensor | Port | Protocol | Variable |
| --- | --- | --- | --- |
| SSH | 22 | TCP | `SSH_HOST_PORT` |
| Telnet | 23 | TCP | `TELNET_HOST_PORT` |
| ADB | 5555 | TCP | `ADB_HOST_PORT` |
| Web | 80 and 443 | TCP | `HTTP_HOST_PORT` and `HTTPS_HOST_PORT` |
| Docker API | 2375 | TCP | `DOCKER_HOST_PORT` |
| Redis | 6379 | TCP | `REDIS_HOST_PORT` |
| MySQL | 3306 | TCP | `MYSQL_HOST_PORT` |
| MSSQL | 1433 | TCP | `MSSQL_HOST_PORT` |
| RDP | 3389 | TCP | `RDP_HOST_PORT` |
| SMB | 445 | TCP | `SMB_HOST_PORT` |
| SIP | 5060 | UDP **and** TCP | `SIP_HOST_PORT` |

The dashboard port (`DASHBOARD_PORT`, 8443 by default) and the admin SSH port are **never** forwarded. Keep them off the list.

The host must not run its own service on any of these ports. For example, a Samba server on 445 or a MySQL server on 3306 would collide with the sensor.

```{warning}
A DMZ forwards **every** port to the host, including the dashboard port and the admin SSH port. Use one only after the host firewall and the upstream dashboard filter are in place. If your router can forward only the ports you need, prefer that.
```

### SIP needs the real source address

The SIP sensor answers each UDP datagram to the address that sent it. Its per-source limits and its verification of the source depend on that address being the attacker's. Docker can break this. For a published port, Docker uses NAT (iptables), which keeps the source address. But when the userland proxy (`docker-proxy`) handles the port, the sensor sees the proxy's address for every datagram. Then every attacker looks like one source.

The userland proxy is on by default and applies to all published ports. To keep the source addresses for SIP, the host owner must turn it off:

1. Add `"userland-proxy": false` to `/etc/docker/daemon.json`. Keep any other keys in the file.
2. Restart the Docker daemon. This stops the containers unless `live-restore` is set, so plan a short window.
3. Test from a machine outside your network. Send one SIP `OPTIONS` request to UDP 5060 and check the `connect` event in the dashboard. Its source address must be the address of the test machine. It must never be a private address of the Docker bridge.

With the proxy off, a connection from the host to its own published ports may stop working. The internet path is the one that matters, and it uses NAT.

## Verify from outside

From a machine outside your network:

- [ ] The sensor ports answer (a connection to port 22 gets an OpenSSH banner, and a connection to 6379 gets a Redis reply).
- [ ] UDP 5060 answers an OPTIONS request, and the SIP `connect` event shows the real source address.
- [ ] The dashboard port does not answer.
- [ ] The admin SSH port does not answer.
- [ ] The tunnel URL reaches the dashboard, and the Live indicator reads "Live" without the "Polling" note.

Then check the logs for new events:

```bash
docker compose logs --tail=50 ingest
```

## After go-live

- Watch the disk usage. Attackers can send a lot of data. Check it every day for the first week.
- Check `docker compose ps` for restarting sensors. A sensor that restarts often points at an attack that hits a limit.
- Keep the host updated. Apply security updates regularly.
- Keep the snapshot up to date when you change the setup.
- Read the logs of the admin SSH service, not only of SuckerPot.

## Planned

- API rate limits beyond the login limits (M8).
