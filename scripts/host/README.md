# Host firewall

SuckerPot publishes honeypot ports on the host and runs untrusted traffic through
Docker containers. Docker's network settings already remove the containers' route to
the internet, but they do not stop a compromised container from opening connections to
the **host itself** (for example its admin SSH port) or to other machines on your LAN.
This nftables table closes that gap.

`firewall.nft` is a template: it contains no addresses from any real network.

## What it blocks

| Rule | Effect |
| --- | --- |
| input, from `sp-ingress` and `sp-dashboard` | Containers of the sensor network and the dashboard network cannot open new connections to the host. |
| input, from `docker0`, `br-*` and `sp-*` to `protected_ports` | No container of any Docker network can reach the admin SSH port or the dashboard port of the host. |
| forward, from `sp-ingress` and `sp-dashboard` | These containers cannot start new connections through the host: no LAN scanning, no outbound traffic, no traffic between sensors. Replies to inbound connections still go out. |
| input, from `sp-egress` and `sp-samples` | The proxy network and the sample network cannot open new connections to the host. Without this, `CONNECT <bridge gateway>:<published port>` through the proxy would reach the host's published ports. |
| input, from `sp-vpn` | The `vpn` container (anonymous egress) cannot open new connections to the host. |
| forward, from `sp-vpn` | The only new connection allowed is UDP to the WireGuard endpoint (`VPN_ENDPOINT_IP`, `VPN_ENDPOINT_PORT`). Everything else is dropped, so the kill switch holds even if the container's own firewall fails. |

Nothing here affects traffic from the internet to the published sensor ports.

## Before you apply it

1. Open `firewall.nft` and set `ADMIN_SSH_PORT` to the port of your host's admin SSH
   daemon. The file ships with `CHANGE_ME` on purpose: it will not load until you
   change it.
2. Check `DASHBOARD_PORT` matches your `.env`.
   If you use the `egress` profile, set `VPN_ENDPOINT_IP` and `VPN_ENDPOINT_PORT` to the
   values of `VPN_WG_ENDPOINT_IP` and `VPN_WG_ENDPOINT_PORT`. The file will not load until you
   do (without the profile, any valid values such as the documentation address
   `203.0.113.10` and port `51820` will do; the rules then never match anything).
3. Nothing to adjust for Docker address pools: rules match network interfaces, not addresses.
4. Keep a second way into the machine (hypervisor console) the first time.

## Important: load it before exposing the host

Without this table, a compromised sensor can reach the host's admin SSH port. Load it
**before** you forward any traffic to the machine, and check it after every reboot:

```
sudo nft list table inet suckerpot_host
```

If that prints an error, the firewall is not active.

## Apply

```
sudo nft -c -f scripts/host/firewall.nft   # syntax check, changes nothing
sudo nft -f scripts/host/firewall.nft      # apply (safe to run again)
sudo nft list table inet suckerpot_host    # see the rules and counters
```

The rules live in memory only until you persist them.

## Persist across reboots

Do **not** use the stock `nftables` service for this: on Debian and Ubuntu,
`/etc/nftables.conf` starts with `flush ruleset`, and starting that service on a
running host wipes Docker's own rules (NAT and published ports) until Docker restarts.

Use the dedicated unit shipped next to this file instead. It only loads the
`suckerpot_host` table, after Docker has started:

```
sudo install -m 0600 scripts/host/firewall.nft /etc/suckerpot-firewall.nft
sudo editor /etc/suckerpot-firewall.nft        # fill in ADMIN_SSH_PORT (and DASHBOARD_PORT)
sudo nft -c -f /etc/suckerpot-firewall.nft     # syntax check, changes nothing
sudo install -m 0644 scripts/host/suckerpot-firewall.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now suckerpot-firewall.service
```

Edit the installed copy, never the tracked file: your admin port must not end up in git.

The table does not clash with Docker: it has its own name, and Docker does not delete
tables it did not create. The rules match interface names as text, so they work even
if the Docker networks are created later.

## Verify

Egress: with the `egress` profile up, run `just egress-check`, then
`sudo nft list table inet suckerpot_host`. The `sp-vpn` accept rule counts the tunnel
handshake packets; the `sp-vpn` drop counters stay at 0 unless something inside `vpn`
tried to leave outside the tunnel.

1. Start the stack, then from the host run `sudo nft list table inet suckerpot_host`.
   Counters on the `drop` rules stay at 0 in normal operation.
2. From inside a sensor, a new connection to the host must fail. For example (replace
   `<sensor-container>` and `<gateway>`; the gateway is the `.1` address of the `sp-ingress` subnet):

   ```
   docker run --rm --network container:<sensor-container> busybox nc -w2 -zv <gateway> <admin-ssh-port>
   ```

   It should time out, and the `input` drop counter should go up.
3. From the internet (or another machine), the sensor ports must still answer.
4. Check that the host listens on the sensor port for IPv4 only: `ss -tlnp | grep ':22 '`
   should show `0.0.0.0:22` and no `[::]:22`.

## Roll back

```
sudo systemctl disable --now suckerpot-firewall.service  # or: sudo nft delete table inet suckerpot_host
```

To remove it permanently: `sudo rm /etc/systemd/system/suckerpot-firewall.service /etc/suckerpot-firewall.nft && sudo systemctl daemon-reload`.

## Also recommended

- Filter the dashboard port upstream (hypervisor or router firewall) so that only your
  reverse tunnel can reach it. Published Docker ports bypass ordinary host input rules.
- Keep the host's admin SSH on a port that is not a sensor port, and restrict it to your
  management network.

## Daily database backup

`scripts/backup-db.sh` dumps the database (custom format, TimescaleDB included) to
`./backups` (override with `BACKUP_DIR`), keeps the newest `BACKUP_KEEP` dumps (default 7) and
refuses to run when the disk has less than twice the last dump's size free. Dumps contain
captured attack data: keep them private and never commit them.

Restore with `just restore backups/FILE.dump` (it asks for confirmation, stops ingest and
the API, restores, runs the migrations and starts them again).

### systemd timer

`/etc/systemd/system/suckerpot-backup.service` (adjust the paths and the user, who must be able to run Docker):

```
[Unit]
Description=SuckerPot database backup

[Service]
Type=oneshot
User=CHANGE_ME
WorkingDirectory=/path/to/suckerpot
Environment=BACKUP_DIR=/path/to/backups
ExecStart=/path/to/suckerpot/scripts/backup-db.sh
```

`/etc/systemd/system/suckerpot-backup.timer`:

```
[Unit]
Description=Daily SuckerPot database backup

[Timer]
OnCalendar=*-*-* 03:30:00
Persistent=true

[Install]
WantedBy=timers.target
```

Enable it with `sudo systemctl enable --now suckerpot-backup.timer` and check it with
`systemctl list-timers suckerpot-backup.timer`.

### cron alternative

```
30 3 * * * cd /path/to/suckerpot && BACKUP_DIR=/path/to/backups scripts/backup-db.sh >> /path/to/backups/backup.log 2>&1
```

Copy the dumps off the machine (they are the only copy of your history), and test a
restore from time to time.
