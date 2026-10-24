# Deployment

This page is a checklist for putting SuckerPot on the internet. Follow the steps in order. Do not skip the snapshot or the firewall rules.

Read [Getting started](getting-started.md) first, and read the [Security](SECURITY.md) page for the threat model.

```{admonition} Build status
:class: note

M1 has no sensors yet, so there is nothing to expose. The steps below describe the go-live procedure that the sensors (M2 onward) will need. The dashboard part applies to M1 already.
```

## Principles

- **Only the sensor ports face the internet.** Every other port stays private.
- **The dashboard is reached through a reverse tunnel.** The tunnel, for example cloudflared, connects from a machine you control to the dashboard port. The dashboard port is never open to everyone.
- **The host's own admin SSH runs on a port that no sensor uses.** It is never exposed to the internet.
- **Filters work upstream of the host.** Docker publishes ports in its own firewall rules, so a host `INPUT` rule does not protect a published port. Filter at the router or hypervisor, or in the `DOCKER-USER` chain.
- **A broken setup must fail closed.** Test the rules before you open the router.

## Owner actions before go-live

The list below is the checklist for the person who runs the host. Each item is a decision or a change on infrastructure that the project does not control. Do them in this order. Tick each one only after you have checked it.

1. [ ] Rotate every secret that was used while the stack was in development. Generate new ones with `openssl rand -base64 32`.
2. [ ] Log out of any AI coding assistant, IDE sync and cloud CLI on the host. Revoke or rotate any git or API token that was used on the host.
3. [ ] Check that no API key or token sits in a file that other users can read.
4. [ ] Move the host's admin SSH to a port that no sensor or dashboard uses. Allow it only from your management network.
5. [ ] Keep `DASHBOARD_BIND` at `127.0.0.1`, unless a tunnel on another machine must reach the dashboard. If it must, set the host's LAN address and filter the port upstream (see step 3 below).
6. [ ] Filter the dashboard port upstream (router, hypervisor firewall or the `DOCKER-USER` chain). Accept it only from the tunnel's address, and drop everything else.
7. [ ] Filter outbound traffic from the host and from the dashboard network. The API must not reach the internet. Test it: from the API container, an outbound connection to an external address must fail.
8. [ ] Keep `API_ENABLE_DOCS=false`.
9. [ ] Take a snapshot of the VM, or a full image of the machine, in a clean state.
10. [ ] Check the sensor networking plan for the release (see [Architecture](ARCHITECTURE.md#planned-sensor-networking-m2)) before you forward any sensor port.
11. [ ] Forward the sensor ports only after steps 1 to 9 are done.
12. [ ] Verify from outside your network (see the checklist below).

## Go-live checklist

### 1. Prepare the host

- [ ] The host is a dedicated VM or machine (see the warning in [Getting started](getting-started.md)).
- [ ] Docker and the Compose plugin are installed and up to date.
- [ ] `.env` has strong, unique secrets. None of them is `change-me`, and each is at least 24 characters.
- [ ] No credentials that matter are stored on the host: no cloud keys, no other SSH keys, no personal files.

### 2. Move the host's admin SSH away from the sensor ports

The sensors take the standard ports (22, 23, 80 and 3389). The host's own SSH must listen on another port, and only on your management network.

- Choose a high port that no sensor or dashboard uses.
- Allow that port only from your management network, in the host firewall and upstream.
- Test a new session from another terminal before you close the current one.

Use `sshd` and systemd settings as your distribution documents. Some systems ignore the `Port` line in `sshd_config` when systemd socket activation is on. Check the port with `ss -tlnp` after each change.

### 3. Restrict the dashboard port

The dashboard port must accept connections only from your tunnel.

- Keep `DASHBOARD_BIND=127.0.0.1` when the tunnel runs on the same host. The port is then reachable only from the host itself.
- If the tunnel runs on another machine, set `DASHBOARD_BIND` to the host's LAN address and filter the port upstream. A host `INPUT` rule is not enough, because Docker publishes the port in its own rules.

Example rules, with documentation addresses only:

| Rule | Source | Port | Action |
| --- | --- | --- | --- |
| 1 | `198.51.100.10` (tunnel host) | 8443/tcp | Accept |
| 2 | any | 8443/tcp | Drop |

Check the rules from a machine that is not the tunnel host. The dashboard port must not answer.

### 4. Take a snapshot

Take a snapshot of the VM, or a full image of the machine, before the first exposure. If the host is compromised, you can restore a clean state in minutes.

Name it clearly, for example `clean-before-internet`.

### 5. Remove development tools and credentials from the host

- Log out of any AI coding assistant, IDE sync or cloud CLI on the host.
- Revoke or rotate any token that was used on the host, including git tokens.
- Check that no API key sits in a file that other users can read.

### 6. Forward the ports

Forward the sensor ports to the host, then verify each one.

```{warning}
A DMZ forwards **every** port to the host, including the dashboard port and the admin SSH port. That is why steps 2 and 3 come first. Use a DMZ only after the upstream filters are in place. If your router can forward only the ports you need, prefer that.
```

### 7. Verify from outside

From a machine outside your network:

- [ ] The sensor ports answer (for example, a connection to port 22 gets a banner).
- [ ] The dashboard port does not answer.
- [ ] The admin SSH port does not answer.
- [ ] The tunnel URL reaches the dashboard.

Then check the logs of the sensors and of ingest for new events.

```bash
docker compose logs --tail=50 ingest
```

## After go-live

- Watch the disk usage. Attackers can send a lot of data. Check it every day for the first week.
- Keep the host updated. Apply security updates regularly.
- Keep the snapshot up to date when you change the setup.
- Read the logs of the admin SSH service, not only of SuckerPot.

## Planned

- Dashboard login with an admin account, a session cookie and rate-limited login (M8).
- API rate limits (M8).
- A retention job that deletes raw events after `RETENTION_DAYS` (M8).
- A backup script for the database volume (M8).
