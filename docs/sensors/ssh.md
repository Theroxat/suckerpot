# SSH sensor

```{admonition} Status
:class: note

Built in M2 and wired into Compose as `sensor-ssh`. Reviewed by the security review process described in [Security](../SECURITY.md).
```

## What it emulates

An OpenSSH 9.6p1 server on Ubuntu, with a shell that is pure emulation. It listens on container port 2222. Compose maps the host port (`SSH_HOST_PORT`, default 22) to it, so no capability is needed.

- **Handshake.** The key exchange, cipher, MAC, compression and host key algorithm lists are those of OpenSSH 9.6 on Ubuntu 24.04, in the same order.
- **Logins.** Password and keyboard-interactive logins succeed for the pairs in `SSH_ACCEPT_CREDENTIALS`, or for any non-empty password with probability `SSH_ACCEPT_RANDOM_PROB`. Public keys are recorded (type and SHA256 fingerprint) and rejected. After `SSH_MAX_AUTH_ATTEMPTS` failures the connection ends with OpenSSH's "Too many authentication failures".
- **Shell.** Interactive PTY sessions, piped input and `exec` requests. An in-memory, copy-on-write fake file system built from a base image. Errors go to the stderr channel when there is no PTY.
- **Downloads.** `wget`, `curl`, `tftp`, `ftpget` and `scp host:path` only emit `download_attempt` events and leave a few-byte stub file. Nothing is fetched. `scp -t` uploads are hashed and discarded, and recorded in a `command` event.
- **Port forwarding** requests are refused and recorded as `scan` events. The `sftp` subsystem is accepted and closed with exit status 127, like an sshd with a broken `sftp-server`.

## What it records

All events use the shared [Event schema](../event-schema.md). `dst_port` is the public port (`SSH_PUBLIC_PORT`).

| Event `type` | `data` keys |
| --- | --- |
| `connect` | `client_version`, `banner` |
| `login_attempt` | `username`, `password` (null for a public key), `success`, `method`. A public key adds `key_type` and `key_fingerprint`. |
| `command` | `input`, `output` (8 KiB cap), `output_preview` (256 characters), `cwd`, `user`, `prompt`, `status` |
| `download_attempt` | `url`, `tool`, `command`, `cwd`, `user` |
| `scan` | `kind` = `tcp_forward_attempt`, `host`, `port`. Also `kind` = `events_suppressed` when events were dropped by a rate limit. |
| `disconnect` | `duration_s`, `reason`, `login_attempts`, `commands`, `downloads`, `events_suppressed`, `replay`, `replay_truncated` |

### Terminal recording

The `disconnect` event carries `data.replay`: a list of frames `[delta_seconds, "o" | "i", text]`. `o` is output sent to the client (including the echo). `i` is input typed by the client. `delta_seconds` is relative to the previous frame. The newest frames that fit in 12 KiB of compact JSON are kept. If older frames were dropped, `data.replay_truncated` is `true`. The whole event stays below 16 KiB.

`command` events also carry `input`, `output` and `prompt` with accurate timestamps, so a command-level replay works even when the raw recording was truncated.

```{warning}
The recording holds attacker-controlled bytes, including terminal escape sequences. The dashboard must render it with the safety contract in [Security](../SECURITY.md#terminal-replay-safety-contract). The replay player itself is planned for M5.
```

## Limits and abuse resistance

| Scope | Limit |
| --- | --- |
| Connections | `SSH_MAX_CONNECTIONS` in total (200), `SSH_MAX_PER_IP` per source (5) |
| Timeouts | Login `SSH_LOGIN_TIMEOUT` (30 s), idle `SSH_IDLE_TIMEOUT` (300 s), whole session `SSH_MAX_SESSION` (1800 s) |
| Per connection | 2 session channels, 20 refused requests, one shared fake file system (1 MiB, 2000 nodes), 5000 commands, auth requests capped at 4 times `SSH_MAX_AUTH_ATTEMPTS` |
| Per shell | 256 variables and 64 KiB, 64 KiB of history, 64 KiB per expanded word |
| Per command line | A CPU budget (`SSH_LINE_BUDGET`, 0.15 s: the line is aborted with `Killed`), 200 simple commands, 64 KiB of output |
| Whole sensor | A memory budget over all sessions (`SSH_MEMORY_BUDGET_MB`, 48: beyond it, new sessions are refused and commands fail with `Cannot allocate memory`) |
| Events | `connect` per source IP (`SSH_EVENTS_PER_SEC`), `scan` and `login_attempt` per session, `command` and `download_attempt` per session in a separate quota, `disconnect` never limited, all but `disconnect` capped sensor-wide (`SSH_GLOBAL_EVENTS_PER_SEC`) |

Suppressed events are counted. The `disconnect` event carries `events_suppressed`, and a `scan` event with `kind = events_suppressed` is emitted.

- **Watchdog.** A thread exits the process (status 70) when the event loop does not run for 10 seconds. Compose then restarts the container.
- **No regular expression on attacker text with nested quantifiers.** `awk` and `sed` programs are parsed by hand, and `grep` patterns are translated to globs.
- **Container.** Non-root (UID 10001), read-only root file system with a `tmpfs` at `/tmp`, all capabilities dropped, 256 MB memory with no swap, 0.5 CPU, 128 processes. A volume holds the host keys.

## Configuration

Compose sets the Redis variables. The rest can be overridden in `.env` where noted. The full table of every variable is in [Configuration](../configuration.md#ssh-sensor).

| Variable | Default | Meaning |
| --- | --- | --- |
| `SSH_HOST_PORT` | `22` | Host port (Compose only) |
| `SSH_BANNER` | `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.14` | Version string |
| `SSH_HOSTNAME` | `srv-web01` | Fake host name |
| `SSH_ACCEPT_CREDENTIALS` | weak set | Comma list of `user:password` |
| `SSH_ACCEPT_RANDOM_PROB` | `0.0` | Chance of accepting any non-empty password |
| `SSH_MAX_AUTH_ATTEMPTS` | `6` | Attempts per connection |
| `SSH_MAX_CONNECTIONS`, `SSH_MAX_PER_IP` | `200`, `5` | Connection caps |

## Fingerprint notes

What an attacker can tell apart from a real OpenSSH:

- The post-quantum key exchange `sntrup761x25519-sha512@openssh.com` is missing (asyncssh does not support it).
- The list of authentication methods is `publickey,keyboard-interactive,password`. Ubuntu's default is `publickey,password`.
- The RSA host key is not offered as `ssh-rsa`, as in a real 9.6 server. Tools such as `nmap`'s `ssh-hostkey` script then list only the ECDSA and ED25519 keys.

The fake machine identity (private address, MAC, uptime, last-login address, DNS answers) comes from a random secret created once, next to the host keys. It is **not** derived from the public host key, so nobody can predict the fake `ip a` output from the key fingerprint and recognise the sensor. Keep the data volume persistent: a warning is logged whenever keys are generated.

Host keys and the secret are generated on first start, mode 0600. They are never committed.

## Test it

```bash
just ssh-test
```

The recipe logs in for real from a throwaway container, runs two commands (one is a fake download) and waits until the session shows up in the API. See [Development](../development.md).
