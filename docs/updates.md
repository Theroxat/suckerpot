# Updates and rollback

Selfhostr updates with one command, `just update`. Before anything changes, the update takes a database dump. If the update fails, or you want to go back, `just rollback` puts the previous code, images and database back.

This page covers:

- what `just update` does, step by step;
- how image signatures are checked;
- the database dump taken before each update;
- `just rollback`, and what it costs;
- the lock that stops a second update after a failed one, and `--force`;
- the optional update check.

```{warning}
A rollback replaces the database with the dump. Everything written after that dump is lost: events, sessions, settings and accounts. Read [Rollback](#rollback) before you use it.
```

## Commands

| Command | What it does |
| --- | --- |
| `just update` | Update to the newest release tag (`v*.*.*`). Asks you to confirm. |
| `just update vX.Y.Z` | Update to a given release. |
| `just update --yes` | Skip the confirmation. |
| `just update --no-backup` | Update without a database dump. Asks you to type `no backup`. Not recommended. |
| `just update --skip-verify` | Do not check the image signatures. Not recommended. |
| `just update --force` | Start an update even though the last one did not finish. See [the unfinished-update lock](#the-unfinished-update-lock). |
| `just rollback` | Go back to the state of the last update. Asks you to type `rollback`. |
| `just version` | Show the checkout version, the install mode, the image version and the version that is running. |

Flags can be combined, for example `just update v0.9.0 --yes`.

## What `just update` does

`just update` runs `scripts/update.sh`. It prints one line per step, `[n/9]`.

1. **Check the installation.** `.env` must exist and name the project and the volume prefix. The stack must be up, with the `backup` service healthy. Tracked files must not have local changes (source mode refuses, images mode warns). It then fetches the tags and works out the target.
2. **Back up the database.** The `backup` service takes a dump named `suckerpot-preupdate-<time>.dump`. If the dump fails, nothing is changed.
3. **Record how to roll back.** It writes `.suckerpot-state/last-update.json` (mode `0600`, ignored by git). The file holds the versions, the commit, the dump name and the image IDs. It holds no secret.
4. **Fetch the new code.** It checks out the release tag. In source mode on a branch, it runs `git pull --ff-only` instead.
5. **Update `.env`.** `scripts/env-migrate.sh` adds the secrets and defaults that are new, and never changes a line that already exists. See [settings that are added](#settings-that-are-added).
6. **Get the new images.** Images mode verifies the signatures and pulls exactly the verified images. Source mode rebuilds from the checkout.
7. **Restart.** `docker compose up` runs. The `migrate` service applies the database changes first.
8. **Check the health.** The dashboard must answer on `/healthz`, every service must be healthy, and the API must report the new version.
9. **Done.** It marks the update as finished in the state file.

Before step 1 finishes, the update prints the current version, the target version and the release notes of the target tag. It asks for your confirmation, unless you pass `--yes`.

If you are already on the target, it says `Already on vX.Y.Z. Nothing to update.` and stops.

### What the target is

| Install mode | `just update` with no version | Notes |
| --- | --- | --- |
| `images` | The newest `v*.*.*` tag. | The release images for that tag are pulled. |
| `source`, on a branch | The newest commit of the branch (`git pull --ff-only`). | The checkout must be clean. |
| `source`, on a tag | The newest `v*.*.*` tag. | The images are rebuilt from the checkout. |

Installs made before the install modes existed count as `source`. An update keeps them on source, unless you change the mode in `.env` yourself.

### Settings that are added

Step 5 adds three kinds of settings to `.env`, under a comment with the date:

- Every secret that is missing. A new secret is generated on this host.
- `SUCKERPOT_INSTALL_MODE=source`, when it is missing. This keeps an older install on source mode.
- Any other setting listed in `MIGRATE_DEFAULTS`.

The script then prints the names of what it added. It never prints a value. It also lists the optional settings from `.env.example` that your `.env` does not have yet. Those are only comments, and they can stay that way.

The database password `POSTGRES_PASSWORD` is never generated during an update. The database owner's password lives inside the data volume, so a new value would lock you out. If it is missing, the update prints it as a name to set by hand.

## Image signatures

Every release image is signed when it is published. The signature proves that the release workflow of the project built the image from a version tag. The signature is made with [cosign](https://docs.sigstore.dev/cosign/) and GitHub's identity, so no private key is kept.

Selfhostr checks 18 images for each release:

| Images |
| --- |
| `redis`, `migrate`, `ingest`, `api`, `collector`, `demo` |
| `sensor-ssh`, `sensor-rdp`, `sensor-telnet`, `sensor-web`, `sensor-redis`, `sensor-docker`, `sensor-mysql`, `sensor-mssql`, `sensor-adb`, `sensor-smb`, `sensor-sip`, `sensor-synology` |

The check uses this rule. The image must be signed by the release workflow of the repository named in `SUCKERPOT_IMAGE_PREFIX`, for the tag you asked for. A fork therefore verifies its own releases.

### Verify, then run by digest

The check is the gate, not a report:

1. For each image, cosign verifies the tag and reports the digest (a fixed fingerprint of the image).
2. The image is pulled by that digest, not by the tag.
3. The local name is pointed at the pulled digest.

So what runs is exactly what was verified. A tag that the registry changes later cannot slip in between the check and the start.

If one image fails, nothing starts. The update, or the installer, exits with an error.

### Run the check yourself

`just verify-images` runs the script below and passes its arguments on.

```bash
just verify-images vX.Y.Z
scripts/verify-images.sh vX.Y.Z           # check only: nothing is pulled or started
scripts/verify-images.sh --pull vX.Y.Z    # check, then pull the verified digests
scripts/verify-images.sh --only api vX.Y.Z
```

| Option or variable | Meaning |
| --- | --- |
| `--pull` | Pull the verified digests and tag them. |
| `--only "api ingest"` | Check only these image names. |
| `VERIFY_IMAGES_NO_AUTH=1` | Do not pass the registry login from `~/.docker/config.json` to cosign. |

The cosign tool runs in a pinned container. It contacts the registry and the public Sigstore services from this host, the same way `docker pull` does. It is not sent through the VPN.

```{note}
Source mode has no signatures to check. You build the images from the checkout you have, so review that checkout first.
```

### `--skip-verify`

`--skip-verify` turns the check off for that run. The update then warns, and pulls the images by tag. Use it only when you accept running images that you could not check, for example for a release that the signing workflow has not finished yet. A failed check is never a reason to ignore the result by default.

## The database dump

Every update takes a dump with the `backup` service before it changes anything. The dump is a complete PostgreSQL dump with the TimescaleDB data. It is stored in the `suckerpot_backups` volume (the name uses your volume prefix).

| Rule | Detail |
| --- | --- |
| Name | `suckerpot-preupdate-<time>.dump` |
| Kept | The newest two pre-update dumps. They are separate from the daily dumps. |
| Daily dumps | Kept by `BACKUP_KEEP` (default 7), as described in [Deployment](deployment.md#daily-backups). |
| Where | The `suckerpot_backups` volume. Not on the host's file system. |

If the backup fails, the update stops and nothing is changed. You can list the dumps with `just backups`.

Migrations are forward-only. A new release may change the database in a way that the old code cannot read. That is why the rollback restores the dump, and does not try to undo migrations.

## The state file

`.suckerpot-state/last-update.json` is written by step 3. It looks like this, with example values:

```json
{
  "from_version": "v0.8.0",
  "from_ref": "9f2c1ab3e4d5...",
  "from_branch": "",
  "mode": "images",
  "dump": "suckerpot-preupdate-20261102T031500Z.dump",
  "target": "v0.9.0",
  "at": "2026-11-02T03:15:00Z",
  "completed": false,
  "images": {
    "api": "sha256:..."
  }
}
```

It is a record for `just rollback`. It has no password and no secret. Step 9 changes `"completed": false` to `"completed": true`.

## The unfinished-update lock

An update that stops after step 3 leaves `"completed": false` in the state file. A new `just update` then refuses to start:

```text
update: the previous update never finished (see .suckerpot-state/last-update.json). Run just rollback, or finish it, or retry with --force
```

The lock protects you from a second update on top of a half-done one. There is no automatic way to finish the first one. Choose one of these:

- **Roll back.** Run `just rollback`. Read [Rollback](#rollback) first.
- **Fix the cause and retry.** Run `just update --force`. This skips the lock check only. It does not skip the backup or the signature check.

After a successful rollback, the state file is kept but marked `"completed": true`, so the lock is released and the next `just update` does not need `--force`. A rollback that fails part way leaves the lock in place.

## Rollback

`just rollback` runs `scripts/rollback.sh`. It restores the state recorded by the last update.

Before it changes anything, it checks:

- the state file exists and is valid;
- the dump is in the `suckerpot_backups` volume (if the retention removed it, rollback stops);
- the update was made with a backup (an update with `--no-backup` cannot be rolled back).

It then prints what it will do and asks you to type `rollback`:

```text
Rollback of the update made at 2026-11-02T03:15:00Z:
  code:     back to v0.8.0 (commit 9f2c1ab3e)
  images:   images mode, then pull
  database: REPLACED by the dump suckerpot-preupdate-20261102T031500Z.dump

Events received since that dump are lost.
Type "rollback" to continue:
```

After you confirm, it runs four steps:

| Step | Action |
| --- | --- |
| `[1/4]` | Checks out the previous code, on its branch when it had one. |
| `[2/4]` | Restores the previous version in `.env`. In images mode it verifies the old images and pulls them by digest. In source mode it rebuilds. |
| `[3/4]` | Restores the database from the dump. `scripts/restore-db.sh` asks its own confirmation. |
| `[4/4]` | Starts the stack and waits until every service is healthy. |

### What a rollback costs

- Every row written to the database after the dump is gone. That includes events, sessions, indicators, reports, alerts, accounts and settings changed after the dump.
- Only the database is restored. The other volumes, such as the sensor data, are not touched.
- `.env` is not rolled back. Settings that the update added stay in it. Only `SUCKERPOT_VERSION` changes, in images mode.

### When a rollback happens

Selfhostr never rolls back by itself. If an update fails after the code has changed, it prints the command to run:

```text
update FAILED after the code was changed. Nothing was rolled back automatically.
  To go back to v0.8.0 and restore the database dump 'suckerpot-preupdate-...':
      just rollback
```

A rollback is your decision, because it replaces the database.

## The optional update check

The update check tells you when a newer release exists. It never installs anything.

It is **off by default**. The installer asks the question, with `no` as the default. To change it later:

```bash
just set UPDATE_CHECK_ENABLED=true
just set UPDATE_CHECK_ENABLED=false
```

### What it does

- It runs through the VPN, and only through the VPN. If the VPN gate is closed, nothing is sent. The state shows `no_egress`, and the check tries again after 30 minutes.
- It runs once, 1 to 6 hours after the stack starts. After that it runs about every 24 hours, with a random offset of up to 6 hours. The request times therefore do not form a pattern.
- It makes one request: the latest release of the repository in `UPDATE_CHECK_REPO`.
- The request carries exactly two headers, `Accept` and `User-Agent`. It carries no version, no install identifier, no cookie and no token.
- From the answer it keeps only the tag name, its date, and the pre-release and draft flags. Release notes are never read or shown from the answer.
- It never downloads, pulls or runs anything.

### Where you see it

- A dot in the footer of the dashboard, with the text "Update available".
- An Updates card in Settings > General, with the current version, the latest version, the time of the last check, a link to the release, and the update command.

The dashboard only compares versions. The update itself is always a command you run on the host.

### What GitHub can see

| Who | What they learn |
| --- | --- |
| GitHub | A VPN exit address asked for the latest release of a public repository, about once a day. |
| Your VPN provider | A TLS connection to GitHub. It already sees all outbound traffic. |
| Attackers | Nothing. The check does not open any inbound port. |

The VPN exit address is shared with other users of the same provider. The request does not say which Selfhostr install made it.

### Forks

`UPDATE_CHECK_REPO` names the repository the check reads, as `owner/name`. Its default is the public project repository. Set it to your fork if you publish your own releases:

Edit `UPDATE_CHECK_REPO` in `.env` by hand, then run `just up`. `just set` does not accept this variable. A value that is not a plain `owner/name` is ignored, and the default is used.

## Version check

```bash
just version
```

Example output, with placeholder values:

```text
checkout: v0.9.0
mode:     images
image:    v0.9.0
running:  v0.9.0
```

If `checkout` and `running` differ, the stack has not been restarted since the update. Run `just up`.

## Troubleshooting

| Symptom | What to do |
| --- | --- |
| `the stack is not up or the backup service is not healthy`. | Run `just up`, wait for it to be healthy, then update. |
| `tracked files have local changes`. (source mode) | Commit or discard the changes with `git status`. |
| `the previous update never finished`. | Read [the unfinished-update lock](#the-unfinished-update-lock). |
| `the image signatures could not be verified`. | Nothing was started. Check the version and the image prefix. Run `scripts/verify-images.sh vX.Y.Z` to see which image failed. |
| `the backup failed; nothing was changed`. | Run `just backup` and read the error. Fix it, then update again. |
| `the dashboard does not answer on .../healthz`. | Run `docker compose logs api`. Then decide: fix and run `just up`, or roll back. |
| `the api reports version ... but ... was expected`. | The new images did not start. Run `docker compose ps` and `docker compose logs api`. |
| `could not fetch tags from the remote`. | The update uses the tags already on this host. Check the network, then run `git fetch --tags`. |
| `the dump ... is no longer in the backups volume`. | The rollback cannot run. Only the newest two pre-update dumps are kept. Run `just backups` to see what is left. If you need the data of another dump, restore it by hand with `just restore volume:<name>`. |

## Next steps

- [Install Selfhostr](install.md)
- [Deployment](deployment.md)
- [Configuration](configuration.md)
