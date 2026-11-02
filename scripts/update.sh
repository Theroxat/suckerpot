#!/usr/bin/env bash
# Safe update of an installed Selfhostr: backup first, then new code, new images, restart, health
# check. Called by `just update [vX.Y.Z]`. See docs/design/m28.md section 6.
#
#   scripts/update.sh [--yes] [--no-backup] [--skip-verify] [--force] [vX.Y.Z]
#
# A database dump is taken first and recorded in .suckerpot-state/last-update.json, together with
# the commit and version you were on, so `just rollback` can put everything back. Migrations are
# forward-only: a rollback restores the dump (events received since are lost). The script never
# rolls back by itself.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/env.sh
. scripts/lib/env.sh

STATE_DIR=.suckerpot-state
STATE=$STATE_DIR/last-update.json
TOTAL=9

assume_yes=0
no_backup=0
skip_verify=0
force=0
target=""
while [ $# -gt 0 ]; do
  case $1 in
    --yes | -y) assume_yes=1 ;;
    --no-backup) no_backup=1 ;;
    --skip-verify) skip_verify=1 ;;
    --force) force=1 ;;
    -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    v[0-9]*) target=$1 ;;
    *) echo "update: unknown argument: $1 (usage: update.sh [--yes] [--no-backup] [--skip-verify] [--force] [vX.Y.Z])" >&2; exit 2 ;;
  esac
  shift
done
if [ -n "$target" ] && ! [[ $target =~ ^v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
  echo "update: the version must look like v1.2.3" >&2
  exit 2
fi

die() { echo "update: $*" >&2; exit 1; }
step() { printf '[%s/%s] %s\n' "$1" "$TOTAL" "$2"; }
confirm() {
  [ "$assume_yes" = 1 ] && return 0
  local a
  printf '%s [y/N]: ' "$1"
  read -r a || a=""
  [ "$a" = y ] || [ "$a" = yes ]
}

[ -f .env ] || die ".env not found. Selfhostr is not installed here (run ./scripts/install.sh)."
need_project
env_drop_loaded

mode=$(env_get SUCKERPOT_INSTALL_MODE source)
case $mode in images | source) ;; *) die "SUCKERPOT_INSTALL_MODE must be images or source" ;; esac
dport=$(env_get DASHBOARD_PORT 8443)
bind=$(env_get DASHBOARD_BIND 127.0.0.1)
[ "$bind" = 0.0.0.0 ] && bind=127.0.0.1

# Safe characters only, for anything that ends up in the state file.
clean() { printf %s "$1" | tr -cd 'A-Za-z0-9._:/@=,+-'; }

# ---------------------------------------------------------------- 1. preflight
step 1 "Checking the installation"
dirty=$(git status --porcelain --untracked-files=no 2> /dev/null || true)
if [ -n "$dirty" ]; then
  if [ "$mode" = source ]; then
    die "tracked files have local changes; commit or discard them first (git status)"
  fi
  echo "      warning: tracked files have local changes (the compose file comes from git too)" >&2
fi

backup_health=$(docker compose ps backup --format '{{.Health}}' 2> /dev/null | head -n 1 || true)
if [ "$backup_health" != healthy ]; then
  if [ "$no_backup" = 0 ]; then
    die "the stack is not up or the backup service is not healthy (state: ${backup_health:-none}). Run: just up"
  fi
  echo "      warning: the backup service is not healthy" >&2
fi

if [ "$force" = 0 ] && [ -f "$STATE" ] && grep -q '"completed": false' "$STATE"; then
  die "the previous update never finished (see $STATE). Run just rollback, or finish it, or retry with --force"
fi

from_ref=$(git rev-parse HEAD 2> /dev/null || true)
[ -n "$from_ref" ] || die "this folder is not a git checkout"
from_branch=$(git symbolic-ref --short -q HEAD 2> /dev/null || true)
from_version=$(git describe --tags --always 2> /dev/null || echo unknown)
if [ "$mode" = images ]; then
  from_version=$(env_get SUCKERPOT_VERSION "$from_version")
fi

fetched=1
git fetch --tags --quiet 2> /dev/null || fetched=0
[ "$fetched" = 1 ] || echo "      warning: could not fetch tags from the remote; using the local ones" >&2

pull_branch=0
if [ -z "$target" ]; then
  if [ "$mode" = source ] && [ -n "$from_branch" ]; then
    pull_branch=1
  else
    target=$(git tag -l 'v*.*.*' --sort=-v:refname | grep -E '^v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' | head -n 1 || true)
    [ -n "$target" ] || die "no release tag found"
  fi
fi
if [ -n "$target" ]; then
  git rev-parse -q --verify "refs/tags/$target" > /dev/null || die "tag $target not found"
  if [ "$target" = "$from_version" ] && [ "$(git rev-parse "$target^{commit}")" = "$from_ref" ]; then
    echo "Already on $target. Nothing to update."
    exit 0
  fi
fi

echo "      current: $from_version"
if [ "$pull_branch" = 1 ]; then
  echo "      target:  newest commit of branch $from_branch (git pull --ff-only)"
else
  echo "      target:  $target"
  notes=$(git tag -l --format='%(contents)' "$target" 2> /dev/null | tr -d '\000-\010\013-\037\177' || true)
  if [ -n "$notes" ]; then
    echo "      release notes:"
    printf '%s\n' "$notes" | sed 's/^/        /'
  fi
fi
confirm "Update now? A database backup is taken first." || { echo "aborted"; exit 1; }

# ---------------------------------------------------------------- 2. backup
step 2 "Backing up the database"
dump=""
if [ "$no_backup" = 1 ]; then
  echo "      Without a backup there is NO way back for the database."
  printf '      Type "no backup" to continue without one: '
  read -r a || a=""
  [ "$a" = "no backup" ] || die "aborted"
else
  docker compose exec -T backup /bin/sh /backup-service.sh now preupdate \
    || die "the backup failed; nothing was changed"
  dump=$(docker compose exec -T backup sh -c 'ls -1t /backups/suckerpot-preupdate-*.dump 2>/dev/null | head -n 1' | tr -d '\r' || true)
  dump=${dump##*/}
  [[ $dump =~ ^suckerpot-preupdate-[A-Za-z0-9._-]+\.dump$ ]] || die "the backup ran but its file could not be found; nothing was changed"
  echo "      dump: $dump"
fi

# ---------------------------------------------------------------- 3. state file
step 3 "Recording how to roll back"
umask 077
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
images_json=""
while IFS='=' read -r svc img; do
  [ -n "$svc" ] && [ -n "$img" ] || continue
  id=$(docker image inspect --format '{{.Id}}' "$img" 2> /dev/null || true)
  [ -n "$id" ] || continue
  images_json+="${images_json:+,
}    \"$(clean "$svc")\": \"$(clean "$id")\""
done < <(docker compose ps -a --format '{{.Service}}={{.Image}}' 2> /dev/null || true)
tmp=$(mktemp "$STATE_DIR/.state.XXXXXX")
cat > "$tmp" << EOF
{
  "from_version": "$(clean "$from_version")",
  "from_ref": "$(clean "$from_ref")",
  "from_branch": "$(clean "$from_branch")",
  "mode": "$mode",
  "dump": "$(clean "$dump")",
  "target": "$(clean "$target")",
  "at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "completed": false,
  "images": {
${images_json}
  }
}
EOF
chmod 600 "$tmp"
mv "$tmp" "$STATE"

changed=0
on_exit() {
  rc=$?
  if [ "$rc" -ne 0 ] && [ "$changed" = 1 ]; then
    echo >&2
    echo "update FAILED after the code was changed. Nothing was rolled back automatically." >&2
    echo "  To go back to $from_version and restore the database dump '${dump:-none}':" >&2
    echo "      just rollback" >&2
    echo "  (events received since the dump are lost by a rollback)" >&2
  fi
}
trap on_exit EXIT

# ---------------------------------------------------------------- 4. code
step 4 "Fetching the new code"
changed=1
if [ "$pull_branch" = 1 ]; then
  git pull --ff-only --quiet || die "git pull --ff-only failed"
else
  git checkout --quiet "$target" || die "could not check out $target"
fi
new_ref=$(git rev-parse HEAD)
[ -f scripts/lib/env.sh ] && . scripts/lib/env.sh

# ---------------------------------------------------------------- 5. environment
step 5 "Updating .env"
bash scripts/env-migrate.sh
env_drop_loaded

# ---------------------------------------------------------------- 6. images
step 6 "Getting the new images"
if [ "$mode" = images ]; then
  env_set_line .env SUCKERPOT_VERSION "$target"
  env_drop_loaded
  if [ "$skip_verify" = 1 ]; then
    echo "      warning: --skip-verify, the image signatures were NOT checked" >&2
    docker compose pull
  else
    # Verify the digest, pull exactly that digest, tag it: what runs is what was verified.
    bash scripts/verify-images.sh --pull "$target" || die "the image signatures could not be verified; nothing was started. Run just rollback to go back, or retry with --skip-verify only if you accept the risk"
    docker compose pull --policy missing
  fi
  expected=$target
else
  expected=$(git describe --tags --always --dirty 2> /dev/null || echo dev)
  SUCKERPOT_BUILD_VERSION=$expected
  SUCKERPOT_BUILD_COMMIT=$(git rev-parse --short HEAD 2> /dev/null || echo unknown)
  export SUCKERPOT_BUILD_VERSION SUCKERPOT_BUILD_COMMIT
  docker compose build
fi

# ---------------------------------------------------------------- 7. start
step 7 "Restarting (migrations run first)"
bash scripts/check-ports.sh --dotenv-only
if [ "$mode" = images ]; then
  docker compose up -d --no-build --pull never --wait --wait-timeout 600
else
  docker compose up -d --wait --wait-timeout 600
fi

# ---------------------------------------------------------------- 8. health
step 8 "Checking health"
ok=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS --max-time 5 "http://$bind:$dport/healthz" > /dev/null 2>&1; then ok=1; break; fi
  sleep 3
done
[ "$ok" = 1 ] || die "the dashboard does not answer on http://$bind:$dport/healthz"
if docker compose ps --format '{{.Service}} {{.Health}}' | grep -qE ' (unhealthy|starting)$'; then
  die "a service is not healthy (docker compose ps)"
fi
running=$(docker compose exec -T api printenv SUCKERPOT_RUNNING_VERSION 2> /dev/null | tr -d '\r' || true)
if [ "$running" != "$expected" ]; then
  die "the api reports version '${running:-unknown}' but '$expected' was expected"
fi

# ---------------------------------------------------------------- 9. done
step 9 "Done"
changed=0
# Final step: mark the recorded update as finished (a new one is refused while this is false).
tmp=$(mktemp "$STATE_DIR/.state.XXXXXX")
sed 's/"completed": false,/"completed": true,/' "$STATE" > "$tmp"
chmod 600 "$tmp"
mv "$tmp" "$STATE"
echo
echo "Selfhostr is now on $expected (commit ${new_ref:0:9})."
if [ -n "$dump" ]; then
  echo "Rollback, if you need it: just rollback   (restores $dump and the previous version)"
fi
