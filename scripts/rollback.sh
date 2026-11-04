#!/usr/bin/env bash
# Puts SuckerPot back to the state recorded by the last `just update`: the previous code and
# version, and the database as it was in the dump taken just before the update.
# Called by `just rollback`.
#
#   scripts/rollback.sh [--yes]
#
# --yes skips both confirmations. Only scripts/auto-update.sh uses it, after a failed automatic
# update.
#
# THIS REPLACES THE DATABASE with the dump. Events received between the dump and now are lost.
# It asks you to type "rollback"; restoring the dump then asks its own confirmation.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/env.sh
. scripts/lib/env.sh

assume_yes=0
case "${1:-}" in
  "") ;;
  --yes | -y) assume_yes=1 ;;
  *) echo "rollback: unknown argument: $1 (usage: rollback.sh [--yes])" >&2; exit 2 ;;
esac

STATE_DIR=.suckerpot-state
STATE=$STATE_DIR/last-update.json
die() { echo "rollback: $*" >&2; exit 1; }

[ -f .env ] || die ".env not found"
need_project
env_drop_loaded
# restore-db.sh reads the volume prefix from the environment (just loads it from .env).
SUCKERPOT_VOLUME_PREFIX=$(env_get SUCKERPOT_VOLUME_PREFIX)
export SUCKERPOT_VOLUME_PREFIX
# One update or rollback at a time (the automatic updater holds this lock and says so).
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
if [ "${SELFHOSTR_UPDATE_LOCK_HELD:-}" != 1 ]; then
  exec 9> "$STATE_DIR/update.lock"
  flock -n 9 || die "another update or rollback is running (lock $STATE_DIR/update.lock)"
fi
[ -f "$STATE" ] || die "no update to roll back ($STATE not found)"

from_version=$(state_get "$STATE" from_version)
from_ref=$(state_get "$STATE" from_ref)
from_branch=$(state_get "$STATE" from_branch)
mode=$(state_get "$STATE" mode)
dump=$(state_get "$STATE" dump)
at=$(state_get "$STATE" at)

[[ $from_ref =~ ^[0-9a-f]{7,64}$ ]] || die "the state file has no valid commit"
case $mode in images | source) ;; *) die "the state file has a bad install mode" ;; esac
[[ $dump =~ ^suckerpot-[A-Za-z0-9._-]+\.dump$ ]] \
  || die "the last update was made without a backup, so there is no database to restore"
[[ $from_version =~ ^[A-Za-z0-9._-]+$ ]] || die "the state file has a bad version"
git rev-parse -q --verify "$from_ref^{commit}" > /dev/null || die "commit $from_ref is not in this checkout"

# The dump must still be there BEFORE anything is changed (code, images or database).
db_image=$(awk '/^  db:/ {indb=1} indb && /image: / {print $2; exit}' docker-compose.yml)
[ -n "$db_image" ] || die "could not read the db image from docker-compose.yml"
# Never let docker create a missing volume (it would be empty, and a false "dump gone" answer).
docker volume inspect "${SUCKERPOT_VOLUME_PREFIX}_backups" > /dev/null 2>&1 \
  || die "the backups volume ${SUCKERPOT_VOLUME_PREFIX}_backups does not exist. Nothing was changed."
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges:true --user 70:70 \
  -v "${SUCKERPOT_VOLUME_PREFIX}_backups:/b:ro" --entrypoint test "$db_image" -s "/b/$dump" \
  || die "the dump $dump is no longer in the backups volume (retention removed it?). Nothing was changed."

echo "Rollback of the update made at $at:"
echo "  code:     back to $from_version (commit ${from_ref:0:9})"
echo "  images:   $mode mode, then $([ "$mode" = images ] && echo 'pull' || echo 'build')"
echo "  database: REPLACED by the dump $dump"
echo
echo "Events received since that dump are lost."
if [ "$assume_yes" = 0 ]; then
  printf 'Type "rollback" to continue: '
  read -r answer || answer=""
  [ "$answer" = "rollback" ] || { echo "aborted"; exit 1; }
fi

echo "[1/4] Restoring the previous code"
if [ -n "$from_branch" ] && [ "$(git rev-parse -q --verify "refs/heads/$from_branch" 2> /dev/null || true)" = "$(git rev-parse "$from_ref^{commit}")" ]; then
  git checkout --quiet "$from_branch"
else
  git checkout --quiet --detach "$from_ref"
fi

echo "[2/4] Restoring the images"
if [ "$mode" = images ]; then
  env_set_line .env SUCKERPOT_VERSION "$from_version"
  env_drop_loaded
  # Same gate as an update: verify the signatures, pull the verified digests, run only those.
  bash scripts/verify-images.sh --pull "$from_version" \
    || die "the image signatures of $from_version could not be verified; nothing was started"
  docker compose pull --policy missing
else
  SUCKERPOT_BUILD_VERSION=$(git describe --tags --always --dirty 2> /dev/null || echo dev)
  SUCKERPOT_BUILD_COMMIT=$(git rev-parse --short HEAD 2> /dev/null || echo unknown)
  export SUCKERPOT_BUILD_VERSION SUCKERPOT_BUILD_COMMIT
  docker compose build
fi

echo "[3/4] Restoring the database from $dump"
if [ "$assume_yes" = 1 ]; then
  bash scripts/restore-db.sh --yes "volume:$dump"
else
  bash scripts/restore-db.sh "volume:$dump"
fi

echo "[4/4] Starting"
bash scripts/check-ports.sh --dotenv-only
if [ "$mode" = images ]; then
  compose_up_recreating -d --no-build --pull never --wait --wait-timeout 600
else
  compose_up_recreating -d --wait --wait-timeout 600
fi
# Mark the recorded update as resolved, so the next `just update` is not blocked by its lock.
tmp=$(mktemp ".suckerpot-state/.state.XXXXXX")
sed 's/"completed": false,/"completed": true,/' "$STATE" > "$tmp"
chmod 600 "$tmp"
mv "$tmp" "$STATE"
echo
echo "Rolled back to $from_version."
