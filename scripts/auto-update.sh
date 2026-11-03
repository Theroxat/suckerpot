#!/usr/bin/env bash
# Automatic update (M32), meant for the user's crontab or a systemd user timer. Never needs sudo.
#
#   scripts/auto-update.sh
#
# Installs the newest release of the SAME major version, and only when ALL of this holds:
#   - AUTO_UPDATE_ENABLED=true in .env, images install mode, no earlier update left unfinished;
#   - the release is newer than the running one and not in .suckerpot-state/bad-versions;
#   - its signed release manifest verifies (scripts/verify-release.sh --auto): signed by the
#     release workflow, its commit is the tag's commit, and the release is old enough
#     (auto_min_age_h, 48 h by default);
#   - its images verify (scripts/verify-images.sh).
# Then it runs scripts/update.sh --yes --auto (backup first). If the update fails after the code
# changed, it runs scripts/rollback.sh --yes, remembers the version as bad and never retries it.
#
# One run at a time (flock on .suckerpot-state/update.lock). A random wait of up to 30 minutes
# keeps a fleet from updating at the same second (AUTO_UPDATE_JITTER_S overrides the maximum).
# Output goes to .suckerpot-state/auto-update.log (rotated at 1 MiB); the outcome of the last run
# is in .suckerpot-state/auto-update.json: {last_run, last_result, from, to, error_code}.
#
# Turn it off: ./scripts/participant.sh auto-update off   (or: just set AUTO_UPDATE_ENABLED=false)
set -euo pipefail

export PATH="$PATH:/usr/local/bin:/usr/bin:/bin:/snap/bin"
cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/env.sh
. scripts/lib/env.sh

STATE_DIR=.suckerpot-state
STATE=$STATE_DIR/last-update.json
RESULT=$STATE_DIR/auto-update.json
LOG=$STATE_DIR/auto-update.log
BAD=$STATE_DIR/bad-versions
LOCK=$STATE_DIR/update.lock

umask 077
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"

[ -f .env ] || exit 0
[ "$(env_get AUTO_UPDATE_ENABLED false)" = true ] || exit 0

# One run at a time, quietly.
exec 9> "$LOCK"
flock -n 9 || exit 0
export SELFHOSTR_UPDATE_LOCK_HELD=1

if [ -f "$LOG" ] && [ "$(wc -c < "$LOG")" -gt 1048576 ]; then mv -f "$LOG" "$LOG.1"; fi
exec 3>&1
exec >> "$LOG" 2>&1
chmod 600 "$LOG" 2> /dev/null || true

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { printf '%s %s\n' "$(now)" "$*"; }
safe() { printf '%s' "$1" | tr -cd 'A-Za-z0-9._-' | cut -c1-40; }

from_version=""
to_version=""
# record RESULT ERROR_CODE: writes the outcome file (constant codes only) and ends the run.
record() {
  local result=$1 code=$2 tmp
  tmp=$(mktemp "$STATE_DIR/.auto.XXXXXX")
  printf '{\n  "last_run": "%s",\n  "last_result": "%s",\n  "from": "%s",\n  "to": "%s",\n  "error_code": "%s"\n}\n' \
    "$(now)" "$result" "$(safe "$from_version")" "$(safe "$to_version")" "$code" > "$tmp"
  mv -f "$tmp" "$RESULT"
  log "result: $result${code:+ ($code)}"
  echo "auto-update: $result${code:+ ($code)}" >&3
  [ "$result" = failed ] && exit 1
  exit 0
}

log "auto-update starts"

if [ "$(env_get SUCKERPOT_INSTALL_MODE source)" != images ]; then record skipped source_mode; fi
if [ -f "$STATE" ] && grep -q '"completed": false' "$STATE"; then record skipped unfinished_update; fi

# Spread the fleet out.
jitter=${AUTO_UPDATE_JITTER_S:-1800}
[[ $jitter =~ ^[0-9]{1,5}$ ]] || jitter=1800
if [ "$jitter" -gt 0 ]; then sleep "$((RANDOM % (jitter + 1)))"; fi

from_version=$(env_get SUCKERPOT_VERSION)
[[ $from_version =~ ^v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || record skipped unknown_version
cur_major=${from_version#v}
cur_major=${cur_major%%.*}

git fetch --tags --quiet || record failed fetch_failed

target=""
while IFS= read -r tag; do
  [[ $tag =~ ^v([0-9]{1,3})\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || continue
  [ "${BASH_REMATCH[1]}" = "$cur_major" ] || continue
  [ "$tag" != "$from_version" ] || continue
  ver_ge "${tag#v}" "${from_version#v}" || continue
  if [ -f "$BAD" ] && grep -qxF "$tag" "$BAD"; then continue; fi
  target=$tag
  break
done < <(git tag -l 'v*.*.*' --sort=-v:refname)
[ -n "$target" ] || record ok up_to_date
to_version=$target
log "candidate: $from_version -> $target"

vr_rc=0
vr_out=$(bash scripts/verify-release.sh --auto "$target") || vr_rc=$?
printf '%s\n' "$vr_out"
case $vr_rc in
  0) ;;
  3) record refused not_signed ;;
  4) record refused too_young ;;
  5) record refused commit_mismatch ;;
  6) record refused signature_invalid ;;
  *) record refused manifest_invalid ;;
esac

bash scripts/verify-images.sh "$target" || record refused images_unverified

head_before=$(git rev-parse HEAD)
up_rc=0
bash scripts/update.sh --yes --auto "$target" || up_rc=$?
if [ "$up_rc" -eq 0 ]; then record updated ""; fi

log "the update failed (exit $up_rc)"
mark_completed() {
  local tmp
  tmp=$(mktemp "$STATE_DIR/.state.XXXXXX")
  sed 's/"completed": false,/"completed": true,/' "$STATE" > "$tmp"
  chmod 600 "$tmp"
  mv -f "$tmp" "$STATE"
}
if [ "$(git rev-parse HEAD)" = "$head_before" ]; then
  # The code never changed (backup, verification or checkout failed): nothing to put back.
  if [ -f "$STATE" ] && grep -q '"completed": false' "$STATE"; then mark_completed; fi
  record failed update_failed
fi

log "rolling back to $from_version"
if bash scripts/rollback.sh --yes; then
  printf '%s\n' "$target" >> "$BAD"
  record failed update_failed_rolled_back
fi
printf '%s\n' "$target" >> "$BAD"
record failed rollback_failed
