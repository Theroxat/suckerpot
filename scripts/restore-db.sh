#!/usr/bin/env bash
# Restores a dump made by scripts/backup-db.sh into the running db container.
# THIS REPLACES THE WHOLE DATABASE.
#
#   scripts/restore-db.sh [--yes] FILE|latest|volume:NAME
#
# FILE is a dump on the host (made by scripts/backup-db.sh). "latest" and "volume:NAME" read
# a dump of the daily `backup` service from the external suckerpot_backups volume.
#
# Steps: check the dump with pg_restore -l, stop ingest, api and backup, recreate the database, restore the dump with the
# TimescaleDB pre/post-restore hooks, run migrations (which re-apply the role
# grants), then start ingest, api and backup again. Sensors keep running; their events wait
# in Redis and are ingested afterwards.
set -euo pipefail

cd "$(dirname "$0")/.."
yes=0
if [ "${1:-}" = "--yes" ]; then yes=1; shift; fi
file=${1:-}
image=$(awk '/^  db:/ {indb=1} indb && /image: / {print $2; exit}' docker-compose.yml)
# Runs a command on the backups volume (read-only, no network).
in_backups() {
  docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges:true \
    --user 70:70 -v "${SUCKERPOT_VOLUME_PREFIX:?SUCKERPOT_VOLUME_PREFIX must be set}_backups:/b:ro" --entrypoint "$1" "$image" "${@:2}"
}
from_volume=""
case $file in
  latest)
    from_volume=$(in_backups sh -c 'ls -1t /b/suckerpot-*.dump 2>/dev/null | head -n 1' || true)
    from_volume=${from_volume##*/}
    [ -n "$from_volume" ] || { echo "restore: no dump in the backups volume" >&2; exit 2; }
    file="volume:$from_volume"
    ;;
  volume:*)
    from_volume=${file#volume:}
    case $from_volume in *[!A-Za-z0-9._-]* | .* | "") echo "restore: bad dump name" >&2; exit 2 ;; esac
    in_backups test -s "/b/$from_volume" || { echo "restore: $from_volume not found in the backups volume" >&2; exit 2; }
    ;;
  *)
    if [ -z "$file" ] || [ ! -f "$file" ]; then
      echo "usage: $0 [--yes] DUMP_FILE|latest|volume:NAME" >&2
      exit 2
    fi
    ;;
esac
# Streams the chosen dump to stdout.
read_dump() {
  if [ -n "$from_volume" ]; then in_backups cat "/b/$from_volume"; else cat "$file"; fi
}

if [ "$yes" -ne 1 ]; then
  echo "WARNING: this DELETES the current SuckerPot database and replaces it with:"
  echo "  $file"
  printf 'Type "restore" to continue: '
  read -r answer
  [ "$answer" = "restore" ] || { echo "aborted"; exit 1; }
fi

# Runs psql in the db container as the owner role, against the given database.
psqlx() {
  local database=$1
  shift
  docker compose exec -T db sh -c \
    'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -v ON_ERROR_STOP=1 -q -h 127.0.0.1 -U "$POSTGRES_USER" -d "$0" "$@"' "$database" "$@"
}

echo "restore: checking that the dump is readable"
if ! read_dump | docker compose exec -T db pg_restore -l > /dev/null; then
  echo "restore: the dump is not readable (pg_restore -l failed), nothing was changed" >&2
  exit 1
fi

echo "restore: stopping ingest, api and backup"
docker compose stop ingest api backup

echo "restore: recreating the database"
db=$(docker compose exec -T db sh -c 'printf %s "$POSTGRES_DB"')
psqlx postgres -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$db' AND pid <> pg_backend_pid()" > /dev/null
psqlx postgres -c "DROP DATABASE IF EXISTS \"$db\"" -c "CREATE DATABASE \"$db\""
psqlx "$db" -c "CREATE EXTENSION IF NOT EXISTS timescaledb"

echo "restore: loading the dump"
psqlx "$db" -c "SELECT timescaledb_pre_restore()" > /dev/null
# Owners and ACLs are not restored: the roles are re-created by the migration below.
docker compose exec -T db sh -c \
  'PGPASSWORD="$POSTGRES_PASSWORD" exec pg_restore -h 127.0.0.1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" --no-owner --no-acl --exit-on-error' \
  < <(read_dump)
psqlx "$db" -c "SELECT timescaledb_post_restore()" > /dev/null

echo "restore: running migrations"
docker compose run --rm migrate
echo "restore: starting ingest, api and backup"
docker compose up -d --wait ingest api backup
echo "restore: done"
