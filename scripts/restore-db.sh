#!/usr/bin/env bash
# Restores a dump made by scripts/backup-db.sh into the running db container.
# THIS REPLACES THE WHOLE DATABASE.
#
#   scripts/restore-db.sh [--yes] FILE
#
# Steps: stop ingest and api, recreate the database, restore the dump with the
# TimescaleDB pre/post-restore hooks, run migrations (which re-apply the role
# grants), then start ingest and api again. Sensors keep running; their events wait
# in Redis and are ingested afterwards.
set -euo pipefail

cd "$(dirname "$0")/.."
yes=0
if [ "${1:-}" = "--yes" ]; then yes=1; shift; fi
file=${1:-}
if [ -z "$file" ] || [ ! -f "$file" ]; then
  echo "usage: $0 [--yes] DUMP_FILE" >&2
  exit 2
fi

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

echo "restore: stopping ingest and api"
docker compose stop ingest api

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
  < "$file"
psqlx "$db" -c "SELECT timescaledb_post_restore()" > /dev/null

echo "restore: running migrations"
docker compose run --rm migrate
echo "restore: starting ingest and api"
docker compose up -d --wait ingest api
echo "restore: done"
