#!/usr/bin/env bash
# Creates the external data volumes of the live stack (see the `volumes:` section of
# docker-compose.yml) when they are missing. `docker volume create` is idempotent. Run by
# `just up` before `docker compose up`.
#
#   scripts/ensure-volumes.sh [--force-empty]
#
# Safety check: when the database volume is MISSING but the backups volume holds dumps, the
# script stops instead of letting Postgres initialise an empty database on top of what was
# probably lost by accident. Restore the newest dump (`just restore latest`, after starting
# only db) or accept an empty database on purpose with `--force-empty` or
# SUCKERPOT_ALLOW_EMPTY_DB=1.
#
# It only ever CREATES volumes. It never removes or modifies the data of an existing one.
set -euo pipefail

cd "$(dirname "$0")/.."
force=0
if [ "${1:-}" = "--force-empty" ] || [ "${SUCKERPOT_ALLOW_EMPTY_DB:-0}" = "1" ]; then force=1; fi

mapfile -t volumes < <(grep -oE '^    name: suckerpot_[a-z0-9-]+$' docker-compose.yml | awk '{print $2}')
if [ "${#volumes[@]}" -lt 10 ]; then
  echo "ensure-volumes: could not read the volume names from docker-compose.yml" >&2
  exit 1
fi
image=$(awk '/^  db:/ {indb=1} indb && /image: / {print $2; exit}' docker-compose.yml)
if [ -z "$image" ]; then
  echo "ensure-volumes: could not read the db image from docker-compose.yml" >&2
  exit 1
fi

exists() { docker volume inspect "$1" > /dev/null 2>&1; }

if ! exists suckerpot_db-data && exists suckerpot_backups; then
  dumps=$(docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges:true \
    --user 70:70 --entrypoint sh -v suckerpot_backups:/b:ro "$image" \
    -c 'ls -1 /b/suckerpot-*.dump 2>/dev/null | wc -l' || echo 0)
  if [ "${dumps:-0}" -gt 0 ] && [ "$force" -ne 1 ]; then
    cat >&2 << EOF
ensure-volumes: STOP. The database volume suckerpot_db-data does not exist, but the
backups volume suckerpot_backups holds $dumps dump(s). Starting now would create an EMPTY database.

  - To restore the newest dump: create the volumes and start only the database, then restore:
        scripts/ensure-volumes.sh --force-empty && docker compose up -d --wait db && just restore latest
  - To really start from scratch: just up --force-empty   (or SUCKERPOT_ALLOW_EMPTY_DB=1)
EOF
    exit 3
  fi
fi

for v in "${volumes[@]}"; do
  if exists "$v"; then continue; fi
  docker volume create "$v" > /dev/null
  echo "ensure-volumes: created $v"
  if [ "$v" = "suckerpot_backups" ]; then
    # The backup service runs as uid 70 (postgres); a new volume starts root-owned.
    docker run --rm --network none --cap-drop ALL --cap-add CHOWN --security-opt no-new-privileges:true \
      --user 0:0 --entrypoint chown -v "$v:/b" "$image" 70:70 /b
  fi
done
