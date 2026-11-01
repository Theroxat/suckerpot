#!/bin/sh
# Entry point of the `backup` compose service (runs inside the timescaledb image, as uid 70).
#
#   backup-service.sh          loop: dump when the newest dump is older than 24 h, check hourly
#   backup-service.sh now      dump once, right now, then exit (used by `just backup`)
#
# Dumps are custom-format pg_dump files (TimescaleDB data included) in /backups, mode 0600.
# The newest BACKUP_KEEP dumps are kept. The owner credentials come from the environment and
# are never printed. A failed dump is logged and retried the next hour; the healthcheck
# (a dump younger than 26 h) turns unhealthy when it keeps failing.
set -eu

DIR=/backups
KEEP=${BACKUP_KEEP:-7}
case $KEEP in '' | *[!0-9]* | 0) echo "backup: BACKUP_KEEP must be a positive number" >&2; exit 2 ;; esac
umask 077

newest() { ls -1t "$DIR"/suckerpot-*.dump 2>/dev/null | head -n 1 || true; }

dump() {
  name="suckerpot-$(date -u +%Y%m%dT%H%M%SZ).dump"
  tmp="$DIR/.$name.partial"
  last=$(newest)
  need=$((256 * 1024 * 1024))
  if [ -n "$last" ]; then need=$(($(stat -c %s "$last") * 2)); fi
  free=$(($(df -Pk "$DIR" | awk 'NR==2 {print $4}') * 1024))
  if [ "$free" -lt "$need" ]; then
    echo "backup: not enough free space in $DIR (free $free bytes, need $need)" >&2
    return 1
  fi
  if ! PGPASSWORD="$POSTGRES_PASSWORD" pg_dump -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" \
    -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc > "$tmp"; then
    rm -f "$tmp"
    echo "backup: pg_dump failed" >&2
    return 1
  fi
  if [ ! -s "$tmp" ]; then
    rm -f "$tmp"
    echo "backup: the dump is empty" >&2
    return 1
  fi
  mv "$tmp" "$DIR/$name"
  echo "backup: wrote $name ($(stat -c %s "$DIR/$name") bytes)"
  ls -1t "$DIR"/suckerpot-*.dump | tail -n +"$((KEEP + 1))" | while read -r old; do
    rm -f -- "$old"
    echo "backup: removed old dump ${old##*/}"
  done
}

rm -f "$DIR"/.suckerpot-*.partial

if [ "${1:-}" = "now" ]; then
  dump
  exit $?
fi

while true; do
  if [ -z "$(find "$DIR" -maxdepth 1 -name 'suckerpot-*.dump' -mmin -1440 2>/dev/null | head -n 1)" ]; then
    dump || true
  fi
  sleep 3600
done
