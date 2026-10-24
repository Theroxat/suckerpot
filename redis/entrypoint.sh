#!/bin/sh
# Generates the Redis ACL file from environment variables, then execs the server.
# The file goes to a tmpfs (/run/redis), mode 0600, and stores SHA-256 hashes
# instead of clear-text passwords. Secrets are never put on a command line or logged.
set -eu
umask 077

ACL_FILE=/run/redis/users.acl

ALLOW_DEFAULT=${SUCKERPOT_ALLOW_DEFAULT_SECRETS:-0}

check() {
  name=$1
  eval "value=\${$name:-}"
  if [ -z "$value" ]; then
    echo "FATAL: $name is empty or unset" >&2
    exit 1
  fi
  if [ "$ALLOW_DEFAULT" != "1" ] && [ "${#value}" -lt 24 ]; then
    echo "FATAL: $name must be at least 24 characters (generate one with: openssl rand -base64 32)" >&2
    exit 1
  fi
}

distinct() {
  # Compares two secrets without printing them.
  if [ "$ALLOW_DEFAULT" != "1" ] && [ "$(eval "echo \"\$$1\"")" = "$(eval "echo \"\$$2\"")" ]; then
    echo "FATAL: $1 and $2 must be different" >&2
    exit 1
  fi
}

hash() {
  printf '%s' "$1" | sha256sum | cut -d' ' -f1
}

for v in REDIS_PASSWORD REDIS_SENSOR_PASSWORD REDIS_INGEST_PASSWORD REDIS_HEALTH_PASSWORD; do
  check "$v"
done
distinct REDIS_PASSWORD REDIS_SENSOR_PASSWORD
distinct REDIS_PASSWORD REDIS_INGEST_PASSWORD
distinct REDIS_PASSWORD REDIS_HEALTH_PASSWORD
distinct REDIS_SENSOR_PASSWORD REDIS_INGEST_PASSWORD
distinct REDIS_SENSOR_PASSWORD REDIS_HEALTH_PASSWORD
distinct REDIS_INGEST_PASSWORD REDIS_HEALTH_PASSWORD

admin_h=$(hash "$REDIS_PASSWORD")
sensor_h=$(hash "$REDIS_SENSOR_PASSWORD")
ingest_h=$(hash "$REDIS_INGEST_PASSWORD")
health_h=$(hash "$REDIS_HEALTH_PASSWORD")

cat > "$ACL_FILE" <<ACL
user default off
user admin on #${admin_h} ~* &* +@all
user sensor on #${sensor_h} resetkeys ~events -@all +xadd +hello +auth
user ingest on #${ingest_h} resetkeys ~events -@all +xreadgroup +xack +xgroup|create +xautoclaim +xtrim +hello +auth
user health on #${health_h} resetkeys -@all +ping +hello +auth
ACL
chmod 0600 "$ACL_FILE"

# Do not leak secrets to the server process environment beyond what it needs.
unset REDIS_PASSWORD REDIS_SENSOR_PASSWORD REDIS_INGEST_PASSWORD REDIS_HEALTH_PASSWORD admin_h sensor_h ingest_h health_h

exec "$@"
