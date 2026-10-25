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
  if [ "$ALLOW_DEFAULT" != "1" ] && [ "$(eval "printf %s \"\$$1\"")" = "$(eval "printf %s \"\$$2\"")" ]; then
    echo "FATAL: $1 and $2 must be different" >&2
    exit 1
  fi
}

hash() {
  printf '%s' "$1" | sha256sum | cut -d' ' -f1
}

VARS="REDIS_PASSWORD REDIS_HEALTH_PASSWORD REDIS_INGEST_PASSWORD REDIS_SENSOR_SSH_PASSWORD REDIS_SENSOR_RDP_PASSWORD REDIS_SENSOR_TELNET_PASSWORD REDIS_SENSOR_WEB_PASSWORD REDIS_DEMO_PASSWORD"
for v in $VARS; do
  check "$v"
done
# Pairwise distinct (each pair is compared once).
for a in $VARS; do
  for b in $VARS; do
    if [ "$a" \< "$b" ]; then distinct "$a" "$b"; fi
  done
done

h() { hash "$(eval "printf %s \"\$$1\"")"; }

# One user per sensor: it may only append to its own stream. Telnet, web and RDP
# users are added together with their sensors.
cat > "$ACL_FILE" <<ACL
user default off
user admin on #$(h REDIS_PASSWORD) ~* &* +@all
user health on #$(h REDIS_HEALTH_PASSWORD) resetkeys -@all +ping +hello +auth
user sensor-ssh on #$(h REDIS_SENSOR_SSH_PASSWORD) resetkeys ~events:ssh -@all +xadd +hello +auth
user sensor-rdp on #$(h REDIS_SENSOR_RDP_PASSWORD) resetkeys ~events:rdp -@all +xadd +hello +auth
user sensor-telnet on #$(h REDIS_SENSOR_TELNET_PASSWORD) resetkeys ~events:telnet -@all +xadd +hello +auth
user sensor-web on #$(h REDIS_SENSOR_WEB_PASSWORD) resetkeys ~events:web -@all +xadd +hello +auth
user demo on #$(h REDIS_DEMO_PASSWORD) resetkeys ~events:* -@all +xadd +hello +auth
user ingest on #$(h REDIS_INGEST_PASSWORD) resetkeys ~events:* -@all +xreadgroup +xack +xgroup|create +xautoclaim +xtrim +hello +auth
ACL
chmod 0600 "$ACL_FILE"

# Do not leak secrets to the server process environment beyond what it needs.
unset $VARS

exec "$@"
