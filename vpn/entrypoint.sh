#!/bin/sh
# Entrypoint of the vpn (gluetun) container. POSIX sh, runs on the busybox of the gluetun image.
#
# 1. Picks the WireGuard settings: the file uploaded from Settings -> VPN
#    ($VPN_CONFIG_DIR/wg.env) wins over the VPN_WG_* values of .env. The file is NEVER sourced or
#    evaluated: each value is read with a fixed pattern, and any mismatch stops the container
#    (fail closed, so no traffic can leave outside the tunnel).
# 2. Drops IPv6 interface addresses (the Docker networks have no IPv6 and gluetun refuses them).
# 3. Runs gluetun as a child and watches wg.env: when it changes, gluetun is stopped and this
#    script exits 0, so "restart: unless-stopped" restarts the container on the new settings.
#    It also watches $VPN_CONFIG_DIR/restart (written by the API for "Reconnect"): only its
#    checksum is used, its content is never read or parsed and never affects the settings.
#
# Log lines never contain a value from the file.

CONF_DIR=${VPN_CONFIG_DIR:-/vpn-config}
GLUETUN=${VPN_GLUETUN_BIN:-/gluetun-entrypoint}
INTERVAL=${VPN_WATCH_INTERVAL:-10}
LIVE_ENV="$CONF_DIR/wg.env"
RESTART_FILE="$CONF_DIR/restart"
SNAPSHOT=${VPN_SNAPSHOT:-/tmp/wg.env.snapshot}
WG_ENV=$SNAPSHOT # parsed copy of LIVE_ENV

log() { printf 'vpn-entrypoint: %s\n' "$1" >&2; }

OCTET='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
IPV4="$OCTET\\.$OCTET\\.$OCTET\\.$OCTET"
ADDR_ITEM="($IPV4/[0-9]{1,2}|[0-9a-fA-F:]*:[0-9a-fA-F:]*/[0-9]{1,3})"

# checksum_of FILE: sha256 of the file, or "absent".
checksum_of() {
  if [ -f "$1" ]; then
    sha256sum "$1" 2>/dev/null | cut -d' ' -f1
  else
    echo absent
  fi
}

# value_of KEY PATTERN: prints the value of KEY if the file has exactly one KEY= line and the
# whole line matches KEY=PATTERN. Returns 1 otherwise.
value_of() {
  [ "$(grep -c "^$1=" "$WG_ENV")" = 1 ] || return 1
  grep -Eq "^$1=$2\$" "$WG_ENV" || return 1
  sed -n "s/^$1=//p" "$WG_ENV"
}

# is_global_v4 A.B.C.D: false for private, loopback, link-local, CGNAT, documentation,
# benchmarking, multicast and reserved ranges (defence in depth; the API checks it too).
is_global_v4() {
  oldifs=$IFS
  IFS=.
  set -- $1
  IFS=$oldifs
  a=$1 b=$2 c=$3
  case $a in
    0 | 10 | 127) return 1 ;;
  esac
  [ "$a" -ge 224 ] && return 1
  [ "$a" = 100 ] && [ "$b" -ge 64 ] && [ "$b" -le 127 ] && return 1
  [ "$a" = 169 ] && [ "$b" = 254 ] && return 1
  [ "$a" = 172 ] && [ "$b" -ge 16 ] && [ "$b" -le 31 ] && return 1
  [ "$a" = 192 ] && [ "$b" = 0 ] && { [ "$c" = 0 ] || [ "$c" = 2 ]; } && return 1
  [ "$a" = 192 ] && [ "$b" = 168 ] && return 1
  [ "$a" = 198 ] && { [ "$b" = 18 ] || [ "$b" = 19 ]; } && return 1
  [ "$a" = 198 ] && [ "$b" = 51 ] && [ "$c" = 100 ] && return 1
  [ "$a" = 203 ] && [ "$b" = 0 ] && [ "$c" = 113 ] && return 1
  return 0
}

load_uploaded() {
  # Any line that is not one of the five expected keys makes the file invalid.
  if grep -Evq '^(WIREGUARD_PRIVATE_KEY|WIREGUARD_PUBLIC_KEY|WIREGUARD_ADDRESSES|WIREGUARD_ENDPOINT_IP|WIREGUARD_ENDPOINT_PORT)=' "$WG_ENV"; then
    log "invalid wg.env: unexpected line; refusing to start"
    exit 1
  fi
  for key in WIREGUARD_PRIVATE_KEY WIREGUARD_PUBLIC_KEY WIREGUARD_ADDRESSES WIREGUARD_ENDPOINT_IP WIREGUARD_ENDPOINT_PORT; do
    case $key in
      WIREGUARD_PRIVATE_KEY | WIREGUARD_PUBLIC_KEY) pattern='[A-Za-z0-9+/]{43}=' ;;
      WIREGUARD_ADDRESSES) pattern="$ADDR_ITEM(,$ADDR_ITEM)*" ;;
      WIREGUARD_ENDPOINT_IP) pattern="$IPV4" ;;
      *) pattern='[0-9]{1,5}' ;;
    esac
    if ! value=$(value_of "$key" "$pattern") || [ -z "$value" ]; then
      log "invalid wg.env: $key is missing, duplicated or malformed; refusing to start"
      exit 1
    fi
    if [ "$key" = WIREGUARD_ENDPOINT_IP ] && ! is_global_v4 "$value"; then
      log "invalid wg.env: $key is not a global address; refusing to start"
      exit 1
    fi
    if [ "$key" = WIREGUARD_ENDPOINT_PORT ] && { [ "$value" -lt 1 ] || [ "$value" -gt 65535 ]; }; then
      log "invalid wg.env: $key is out of range; refusing to start"
      exit 1
    fi
    export "$key=$value"
  done
  log "using the VPN configuration uploaded from the dashboard"
}

initial=absent
if [ -e "$LIVE_ENV" ]; then
  if [ ! -f "$LIVE_ENV" ] || [ ! -r "$LIVE_ENV" ]; then
    log "wg.env is not a readable file; refusing to start"
    exit 1
  fi
  # One copy on tmpfs: it is parsed AND checksummed, so a rewrite of the live file in between
  # cannot make the running settings differ from the checksum the watcher compares with.
  trap 'rm -f "$SNAPSHOT"' EXIT
  (umask 077 && cp "$LIVE_ENV" "$SNAPSHOT") 2>/dev/null || { log "cannot snapshot wg.env; refusing to start"; exit 1; }
  initial=$(checksum_of "$SNAPSHOT")
  load_uploaded
  rm -f "$SNAPSHOT"
else
  log "no uploaded VPN configuration; using the .env values"
fi

restart_initial=$(checksum_of "$RESTART_FILE")

# Keep IPv4 entries only.
WIREGUARD_ADDRESSES=$(printf '%s' "$WIREGUARD_ADDRESSES" | tr ',' '\n' | grep -v ':' | paste -sd, -)
export WIREGUARD_ADDRESSES

"$GLUETUN" &
child=$!

# Forward termination to gluetun, wait for it, then leave.
on_signal() {
  kill -TERM "$child" 2>/dev/null
  wait "$child" 2>/dev/null
  exit 0
}
trap on_signal TERM INT

tick=0
while :; do
  sleep 1 &
  wait $!
  if ! kill -0 "$child" 2>/dev/null; then
    wait "$child"
    exit $?
  fi
  tick=$((tick + 1))
  if [ "$tick" -ge "$INTERVAL" ]; then
    tick=0
    if [ "$(checksum_of "$LIVE_ENV")" != "$initial" ]; then
      log "VPN configuration changed, restarting"
      kill -TERM "$child" 2>/dev/null
      wait "$child" 2>/dev/null
      exit 0
    fi
    if [ "$(checksum_of "$RESTART_FILE")" != "$restart_initial" ]; then
      log "VPN reconnect requested, restarting"
      kill -TERM "$child" 2>/dev/null
      wait "$child" 2>/dev/null
      exit 0
    fi
  fi
done
