#!/bin/sh
# Validates the VPN / anonymous-egress settings when the "egress" compose profile is on
# (COMPOSE_PROFILES=egress, from the environment or .env). Prints variable NAMES only, never values.
#   - the WireGuard variables and the endpoint IP/port are all set;
#   - VPN_WG_ENDPOINT, when set, equals VPN_WG_ENDPOINT_IP:VPN_WG_ENDPOINT_PORT;
#   - the endpoint IP is not private, loopback or link-local;
#   - EGRESS_PROXY_PASSWORD and the collector/analyzer database passwords are at least 24
#     characters, and those two differ from each other and from the other database passwords.
set -eu

cd "$(dirname "$0")/.."

get() {
  eval "val=\${$1:-}"
  if [ -z "$val" ] && [ -f .env ]; then
    val=$(sed -n "s/^$1=//p" .env | tail -n 1 | tr -d "\"' \r")
  fi
  printf '%s' "${val:-$2}"
}

fail=0
err() { echo "check-vpn-env: $*" >&2; fail=1; }

case ",$(get COMPOSE_PROFILES ''), " in
  *,egress,* | *", egress,"*) ;;
  *) exit 0 ;;
esac

for name in VPN_WG_PRIVATE_KEY VPN_WG_ADDRESSES VPN_WG_PEER_PUBLIC_KEY VPN_WG_ENDPOINT_IP VPN_WG_ENDPOINT_PORT; do
  [ -n "$(get "$name" '')" ] || err "$name is not set (required by the egress profile)"
done

ip=$(get VPN_WG_ENDPOINT_IP '')
port=$(get VPN_WG_ENDPOINT_PORT '')
if [ -n "$port" ]; then
  case $port in
    *[!0-9]*) err "VPN_WG_ENDPOINT_PORT is not a port number" ;;
    *) { [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; } || err "VPN_WG_ENDPOINT_PORT is out of range" ;;
  esac
fi
if [ -n "$ip" ]; then
  case $ip in
    *[!0-9.]*) err "VPN_WG_ENDPOINT_IP must be an IPv4 address (not a host name)" ;;
    10.* | 127.* | 169.254.* | 192.168.* | 0.* | 172.1[6-9].* | 172.2[0-9].* | 172.3[01].* | 100.6[4-9].* | 100.[7-9][0-9].* | 100.1[01][0-9].* | 100.12[0-7].*)
      err "VPN_WG_ENDPOINT_IP is a private, loopback or link-local address" ;;
    192.0.2.* | 198.51.100.* | 203.0.113.*) err "VPN_WG_ENDPOINT_IP is a documentation address (placeholder not replaced)" ;;
  esac
fi
combined=$(get VPN_WG_ENDPOINT '')
if [ -n "$combined" ] && [ -n "$ip" ] && [ -n "$port" ] && [ "$combined" != "$ip:$port" ]; then
  err "VPN_WG_ENDPOINT differs from VPN_WG_ENDPOINT_IP:VPN_WG_ENDPOINT_PORT"
fi

check_len() {
  v=$(get "$1" '')
  if [ -z "$v" ]; then err "$1 is not set (required by the egress profile)"; return; fi
  [ "${#v}" -ge 24 ] || err "$1 must be at least 24 characters"
}
for name in EGRESS_PROXY_PASSWORD POSTGRES_COLLECTOR_PASSWORD POSTGRES_ANALYZER_PASSWORD; do
  check_len "$name"
done
c=$(get POSTGRES_COLLECTOR_PASSWORD '')
a=$(get POSTGRES_ANALYZER_PASSWORD '')
if [ -n "$c" ] && [ "$c" = "$a" ]; then
  err "POSTGRES_COLLECTOR_PASSWORD and POSTGRES_ANALYZER_PASSWORD must differ"
fi
for other in POSTGRES_PASSWORD POSTGRES_INGEST_PASSWORD POSTGRES_API_PASSWORD; do
  o=$(get "$other" '')
  if [ -n "$o" ] && { [ "$o" = "$c" ] || [ "$o" = "$a" ]; }; then
    err "the collector and analyzer database passwords must differ from $other"
  fi
done

exit "$fail"
