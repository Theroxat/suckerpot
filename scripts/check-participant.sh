#!/bin/sh
# Validates the settings of a participant install (SUCKERPOT_STACK_MODE=participant, M32), from the
# environment or .env. Does nothing for a full install. Prints variable NAMES only, never values.
#   - the participant overlay is in COMPOSE_FILE, and the dashboard profile is not in COMPOSE_PROFILES
#     (the api, and with it the dashboard port, must not start);
#   - exactly one way out: profile "direct" with EGRESS_MODE=direct (hubproxy), or profile "egress"
#     with EGRESS_MODE=vpn (never both: hubproxy and vpn must not coexist);
#   - direct: HUBPROXY_ALLOW is a short list of host:443 pairs with public DNS names (no address
#     literal, no wildcard), and the egress URLs point at hubproxy;
#   - vpn: the egress URLs point at vpn and HUBPROXY_ALLOW is empty;
#   - a verifier needs the VPN and the collector;
#   - EGRESS_PROXY_PASSWORD has at least 24 characters.
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
err() { echo "check-participant: $*" >&2; fail=1; }

[ "$(get SUCKERPOT_STACK_MODE full)" = participant ] || exit 0

case ":$(get COMPOSE_FILE ''):" in
  *:docker-compose.participant.yml:*) ;;
  *) err "COMPOSE_FILE must include docker-compose.participant.yml (the dashboard would start without it)" ;;
esac

profiles=$(get COMPOSE_PROFILES '')
case $profiles in
  direct | egress) ;;
  *) err "COMPOSE_PROFILES must be exactly 'direct' (no VPN) or 'egress' (with a VPN)" ;;
esac

mode=$(get EGRESS_MODE vpn)
case "$profiles:$mode" in
  direct:direct | egress:vpn) ;;
  *) err "EGRESS_MODE ($mode) does not match COMPOSE_PROFILES ($profiles): direct goes with direct, vpn with egress" ;;
esac

proxy=$(get EGRESS_PROXY_URL '')
control=$(get EGRESS_CONTROL_URL '')
allow=$(get HUBPROXY_ALLOW '')
if [ "$profiles" = direct ]; then
  case $proxy in http://hubproxy:8888) ;; *) err "EGRESS_PROXY_URL must be http://hubproxy:8888 in direct mode" ;; esac
  case $control in http://hubproxy:8000) ;; *) err "EGRESS_CONTROL_URL must be http://hubproxy:8000 in direct mode" ;; esac
  if [ -z "$allow" ]; then
    err "HUBPROXY_ALLOW is empty (hubproxy refuses to start without an allow list)"
  else
    count=0
    old_ifs=$IFS
    IFS=,
    for entry in $allow; do
      count=$((count + 1))
      case $entry in
        *[!a-z0-9.:-]* | "" | .* | *..* | *-.* | *.-*) err "HUBPROXY_ALLOW has a malformed entry (lowercase DNS names with :443 only)" ;;
        *:443) ;;
        *) err "every HUBPROXY_ALLOW entry must end in :443" ;;
      esac
      host=${entry%:443}
      case $host in
        *[!0-9.]*) ;; # has a letter: a name
        *) err "HUBPROXY_ALLOW must hold names, not address literals" ;;
      esac
      case $host in
        *.*) ;;
        *) err "HUBPROXY_ALLOW entries must be public DNS names with a dot" ;;
      esac
      case $host in
        localhost | *.local | *.lan | *.internal | *.localhost | *.test | *.home.arpa)
          err "HUBPROXY_ALLOW has a local name"
          ;;
      esac
    done
    IFS=$old_ifs
    [ "$count" -le 3 ] || err "HUBPROXY_ALLOW has more than 3 entries"
  fi
else
  case $proxy in "" | http://vpn:8888) ;; *) err "EGRESS_PROXY_URL must be http://vpn:8888 with a VPN" ;; esac
  case $control in "" | http://vpn:8000) ;; *) err "EGRESS_CONTROL_URL must be http://vpn:8000 with a VPN" ;; esac
  [ -z "$allow" ] || err "HUBPROXY_ALLOW must be empty with a VPN (hubproxy does not run)"
fi

if [ "$(get NETWORK_VERIFIER false)" = true ]; then
  [ "$profiles" = egress ] || err "NETWORK_VERIFIER needs a VPN (COMPOSE_PROFILES=egress)"
  [ "$(get COLLECTOR_ENABLED false)" = true ] || err "NETWORK_VERIFIER needs COLLECTOR_ENABLED=true"
fi

pw=$(get EGRESS_PROXY_PASSWORD '')
[ "${#pw}" -ge 24 ] || err "EGRESS_PROXY_PASSWORD must be at least 24 characters"

exit "$fail"
