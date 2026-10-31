#!/bin/bash
# Live check of the anonymous egress (M21). Run it on the machine with the stack up and
# COMPOSE_PROFILES=egress. Prints PASS or FAIL per line, exits non-zero on any FAIL.
# It never prints the VPN exit address.
#
#   scripts/egress-check.sh           everything, including the kill-switch tests
#                                     (briefly takes the tunnel down, then stops/starts vpn)
#   scripts/egress-check.sh --quick   read-only checks only
set -uo pipefail
cd "$(dirname "$0")/.."

quick=0
[ "${1:-}" = "--quick" ] && quick=1

fails=0
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails + 1)); }
# check "label" cmd...   (PASS when the command succeeds)
check() { local label=$1; shift; if "$@" >/dev/null 2>&1; then pass "$label"; else fail "$label"; fi; }
# check_not "label" cmd... (PASS when the command fails)
check_not() { local label=$1; shift; if "$@" >/dev/null 2>&1; then fail "$label"; else pass "$label"; fi; }

dc() { docker compose "$@"; }
selftest() { local svc=$1; shift; dc exec -T "$svc" python -m suckerpot_egress.selftest "$@"; }

case ",${COMPOSE_PROFILES:-}," in
  *,egress,*) ;;
  *) if ! grep -qs '^COMPOSE_PROFILES=.*egress' .env; then
       echo "egress-check: COMPOSE_PROFILES does not include egress" >&2; exit 2; fi ;;
esac

for svc in vpn ingest collector analyzer; do
  state=$(dc ps --format '{{.State}}' "$svc" 2>/dev/null | head -n 1)
  [ "$state" = "running" ] && pass "$svc is running" || fail "$svc is running (state: ${state:-none})"
done

# Addresses learned from Docker, used only as probe targets and never printed.
vpn_cid=$(dc ps -q vpn 2>/dev/null | head -n 1)
gateway=""
vpn_ip=""
if [ -n "$vpn_cid" ]; then
  gateway=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{if eq $k "sp-vpn"}}{{$v.Gateway}}{{end}}{{end}}' "$vpn_cid")
  vpn_ip=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{if ne $k "sp-vpn"}}{{$v.IPAddress}}{{end}}{{end}}' "$vpn_cid")
fi
proxy_gw=""
if [ -n "$vpn_cid" ]; then
  proxy_gw=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{if ne $k "sp-vpn"}}{{$v.Gateway}}{{end}}{{end}}' "$vpn_cid")
fi
if [ -z "$proxy_gw" ] && [ -n "$vpn_cid" ]; then
  pass "egress-proxy bridge has no gateway address (isolated): the host is not reachable through it"
fi
dash_port=${DASHBOARD_PORT:-$(sed -n 's/^DASHBOARD_PORT=//p' .env 2>/dev/null | tail -n 1)}
dash_port=${dash_port:-8443}

# Direct connections, external DNS and name resolution must fail; then the gate must be open.
for svc in ingest collector; do
  check "$svc: no direct route, no external DNS" selftest "$svc" --direct
  check "$svc: egress gate open, exit address in the allow-list" selftest "$svc" --gate
  [ -n "$gateway" ] && check "$svc: proxy refuses the sp-vpn gateway on the dashboard port" \
    selftest "$svc" --refuse "$gateway:$dash_port"
  [ -n "$gateway" ] && check "$svc: proxy refuses the sp-vpn gateway (the host) on a sensor port" \
    selftest "$svc" --refuse "$gateway:22"
  if [ -n "$proxy_gw" ]; then
    check "$svc: proxy refuses the egress-proxy gateway (the host) on a sensor port" \
      selftest "$svc" --refuse "$proxy_gw:22"
  fi
  [ -n "$vpn_ip" ] && check "$svc: proxy refuses the vpn control port by private literal" \
    selftest "$svc" --refuse "$vpn_ip:8000"
  check "$svc: proxy refuses a name that resolves to loopback" \
    selftest "$svc" --refuse "localtest.me:80"
done

# The analyzer has no way out at all.
check "analyzer: no direct route, no proxy" selftest analyzer --direct --no-connect vpn:8888

if [ "$quick" -eq 0 ]; then
  echo "-- kill switch (the tunnel goes down for a short while)"
  dc exec -T vpn ip link set wg0 down >/dev/null 2>&1
  sleep 1
  check "tunnel down: nothing leaves through the proxy" selftest ingest --echo-fails
  check_not "tunnel down: the gate closes" selftest ingest --gate
  restored=0
  for _ in $(seq 1 15); do
    if selftest ingest --gate >/dev/null 2>&1; then restored=1; break; fi
    sleep 4
  done
  [ "$restored" -eq 1 ] && pass "tunnel restored: gate open again" || fail "tunnel restored: gate open again"

  echo "-- vpn container stopped"
  dc stop vpn >/dev/null 2>&1
  check "vpn stopped: gate reports no_vpn" selftest ingest --gate --expect no_vpn
  state=$(dc ps --format '{{.Health}}' ingest 2>/dev/null | head -n 1)
  [ "$state" = "healthy" ] && pass "vpn stopped: ingest stays healthy" || fail "vpn stopped: ingest stays healthy (${state:-unknown})"
  dc start vpn >/dev/null 2>&1
  for _ in $(seq 1 15); do
    [ "$(dc ps --format '{{.Health}}' vpn 2>/dev/null | head -n 1)" = "healthy" ] && break
    sleep 4
  done
  [ "$(dc ps --format '{{.Health}}' vpn 2>/dev/null | head -n 1)" = "healthy" ] && pass "vpn started again and healthy" || fail "vpn started again and healthy"
fi

if [ "$fails" -gt 0 ]; then
  echo "egress-check: $fails check(s) failed" >&2
  exit 1
fi
echo "egress-check: all checks passed"
