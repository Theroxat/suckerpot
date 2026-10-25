#!/bin/sh
# Refuses a port layout that would expose the wrong thing:
#   - the dashboard port is one of the classic service ports (22, 23, 80, 443, 3389);
#   - two of DASHBOARD_PORT / *_HOST_PORT are the same;
#   - one of them equals the optional ADMIN_SSH_PORT (the host's own admin SSH port).
# Values come from the environment, then from .env, then from the compose defaults.
set -eu

cd "$(dirname "$0")/.."

# Reads VAR from the environment or from .env (last assignment wins; quotes removed).
get() {
  eval "val=\${$1:-}"
  if [ -z "$val" ] && [ -f .env ]; then
    val=$(sed -n "s/^$1=//p" .env | tail -n 1 | tr -d "\"' \r")
  fi
  printf '%s' "${val:-$2}"
}

fail=0
err() { echo "check-ports: $*" >&2; fail=1; }

list=""
for spec in DASHBOARD_PORT:8443 SSH_HOST_PORT:22 TELNET_HOST_PORT:23 HTTP_HOST_PORT:80 HTTPS_HOST_PORT:443 RDP_HOST_PORT:3389; do
  name=${spec%%:*}
  port=$(get "$name" "${spec#*:}")
  case $port in
    '' | *[!0-9]*) err "$name='$port' is not a port number"; continue ;;
  esac
  if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    err "$name=$port is out of range"
    continue
  fi
  eval "p_$name=$port"
  list="$list $name"
done

admin=$(get ADMIN_SSH_PORT "")

for a in $list; do
  eval "pa=\$p_$a"
  [ -n "$admin" ] && [ "$pa" = "$admin" ] && err "$a=$pa is the host's admin SSH port (ADMIN_SSH_PORT)"
  for b in $list; do
    eval "pb=\$p_$b"
    if [ "$a" \< "$b" ] && [ "$pa" = "$pb" ]; then
      err "$a and $b both use port $pa"
    fi
  done
done

case ${p_DASHBOARD_PORT:-} in
  22 | 23 | 80 | 443 | 3389) err "DASHBOARD_PORT=$p_DASHBOARD_PORT is a service port; pick another one" ;;
esac

[ "$fail" -eq 0 ] && echo "check-ports: ok"
exit "$fail"
