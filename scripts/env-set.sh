#!/usr/bin/env bash
# Changes settings in .env, safely. Called by `just sensors` and `just set`, which then run
# `docker compose up -d --wait` so the change takes effect.
#
#   scripts/env-set.sh sensors                 print the current sensor selection
#   scripts/env-set.sh sensors LIST            LIST = recommended | all | ssh,telnet,web,...
#   scripts/env-set.sh set KEY=VALUE [...]     change allow-listed settings (see lib/env.sh)
#
# Refuses secret-looking keys (*_PASSWORD, *_SECRET, *_HASH, *_KEY except the public
# NETWORK_HUB_KEY, VPN_WG_*, and NETWORK_CONSENT, which only the installer and participant.sh join write) and keys outside
# the allow-list. Prints variable names only, never values of anything secret. The change is
# reverted when scripts/check-ports.sh refuses the resulting port layout.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/env.sh
. scripts/lib/env.sh

die() { echo "env-set: $*" >&2; exit 1; }

[ -f .env ] || die ".env not found. Run ./scripts/install.sh first."
# The values just loaded from the old .env must not win over the file we are about to change.
env_drop_loaded

# Keeps a private copy of .env while a change is applied, so it can be put back.
backup=""
cleanup() { [ -n "$backup" ] && rm -f "$backup"; return 0; }
trap cleanup EXIT

apply_checked() {
  # Runs the port check on the changed file; restores the old one on failure.
  if ! scripts/check-ports.sh --dotenv-only; then
    cp "$backup" .env
    chmod 600 .env
    die "the port check refused this change; .env was left as it was"
  fi
}

begin() {
  backup=$(mktemp)
  chmod 600 "$backup"
  cp .env "$backup"
}

# Succeeds for https://<public DNS name>[:port]: no IP literal, no single label, no local suffix.
hub_url_ok() {
  local url=$1 host
  [[ $url =~ ^https://[a-z0-9.-]+(:[0-9]{1,5})?$ ]] || return 1
  host=${url#https://}
  host=${host%%:*}
  [[ $host == *.* ]] || return 1
  [[ $host =~ ^[0-9.]+$ ]] && return 1
  case $host in
    localhost | .* | *..* | *. | *.local | *.lan | *.internal | *.home.arpa | *.localhost | *.test) return 1 ;;
  esac
  return 0
}

cmd=${1:-}
[ $# -gt 0 ] && shift

case $cmd in
  sensors)
    if [ $# -eq 0 ]; then
      echo "Sensors in .env:"
      for s in "${SENSORS[@]}"; do
        v=$(env_get "$(sensor_var "$s")" 1)
        if [ "$v" = 0 ]; then state=off; else state=on; fi
        printf '  %-9s %s\n' "$s" "$state"
      done
      exit 0
    fi
    [ $# -eq 1 ] || die "usage: sensors [recommended|all|name,name,...]"
    list=$1
    chosen=()
    case $list in
      recommended) chosen=("${RECOMMENDED_SENSORS[@]}") ;;
      all) chosen=("${SENSORS[@]}") ;;
      none | '') die "choose at least one sensor, or 'all'" ;;
      *)
        IFS=, read -r -a chosen <<< "$list"
        for s in "${chosen[@]}"; do
          is_sensor "$s" || die "unknown sensor '$s' (known: ${SENSORS[*]})"
        done
        ;;
    esac
    begin
    for s in "${SENSORS[@]}"; do
      on=0
      for c in "${chosen[@]}"; do [ "$c" = "$s" ] && on=1; done
      env_set_line .env "$(sensor_var "$s")" "$on"
    done
    apply_checked
    echo "env-set: sensors on: ${chosen[*]}"
    ;;
  set)
    [ $# -ge 1 ] || die "usage: set KEY=VALUE [KEY=VALUE ...]"
    # Validate everything first, so a bad pair changes nothing.
    keys=()
    values=()
    for pair in "$@"; do
      [[ $pair == *=* ]] || die "'$pair' is not KEY=VALUE"
      key=${pair%%=*}
      value=${pair#*=}
      settable_key "$key" || die "$key cannot be changed with 'just set' (secret-looking or not allow-listed)"
      settable_value "$value" || die "the value for $key has characters that are not allowed"
      case $key in
        SENSOR_*) [[ $value =~ ^[01]$ ]] || die "$key must be 0 or 1" ;;
        *_ENABLED | COOKIE_SECURE | NETWORK_VERIFY_REVEALS | NETWORK_VERIFIER) [[ $value =~ ^(true|false)$ ]] || die "$key must be true or false" ;;
        *_HOST_PORT | DASHBOARD_PORT)
          [[ $value =~ ^[0-9]{1,5}$ ]] && [ "$value" -ge 1 ] && [ "$value" -le 65535 ] || die "$key must be a port number"
          ;;
        NETWORK_HUB_URL) [ -z "$value" ] || hub_url_ok "$value" || die "NETWORK_HUB_URL must be https://<public DNS name>[:port] (no IP address, no local name)" ;;
        NETWORK_HUB_KEY) [ -z "$value" ] || [[ $value =~ ^[A-Za-z0-9_-]{43}$ ]] || die "NETWORK_HUB_KEY must be 43 base64url characters" ;;
      esac
      keys+=("$key")
      values+=("$value")
    done
    begin
    for i in "${!keys[@]}"; do
      env_set_line .env "${keys[$i]}" "${values[$i]}"
    done
    apply_checked
    echo "env-set: updated ${keys[*]}"
    for k in "${keys[@]}"; do
      if [ "$k" = AUTO_UPDATE_ENABLED ]; then
        echo "env-set: AUTO_UPDATE_ENABLED only sets the flag; ./scripts/participant.sh auto-update on|off also installs or removes the schedule"
      fi
    done
    ;;
  *)
    die "usage: env-set.sh sensors [LIST] | set KEY=VALUE [...]"
    ;;
esac
