#!/usr/bin/env bash
# Shows what runs, what was sent to the network and how updates are doing (also: just status).
#
#   scripts/status.sh [--json] [--last-batch]
#
# Reads `docker compose ps`, .env (no secret is read into the report), the state file of the
# automatic updater and `python -m ingest.network.cli status --json` of the ingest container. The
# report is rendered INSIDE the ingest container (scripts/lib/status_render.py, standard library
# only), so the host needs nothing but Docker and bash.
#
# --json prints the same data as JSON, for monitoring. --last-batch prints the exact JSON of the
# last submission to the network (attacker addresses only, kept 7 days) and nothing else.
# Exit code: 0 OK, 1 warning, 2 error (design: docs/design/m32.md section 10).
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/env.sh
. scripts/lib/env.sh

die() { echo "status: $*" >&2; exit 2; }

want_json=0
last_batch=0
while [ $# -gt 0 ]; do
  case $1 in
    --json) want_json=1 ;;
    --last-batch) last_batch=1 ;;
    -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1 (usage: status.sh [--json] [--last-batch])" ;;
  esac
  shift
done

[ -f .env ] || die "no .env here: Selfhostr is not installed in this folder (./scripts/install.sh)"
command -v docker > /dev/null 2>&1 || die "Docker is not installed"

# JSON string with the escapes the renderer needs (control characters other than \n and \t go).
json_str() {
  printf '%s' "$1" | awk '
    BEGIN { ORS = ""; printf "\"" }
    { gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); gsub(/\t/, "\\t"); gsub(/\r/, ""); if (NR > 1) printf "\\n"; print }
    END { printf "\"" }' | tr -d '\000-\010\013\014\016-\037'
}

stack=$(env_get SUCKERPOT_STACK_MODE full)
install=$(env_get SUCKERPOT_INSTALL_MODE source)
version=$(env_get SUCKERPOT_VERSION)

ps_lines=$(docker compose ps --format '{{.Service}} {{.State}} {{.Health}}' 2> /dev/null || true)
ingest_up=0
ps_json=""
while read -r svc state health _; do
  [ -n "${svc:-}" ] || continue
  [[ $svc =~ ^[a-z0-9_-]+$ ]] || continue
  [ "$svc" = ingest ] && [ "${state:-}" = running ] && ingest_up=1
  ps_json+="${ps_json:+,}[$(json_str "$svc"),$(json_str "${state:-}"),$(json_str "${health:-}")]"
done <<< "$ps_lines"

if [ "$last_batch" = 1 ]; then
  [ "$ingest_up" = 1 ] || die "ingest is not running"
  docker compose exec -T ingest python -m ingest.network.cli status --last-batch
  exit $?
fi

if [ "$ingest_up" = 0 ]; then
  if [ "$want_json" = 1 ]; then
    printf '{"stack":%s,"version":%s,"errors":["ingest_down"],"exit":2}\n' "$(json_str "$stack")" "$(json_str "$version")"
  else
    echo "Selfhostr ${version:-source build}, $stack mode, $install                       ERROR"
    echo
    echo "Ingest is not running, so nothing can be reported. Start it: ./scripts/install.sh --repair"
    echo "Or look at: docker compose ps, docker compose logs ingest"
  fi
  exit 2
fi

cli_raw=""
cli_error=""
if cli_raw=$(docker compose exec -T ingest python -m ingest.network.cli status --json 2> /dev/null); then
  :
else
  cli_raw=""
  cli_error="the network status command failed"
fi

auto_state=""
[ -f .suckerpot-state/auto-update.json ] && auto_state=$(head -c 4096 .suckerpot-state/auto-update.json)
auto_schedule=off
if [ -f scripts/lib/schedule.sh ]; then
  # shellcheck source=scripts/lib/schedule.sh
  . scripts/lib/schedule.sh
  auto_schedule=$(schedule_status 2> /dev/null || true)
  auto_schedule=${auto_schedule:-off}
fi
if [ "$(env_get AUTO_UPDATE_ENABLED false)" = true ]; then auto_enabled=true; else auto_enabled=false; fi

ports_json=""
while read -r rp hp proto sname; do
  [ -n "${rp:-}" ] || continue
  ports_json+="${ports_json:+,}[$(json_str "$rp"),$(json_str "$hp"),$(json_str "$proto"),$(json_str "$sname")]"
done < <(ports_table)

doc=$(printf '{"stack":%s,"install":%s,"version":%s,"ps":[%s],"ports":[%s],"auto_enabled":%s,"auto_schedule":%s,"auto_state_raw":%s,"cli_raw":%s,"cli_error":%s}' \
  "$(json_str "$stack")" "$(json_str "$install")" "$(json_str "$version")" "$ps_json" "$ports_json" \
  "$auto_enabled" "$(json_str "$auto_schedule")" "$(json_str "$auto_state")" "$(json_str "$cli_raw")" "$(json_str "$cli_error")")

src=$(cat scripts/lib/status_render.py)
rc=0
if [ "$want_json" = 1 ]; then
  printf '%s' "$doc" | docker compose exec -T ingest python -I -c "$src" --json || rc=$?
else
  printf '%s' "$doc" | docker compose exec -T ingest python -I -c "$src" || rc=$?
fi
exit "$rc"
