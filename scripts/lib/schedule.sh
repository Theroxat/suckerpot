#!/usr/bin/env bash
# Schedule for the automatic updater (M32). Source this file; it defines functions only.
#
#   schedule_random_time          prints "HOUR MINUTE", a random time between 03:00 and 05:59
#   schedule_install HOUR MINUTE  installs the daily job (idempotent: replaces its own line)
#   schedule_remove               removes the job (idempotent, never touches other lines)
#   schedule_status               prints "cron HH:MM", "systemd HH:MM" or "off"; exit 0 when on
#
# The job runs scripts/auto-update.sh of this checkout, as the CURRENT user: first from the user's
# crontab, and when there is no usable crontab, from a systemd USER timer. It never uses sudo.
# The cron line ends with a marker comment (`# selfhostr-auto-update <project>`), so only the
# line of this project is ever replaced or removed. The project comes from COMPOSE_PROJECT_NAME in
# .env (or SCHEDULE_PROJECT). After schedule_install, SCHEDULE_METHOD is "cron" or "systemd".

# shellcheck disable=SC2015
SCHEDULE_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
SCHEDULE_WORD="selfhostr-auto-update"
# Set by schedule_install: "cron" or "systemd" (read by the caller).
export SCHEDULE_METHOD=""

if ! declare -F env_get > /dev/null 2>&1; then
  # shellcheck source=scripts/lib/env.sh
  . "$(dirname "${BASH_SOURCE[0]}")/env.sh"
fi

_schedule_err() { echo "schedule: $*" >&2; }

# Prints the project name, or fails.
_schedule_project() {
  local p=${SCHEDULE_PROJECT:-}
  [ -n "$p" ] || p=$(cd "$SCHEDULE_ROOT" && ENV_FILE="$SCHEDULE_ROOT/.env" env_get COMPOSE_PROJECT_NAME)
  [[ $p =~ ^[a-z0-9][a-z0-9_-]{0,40}$ ]] || { _schedule_err "no valid COMPOSE_PROJECT_NAME in .env"; return 1; }
  printf '%s' "$p"
}

_schedule_unit_dir() { printf '%s/systemd/user' "${XDG_CONFIG_HOME:-$HOME/.config}"; }

schedule_random_time() {
  printf '%s %s\n' "$((3 + RANDOM % 3))" "$((RANDOM % 60))"
}

# Prints the crontab without the lines of this project. Returns 1 when the crontab cannot be read.
_schedule_cron_without() {
  local project=$1 current rc=0
  command -v crontab > /dev/null 2>&1 || return 1
  current=$(crontab -l 2>&1) || rc=$?
  if [ "$rc" -ne 0 ]; then
    # "no crontab for user" is fine (empty); anything else means we must not overwrite it.
    printf '%s' "$current" | grep -qi 'no crontab' || return 1
    current=""
  fi
  [ -n "$current" ] || return 0
  printf '%s\n' "$current" | grep -v -E "# $SCHEDULE_WORD $project\$" || true
}

_schedule_systemd_install() {
  local project=$1 hour=$2 minute=$3 dir name linger
  command -v systemctl > /dev/null 2>&1 && systemctl --user show-environment > /dev/null 2>&1 \
    || { _schedule_err "neither a usable crontab nor a systemd user session was found"; return 1; }
  dir=$(_schedule_unit_dir)
  name="$SCHEDULE_WORD-$project"
  mkdir -p "$dir"
  cat > "$dir/$name.service" << EOF
[Unit]
Description=Selfhostr automatic update ($project)

[Service]
Type=oneshot
WorkingDirectory=$SCHEDULE_ROOT
ExecStart=/usr/bin/env bash scripts/auto-update.sh
EOF
  cat > "$dir/$name.timer" << EOF
[Unit]
Description=Selfhostr automatic update, daily ($project)

[Timer]
OnCalendar=*-*-* $(printf '%02d:%02d' "$((10#$hour))" "$((10#$minute))"):00
Persistent=false

[Install]
WantedBy=timers.target
EOF
  systemctl --user daemon-reload && systemctl --user enable --now "$name.timer" > /dev/null 2>&1 \
    || { _schedule_err "could not enable the systemd user timer"; return 1; }
  linger=$(loginctl show-user "$(id -un)" -p Linger --value 2> /dev/null || true)
  if [ "$linger" != yes ]; then
    _schedule_err "warning: lingering is off, so the timer runs only while you are logged in (loginctl enable-linger, needs admin rights)"
  fi
  SCHEDULE_METHOD=systemd
}

schedule_install() {
  local hour=${1:-} minute=${2:-} project line others rc=0
  [[ $hour =~ ^[0-9]{1,2}$ ]] && [ "$((10#$hour))" -le 23 ] || { _schedule_err "hour must be 0 to 23"; return 1; }
  [[ $minute =~ ^[0-9]{1,2}$ ]] && [ "$((10#$minute))" -le 59 ] || { _schedule_err "minute must be 0 to 59"; return 1; }
  [[ $SCHEDULE_ROOT =~ ^[A-Za-z0-9._/@+-]+$ ]] \
    || { _schedule_err "the install path has characters that cannot be quoted safely for cron"; return 1; }
  project=$(_schedule_project) || return 1
  line="$((10#$minute)) $((10#$hour)) * * * cd $SCHEDULE_ROOT && bash scripts/auto-update.sh > /dev/null 2>&1 # $SCHEDULE_WORD $project"
  if others=$(_schedule_cron_without "$project"); then
    { [ -z "$others" ] || printf '%s\n' "$others"; printf '%s\n' "$line"; } | crontab - && rc=0 || rc=$?
    if [ "$rc" -eq 0 ]; then SCHEDULE_METHOD=cron; return 0; fi
  fi
  _schedule_systemd_install "$project" "$hour" "$minute"
}

schedule_remove() {
  local project others dir name had=0
  project=$(_schedule_project) || return 1
  if command -v crontab > /dev/null 2>&1 && crontab -l 2> /dev/null | grep -qE "# $SCHEDULE_WORD $project\$"; then
    if others=$(_schedule_cron_without "$project"); then
      if [ -n "$others" ]; then printf '%s\n' "$others" | crontab -; else crontab -r; fi
    else
      _schedule_err "could not rewrite the crontab; remove the '$SCHEDULE_WORD $project' line by hand"
      return 1
    fi
  fi
  dir=$(_schedule_unit_dir)
  name="$SCHEDULE_WORD-$project"
  [ -e "$dir/$name.timer" ] && had=1
  if [ "$had" = 1 ]; then
    command -v systemctl > /dev/null 2>&1 && systemctl --user disable --now "$name.timer" > /dev/null 2>&1 || true
    rm -f "$dir/$name.timer" "$dir/$name.service"
    command -v systemctl > /dev/null 2>&1 && systemctl --user daemon-reload > /dev/null 2>&1 || true
  fi
  return 0
}

schedule_status() {
  local project line dir name when
  project=$(_schedule_project) || { echo off; return 1; }
  if command -v crontab > /dev/null 2>&1; then
    line=$(crontab -l 2> /dev/null | grep -E "# $SCHEDULE_WORD $project\$" | head -n 1 || true)
    if [ -n "$line" ]; then
      printf 'cron %02d:%02d\n' "$((10#$(printf '%s' "$line" | awk '{print $2}')))" "$((10#$(printf '%s' "$line" | awk '{print $1}')))"
      return 0
    fi
  fi
  dir=$(_schedule_unit_dir)
  name="$SCHEDULE_WORD-$project"
  if [ -f "$dir/$name.timer" ]; then
    when=$(sed -n 's/^OnCalendar=\*-\*-\* \([0-9][0-9]:[0-9][0-9]\):00$/\1/p' "$dir/$name.timer" | head -n 1)
    echo "systemd ${when:-??:??}"
    return 0
  fi
  echo off
  return 1
}
