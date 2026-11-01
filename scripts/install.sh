#!/usr/bin/env bash
# Selfhostr installer. Run it from a checkout of a release tag:
#
#   git clone --depth 1 --branch vX.Y.Z <repository-url> suckerpot && cd suckerpot
#   ./scripts/install.sh
#
# It checks the machine, asks a few questions, generates every secret on this host, writes .env
# (mode 0600), creates the data volumes and starts the stack. See docs/design/m28.md section 2.
#
# It never overwrites an existing .env, never adopts existing data volumes, never edits the
# host's sshd configuration and never looks up this machine's public address (that request would
# leave from the home address). Host traffic (git, image pulls) is outside the anonymous egress
# of the stack and uses this host's own address.
#
#   scripts/install.sh [--yes] [--source | --images] [--version vX.Y.Z]
#                      [--project NAME] [--prefix NAME]
#                      [--sensors recommended|all|ssh,telnet,...]
#                      [--dashboard-bind 127.0.0.1] [--dashboard-port 8443]
#                      [--public-host HOST]  (dashboard behind an HTTPS tunnel: sets the host
#                                             and origin allow-lists and COOKIE_SECURE=true)
#                      [--admin-user admin] [--admin-password-stdin]
#                      [--admin-ssh-port N] [--lowmem auto|on|off] [--wg-conf PATH]
#                      [--dry-run --env-out PATH]
#
# --yes takes the defaults; it reads the admin password from stdin with --admin-password-stdin
# or generates one and prints it once. --dry-run --env-out writes the would-be .env to PATH with
# a placeholder admin hash and makes no Docker call (used by the tests).
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/env.sh
. scripts/lib/env.sh

TOTAL=10
LOG=install.log

die() {
  echo "install: $*" >&2
  log "FAILED: $*"
  exit 1
}
log() { [ "$dry_run" = 1 ] || printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$LOG"; }
step() {
  printf '[%s/%s] %s\n' "$1" "$TOTAL" "$2"
  log "step $1: $2"
}
note() { echo "      $*"; }
warn() { echo "      warning: $*" >&2; }

# ---------------------------------------------------------------- arguments
assume_yes=0
mode=""
version=""
project=""
prefix=""
sensors_arg=""
bind=""
dport=""
public_host=""
admin_user=""
pw_stdin=0
admin_ssh_port=""
lowmem=""
wg_conf=""
dry_run=0
env_out=""

need_value() { [ $# -ge 2 ] && [ -n "$2" ] || die "$1 needs a value"; }
while [ $# -gt 0 ]; do
  case $1 in
    --yes | -y) assume_yes=1 ;;
    --source) mode=source ;;
    --images) mode=images ;;
    --version) need_value "$@"; version=$2; shift ;;
    --project) need_value "$@"; project=$2; shift ;;
    --prefix) need_value "$@"; prefix=$2; shift ;;
    --sensors) need_value "$@"; sensors_arg=$2; shift ;;
    --dashboard-bind) need_value "$@"; bind=$2; shift ;;
    --dashboard-port) need_value "$@"; dport=$2; shift ;;
    --public-host) need_value "$@"; public_host=$2; shift ;;
    --admin-user) need_value "$@"; admin_user=$2; shift ;;
    --admin-password-stdin) pw_stdin=1 ;;
    --admin-ssh-port) need_value "$@"; admin_ssh_port=$2; shift ;;
    --lowmem) need_value "$@"; lowmem=$2; shift ;;
    --wg-conf) need_value "$@"; wg_conf=$2; shift ;;
    --dry-run) dry_run=1 ;;
    --env-out) need_value "$@"; env_out=$2; shift ;;
    -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
  shift
done

if [ "$dry_run" = 1 ] && [ -z "$env_out" ]; then die "--dry-run needs --env-out PATH"; fi
if [ "$dry_run" = 0 ] && [ -n "$env_out" ]; then die "--env-out is only for --dry-run"; fi
case ${lowmem:-auto} in auto | on | off) ;; *) die "--lowmem must be auto, on or off" ;; esac
lowmem=${lowmem:-auto}

# Interactive answers come from the terminal (or SELFHOSTR_TTY, used by the tests), so that
# stdin stays free for --admin-password-stdin.
if [ "$assume_yes" = 0 ]; then
  tty=${SELFHOSTR_TTY:-/dev/tty}
  [ -r "$tty" ] || die "no terminal to ask questions on; use --yes"
  exec 3< "$tty"
fi

# ask VAR "question" "default": sets VAR to the answer (the default with --yes or on Enter).
ask() {
  local __var=$1 __q=$2 __d=$3 __ans=""
  if [ "$assume_yes" = 1 ]; then
    printf -v "$__var" %s "$__d"
    return 0
  fi
  printf '  %s [%s]: ' "$__q" "$__d" >&2
  IFS= read -r __ans <&3 || __ans=""
  printf -v "$__var" %s "${__ans:-$__d}"
}

# ---------------------------------------------------------------- 1. preflight
step 1 "Checking this machine"

[ "${BASH_VERSINFO[0]}" -ge 4 ] || die "Bash 4 or newer is required"
[ "$(uname -s)" = Linux ] || die "Linux is required"
case $(uname -m) in x86_64 | aarch64) ;; *) die "unsupported CPU architecture $(uname -m) (x86_64 or aarch64)" ;; esac
if in_linked_worktree; then
  die "this is a linked git worktree, a scratch checkout. Install from a normal clone."
fi

target=${env_out:-.env}
if [ -e .env ]; then
  die "Selfhostr is already installed here (.env exists). Use \`just update\`."
fi
if [ "$dry_run" = 1 ] && [ -e "$env_out" ]; then
  die "$env_out already exists; the dry run does not overwrite files"
fi
[ -f .env.example ] || die ".env.example not found: run this from a Selfhostr checkout"

project=${project:-suckerpot}
prefix=${prefix:-$project}
[ -n "$project" ] && [ -n "$prefix" ] || die "project and prefix must not be empty"
valid_project_name "$project" || die "bad project name '$project': use lowercase letters, digits, - and _ (at most 41 characters), and not sp-it-*, sp-test or sp-ci"
valid_project_name "$prefix" || die "bad volume prefix '$prefix': use lowercase letters, digits, - and _ (at most 41 characters), and not sp-it-*, sp-test or sp-ci"

if [ "$dry_run" = 1 ]; then
  note "dry run: Docker, memory, disk and volume checks skipped"
else
  command -v docker > /dev/null 2>&1 || die "Docker is not installed"
  engine=$(docker version --format '{{.Server.Version}}' 2> /dev/null) \
    || die "Docker does not answer for this user. Try: sudo usermod -aG docker \$USER, then log in again."
  ver_ge "${engine%%[-+]*}" 24.0 || die "Docker Engine 24 or newer is required (found $engine)"
  cver=$(docker compose version --short 2> /dev/null) || die "Docker Compose v2 is not available"
  ver_ge "${cver#v}" 2.24 || die "Docker Compose 2.24 or newer is required (found $cver)"

  meminfo=${SELFHOSTR_MEMINFO:-/proc/meminfo}
  mem_kb=$(awk '/^MemTotal:/ {print $2}' "$meminfo" 2> /dev/null || true)
  [[ ${mem_kb:-} =~ ^[0-9]+$ ]] || die "cannot read the memory size from $meminfo"
  if [ "$mem_kb" -lt $((2 * 1024 * 1024 - 65536)) ]; then
    die "less than 2 GiB of memory: Selfhostr needs at least 2 GiB (with --lowmem on)"
  fi

  root=$(docker info --format '{{.DockerRootDir}}' 2> /dev/null || true)
  free_kb=${SELFHOSTR_FREE_DISK_KB:-$(df -Pk "${root:-/}" 2> /dev/null | awk 'NR==2 {print $4}')}
  [[ ${free_kb:-} =~ ^[0-9]+$ ]] || die "cannot read the free disk space"
  if [ "$free_kb" -lt $((15 * 1024 * 1024)) ]; then
    die "less than 15 GiB free under Docker's data folder"
  elif [ "$free_kb" -lt $((30 * 1024 * 1024)) ]; then
    warn "less than 30 GiB free under Docker's data folder; logs and payloads need room"
  fi

  if docker volume inspect "${prefix}_db-data" > /dev/null 2>&1; then
    die "Data volumes for the prefix '$prefix' already exist. Restore your old .env, or pick another --prefix. (They are never adopted: the database password lives inside the data.)"
  fi
fi

# ---------------------------------------------------------------- 2. questions
step 2 "Settings"

if [ -z "$mode" ]; then
  ask a "Install mode: images (download) or source (build here)" images
  case $a in images | source) mode=$a ;; *) die "install mode must be images or source" ;; esac
fi

if [ -z "$sensors_arg" ]; then
  ask sensors_arg "Sensors: recommended, all, or a list like ssh,web" recommended
fi
chosen=()
case $sensors_arg in
  recommended) chosen=("${RECOMMENDED_SENSORS[@]}") ;;
  all) chosen=("${SENSORS[@]}") ;;
  *)
    IFS=, read -r -a chosen <<< "$sensors_arg"
    [ "${#chosen[@]}" -gt 0 ] || die "no sensor chosen"
    for s in "${chosen[@]}"; do
      is_sensor "$s" || die "unknown sensor '$s' (known: ${SENSORS[*]})"
    done
    ;;
esac
sensor_on() {
  local s
  for s in "${chosen[@]}"; do [ "$s" = "$1" ] && return 0; done
  return 1
}

if [ -z "$bind" ] && [ -z "$public_host" ]; then
  ask a "Dashboard reached [l]ocally or through an SSH tunnel, or through an [h]ttps tunnel such as cloudflared" l
  case $a in
    l | local) ;;
    h | https)
      ask public_host "Public host name of the dashboard (for example dash.example.org)" ""
      [ -n "$public_host" ] || die "a host name is required for an https tunnel"
      ;;
    *) die "answer l or h" ;;
  esac
fi
bind=${bind:-127.0.0.1}
dport=${dport:-8443}
[[ $bind =~ ^[0-9.]{7,15}$ ]] || die "--dashboard-bind must be an IPv4 address"
[[ $dport =~ ^[0-9]{1,5}$ ]] && [ "$dport" -ge 1 ] && [ "$dport" -le 65535 ] || die "--dashboard-port must be a port number"
if [ -n "$public_host" ]; then
  [[ $public_host =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]] || die "bad --public-host"
fi

if [ -z "$admin_user" ]; then ask admin_user "Admin user name" admin; fi
[[ $admin_user =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "the admin user name may only contain letters, digits, . _ -"

pw=""
pw_generated=0
if [ "$pw_stdin" = 1 ]; then
  IFS= read -r pw || true
elif [ "$assume_yes" = 1 ]; then
  pw=$(gen_secret 24)
  pw_generated=1
else
  printf '  Admin password (at least 12 characters, empty = generate one): ' >&2
  IFS= read -rs pw <&3 || pw=""
  echo >&2
  if [ -z "$pw" ]; then
    pw=$(gen_secret 24)
    pw_generated=1
  else
    printf '  Repeat the password: ' >&2
    IFS= read -rs pw2 <&3 || pw2=""
    echo >&2
    [ "$pw" = "$pw2" ] || die "the two passwords differ"
    unset pw2
  fi
fi
[ "${#pw}" -ge 12 ] || die "the admin password must have at least 12 characters"

if [ "$lowmem" = auto ]; then
  if [ "$dry_run" = 1 ]; then
    lowmem=off
  elif [ "$mem_kb" -lt $((6 * 1024 * 1024)) ]; then
    ask a "This machine has less than 6 GiB of memory. Use the low-memory mode? (yes/no)" yes
    case $a in y | yes) lowmem=on ;; *) lowmem=off ;; esac
  else
    lowmem=off
  fi
fi
if [ "$lowmem" = on ] && [ ! -f docker-compose.lowmem.yml ]; then
  die "this checkout has no docker-compose.lowmem.yml, so --lowmem on is not possible"
fi

if [ -z "$wg_conf" ]; then ask wg_conf "Path to a WireGuard .conf from your VPN provider (empty = upload it later in the dashboard)" ""; fi
wg_private="" wg_peer="" wg_addr="" wg_dns="" wg_ep_ip="" wg_ep_port=""
if [ -n "$wg_conf" ]; then
  [ -f "$wg_conf" ] || die "WireGuard file not found: $wg_conf"
  # Plain key = value parser: nothing in the file is ever executed.
  section=""
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%%#*}
    line=${line//$'\r'/}
    case $line in
      *"["*"]"*) section=$(printf %s "$line" | tr -d '[] \t' | tr '[:upper:]' '[:lower:]'); continue ;;
    esac
    [[ $line == *=* ]] || continue
    k=$(printf %s "${line%%=*}" | tr -d ' \t' | tr '[:upper:]' '[:lower:]')
    v=$(printf %s "${line#*=}" | sed -e 's/^[ \t]*//' -e 's/[ \t]*$//')
    case $section:$k in
      interface:privatekey) wg_private=$v ;;
      interface:address) wg_addr=$(printf %s "$v" | tr -d ' ') ;;
      interface:dns) wg_dns=$(printf %s "$v" | tr -d ' ') ;;
      peer:publickey) wg_peer=$v ;;
      peer:endpoint)
        wg_ep_port=${v##*:}
        wg_ep_ip=${v%:*}
        ;;
    esac
  done < "$wg_conf"
  [ -n "$wg_private" ] && [ -n "$wg_peer" ] && [ -n "$wg_addr" ] && [ -n "$wg_ep_ip" ] && [ -n "$wg_ep_port" ] \
    || die "the WireGuard file lacks PrivateKey, Address, PublicKey or Endpoint. Upload it in the dashboard instead."
  [[ $wg_ep_ip =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] \
    || die "the WireGuard Endpoint must be an IPv4 address, not a host name. Upload the file in the dashboard instead."
  [[ $wg_ep_port =~ ^[0-9]{1,5}$ ]] || die "bad WireGuard Endpoint port"
  for v in "$wg_private" "$wg_peer" "$wg_addr" "$wg_dns"; do
    [[ $v =~ ^[A-Za-z0-9+/=_.,:-]*$ ]] || die "the WireGuard file has unexpected characters. Upload it in the dashboard instead."
  done
fi

self_addr=""
ask self_addr "Your own public address, if you know it (the dashboard learns it from traffic otherwise; this script never looks it up)" ""
[[ -z $self_addr || $self_addr =~ ^[0-9A-Fa-f.:,]+$ ]] || die "the public address has unexpected characters"

# ---------------------------------------------------------------- 3. ports
step 3 "Checking ports"
declare -A port_override=()
declare -A sensor_off=()

busy_ports=""
if [ "$dry_run" = 1 ]; then
  note "dry run: port check skipped"
elif command -v ss > /dev/null 2>&1; then
  busy_ports=$(ss -Hltnu 2> /dev/null | awk '{n = split($5, a, ":"); print a[n]}' | sort -un | tr '\n' ' ' || true)
else
  warn "'ss' is not available; the port check is skipped"
fi
is_busy() { [[ " $busy_ports " == *" $1 "* ]]; }

ssh_moved=0
for s in "${chosen[@]}"; do
  while IFS=: read -r var def _; do
    port=$def
    if is_busy "$port"; then
      if [ "$s" = ssh ] && [ "$port" = 22 ]; then
        note "Port 22 is used on this machine (its own sshd, most likely)."
        ask a "SSH sensor: [m]ap it to host port 2222 and forward router port 22 to it, leave it [o]ff, or [k]eep 22 (you moved the admin SSH yourself)" m
        case $a in
          m | map) port_override[$var]=2222; ssh_moved=1 ;;
          o | off) sensor_off[$s]=1 ;;
          k | keep) die "port 22 is still in use. Move your admin SSH first (this script never edits sshd_config), then run the installer again." ;;
          *) die "answer m, o or k" ;;
        esac
        [ "$assume_yes" = 1 ] && [ -z "${sensor_off[$s]:-}" ] && note "Mapped the SSH sensor to host port 2222."
      elif [ "$assume_yes" = 1 ]; then
        warn "port $port ($var) is in use: the $s sensor is left off. Free the port and run: just sensors ..."
        sensor_off[$s]=1
      else
        ask a "Port $port ($var) is in use. Another host port, or 'off' to skip the $s sensor" off
        if [ "$a" = off ]; then
          sensor_off[$s]=1
        elif [[ $a =~ ^[0-9]{1,5}$ ]] && [ "$a" -ge 1 ] && [ "$a" -le 65535 ] && ! is_busy "$a"; then
          port_override[$var]=$a
        else
          die "'$a' is not a free port"
        fi
      fi
    fi
  done < <(sensor_ports "$s")
done
if [ "$dry_run" = 0 ] && is_busy "$dport"; then
  die "the dashboard port $dport is in use on this machine; pass --dashboard-port with a free port"
fi
if [ -z "$admin_ssh_port" ]; then
  if [ "$ssh_moved" = 1 ] || { [ "$dry_run" = 0 ] && is_busy 22; }; then admin_ssh_port=22; fi
  if [ "$assume_yes" = 0 ]; then
    ask admin_ssh_port "Port of this machine's own admin SSH (so no sensor can take it; empty = none)" "$admin_ssh_port"
  fi
fi
[[ -z $admin_ssh_port || $admin_ssh_port =~ ^[0-9]{1,5}$ ]] || die "bad admin SSH port"

# ---------------------------------------------------------------- 4. secrets
step 4 "Generating secrets"
declare -A secret=()
declare -A seen=()
for name in "${SECRET_VARS[@]}"; do
  while :; do
    value=$(gen_for "$name")
    [ -z "${seen[$value]:-}" ] && break
  done
  seen[$value]=1
  secret[$name]=$value
done
unset seen
note "${#SECRET_VARS[@]} secrets generated (written to .env only)"

# ---------------------------------------------------------------- 5. admin hash
step 5 "Hashing the admin password"
version=${version:-}
if [ "$mode" = images ] && [ -z "$version" ]; then
  version=$(git describe --tags --exact-match HEAD 2> /dev/null || true)
fi
if [ "$mode" = images ]; then
  if [ -z "$version" ]; then
    [ "$dry_run" = 1 ] && version=dev || die "images mode needs --version vX.Y.Z (or install from a release tag, or use --source)"
  fi
  [[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ || ( $dry_run = 1 && $version = dev ) ]] || die "--version must look like v1.2.3"
fi
image_prefix=${SUCKERPOT_IMAGE_PREFIX:-ghcr.io/theroxat/suckerpot}
if [ "$dry_run" = 1 ]; then
  hash='$argon2id$v=19$m=65536,t=3,p=4$cGxhY2Vob2xkZXI$cGxhY2Vob2xkZXItaGFzaC1ub3QtcmVhbA'
  note "dry run: placeholder hash"
else
  if [ "$mode" = images ]; then
    api_image="${image_prefix}-api:${version}"
    docker pull "$api_image" > /dev/null || die "could not pull $api_image"
  else
    api_image=suckerpot-install-api
    docker build -q -f api/Dockerfile -t "$api_image" . > /dev/null || die "could not build the api image"
  fi
  hash=$(printf '%s\n' "$pw" | docker run --rm -i --network none --cap-drop ALL \
    --security-opt no-new-privileges:true "$api_image" python -m api.hashpw --stdin) \
    || die "could not hash the admin password"
  hash=${hash//$'\r'/}
fi
case $hash in '$argon2'*) ;; *) die "the password hasher returned something unexpected" ;; esac
if [ "$pw_stdin" = 1 ] || [ "$pw_generated" = 0 ]; then pw=""; fi

# ---------------------------------------------------------------- 6. .env
step 6 "Writing $target"
umask 077
tmp="${target}.tmp"
rm -f "$tmp"
cp .env.example "$tmp"
chmod 600 "$tmp"

setv() { env_set_line "$tmp" "$1" "$2"; }

setv COMPOSE_PROJECT_NAME "$project"
setv SUCKERPOT_VOLUME_PREFIX "$prefix"
for name in "${SECRET_VARS[@]}"; do setv "$name" "${secret[$name]}"; done
unset secret
setv ADMIN_USERNAME "$admin_user"
setv ADMIN_PASSWORD_HASH "'$hash'"
unset hash
setv DASHBOARD_BIND "$bind"
setv DASHBOARD_PORT "$dport"
if [ -n "$public_host" ]; then
  setv API_ALLOWED_HOSTS "$public_host"
  setv API_ALLOWED_ORIGINS "https://$public_host"
  setv COOKIE_SECURE true
else
  setv COOKIE_SECURE false
fi
[ -n "$admin_ssh_port" ] && setv ADMIN_SSH_PORT "$admin_ssh_port"
[ -n "$self_addr" ] && setv INDICATORS_IGNORE "$self_addr"
setv COMPOSE_PROFILES egress
if [ -n "$wg_conf" ]; then
  setv VPN_WG_PRIVATE_KEY "$wg_private"
  setv VPN_WG_PEER_PUBLIC_KEY "$wg_peer"
  setv VPN_WG_ADDRESSES "$wg_addr"
  [ -n "$wg_dns" ] && setv VPN_WG_DNS "$wg_dns"
  setv VPN_WG_ENDPOINT_IP "$wg_ep_ip"
  setv VPN_WG_ENDPOINT_PORT "$wg_ep_port"
  wg_private="" wg_peer=""
fi

printf '\n# Added by the Selfhostr installer\n' >> "$tmp"
setv SUCKERPOT_INSTALL_MODE "$mode"
[ "$mode" = images ] && setv SUCKERPOT_VERSION "$version"
for s in "${SENSORS[@]}"; do
  if sensor_on "$s" && [ -z "${sensor_off[$s]:-}" ]; then v=1; else v=0; fi
  setv "$(sensor_var "$s")" "$v"
done
for var in "${!port_override[@]}"; do setv "$var" "${port_override[$var]}"; done
if [ "$lowmem" = on ]; then setv COMPOSE_FILE docker-compose.yml:docker-compose.lowmem.yml; fi

# Final checks on the file before it goes live.
if grep -v '^[[:space:]]*#' "$tmp" | grep -q 'change-me'; then
  rm -f "$tmp"
  die "a placeholder (change-me) is still in the generated file"
fi
ENV_FILE=$tmp
export ENV_FILE
for name in "${SECRET_VARS[@]}"; do
  v=$(env_get "$name")
  if [ "${#v}" -lt 24 ]; then
    rm -f "$tmp"
    die "$name is missing or shorter than 24 characters in the generated file"
  fi
done
unset ENV_FILE
mv "$tmp" "$target"
chmod 600 "$target"
note "wrote $target (mode 0600)"

if [ "$dry_run" = 1 ]; then
  echo
  echo "Dry run finished: $target holds the would-be configuration. No Docker call was made."
  exit 0
fi

# ---------------------------------------------------------------- 7. volumes
step 7 "Creating the data volumes"
SUCKERPOT_VOLUME_PREFIX=$prefix bash scripts/ensure-volumes.sh

# ---------------------------------------------------------------- 8. guards
step 8 "Checking the port layout and VPN settings"
scripts/check-ports.sh
if [ -n "$wg_conf" ]; then
  scripts/check-vpn-env.sh
else
  note "no WireGuard file given: upload it in the dashboard (Settings > VPN); the gate stays closed until then"
fi

# ---------------------------------------------------------------- 9. start
step 9 "Starting Selfhostr (this can take several minutes)"
if [ "$mode" = images ]; then
  docker compose pull || die "could not pull the images. Check the version and your network, then run: docker compose pull"
  docker compose up -d --wait --wait-timeout 600 || die "the stack did not become healthy. See: docker compose ps, docker compose logs"
else
  SUCKERPOT_BUILD_VERSION=$(git describe --tags --always --dirty 2> /dev/null || echo dev)
  SUCKERPOT_BUILD_COMMIT=$(git rev-parse --short HEAD 2> /dev/null || echo unknown)
  export SUCKERPOT_BUILD_VERSION SUCKERPOT_BUILD_COMMIT
  docker compose up -d --build --wait --wait-timeout 900 || die "the stack did not become healthy. See: docker compose ps, docker compose logs"
fi
hbind=$bind
[ "$hbind" = 0.0.0.0 ] && hbind=127.0.0.1
ok=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS --max-time 5 "http://$hbind:$dport/healthz" > /dev/null 2>&1; then ok=1; break; fi
  sleep 3
done
[ "$ok" = 1 ] || die "the dashboard does not answer on http://$hbind:$dport/healthz. See: docker compose logs api"

# ---------------------------------------------------------------- 10. summary
step 10 "Done"
echo
echo "Selfhostr is running."
if [ -n "$public_host" ]; then
  echo "  Dashboard: https://$public_host  (through your tunnel to http://$hbind:$dport)"
else
  echo "  Dashboard: http://$hbind:$dport"
  if [ "$bind" = 127.0.0.1 ]; then
    echo "  On a remote machine, open a tunnel first:"
    echo "    ssh -L $dport:127.0.0.1:$dport <you>@<this-host>"
  fi
fi
echo "  Admin user: $admin_user"
if [ "$pw_generated" = 1 ]; then
  echo "  Admin password (shown once, store it in your password manager now): $pw"
fi
pw=""
echo
echo "Next steps:"
echo "  1. Sign in. The setup opens by itself."
echo "  2. Forward the ports listed on the Ports page of the dashboard on your router."
echo "     Never forward the dashboard port ($dport) or your admin SSH port."
echo "  3. Install the host firewall: docs/deployment.md#host-firewall"
echo "  4. Take a snapshot of the machine."
