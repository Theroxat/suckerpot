#!/usr/bin/env bash
# Renders the SuckerPot host firewall (nftables) with every value filled in. Pure: no root, no
# change to the system; it only reads the resolver configuration and writes the ruleset.
#
#   render-firewall.sh --participant --admin-ssh-port N [--out FILE]
#   render-firewall.sh --full --admin-ssh-port N [--dashboard-port N] [--vpn-endpoint IP:PORT]
#                      [--out FILE]
#
# Common options:
#   --dns IP           an upstream resolver for hubproxy's DNS (repeat it); replaces the ones read
#                      from the resolver configuration. Use it when /etc/docker/daemon.json sets
#                      "dns".
#   --resolv-conf F    read F instead of /etc/resolv.conf
#   --systemd-resolv-conf F
#                      the systemd-resolved upstream list (default /run/systemd/resolve/resolv.conf)
#   --vpn-endpoint IP:PORT
#                      participant with a VPN, or full mode with the egress profile: the one
#                      WireGuard endpoint sp-vpn may reach. Without it, sp-vpn may open nothing.
#
# The ruleset goes to stdout, or to --out FILE (mode 0600; the admin port is private). When nft is
# installed and allowed to (root), the result is syntax-checked with `nft -c -f`; otherwise the
# check is skipped with a note (install-firewall.sh always checks before loading).
#
# Exit codes: 0 rendered; 1 the rendered ruleset failed `nft -c`; 2 bad arguments.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

die() {
  echo "render-firewall: $*" >&2
  exit 2
}
note() { echo "render-firewall: $*" >&2; }

valid_port() {
  [[ $1 =~ ^[1-9][0-9]{0,4}$ ]] && ((10#$1 <= 65535))
}

valid_ipv4() {
  local IFS=. octet
  [[ $1 =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  # shellcheck disable=SC2086 # split on dots on purpose
  for octet in $1; do
    [[ $octet =~ ^(0|[1-9][0-9]*)$ ]] && ((octet <= 255)) || return 1
  done
}

mode=""
admin_port=""
dashboard_port=8443
vpn_endpoint=""
out=""
resolv_conf=/etc/resolv.conf
systemd_resolv_conf=/run/systemd/resolve/resolv.conf
dns=()

need_value() { { [ "$#" -ge 2 ] && [ -n "$2" ]; } || die "$1 needs a value"; }

while [ "$#" -gt 0 ]; do
  case $1 in
    --participant | --full)
      [ -z "$mode" ] || die "choose one of --participant and --full"
      mode=${1#--}
      shift
      ;;
    --admin-ssh-port | --dashboard-port | --vpn-endpoint | --out | --dns | --resolv-conf | --systemd-resolv-conf)
      need_value "$@"
      case $1 in
        --admin-ssh-port) admin_port=$2 ;;
        --dashboard-port) dashboard_port=$2 ;;
        --vpn-endpoint) vpn_endpoint=$2 ;;
        --out) out=$2 ;;
        --dns) dns+=("$2") ;;
        --resolv-conf) resolv_conf=$2 ;;
        --systemd-resolv-conf) systemd_resolv_conf=$2 ;;
      esac
      shift 2
      ;;
    -h | --help)
      sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d; s/^# \{0,1\}//'
      exit 0
      ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

[ -n "$mode" ] || die "choose --participant or --full"
[ -n "$admin_port" ] || die "--admin-ssh-port is required (the port of this host's admin SSH daemon)"
valid_port "$admin_port" || die "--admin-ssh-port must be a whole number from 1 to 65535"
valid_port "$dashboard_port" || die "--dashboard-port must be a whole number from 1 to 65535"
[ "$mode" = full ] || [ "$dashboard_port" = 8443 ] || die "--dashboard-port is only for --full"
[ "$admin_port" != "$dashboard_port" ] || [ "$mode" = participant ] ||
  die "the admin SSH port and the dashboard port must differ"

vpn_ip=127.0.0.1
vpn_port=51820
if [ -n "$vpn_endpoint" ]; then
  vpn_ip=${vpn_endpoint%:*}
  vpn_port=${vpn_endpoint##*:}
  [ "$vpn_ip" != "$vpn_endpoint" ] || die "--vpn-endpoint must be IP:PORT"
  valid_ipv4 "$vpn_ip" || die "--vpn-endpoint: '$vpn_ip' is not an IPv4 address"
  valid_port "$vpn_port" || die "--vpn-endpoint: '$vpn_port' is not a port"
fi

# Nameservers of a resolv.conf file, in order.
nameservers() {
  [ -r "$1" ] || return 0
  awk '$1 == "nameserver" && NF >= 2 { print $2 }' "$1"
}

# The upstream resolvers Docker's embedded resolver forwards to from the container namespace,
# which is what crosses sp-hubgate: Docker reads /etc/resolv.conf, or the systemd-resolved
# upstream list when /etc/resolv.conf only names the stub 127.0.0.53. Loopback upstreams are
# queried from the host namespace (never through the bridge), and the bridge has no IPv6.
resolvers=()
if [ "${#dns[@]}" -gt 0 ]; then
  for ip in "${dns[@]}"; do
    valid_ipv4 "$ip" || die "--dns: '$ip' is not an IPv4 address"
    resolvers+=("$ip")
  done
else
  mapfile -t found < <(nameservers "$resolv_conf")
  if [ "${found[*]:-}" = 127.0.0.53 ] && [ -r "$systemd_resolv_conf" ]; then
    mapfile -t found < <(nameservers "$systemd_resolv_conf")
  fi
  for ip in "${found[@]}"; do
    ip=${ip%%%*}
    valid_ipv4 "$ip" || continue # IPv6: no IPv6 on sp-hubgate
    case $ip in 127.* | 0.*) continue ;; esac
    resolvers+=("$ip")
  done
  if grep -qs '"dns"' /etc/docker/daemon.json 2> /dev/null; then
    note "/etc/docker/daemon.json sets \"dns\": pass those servers with --dns"
  fi
fi
# Unique, order kept.
declare -A seen=()
uniq=()
for ip in "${resolvers[@]}"; do
  [ -n "${seen[$ip]:-}" ] || uniq+=("$ip")
  seen[$ip]=1
done
if [ "${#uniq[@]}" -eq 0 ]; then
  hubgate_dns="{ 127.0.0.1 }"
  [ "$mode" = full ] ||
    note "no non-loopback IPv4 resolver found: hubproxy's DNS goes through the host namespace, sp-hubgate gets no DNS rule"
else
  joined=$(
    IFS=,
    echo "${uniq[*]}"
  )
  hubgate_dns="{ ${joined//,/, } }"
fi

if [ "$mode" = participant ]; then
  template=$here/firewall-participant.nft
else
  template=$here/firewall.nft
fi
[ -r "$template" ] || die "template not found: $template"

rendered=$(
  awk -v admin="$admin_port" -v dash="$dashboard_port" -v vip="$vpn_ip" -v vport="$vpn_port" \
    -v dnsset="$hubgate_dns" -v vpn="$vpn_endpoint" '
    /^define ADMIN_SSH_PORT = /    { print "define ADMIN_SSH_PORT = " admin; next }
    /^define DASHBOARD_PORT = /    { print "define DASHBOARD_PORT = " dash; next }
    /^define VPN_ENDPOINT_IP = /   { print "define VPN_ENDPOINT_IP = " vip; next }
    /^define VPN_ENDPOINT_PORT = / { print "define VPN_ENDPOINT_PORT = " vport; next }
    /^define HUBGATE_DNS = /       { print "define HUBGATE_DNS = " dnsset; next }
    /^ *# @VPN_ACCEPT@$/ {
      if (vpn != "") {
        sub(/# @VPN_ACCEPT@/, "iifname \"sp-vpn\" ct state new ip daddr " vip " udp dport " vport " counter accept")
      } else {
        sub(/# @VPN_ACCEPT@/, "# (no --vpn-endpoint: sp-vpn may open nothing)")
      }
      print; next
    }
    { print }
  ' "$template"
)
header="# Rendered by scripts/host/render-firewall.sh --$mode on $(date -u +%Y-%m-%dT%H:%M:%SZ)."
rendered="$header"$'\n'"$rendered"

if grep -q 'CHANGE_ME\|@[A-Z_]*@' <<< "$rendered"; then
  echo "render-firewall: a placeholder is left in the rendered ruleset (template changed?)" >&2
  exit 1
fi

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
chmod 600 "$tmp"
printf '%s\n' "$rendered" > "$tmp"

# Syntax check when this user may run it. nft talks to the kernel even with -c, so it needs root.
if command -v nft > /dev/null 2>&1; then
  if check=$(nft -c -f "$tmp" 2>&1); then
    note "nft -c: ruleset is valid"
  elif grep -qi 'not permitted\|permission denied' <<< "$check"; then
    note "nft -c skipped (needs root); install-firewall.sh checks it before loading"
  else
    echo "render-firewall: nft -c refused the ruleset:" >&2
    echo "$check" >&2
    exit 1
  fi
else
  note "nft not installed: syntax check skipped"
fi

if [ -n "$out" ]; then
  # Same directory as the target, so the final rename is atomic.
  final=$(mktemp "$(dirname "$out")/.render-firewall.XXXXXX")
  chmod 600 "$final"
  cat "$tmp" > "$final"
  mv -f "$final" "$out"
  note "wrote $out"
else
  cat "$tmp"
fi
