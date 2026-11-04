#!/usr/bin/env bash
# Installs a rendered SuckerPot host firewall (render-firewall.sh) so that it loads now and after
# every reboot, through its own systemd unit (never the stock nftables service, whose
# /etc/nftables.conf starts with "flush ruleset" and would wipe Docker's rules).
#
#   install-firewall.sh FILE          check FILE, install it, enable and (re)load the unit
#   install-firewall.sh --uninstall   unload the table, disable and remove the unit and the file
#
# Needs root: it re-runs itself through sudo when started as another user. It only touches
# /etc/suckerpot-firewall.nft, /etc/systemd/system/suckerpot-firewall.service and the nftables
# table "inet suckerpot_host"; Docker's own tables are left alone.
#
# Exit codes: 0 done; 2 bad arguments; 3 nft or systemctl missing; 4 FILE refused (placeholder
# left, or `nft -c` failed); 5 loading or verifying failed (the previous table, if any, stays).
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
target=/etc/suckerpot-firewall.nft
unit=suckerpot-firewall.service
unit_path=/etc/systemd/system/$unit

usage() {
  echo "usage: install-firewall.sh FILE | --uninstall" >&2
  exit 2
}
fail() {
  local code=$1
  shift
  echo "install-firewall: $*" >&2
  exit "$code"
}

[ "$#" -eq 1 ] || usage
case $1 in -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;; esac

if [ "$(id -u)" -ne 0 ]; then
  command -v sudo > /dev/null 2>&1 || fail 3 "run it as root (sudo is not installed)"
  arg=$1
  [ "$arg" = --uninstall ] || arg=$(cd "$(dirname "$arg")" && pwd)/$(basename "$arg")
  exec sudo -- "$here/install-firewall.sh" "$arg"
fi

command -v nft > /dev/null 2>&1 || fail 3 "nft not found: install the nftables package first"
command -v systemctl > /dev/null 2>&1 || fail 3 "systemctl not found: load it by hand with nft -f (scripts/host/README.md)"

if [ "$1" = --uninstall ]; then
  systemctl disable --now "$unit" > /dev/null 2>&1 || true
  nft delete table inet suckerpot_host > /dev/null 2>&1 || true
  rm -f "$unit_path" "$target"
  systemctl daemon-reload
  echo "install-firewall: removed; the host firewall table is no longer loaded"
  exit 0
fi

src=$1
{ [ -f "$src" ] && [ -r "$src" ]; } || fail 2 "cannot read $src"
if grep -q 'CHANGE_ME\|@[A-Z_]*@' "$src"; then
  fail 4 "$src still holds a placeholder: render it with scripts/host/render-firewall.sh"
fi
grep -q '^table inet suckerpot_host' "$src" || fail 4 "$src is not a SuckerPot host firewall"
nft -c -f "$src" || fail 4 "nft -c refused $src (nothing was changed)"

install -m 0600 -o root -g root "$src" "$target"
install -m 0644 -o root -g root "$here/suckerpot-firewall.service" "$unit_path"
systemctl daemon-reload
systemctl enable "$unit" > /dev/null 2>&1 || fail 5 "systemctl enable $unit failed"
# restart: loads the new file even when the unit was already active (the file is idempotent).
systemctl restart "$unit" || fail 5 "the unit failed to load the table: journalctl -u $unit"
nft list table inet suckerpot_host > /dev/null 2>&1 || fail 5 "table inet suckerpot_host is not loaded"

cat << EOF
install-firewall: loaded table inet suckerpot_host; it is reloaded after every reboot ($unit).
  See the rules and counters: sudo nft list table inet suckerpot_host
  Undo for this boot only:    sudo nft delete table inet suckerpot_host
  Undo for good:              sudo $here/install-firewall.sh --uninstall
EOF
