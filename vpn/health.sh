#!/bin/sh
# Healthcheck of the vpn container (M28). Healthy when the entrypoint is in idle mode (no VPN
# configuration yet: nothing runs, nothing can leave) or when gluetun's own check passes.
[ -e "${VPN_IDLE_MARKER:-/tmp/vpn-idle}" ] && exit 0
exec "${VPN_GLUETUN_BIN:-/gluetun-entrypoint}" healthcheck
