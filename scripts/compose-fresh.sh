#!/usr/bin/env bash
# Runs docker compose with the settings of .env as they are NOW. `just` exports the values .env
# had when the recipe started, and those beat the file; a recipe that changed .env (just set,
# just sensors) uses this wrapper for the compose call that follows, so the change takes effect.
#
#   scripts/compose-fresh.sh up -d --wait
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/env.sh
. scripts/lib/env.sh

env_drop_loaded
# Images mode runs only images that the installer or updater verified: never build or pull here.
if [ "$(env_get SUCKERPOT_INSTALL_MODE source)" = images ] && [ "${1:-}" = up ]; then
  shift
  docker compose up --no-build --pull never "$@" || {
    echo "compose-fresh: an image may be missing locally; run: just update (it verifies and pulls the release images)" >&2
    exit 1
  }
  exit 0
fi
exec docker compose "$@"
