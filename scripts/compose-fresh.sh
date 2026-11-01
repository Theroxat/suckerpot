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
exec docker compose "$@"
