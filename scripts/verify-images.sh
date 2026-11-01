#!/bin/sh
# Verifies the cosign signature of every published image of a release (M28), against the identity of
# this project's release workflow. Nothing is pulled or started: cosign only reads signatures.
#
#   scripts/verify-images.sh [vX.Y.Z]
#
# The version comes from the argument, then SUCKERPOT_VERSION (environment or .env). The registry
# prefix comes from SUCKERPOT_IMAGE_PREFIX (same lookup, default ghcr.io/theroxat/suckerpot); the
# GitHub repository whose workflow must have signed the images is taken from that prefix
# (ghcr.io/<owner>/<repo>), so a fork verifies its own releases.
#
# cosign runs in a pinned container (host traffic: it contacts the registry and the Sigstore
# transparency log from this machine, like `docker pull` does). It never sees a secret, unless you
# have a registry login in ~/.docker/config.json: that file is then mounted read-only so private
# packages can be read. Set VERIFY_IMAGES_NO_AUTH=1 to skip it.
set -eu

cd "$(dirname "$0")/.."

COSIGN_IMAGE="ghcr.io/sigstore/cosign/cosign:v3.1.4@sha256:0f06154836d2de34f887a5c273506d52ca43edaa1d9e53e6510fa78a48f69c2d"
ISSUER="https://token.actions.githubusercontent.com"
IMAGES="redis migrate ingest api collector demo sensor-ssh sensor-rdp sensor-telnet sensor-web sensor-redis sensor-docker sensor-mysql sensor-mssql sensor-adb sensor-smb sensor-sip sensor-synology"

# Reads VAR from the environment or from .env (last assignment wins; quotes removed).
get() {
  eval "val=\${$1:-}"
  if [ -z "$val" ] && [ -f .env ]; then
    val=$(sed -n "s/^$1=//p" .env | tail -n 1 | tr -d "\"' \r")
  fi
  printf '%s' "${val:-$2}"
}

die() { echo "verify-images: $*" >&2; exit 1; }

version=${1:-$(get SUCKERPOT_VERSION '')}
[ -n "$version" ] || die "no version: pass vX.Y.Z or set SUCKERPOT_VERSION"
printf '%s' "$version" | grep -Eq '^v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' \
  || die "'$version' is not a release version (vX.Y.Z); a source build has nothing to verify"

prefix=$(get SUCKERPOT_IMAGE_PREFIX ghcr.io/theroxat/suckerpot)
printf '%s' "$prefix" | grep -Eq '^ghcr\.io/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$' \
  || die "SUCKERPOT_IMAGE_PREFIX must look like ghcr.io/<owner>/<name>"
repo=${prefix#ghcr.io/}
# Dots in the repository path are literal in the identity pattern; the owner part is matched
# case-insensitively because GHCR names are lower case and GitHub account names are not.
escaped=$(printf '%s' "$repo" | sed 's/\./\\./g')
identity="^https://github\\.com/$escaped/\\.github/workflows/release\\.yml@refs/tags/$(printf '%s' "$version" | sed 's/\./\\./g')\$"

auth=""
if [ "${VERIFY_IMAGES_NO_AUTH:-0}" != 1 ] && [ -f "$HOME/.docker/config.json" ]; then
  auth="-v $HOME/.docker/config.json:/home/nonroot/.docker/config.json:ro"
fi

echo "verify-images: $version, signer github.com/$repo release workflow"
fail=0
for image in $IMAGES; do
  ref="$prefix-$image:$version"
  # shellcheck disable=SC2086
  if docker run --rm --user 65532:65532 --read-only --cap-drop ALL \
      --security-opt no-new-privileges:true --tmpfs /tmp:rw,noexec,nosuid,size=32m,uid=65532,gid=65532 \
      -e HOME=/tmp -e TUF_ROOT=/tmp/tuf $auth \
      -e DOCKER_CONFIG=/home/nonroot/.docker \
      "$COSIGN_IMAGE" verify \
      --certificate-identity-regexp "(?i)$identity" \
      --certificate-oidc-issuer "$ISSUER" \
      "$ref" >/dev/null 2>"${TMPDIR:-/tmp}/verify-images.$$"; then
    echo "  ok      $image"
  else
    echo "  FAILED  $image" >&2
    sed 's/^/          /' "${TMPDIR:-/tmp}/verify-images.$$" | tail -n 3 >&2
    fail=1
  fi
done
rm -f "${TMPDIR:-/tmp}/verify-images.$$"

if [ "$fail" -ne 0 ]; then
  die "at least one image did not verify: do not run this version"
fi
echo "verify-images: all $(echo "$IMAGES" | wc -w | tr -d ' ') images carry a valid signature"
