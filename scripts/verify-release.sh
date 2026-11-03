#!/usr/bin/env bash
# Verifies the signed release manifest of a release (M32): the file that binds a version tag to one
# commit, to the image digests and to the network defaults, signed by this project's release
# workflow (cosign keyless, the same identity rule as the images).
#
#   scripts/verify-release.sh [--auto] vX.Y.Z
#
# What it checks, in this order (any failure stops with a non-zero exit):
#   1. release-manifest.json and its Sigstore bundle download from the GitHub release;
#   2. cosign verify-blob: signed by the release workflow of the repository named in
#      SUCKERPOT_IMAGE_PREFIX, on refs/tags/<this tag>;
#   3. schema, version (= the tag), major, digest shapes;
#   4. commit == `git rev-parse <tag>^{commit}` (the tag was not moved after signing);
#   5. network_defaults_sha256 == sha256 of config/network-defaults.env in the tag's tree;
#   6. the release time is not in the future. Its age is the later of the manifest's signed
#      released_at and the Sigstore transparency-log time, when the bundle carries one.
#
# --auto (used by the automatic updater): a missing manifest is never accepted, and a release
# younger than the manifest's auto_min_age_h is refused.
#
# Prints key=value lines on stdout (version, commit, released_at, age_h, auto_min_age_h, major)
# and a human summary on stderr. Exit codes: 0 verified, 1 failure, 2 usage, 3 no manifest (with
# --auto always; without it only for a release older than v0.6.0, which has none), 4 too young (--auto),
# 5 the manifest does not match the tag (commit, version, major or defaults), 6 bad signature.
#
# cosign runs in a pinned container, like scripts/verify-images.sh (host traffic: the download
# and Sigstore are contacted from this machine, not through the VPN).
set -euo pipefail

cd "$(dirname "$0")/.."

COSIGN_IMAGE="ghcr.io/sigstore/cosign/cosign:v3.1.4@sha256:0f06154836d2de34f887a5c273506d52ca43edaa1d9e53e6510fa78a48f69c2d"
ISSUER="https://token.actions.githubusercontent.com"
MANIFEST_SINCE="0.6.0"
MANIFEST_NAME="release-manifest.json"
BUNDLE_NAME="release-manifest.json.sigstore.json"

die() { echo "verify-release: $1" >&2; exit "${2:-1}"; }

# Reads VAR from the environment or from .env (last assignment wins; quotes removed).
get() {
  eval "val=\${$1:-}"
  if [ -z "$val" ] && [ -f .env ]; then
    val=$(sed -n "s/^$1=//p" .env | tail -n 1 | tr -d "\"' \r")
  fi
  printf '%s' "${val:-$2}"
}

auto=0
if [ "${1:-}" = "--auto" ]; then auto=1; shift; fi
[ $# -eq 1 ] || die "usage: verify-release.sh [--auto] vX.Y.Z" 2
tag=$1
[[ $tag =~ ^v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || die "'$tag' is not a release version (vX.Y.Z)" 2
tag_major=${tag#v}
tag_major=${tag_major%%.*}

prefix=$(get SUCKERPOT_IMAGE_PREFIX ghcr.io/theroxat/suckerpot)
[[ $prefix =~ ^ghcr\.io/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$ ]] \
  || die "SUCKERPOT_IMAGE_PREFIX must look like ghcr.io/<owner>/<name>" 2
repo=${prefix#ghcr.io/}
escaped=$(printf '%s' "$repo" | sed 's/\./\\./g')
identity="^https://github\\.com/$escaped/\\.github/workflows/release\\.yml@refs/tags/$(printf '%s' "$tag" | sed 's/\./\\./g')\$"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# The container user (65532) must read the files; they are public release assets.
chmod 755 "$work"

fetch() {
  local url=$1 out=$2 code
  code=$(curl -sS --proto '=https' --proto-redir '=https' --tlsv1.2 -L --max-time 30 \
    --max-filesize 65536 -o "$out" -w '%{http_code}' "$url") || return 1
  printf '%s' "$code"
}

base="https://github.com/$repo/releases/download/$tag"
code=$(fetch "$base/$MANIFEST_NAME" "$work/$MANIFEST_NAME") \
  || die "could not download the release manifest of $tag"
if [ "$code" = 404 ]; then
  oldest=$(printf '%s\n%s\n' "${tag#v}" "$MANIFEST_SINCE" | sort -V | head -n 1)
  if [ "$auto" = 0 ] && [ "$oldest" = "${tag#v}" ] && [ "${tag#v}" != "$MANIFEST_SINCE" ]; then
    echo "verify-release: $tag has no signed release manifest (it predates v$MANIFEST_SINCE)" >&2
    exit 3
  fi
  # An automatic update reports "unsigned" (3); a manual one treats a missing manifest of a
  # release that should have one as a plain failure (1).
  if [ "$auto" = 1 ]; then die "$tag has no signed release manifest" 3; fi
  die "$tag has no signed release manifest"
fi
[ "$code" = 200 ] || die "downloading the release manifest answered HTTP $code"
code=$(fetch "$base/$BUNDLE_NAME" "$work/$BUNDLE_NAME") \
  || die "could not download the manifest signature of $tag"
[ "$code" = 200 ] || die "the manifest signature of $tag answered HTTP $code (not signed?)" 6
chmod 644 "$work/$MANIFEST_NAME" "$work/$BUNDLE_NAME"

# ---- 2. the signature (before anything in the file is trusted or even parsed)
size=$(wc -c < "$work/$MANIFEST_NAME" | tr -d ' ')
{ [ "$size" -gt 0 ] && [ "$size" -le 16384 ]; } || die "the release manifest has a bad size"
if ! docker run --rm --user 65532:65532 --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --tmpfs /tmp:rw,noexec,nosuid,size=32m,uid=65532,gid=65532 \
  -e HOME=/tmp -e TUF_ROOT=/tmp/tuf -v "$work:/m:ro" \
  "$COSIGN_IMAGE" verify-blob \
  --bundle "/m/$BUNDLE_NAME" \
  --certificate-identity-regexp "(?i)$identity" \
  --certificate-oidc-issuer "$ISSUER" \
  "/m/$MANIFEST_NAME" > "$work/cosign.out" 2> "$work/cosign.err"; then
  sed 's/^/          /' "$work/cosign.err" | tail -n 3 >&2
  die "the signature of the release manifest of $tag is not valid" 6
fi

# ---- 3. fields (the file is flat JSON written by the release workflow)
flat=$(tr -d '\n\r' < "$work/$MANIFEST_NAME")
jstr() { printf '%s' "$flat" | sed -n "s/.*\"$1\" *: *\"\\([^\"]*\\)\".*/\\1/p" | head -n 1; }
jnum() { printf '%s' "$flat" | sed -n "s/.*\"$1\" *: *\\([0-9]\\{1,12\\}\\)[ ,}].*/\\1/p" | head -n 1; }

schema=$(jstr schema)
m_version=$(jstr version)
m_commit=$(jstr commit)
m_defaults=$(jstr network_defaults_sha256)
m_major=$(jnum major)
m_min_age=$(jnum auto_min_age_h)
m_released=$(jnum released_at)

[ "$schema" = "selfhostr-release/1" ] || die "unknown manifest schema '${schema:-none}'" 5
[ "$m_version" = "$tag" ] || die "the manifest is for '${m_version:-none}', not $tag" 5
[[ $m_commit =~ ^[0-9a-f]{40}$ ]] || die "the manifest has no valid commit" 5
[[ $m_defaults =~ ^[0-9a-f]{64}$ ]] || die "the manifest has no valid defaults hash" 5
[ "$m_major" = "$tag_major" ] || die "the manifest major version '${m_major:-none}' does not match $tag" 5
{ [ -n "$m_min_age" ] && [ "$m_min_age" -le 720 ]; } || die "the manifest has no valid auto_min_age_h" 5
[ -n "$m_released" ] || die "the manifest has no released_at" 5
digests=$(printf '%s' "$flat" | grep -o 'sha256:[0-9A-Za-z]*' || true)
[ -n "$digests" ] || die "the manifest lists no image digest" 5
if printf '%s\n' "$digests" | grep -qvE '^sha256:[0-9a-f]{64}$'; then
  die "the manifest has a malformed image digest" 5
fi

# ---- 4. the tag still points at the signed commit
tag_commit=$(git rev-parse "$tag^{commit}" 2> /dev/null || true)
[ -n "$tag_commit" ] || die "tag $tag not found in this checkout (git fetch --tags)" 5
[ "$tag_commit" = "$m_commit" ] \
  || die "the tag $tag points at ${tag_commit:0:12} but the signed manifest names ${m_commit:0:12}" 5

# ---- 5. the network defaults of that tag are the signed ones
defaults_sha=$(git show "$tag:config/network-defaults.env" 2> /dev/null | sha256sum | cut -d' ' -f1 || true)
[ "$defaults_sha" = "$m_defaults" ] || die "config/network-defaults.env of $tag does not match the signed hash" 5

# ---- 6. age
now=$(date -u +%s)
[ "$m_released" -le $((now + 600)) ] || die "the manifest claims a release time in the future" 5
effective=$m_released
logged=$(grep -o '"integratedTime" *: *"\{0,1\}[0-9]\{1,12\}' "$work/$BUNDLE_NAME" | grep -o '[0-9]*$' | head -n 1 || true)
if [ -n "$logged" ] && [ "$logged" -gt "$effective" ]; then effective=$logged; fi
if [ "$effective" -gt "$now" ]; then age_h=0; else age_h=$(((now - effective) / 3600)); fi

{
  echo "verify-release: $tag is signed by the release workflow of github.com/$repo"
  echo "verify-release: commit ${m_commit:0:12}, released $(date -u -d "@$effective" +%Y-%m-%dT%H:%MZ 2> /dev/null || echo "$effective"), ${age_h} h ago"
} >&2
echo "version=$tag"
echo "commit=$m_commit"
echo "released_at=$effective"
echo "age_h=$age_h"
echo "auto_min_age_h=$m_min_age"
echo "major=$m_major"

if [ "$auto" = 1 ] && [ "$age_h" -lt "$m_min_age" ]; then
  die "$tag is ${age_h} h old; an automatic update waits for ${m_min_age} h" 4
fi
