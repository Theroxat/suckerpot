#!/bin/sh
# fetch-verify.sh: download SuckerPot community lists, verify them, then replace the local copies.
#
# Usage:
#   fetch-verify.sh [-b BASE_URL] [-d DEST_DIR] [-P PUBKEY] FILE...
#   FEED_PUBKEY=RW... fetch-verify.sh outbound.txt
#
# Examples:
#   fetch-verify.sh -b https://feeds.example.org/v1 -d /var/lib/lists -P RW... outbound.txt
#   FEED_PUBKEY=RW... fetch-verify.sh -d /var/lib/lists outbound-domains.txt
#
# Options:
#   -b BASE_URL  https address of the feed. Default: https://feeds.example.org/v1
#   -d DEST_DIR  directory for the verified files. Default: the current directory
#   -P PUBKEY    minisign public key of the feed ("RW..."). Or set FEED_PUBKEY.
#   -h           show this text
#
# Steps:
#   1. Download index.json and index.json.minisig into a private temporary directory.
#   2. Verify index.json with minisign. The signed comment must name index.json. The index must
#      not be past its valid_until, and its serial must not be lower than the one stored in
#      DEST_DIR/.selfhostr-serial (rollback protection).
#   3. For each FILE: download it and FILE.minisig, verify the signature, check that the signed
#      comment names FILE and the index serial, and check the sha256 against index.json.
#   4. Only a file that passed every check is copied to a temporary name in DEST_DIR and renamed
#      over the old file. A rename within one directory is atomic, so readers see the old file or
#      the new one, never a partial file.
#
# A failed check stops the run with exit status 1 and a message that names the check. The old
# files stay in place. Redirects are not followed, and only https is accepted.
#
# Needs: sh (POSIX), curl, minisign, sha256sum, mktemp, date, sort, grep, sed, cut, head.
# Nothing is evaluated: file names and values are checked with patterns, never passed to eval.

set -eu
umask 022

PROG=fetch-verify.sh
BASE=https://feeds.example.org/v1
DEST=.
PUBKEY=${FEED_PUBKEY:-}
TMP=
NEW=

usage() {
	cat <<'USAGE'
usage: fetch-verify.sh [-b BASE_URL] [-d DEST_DIR] [-P PUBKEY] FILE...
  -b BASE_URL  https address of the feed (default https://feeds.example.org/v1)
  -d DEST_DIR  directory for the verified files (default: current directory)
  -P PUBKEY    minisign public key, "RW..." (or set FEED_PUBKEY)
  -h           show this text
example: fetch-verify.sh -d /var/lib/lists -P RW... outbound.txt
USAGE
}

die() {
	printf '%s: %s\n' "$PROG" "$*" >&2
	exit 1
}

cleanup() {
	if [ -n "$NEW" ]; then
		rm -f -- "$NEW"
	fi
	if [ -n "$TMP" ]; then
		rm -rf -- "$TMP"
	fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

while getopts 'b:d:P:h' opt; do
	case $opt in
	b) BASE=$OPTARG ;;
	d) DEST=$OPTARG ;;
	P) PUBKEY=$OPTARG ;;
	h)
		usage
		exit 0
		;;
	*)
		usage >&2
		exit 2
		;;
	esac
done
shift $((OPTIND - 1))
if [ "$#" -lt 1 ]; then
	usage >&2
	exit 2
fi

for tool in curl minisign sha256sum mktemp date sort grep sed cut head; do
	command -v "$tool" >/dev/null 2>&1 || die "missing command: $tool"
done
[ -n "$PUBKEY" ] || die "no public key: set FEED_PUBKEY or pass -P"
case $BASE in
https://?*) ;;
*) die "the base address must start with https://" ;;
esac
BASE=${BASE%/}
[ -d "$DEST" ] || die "destination directory does not exist"

# A list file name: lower case letters, digits, dot, dash and underscore. No "..", no index.json.
valid_name() {
	case $1 in
	*..* | index.json) return 1 ;;
	esac
	printf '%s\n' "$1" | grep -Eq '^[a-z0-9][a-z0-9._-]{0,63}$'
}

fetch() {
	# fetch NAME TARGET: one https GET, no redirects, bounded in size and time.
	curl --fail --silent --show-error --proto '=https' --max-redirs 0 \
		--connect-timeout 10 --max-time 120 --max-filesize 8388608 \
		--output "$2" "$BASE/$1" || die "download failed: $1"
}

# verify SIGNED SIG NAME SERIAL: minisign, then the signed comment must name NAME and SERIAL.
verify() {
	minisign -q -V -m "$1" -x "$2" -P "$PUBKEY" >/dev/null 2>&1 ||
		die "signature check failed: $3"
	comment=$(sed -n 's/^trusted comment: //p' "$2" | head -n 1)
	case $comment in
	"timestamp:"*" file:$3 serial:$4") ;;
	*) die "the signed comment does not name $3 and serial $4" ;;
	esac
}

# sha_for NAME: the sha256 that index.json gives for NAME (empty when there is none).
sha_for() {
	escaped=$(printf '%s\n' "$1" | sed 's/\./\\./g')
	grep -o "\"name\":\"$escaped\"[^}]*\"sha256\":\"[0-9a-f]\{64\}\"" "$TMP/index.json" |
		head -n 1 | sed 's/.*"sha256":"\([0-9a-f]\{64\}\)".*/\1/'
}

TMP=$(mktemp -d)
fetch index.json "$TMP/index.json"
fetch index.json.minisig "$TMP/index.json.minisig"
# The signature covers the whole index. The serial is read only after it verifies.
minisign -q -V -m "$TMP/index.json" -x "$TMP/index.json.minisig" -P "$PUBKEY" >/dev/null 2>&1 ||
	die "signature check failed: index.json"
case $(sed -n 's/^trusted comment: //p' "$TMP/index.json.minisig" | head -n 1) in
*" file:index.json "*) ;;
*) die "the signed comment does not name index.json" ;;
esac
grep -q '"schema":"selfhostr-feeds/1"' "$TMP/index.json" || die "index.json has an unknown schema"
serial=$(grep -o '"serial":[0-9]*' "$TMP/index.json" | head -n 1 | cut -d: -f2)
case $serial in
'' | *[!0-9]*) die "index.json has no serial" ;;
esac
valid=$(grep -o '"valid_until":"[^"]*"' "$TMP/index.json" | head -n 1 | cut -d'"' -f4)
case $valid in
[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z) ;;
*) die "index.json has no valid_until" ;;
esac
now=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
earliest=$(printf '%s\n%s\n' "$now" "$valid" | sort | head -n 1)
[ "$earliest" = "$now" ] || die "index.json expired at $valid: refusing to use it"

STATE="$DEST/.selfhostr-serial"
if [ -f "$STATE" ]; then
	known=$(head -n 1 "$STATE")
	case $known in
	'' | *[!0-9]*) die "the serial state file is damaged: remove $STATE to start again" ;;
	esac
	[ "$serial" -ge "$known" ] || die "index serial $serial is older than $known: rollback refused"
fi

for name in "$@"; do
	valid_name "$name" || die "not a list file name: $name"
	fetch "$name" "$TMP/$name"
	fetch "$name.minisig" "$TMP/$name.minisig"
	verify "$TMP/$name" "$TMP/$name.minisig" "$name" "$serial"
	want=$(sha_for "$name")
	case $want in
	'') die "index.json does not list $name" ;;
	esac
	got=$(sha256sum "$TMP/$name" | cut -d' ' -f1)
	[ "$got" = "$want" ] || die "sha256 does not match index.json: $name"
	NEW=$(mktemp "$DEST/.$name.XXXXXX")
	cat "$TMP/$name" >"$NEW"
	chmod 644 "$NEW"
	mv -f "$NEW" "$DEST/$name"
	NEW=
	printf 'updated %s (serial %s)\n' "$name" "$serial"
done

NEW=$(mktemp "$DEST/.selfhostr-serial.XXXXXX")
printf '%s\n' "$serial" >"$NEW"
mv -f "$NEW" "$STATE"
NEW=
