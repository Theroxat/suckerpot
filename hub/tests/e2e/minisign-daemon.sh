#!/bin/sh
# Test helper: runs the REAL upstream minisign for the feed end-to-end test, which cannot start
# containers itself. The test writes one request file into /io; this loop answers it.
#
#   /io/<id>.req   one line: "verify <file> <public key>"   check /feeds/<file> against
#                                                            /feeds/<file>.minisig
#                           "verifyio <file> <public key>"  the same for /io/<file>
#                           "sign <file> <secret key file>"  sign /io/<file> with a key file
#                                                            in /io, write /io/<file>.minisig
#                           "gen <name>"                     new unencrypted key pair
#                                                            /io/<name>.pub and /io/<name>.key
#   /io/<id>.res   "ok" or "fail", first line; the rest is minisign's own output.
#
# Names are restricted to [A-Za-z0-9._-]. Not for production: it is only in the test overlay.
set -u
umask 000
safe() { case "$1" in ''|*[!A-Za-z0-9._-]*|.*) return 1 ;; esac; }
while true; do
  for req in /io/*.req; do
    [ -e "$req" ] || continue
    id="${req%.req}"
    read -r cmd a b < "$req" || true
    rm -f "$req"
    out="$id.out"
    ok=fail
    case "$cmd" in
      verify)
        if safe "$a" && [ -f "/feeds/$a" ] \
          && minisign -V -m "/feeds/$a" -x "/feeds/$a.minisig" -P "$b" > "$out" 2>&1; then ok=ok; fi ;;
      verifyio)
        if safe "$a" && [ -f "/io/$a" ] \
          && minisign -V -m "/io/$a" -x "/io/$a.minisig" -P "$b" > "$out" 2>&1; then ok=ok; fi ;;
      sign)
        if safe "$a" && safe "$b" && [ -f "/io/$a" ] \
          && minisign -S -m "/io/$a" -s "/io/$b" -x "/io/$a.minisig" \
            -t "timestamp:1700000000 file:$a serial:9" > "$out" 2>&1; then ok=ok; fi ;;
      gen)
        if safe "$a" \
          && minisign -G -W -f -p "/io/$a.pub" -s "/io/$a.key" > "$out" 2>&1; then
          chmod 666 "/io/$a.key" "/io/$a.pub"  # upstream makes the secret key 0600; the test reads it
          ok=ok
        fi ;;
      *) echo "unknown request" > "$out" ;;
    esac
    { echo "$ok"; cat "$out" 2>/dev/null; } > "$id.res.tmp"
    mv "$id.res.tmp" "$id.res"
    rm -f "$out"
  done
  sleep 0.3
done
