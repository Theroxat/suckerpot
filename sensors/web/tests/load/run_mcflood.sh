#!/usr/bin/env bash
# Manual CPU test: <ips> client containers x <threads> threads of mcflood.py (gzip multicall)
# against the hardened sensor (0.5 CPU, 256 MB), plus probe.py measuring GET / latency from a
# separate container. Prints the sensor's CPU samples, the flood result and the probe latency.
#
# Usage: run_mcflood.sh <image> [ips=5] [threads=4] [seconds=60]
set -euo pipefail
IMAGE=${1:?image}; IPS=${2:-5}; THREADS=${3:-4}; DUR=${4:-60}
NET=sp-mc-net; SENSOR=sp-web; HERE=$(cd "$(dirname "$0")" && pwd); PY=python:3.13.17-slim-bookworm
cleanup() {
  docker rm -f $(docker ps -aq --filter "label=sp-mc=1") >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
docker network create "$NET" >/dev/null
docker run -d --name "$SENSOR" --label sp-mc=1 --network "$NET" \
  --user 10001:10001 --read-only --tmpfs /tmp:size=16m,uid=10001,gid=10001 \
  --tmpfs /data:size=4m,uid=10001,gid=10001,mode=0700 --cap-drop ALL \
  --security-opt no-new-privileges:true --memory 256m --memory-swap 256m --cpus 0.5 \
  --pids-limit 128 -e REDIS_HOST=sp-absent -e REDIS_PASSWORD=x -e WEB_DATA_DIR=/data "$IMAGE" >/dev/null
for _ in $(seq 1 40); do
  docker exec "$SENSOR" python -m web_sensor.healthcheck >/dev/null 2>&1 && break; sleep 0.5
done
docker run --rm --network "$NET" -v "$HERE:/l:ro" $PY python -I /l/probe.py --host "$SENSOR" --duration 8 | sed 's/^/idle /'
for i in $(seq 1 "$IPS"); do
  docker run -d --name "sp-mc-c$i" --label sp-mc=1 --network "$NET" -v "$HERE:/l:ro" $PY \
    python -I /l/mcflood.py --host "$SENSOR" --threads "$THREADS" --duration "$DUR" >/dev/null
done
docker run -d --name sp-mc-probe --label sp-mc=1 --network "$NET" -v "$HERE:/l:ro" $PY \
  python -I /l/probe.py --host "$SENSOR" --duration "$DUR" >/dev/null
cpu=(); health=()
for _ in $(seq 1 $((DUR / 5))); do
  cpu+=("$(docker stats --no-stream --format '{{.CPUPerc}}' "$SENSOR")")
  health+=("$(docker exec "$SENSOR" python -m web_sensor.healthcheck >/dev/null 2>&1 && echo ok || echo FAIL)")
  sleep 3
done
echo "cpu samples: ${cpu[*]}"; echo "healthcheck: ${health[*]}"
for i in $(seq 1 "$IPS"); do docker wait "sp-mc-c$i" >/dev/null; docker logs "sp-mc-c$i" 2>&1 | tail -1; done
docker wait sp-mc-probe >/dev/null; docker logs sp-mc-probe 2>&1 | tail -1 | sed 's/^/flood /'
