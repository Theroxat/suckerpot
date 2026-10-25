#!/usr/bin/env bash
# Manual load test: the hardened sensor container (256 MB, 0.5 CPU, read-only) against N
# throwaway client containers (one source IP each) running churn.py, while memory is sampled.
#
# Usage: run_load.sh <image> <plain clients> <tls clients> <pipeline> <seconds> [label]
# Example: run_load.sh sp-web:after 20 0 3 600 plain-x3
#
# Prints one line per sample (elapsed s, docker-stats memory) and a summary: peak, mean of the
# last third (the plateau), and whether the sensor survived (not OOM-killed, still running).
set -euo pipefail
IMAGE=${1:?image}; PLAIN=${2:?plain clients}; TLS=${3:?tls clients}; PIPE=${4:?pipeline}
DUR=${5:?seconds}; LABEL=${6:-run}
NET=sp-load-net; SENSOR=sp-web; CLIENT_IMAGE=python:3.13.17-slim-bookworm
HERE=$(cd "$(dirname "$0")" && pwd)

cleanup() {
  docker rm -f $(docker ps -aq --filter "label=sp-load=1") >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
docker network create "$NET" >/dev/null

docker run -d --name "$SENSOR" --label sp-load=1 --network "$NET" \
  --user 10001:10001 --read-only --tmpfs /tmp:size=16m,uid=10001,gid=10001 \
  --tmpfs /data:size=4m,uid=10001,gid=10001,mode=0700 \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --memory 256m --memory-swap 256m --cpus 0.5 --pids-limit 128 \
  -e REDIS_HOST=sp-load-redis-absent -e REDIS_PASSWORD=x -e EVENTS_STREAM=events:web \
  -e WEB_DATA_DIR=/data "$IMAGE" >/dev/null
for _ in $(seq 1 40); do
  if docker exec "$SENSOR" python -m web_sensor.healthcheck >/dev/null 2>&1; then break; fi
  sleep 0.5
done
base=$(docker stats --no-stream --format '{{.MemUsage}}' "$SENSOR" | cut -d/ -f1)
echo "[$LABEL] baseline $base"

start_client() {  # $1 = name, $2.. = churn.py arguments
  local name=$1; shift
  docker run -d --name "$name" --label sp-load=1 --network "$NET" --memory 128m \
    -v "$HERE/churn.py:/churn.py:ro" "$CLIENT_IMAGE" \
    python -I /churn.py --host "$SENSOR" --duration "$DUR" --pipeline "$PIPE" "$@" >/dev/null
}
for i in $(seq 1 "$PLAIN"); do start_client "sp-load-p$i"; done
for i in $(seq 1 "$TLS"); do start_client "sp-load-t$i" --tls; done

t0=$(date +%s); samples=()
while :; do
  now=$(( $(date +%s) - t0 ))
  [ "$now" -ge "$DUR" ] && break
  state=$(docker inspect -f '{{.State.Status}} {{.State.OOMKilled}}' "$SENSOR" 2>/dev/null || echo "gone true")
  if [ "${state%% *}" != "running" ]; then echo "[$LABEL] sensor $state at ${now}s"; break; fi
  mem=$(docker stats --no-stream --format '{{.MemUsage}}' "$SENSOR" | cut -d/ -f1 | tr -d ' ')
  mib=$(python3 -c "import sys;v=sys.argv[1];u={'KiB':1/1024,'MiB':1,'GiB':1024};print(round(float(v[:-3])*u[v[-3:]],1))" "$mem")
  samples+=("$mib"); echo "[$LABEL] t=${now}s mem=${mib}MiB"
  sleep 10
done
state=$(docker inspect -f '{{.State.Status}} oom={{.State.OOMKilled}} exit={{.State.ExitCode}}' "$SENSOR")
python3 - "$LABEL" "$state" "${samples[@]}" <<'EOF'
import sys
label, state, *vals = sys.argv[1:]
v = [float(x) for x in vals] or [0.0]
tail = v[len(v) * 2 // 3:] or v
print(f"[{label}] SUMMARY peak={max(v):.1f}MiB plateau={sum(tail)/len(tail):.1f}MiB "
      f"samples={len(v)} state=({state})")
EOF
docker logs --tail 3 "$SENSOR" 2>&1 | cut -c1-400
