#!/usr/bin/env bash
# Manual tool: measured memory cost of one stuck connection (non-reading client, response
# pending), plain or TLS, pipelined or not. Opens N connections from one container against a
# sensor with caps and budget lifted (1 GB container, so the memory guard stays quiet), and
# prints (memory with N connections - baseline) / N.
#
# Usage: measure.sh <image> <n> <plain|tls> <pipeline>
set -euo pipefail
IMAGE=${1:?image}; N=${2:?n}; MODE=${3:?plain|tls}; PIPE=${4:?pipeline}
NET=sp-measure-net; SENSOR=sp-web-m; HERE=$(cd "$(dirname "$0")" && pwd)
cleanup() {
  docker rm -f $(docker ps -aq --filter "label=sp-measure=1") >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
docker network create "$NET" >/dev/null
docker run -d --name "$SENSOR" --label sp-measure=1 --network "$NET" \
  --user 10001:10001 --read-only --tmpfs /tmp:size=16m,uid=10001,gid=10001 \
  --tmpfs /data:size=4m,uid=10001,gid=10001,mode=0700 --cap-drop ALL \
  --memory 1g --memory-swap 1g --cpus 1 \
  -e REDIS_HOST=sp-absent -e REDIS_PASSWORD=x -e WEB_DATA_DIR=/data \
  -e WEB_MAX_CONNECTIONS=1000 -e WEB_MAX_PER_IP=1000 -e WEB_MAX_TLS_CONNECTIONS=1000 \
  -e WEB_CONN_RATE=1000 -e WEB_CONN_BURST=1000 -e WEB_MEMORY_BUDGET_MB=900 \
  -e WEB_WRITE_CHUNK_TIMEOUT=60 "$IMAGE" >/dev/null
for _ in $(seq 1 40); do
  docker exec "$SENSOR" python -m web_sensor.healthcheck >/dev/null 2>&1 && break; sleep 0.5
done
sleep 3
mem() { docker stats --no-stream --format '{{.MemUsage}}' "$SENSOR" | cut -d/ -f1 | tr -d ' ' |
  python3 -c "import sys;v=sys.stdin.read().strip();u={'KiB':1/1024,'MiB':1,'GiB':1024};print(float(v[:-3])*u[v[-3:]])"; }
base=$(mem)
flag=""; [ "$MODE" = tls ] && flag="--tls"
docker run -d --name sp-measure-c --label sp-measure=1 --network "$NET" \
  -v "$HERE/churn.py:/churn.py:ro" python:3.13.17-slim-bookworm \
  python -I /churn.py --host "$SENSOR" --pipeline "$PIPE" --interval 0.02 \
  --count "$N" --duration 60 --hold 120 $flag >/dev/null
for _ in $(seq 1 120); do docker logs sp-measure-c 2>&1 | grep -q opened= && break; sleep 0.5; done
sleep 8
with=$(mem)
opened=$(docker logs sp-measure-c 2>&1 | tail -1)
n_open=$(echo "$opened" | sed -n 's/.*opened=\([0-9]*\).*/\1/p')
python3 -c "import sys;b,w,n=float(sys.argv[1]),float(sys.argv[2]),int(sys.argv[3]);print(f'mode=$MODE pipeline=$PIPE n={n} base={b:.1f}MiB with={w:.1f}MiB per_conn={(w-b)*1024/n:.0f}KiB  ({sys.argv[4]})')" "$base" "$with" "$n_open" "$opened"
