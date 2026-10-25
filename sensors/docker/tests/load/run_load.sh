#!/usr/bin/env bash
# Manual memory test. Needs a hardened sensor container named sp-docker-lt (alias "sensor") on the network sp-docker-lt-net; see README, Limits.
# 19 client containers x 8 connections against a sensor with the default caps (150 global, 8 per IP)
set -e
MODE=${1:-mixed}
SECS=${2:-40}
for i in $(seq 1 19); do
  docker run -d --rm --name sp-docker-lt-cl$i --network sp-docker-lt-net --memory 48m -v "$(git rev-parse --show-toplevel)/sensors/docker/tests/flood.py":/flood.py:ro python:3.13.17-slim-bookworm python /flood.py sensor 2375 $MODE 8 $SECS >/dev/null
done
for t in 5 15 25 35 45; do
  sleep 10
  docker stats --no-stream --format '{{.Name}} {{.MemUsage}} {{.CPUPerc}} pids={{.PIDs}}' sp-docker-lt
done
docker logs sp-docker-lt 2>&1 | tail -1
docker rm -f $(docker ps -aq --filter name=sp-docker-lt-cl) >/dev/null 2>&1 || true
