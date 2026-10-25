#!/usr/bin/env bash
# Manual memory test. Needs a hardened sensor container named sp-docker-lt (alias "sensor") on the network sp-docker-lt-net; see README, Limits.
for i in $(seq 1 6); do
  docker run -d --rm --name sp-docker-lt-cl$i --network sp-docker-lt-net --memory 48m -v "$(git rev-parse --show-toplevel)/sensors/docker/tests/flood.py":/flood.py:ro python:3.13.17-slim-bookworm python /flood.py sensor 2375 churn 6 115 >/dev/null
done
for t in 1 2 3 4 5 6; do
  sleep 20
  docker stats --no-stream --format '{{.MemUsage}} {{.CPUPerc}}' sp-docker-lt
done
docker logs sp-docker-lt 2>&1 | tail -1 | cut -c1-500
docker rm -f $(docker ps -aq --filter name=sp-docker-lt-cl) >/dev/null 2>&1 || true
