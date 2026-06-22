#!/usr/bin/env bash
# Benchmark the no-mux baseline (4 asyncio servers on one SO_REUSEPORT socket)
# with the same loadgen and concurrency ladder as deploy/bench.sh, so the two
# result sets line up directly.
set -uo pipefail
cd "$(dirname "$0")/.."

LEVELS=${LEVELS:-"1000 5000 10000 25000 50000"}
DUR=${DUR:-12s}
PROJ=muxbase
NET=${PROJ}_default
COMPOSE="docker compose -f deploy/docker-compose.baseline.yml -p $PROJ"

cleanup(){ $COMPOSE down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

echo "############ baseline = 4x asyncio + SO_REUSEPORT (no mux) ############"
$COMPOSE up -d >/dev/null 2>&1

ready=0
for _ in $(seq 1 60); do
  if docker run --rm --network "$NET" curlimages/curl:8.8.0 -s --max-time 2 http://baseline:5000/ >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 1
done
[ "$ready" = 1 ] && echo "baseline ready" || { echo "baseline did not converge"; exit 1; }

for c in $LEVELS; do
  docker run --rm --network "$NET" --ulimit nofile=1048576 \
    -v "$PWD/bench:/b" -w /b golang:1.22-alpine \
    go run . -target baseline:5000 -c "$c" -d "$DUR" 2>&1 | grep -vE '^go: (downloading|finding)'
done
