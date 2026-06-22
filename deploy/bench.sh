#!/usr/bin/env bash
# Benchmark a Python worker mode under ramping concurrency through the full mux
# stack, in Docker (Linux/epoll, high fd limits to bypass the host cap).
#
#   ./deploy/bench.sh app_async.py     # asyncio worker (one event loop)
#   ./deploy/bench.sh app.py           # thread-per-connection worker
#
# Requires the mux-daemons:latest image (docker build -t mux-daemons:latest .).
set -uo pipefail
cd "$(dirname "$0")/.."

APP=${1:-app_async.py}
LEVELS=${LEVELS:-"1000 5000 10000 25000 50000"}
DUR=${DUR:-12s}
export MUX_TOKEN=s3cr3t APP
PROJ=muxbench
NET=${PROJ}_default
COMPOSE="docker compose -f deploy/docker-compose.bench.yml -p $PROJ"

cleanup(){ $COMPOSE down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

echo "############ worker = $APP ############"
$COMPOSE up -d --build >/dev/null 2>&1

# wait until the edge serves a request end-to-end
ready=0
for _ in $(seq 1 60); do
  if docker run --rm --network "$NET" curlimages/curl:8.8.0 -s --max-time 2 http://edge:5000/ >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 1
done
[ "$ready" = 1 ] && echo "stack ready" || { echo "stack did not converge"; exit 1; }

for c in $LEVELS; do
  docker run --rm --network "$NET" --ulimit nofile=1048576 \
    -v "$PWD/bench:/b" -w /b golang:1.22-alpine \
    go run . -target edge:5000 -c "$c" -d "$DUR" 2>&1 | grep -vE '^go: (downloading|finding)'
done
