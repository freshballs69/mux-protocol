#!/usr/bin/env bash
# Local end-to-end demo: edge + edge-peer router + two Python workers on unix
# sockets with weights 1 and 3, then fire requests and show the balance.
#
#   ./deploy/run_demo.sh
#
# Requires: the CMake build (build/edge, build/edge-peer) and the muxpeer
# extension built (cd python && uv run --with setuptools python setup.py build_ext --inplace).
set -euo pipefail
cd "$(dirname "$0")/.."

export ASAN_OPTIONS=detect_leaks=0
TOK=${MUX_TOKEN:-s3cr3t}
ACCEPT=${ACCEPT_PORT:-15000}
MUX=${MUX_PORT:-15001}

cleanup() { pkill -f 'build/edge' 2>/dev/null || true; pkill -f 'python/worker.py' 2>/dev/null || true; }
trap cleanup EXIT
cleanup; sleep 0.3
rm -f /tmp/pw0.sock /tmp/pw1.sock

( cd python && uv run python worker.py /tmp/pw0.sock PY0 1 "$TOK" ) &
( cd python && uv run python worker.py /tmp/pw1.sock PY1 3 "$TOK" ) &
sleep 2.5

./build/edge --accept-port "$ACCEPT" --mux-port "$MUX" --token "$TOK" &
sleep 0.4
./build/edge-peer --connect 127.0.0.1:"$MUX" \
    --worker /tmp/pw0.sock --worker /tmp/pw1.sock --token "$TOK" &
sleep 1.5

echo "=== 40 requests through the mux (expect ~1:3 PY0:PY1) ==="
for _ in $(seq 1 40); do curl -s --max-time 5 "http://127.0.0.1:$ACCEPT/"; done | sort | uniq -c
