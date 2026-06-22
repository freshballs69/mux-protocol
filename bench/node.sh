#!/usr/bin/env bash
# Worker node: launch N=nproc asyncio workers (one per core), each on its own
# unix socket, then an edge-peer that dials the EDGE and all those sockets.
#
#   EDGE=192.168.50.109:15001 MUX_TOKEN=s3cr3t ./bench/node.sh
#
# Run from the repo root (mux-bench). Stays in the foreground (edge-peer); the
# worker logs go to /tmp/muxw_*.log.
set -u
cd "$(dirname "$0")/.."

EDGE=${EDGE:?set EDGE=host:port (the edge uplink)}
TOKEN=${MUX_TOKEN:-s3cr3t}
N=${N:-$(nproc)}
SOCKDIR=${SOCKDIR:-/tmp/muxsock}
# PY: a python interpreter that can import muxpeer (matching the built .so) and
# ideally uvloop. Defaults to a prebuilt venv next to the repo.
PY=${PY:-./.venv/bin/python}

pkill -f app_async.py 2>/dev/null; pkill -f build/edge-peer 2>/dev/null; sleep 0.4
rm -rf "$SOCKDIR"; mkdir -p "$SOCKDIR"

workers=()
for i in $(seq 0 $((N - 1))); do
    s="$SOCKDIR/w$i.sock"
    workers+=(--worker "$s")
    "$PY" examples/python-app/app_async.py \
        "$s" "W$(printf '%02d' "$i")" 1 "$TOKEN" >"/tmp/muxw_$i.log" 2>&1 &
done
echo "[node] launched $N workers; waiting for sockets..."
for i in $(seq 0 $((N - 1))); do
    for _ in $(seq 1 100); do [ -S "$SOCKDIR/w$i.sock" ] && break; sleep 0.1; done
done
echo "[node] starting edge-peer -> $EDGE  ($N workers)"
exec ./build/edge-peer --connect "$EDGE" "${workers[@]}" --token "$TOKEN"
