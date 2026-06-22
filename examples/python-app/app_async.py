#!/usr/bin/env python3
"""asyncio backend on muxpeer — single event loop, no thread-per-connection.

    python3 app_async.py /sockets/app_00.sock W00 1 s3cr3t

Compare against app.py (thread-per-connection) under load: this version drives
all streams over one tunnel fd from one event loop via muxpeer's readiness API.
"""
import asyncio
import os
import socket
import sys

# uvloop is a drop-in, much faster asyncio loop; it supports add_reader, which
# the muxpeer readiness bridge relies on. Optional — fall back to stdlib asyncio.
try:
    import uvloop

    uvloop.install()
    _LOOP = "uvloop"
except Exception:                            # noqa: BLE001
    _LOOP = "asyncio"

# Find muxpeer_aio next to us (container) or in the repo's python/ dir (native).
_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(_HERE, "..", "..", "python")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import muxpeer
from muxpeer_aio import serve

WID = "W?"


async def handle(conn):
    await conn.read(65536)                  # read the request (best-effort)
    body = f"async hello from {WID} on {socket.gethostname()} (pid {os.getpid()})\n".encode()
    await conn.write(
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: %d\r\n"
        b"Connection: close\r\n\r\n" % len(body)
        + body
    )


async def main():
    global WID
    sock, WID, weight, token = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
    peer = muxpeer.listen(sock, token=token, id=WID, weight=weight)
    print(f"[{WID}] async ({_LOOP}) listening on {sock} weight={weight}", file=sys.stderr, flush=True)
    await serve(peer, handle)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
