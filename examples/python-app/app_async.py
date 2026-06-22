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

# Find the muxpeer extension + muxpeer_aio: next to us (container copies both
# here) or in the repo (native: the .so is built into python/, muxpeer_aio.py is
# at the repo root). Unnecessary once `pip install muxpeer` puts both on the path.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.join(_HERE, "..", "..")
for _p in (_HERE, _ROOT, os.path.join(_ROOT, "python")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import muxpeer
from muxpeer_aio import serve

WID = "W?"


async def handle(conn):
    # HTTP/1.1 keep-alive: frame requests at the blank line and serve many per
    # stream, so the mux tunnel is exercised in its steady state (long-lived
    # streams) instead of being churned open/closed per request. Honors
    # "Connection: close" for the close-per-request benchmark mode.
    body = f"async hello from {WID} on {socket.gethostname()} (pid {os.getpid()})\n".encode()
    buf = bytearray()
    while True:
        while b"\r\n\r\n" not in buf:
            chunk = await conn.read(65536)
            if not chunk:
                conn.close()
                return
            buf += chunk
        idx = buf.index(b"\r\n\r\n") + 4
        req = bytes(buf[:idx]); del buf[:idx]
        close = b"connection: close" in req.lower()
        hdr = (b"Connection: close\r\n" if close else b"")
        await conn.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Content-Length: %d\r\n%s\r\n%s" % (len(body), hdr, body)
        )
        if close:
            break
    conn.close()


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
