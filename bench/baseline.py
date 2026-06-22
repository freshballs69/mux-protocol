#!/usr/bin/env python3
"""Baseline control for the benchmark: a plain asyncio HTTP server on an ordinary
listening socket — no mux. Run N copies bound to the same port with SO_REUSEPORT
so the kernel load-balances accepts across processes (the "master socket" model
that the mux edge-peer replaces). Same HTTP reply, benchmarked the same way, so
the delta vs the mux path is the mux overhead.

    python3 baseline.py 5000
"""
import asyncio
import os
import sys


async def handle(reader, writer):
    try:
        await reader.read(65536)             # read the request (best-effort)
        body = b"baseline from pid %d\n" % os.getpid()
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: %d\r\n"
            b"Connection: close\r\n\r\n" % len(body)
            + body
        )
        await writer.drain()
    except Exception:                        # noqa: BLE001
        pass
    finally:
        try:
            writer.close()
        except Exception:                    # noqa: BLE001
            pass


async def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    server = await asyncio.start_server(handle, "0.0.0.0", port, reuse_port=True)
    print(f"[baseline] pid {os.getpid()} listening on :{port}", file=sys.stderr, flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
