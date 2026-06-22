#!/usr/bin/env python3
"""Example Python backend on the muxpeer SDK.

Run directly:  python3 app.py /sockets/app_00.sock W00 1 s3cr3t
Under supervisord: see supervisord.conf (numprocs replicas, one socket each).

Each inbound logical stream is handled like a socket connection — recv the
request, send an HTTP reply that names this replica, close. Thread-per-conn over
ONE tunnel fd; the blocking calls release the GIL.
"""
import os
import socket
import sys
import threading

import muxpeer


def handle(conn, wid):
    try:
        conn.recv(65536)                       # read the request (best-effort)
        body = f"hello from {wid} on {socket.gethostname()} (pid {os.getpid()})\n".encode()
        conn.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: %d\r\n"
            b"Connection: close\r\n\r\n" % len(body)
            + body
        )
    finally:
        conn.close()


def main():
    if len(sys.argv) < 5:
        print("usage: app.py SOCKET ID WEIGHT TOKEN", file=sys.stderr)
        raise SystemExit(2)
    sock, wid, weight, token = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
    peer = muxpeer.listen(sock, token=token, id=wid, weight=weight)
    print(f"[{wid}] listening on {sock} weight={weight}", file=sys.stderr, flush=True)
    try:
        while (conn := peer.accept()) is not None:
            threading.Thread(target=handle, args=(conn, wid), daemon=True).start()
    finally:
        peer.close()


if __name__ == "__main__":
    main()
