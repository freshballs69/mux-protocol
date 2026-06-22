#!/usr/bin/env python3
"""A worker built on the muxpeer SDK — the user's "backend uses mux as transport"
model. Each replica binds its own unix socket; the edge-peer dials in and routes
balanced streams here. Thread-per-connection; each conn looks like a socket.

    python worker.py /run/app_00.sock W0 4 s3cr3t
"""
import sys
import threading
import muxpeer


def handle(conn, wid):
    try:
        conn.recv(65536)                       # read the request (best-effort)
        body = f"handled by python worker {wid}\n".encode()
        resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: %d\r\n"
            b"Connection: close\r\n\r\n" % len(body)
        ) + body
        conn.sendall(resp)
    finally:
        conn.close()


def main():
    addr, wid, weight, token = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
    peer = muxpeer.listen(addr, token=token, id=wid, weight=weight)
    print(f"[{wid}] listening on {addr} weight={weight}", file=sys.stderr, flush=True)
    try:
        while True:
            conn = peer.accept()               # blocking; releases the GIL
            if conn is None:
                break
            threading.Thread(target=handle, args=(conn, wid), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        peer.close()


if __name__ == "__main__":
    main()
