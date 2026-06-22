"""asyncio adapter for muxpeer.

Bridges the single readiness fd (muxpeer.Peer.fileno) into the asyncio loop with
loop.add_reader, turning each inbound mux stream into an awaitable connection.
No thread-per-connection: one event loop drives 100k+ streams over one tunnel fd.

    import asyncio, muxpeer
    from muxpeer_aio import serve

    async def handle(conn):           # conn: MuxStream
        req = await conn.read(65536)
        await conn.write(b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\n\\r\\nhi")

    async def main():
        peer = muxpeer.listen("/sockets/app.sock", token="k", id="W0", weight=1)
        await serve(peer, handle)     # runs until cancelled

    asyncio.run(main())
"""
import asyncio

import muxpeer


class MuxStream:
    """A single inbound stream, presented as an async read/write connection.

    Supports multiple concurrent readers and writers: each awaits its own future
    and every waiter is woken (lists, not a single slot), and both directions are
    woken on EOF/reset so a backpressured writer never strands when the peer dies.
    """

    __slots__ = ("_raw", "_rbuf", "_eof", "_reset", "_rwaiters", "_wwaiters")

    def __init__(self, raw):
        self._raw = raw
        self._rbuf = bytearray()
        self._eof = False
        self._reset = False
        self._rwaiters = []
        self._wwaiters = []

    @staticmethod
    def _wake_all(waiters):
        for w in waiters:
            if not w.done():
                w.set_result(None)
        waiters.clear()

    # --- fed by the readiness callback (sync, in the loop thread) ---
    def _feed_readable(self):
        while True:
            try:
                chunk = self._raw.recv_nb(65536)
            except OSError:                 # reset
                self._reset = True
                self._eof = True
                break
            if chunk is None:               # would block: drained
                break
            if not chunk:                    # EOF
                self._eof = True
                break
            self._rbuf += chunk
        self._wake_all(self._rwaiters)
        if self._eof:                        # also release any backpressured writer
            self._wake_all(self._wwaiters)

    def _feed_closed(self):
        self._eof = True
        self._wake_all(self._rwaiters)
        self._wake_all(self._wwaiters)       # a writer must wake to see the reset

    def _feed_writable(self):
        self._wake_all(self._wwaiters)

    # --- async API ---
    async def read(self, n=65536):
        while not self._rbuf and not self._eof:
            fut = asyncio.get_event_loop().create_future()
            self._rwaiters.append(fut)
            await fut
        if self._rbuf:
            data = bytes(self._rbuf[:n])
            del self._rbuf[:n]
            return data
        return b""                          # EOF

    async def write(self, data):
        mv = memoryview(data)
        while mv:
            r = self._raw.send_nb(mv)        # raises OSError on a dead stream
            if r is None:                    # send buffer full: await WRITABLE/close
                if self._eof:
                    raise ConnectionResetError("stream closed")
                fut = asyncio.get_event_loop().create_future()
                self._wwaiters.append(fut)
                await fut
                continue
            mv = mv[r:]

    @property
    def meta(self):
        return self._raw.meta

    def close(self):
        self._raw.close()


async def serve(peer, handler, *, max_events=512):
    """Drive `peer` on the running loop, spawning `handler(MuxStream)` per stream.
    Runs until cancelled; closes the peer on exit."""
    loop = asyncio.get_event_loop()
    streams = {}                            # id(raw) -> MuxStream
    done = loop.create_future()

    def on_ready():
        for raw, events in peer.poll(max_events):
            if events & muxpeer.ACCEPT:
                ms = MuxStream(raw)
                streams[id(raw)] = ms

                async def run(ms=ms, raw=raw):
                    try:
                        await handler(ms)
                    except Exception:        # noqa: BLE001 - keep the loop alive
                        pass
                    finally:
                        ms.close()
                        streams.pop(id(raw), None)

                loop.create_task(run())
            else:
                ms = streams.get(id(raw))
                if ms is None:
                    continue
                if events & (muxpeer.READABLE | muxpeer.CLOSED):
                    ms._feed_readable()
                if events & muxpeer.CLOSED:
                    ms._feed_closed()
                if events & muxpeer.WRITABLE:
                    ms._feed_writable()

    fd = peer.fileno()
    loop.add_reader(fd, on_ready)
    try:
        await done                          # until cancelled
    finally:
        loop.remove_reader(fd)
        peer.close()
