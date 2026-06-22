#!/usr/bin/env python3
"""Multi-core async HTTP load generator (pure Python, stdlib + optional uvloop).

Forks one process per core; each runs an asyncio loop driving its share of the
concurrency as connect -> GET -> read -> close loops, until the duration ends.
Aggregates throughput and latency percentiles across all processes.

    python3 loadbench.py --target 127.0.0.1:15000 -c 4000 -d 12 -p $(nproc)
"""
import argparse
import asyncio
import math
import multiprocessing as mp
import time

REQ = b"GET / HTTP/1.1\r\nHost: bench\r\nConnection: close\r\n\r\n"
NB = 256  # latency histogram buckets, log scale (factor 2^(1/8))


def _bucket(us):
    if us < 1:
        us = 1
    b = int(math.log2(us) * 8)
    return 0 if b < 0 else (NB - 1 if b >= NB else b)


def _bucket_ms(b):
    return (2 ** (b / 8)) / 1000.0


async def _conn_loop(host, port, deadline, hist, count):
    while time.monotonic() < deadline:
        t0 = time.monotonic()
        try:
            reader, writer = await asyncio.open_connection(host, port)
            writer.write(REQ)
            await writer.drain()
            data = await reader.read(4096)            # first chunk has the status line
            while await reader.read(65536):           # drain to EOF (server closes)
                pass
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            if data[:12] == b"HTTP/1.1 200":
                count[0] += 1
                hist[_bucket((time.monotonic() - t0) * 1e6)] += 1
            else:
                count[1] += 1
        except Exception:
            count[1] += 1


def _proc(host, port, dur, conc, q):
    try:
        import uvloop
        uvloop.install()
        loopname = "uvloop"
    except Exception:
        loopname = "asyncio"

    async def run():
        deadline = time.monotonic() + dur
        hist = [0] * NB
        count = [0, 0]                                 # [ok, err]
        await asyncio.gather(*[_conn_loop(host, port, deadline, hist, count) for _ in range(conc)])
        return count, hist

    count, hist = asyncio.run(run())
    q.put((count[0], count[1], hist, loopname))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="127.0.0.1:15000")
    ap.add_argument("-c", type=int, default=2000, help="total concurrency")
    ap.add_argument("-d", type=int, default=12, help="duration seconds")
    ap.add_argument("-p", type=int, default=mp.cpu_count(), help="processes (cores)")
    a = ap.parse_args()
    host, port = a.target.rsplit(":", 1)
    port = int(port)
    per = max(1, a.c // a.p)

    q = mp.Queue()
    procs = [mp.Process(target=_proc, args=(host, port, a.d, per, q)) for _ in range(a.p)]
    t0 = time.monotonic()
    for p in procs:
        p.start()
    ok = err = 0
    merged = [0] * NB
    loopname = "asyncio"
    for _ in procs:
        o, e, h, loopname = q.get()
        ok += o
        err += e
        for i in range(NB):
            merged[i] += h[i]
    for p in procs:
        p.join()
    secs = time.monotonic() - t0

    total = sum(merged)

    def pct(pp):
        tgt = total * pp
        c = 0
        for b in range(NB):
            c += merged[b]
            if c >= tgt:
                return _bucket_ms(b)
        return _bucket_ms(NB - 1)

    print("\n================ loadbench (python/%s) ================" % loopname)
    print("target          %s" % a.target)
    print("processes       %d   concurrency %d (%d/proc)" % (a.p, a.p * per, per))
    print("duration        %.1fs" % secs)
    print("completed       %d  (%.0f req/s)" % (ok, ok / secs))
    print("errors          %d  (%.2f%%)" % (err, 100 * err / max(1, ok + err)))
    print("latency  p50    %.2f ms" % pct(0.50))
    print("         p90    %.2f ms" % pct(0.90))
    print("         p99    %.2f ms" % pct(0.99))
    print("         max   ~%.0f ms" % pct(0.999))
    print("=" * 56)


if __name__ == "__main__":
    main()
