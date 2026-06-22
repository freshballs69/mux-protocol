#!/usr/bin/env python3
"""Multi-core async HTTP load generator (pure Python, stdlib + optional uvloop).

Forks one process per core; each runs an asyncio loop driving its share of the
concurrency as connect -> GET -> read -> close loops, until the duration ends.
Aggregates throughput and latency percentiles across all processes.

    python3 loadbench.py --target 127.0.0.1:15000 -c 4000 -d 12 -p $(nproc)
"""
import argparse
import asyncio
import ipaddress
import math
import multiprocessing as mp
import struct
import time

REQ = b"GET / HTTP/1.1\r\nHost: bench\r\nConnection: close\r\n\r\n"
REQ_KA = b"GET / HTTP/1.1\r\nHost: bench\r\n\r\n"   # keep-alive (no close)
NB = 256  # latency histogram buckets, log scale (factor 2^(1/8))


def parse_proxy(s):
    """'user:pass@host:port' -> (user, pass, host, port). Auth optional."""
    s = s.strip()
    if not s:
        return None
    user = pw = None
    if "@" in s:
        cred, s = s.rsplit("@", 1)
        if ":" in cred:
            user, pw = cred.split(":", 1)
        else:
            user = cred
    host, port = s.rsplit(":", 1)
    return (user, pw, host, int(port))


def _socks5_addr(host, port):
    try:
        ip = ipaddress.ip_address(host)
        addr = (b"\x01" + ip.packed) if ip.version == 4 else (b"\x04" + ip.packed)
    except ValueError:
        h = host.encode(); addr = b"\x03" + bytes([len(h)]) + h
    return addr + struct.pack("!H", port)


async def _socks5_connect(proxy, dst_host, dst_port):
    """Open a SOCKS5 (RFC1928) tunnel via `proxy` to dst, return (reader,writer).

    Strict request/reply turn-taking: greeting -> auth (RFC1929) -> CONNECT, each
    waiting for its reply. NOTE: optimistic pipelining (blasting all three plus
    the request in one write) was tried and these commercial proxies time out on
    it — they discard bytes received before they've answered the prior step. So
    we pay the per-step round trip to the proxy.
    """
    user, pw, phost, pport = proxy
    reader, writer = await asyncio.open_connection(phost, pport)
    writer.write(b"\x05\x01\x02")                        # offer only user/pass
    await writer.drain()
    ver, method = await reader.readexactly(2)
    if ver != 0x05 or method != 0x02:
        raise OSError("socks5 no user/pass")
    u = (user or "").encode(); p = (pw or "").encode()
    writer.write(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
    await writer.drain()
    _, status = await reader.readexactly(2)
    if status != 0x00:
        raise OSError("socks5 auth rejected")
    writer.write(b"\x05\x01\x00" + _socks5_addr(dst_host, dst_port))
    await writer.drain()
    _, rep, _, atyp = await reader.readexactly(4)
    if rep != 0x00:
        raise OSError("socks5 connect rep=%d" % rep)
    if atyp == 0x01:
        await reader.readexactly(4 + 2)
    elif atyp == 0x04:
        await reader.readexactly(16 + 2)
    elif atyp == 0x03:
        ln = (await reader.readexactly(1))[0]
        await reader.readexactly(ln + 2)
    return reader, writer


async def _open(host, port, proxy, payload=b""):
    """Return (reader, writer, sent). `sent` is always False here (these proxies
    reject pipelining), so the caller writes the request itself."""
    if proxy is None:
        reader, writer = await asyncio.open_connection(host, port)
    else:
        reader, writer = await _socks5_connect(proxy, host, port)
    return reader, writer, False


def _bucket(us):
    if us < 1:
        us = 1
    b = int(math.log2(us) * 8)
    return 0 if b < 0 else (NB - 1 if b >= NB else b)


def _bucket_ms(b):
    return (2 ** (b / 8)) / 1000.0


async def _conn_loop(host, port, proxy, deadline, hist, count):
    while time.monotonic() < deadline:
        t0 = time.monotonic()
        try:
            reader, writer, sent = await _open(host, port, proxy, REQ)  # pipelined
            if not sent:
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


async def _conn_loop_ka(host, port, proxy, deadline, hist, count):
    """Keep-alive: one connection, many requests, no per-request connect churn.
    The first request is pipelined into the SOCKS handshake (optimistic)."""
    try:
        reader, writer, sent = await _open(host, port, proxy, REQ_KA)
    except Exception:
        count[1] += 1
        return
    first = True
    while time.monotonic() < deadline:
        t0 = time.monotonic()
        try:
            if not (first and sent):
                writer.write(REQ_KA)
                await writer.drain()
            first = False
            headers = await reader.readuntil(b"\r\n\r\n")
            cl = 0
            for line in headers.split(b"\r\n"):
                if line[:15].lower() == b"content-length:":
                    cl = int(line[15:].strip())
                    break
            if cl:
                await reader.readexactly(cl)
            count[0] += 1
            hist[_bucket((time.monotonic() - t0) * 1e6)] += 1
        except Exception:
            count[1] += 1
            break
    try:
        writer.close()
    except Exception:
        pass


async def _warm_then_burst(host, port, proxy, start_evt, settle, n_total,
                           burst_deadline, dur, hist, count):
    """Phase 1: open a keep-alive connection (full SOCKS handshake) and report
    ready. Phase 2: once every connection in the fleet is up, all fire requests
    in lockstep until the shared burst deadline — a true synchronized burst."""
    writer = None
    try:
        reader, writer, _ = await _open(host, port, proxy, REQ_KA)
    except Exception:
        count[1] += 1
    # mark this connection settled (up or failed); last one releases the burst.
    # Stamp the burst window BEFORE waking anyone so no worker reads deadline 0.
    settle[0] += 1
    if settle[0] >= n_total and not start_evt.is_set():
        burst_deadline[0] = time.monotonic() + dur
        start_evt.set()
    await start_evt.wait()
    if writer is None:
        return
    while time.monotonic() < burst_deadline[0]:
        t0 = time.monotonic()
        try:
            writer.write(REQ_KA)
            await writer.drain()
            headers = await reader.readuntil(b"\r\n\r\n")
            cl = 0
            for line in headers.split(b"\r\n"):
                if line[:15].lower() == b"content-length:":
                    cl = int(line[15:].strip()); break
            if cl:
                await reader.readexactly(cl)
            count[0] += 1
            hist[_bucket((time.monotonic() - t0) * 1e6)] += 1
        except Exception:
            count[1] += 1
            break
    try:
        writer.close()
    except Exception:
        pass


def _proc(host, port, dur, conc, q, keepalive, rampup, proxies, pidx, warmup=False, warm_timeout=45.0):
    try:
        import uvloop
        uvloop.install()
        loopname = "uvloop"
    except Exception:
        loopname = "asyncio"
    loopfn = _conn_loop_ka if keepalive else _conn_loop
    np = len(proxies) if proxies else 0

    async def run_warm():
        hist = [0] * NB
        count = [0, 0]
        start_evt = asyncio.Event()
        settle = [0]
        burst_deadline = [0.0]

        async def guard():                                # don't let dead proxies stall the burst
            await asyncio.sleep(warm_timeout)
            if not start_evt.is_set():
                burst_deadline[0] = time.monotonic() + dur
                start_evt.set()
        g = asyncio.ensure_future(guard())

        async def one(i):
            proxy = proxies[(pidx * conc + i) % np] if np else None
            await _warm_then_burst(host, port, proxy, start_evt, settle, conc,
                                   burst_deadline, dur, hist, count)

        await asyncio.gather(*[one(i) for i in range(conc)])
        g.cancel()
        return count, hist

    async def run():
        # Stagger connection opens across `rampup` seconds so 50k clients don't
        # all SYN at t=0 (a thundering herd that overflows the edge's accept
        # backlog). Real clients arrive spread over time; the deadline is pushed
        # out by rampup so every connection still gets the full duration.
        deadline = time.monotonic() + rampup + dur
        hist = [0] * NB
        count = [0, 0]                                 # [ok, err]

        async def staggered(i):
            if rampup > 0 and conc > 1:
                await asyncio.sleep(rampup * i / conc)
            # Spread connections across proxies (offset by process so the global
            # set is balanced); each conn sticks to one proxy = one source IP.
            proxy = proxies[(pidx * conc + i) % np] if np else None
            await loopfn(host, port, proxy, deadline, hist, count)

        await asyncio.gather(*[staggered(i) for i in range(conc)])
        return count, hist

    count, hist = asyncio.run(run_warm() if (warmup and keepalive) else run())
    q.put((count[0], count[1], hist, loopname))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="127.0.0.1:15000")
    ap.add_argument("-c", type=int, default=2000, help="total concurrency")
    ap.add_argument("-d", type=int, default=12, help="duration seconds")
    ap.add_argument("-p", type=int, default=mp.cpu_count(), help="processes (cores)")
    ap.add_argument("--keepalive", action="store_true", help="reuse connections (HTTP keep-alive)")
    ap.add_argument("--rampup", type=float, default=3.0, help="seconds to stagger connection opens over")
    ap.add_argument("--proxies", default="", help="SOCKS5 proxies user:pass@host:port, comma/space/newline separated")
    ap.add_argument("--proxy-file", default="", help="file with one SOCKS5 proxy per line")
    ap.add_argument("--warmup", action="store_true", help="open all keep-alive conns first, then fire requests in a synchronized burst")
    ap.add_argument("--warm-timeout", type=float, default=45.0, help="max seconds to wait for the connection fleet before bursting anyway")
    a = ap.parse_args()
    host, port = a.target.rsplit(":", 1)
    port = int(port)
    per = max(1, a.c // a.p)

    raw = a.proxies.replace(",", " ").split()
    if a.proxy_file:
        with open(a.proxy_file) as f:
            raw += f.read().split()
    proxies = [parse_proxy(s) for s in raw if s.strip()]
    if proxies:
        print("proxies         %d (each conn sticks to one -> %d source IPs)" % (len(proxies), len(proxies)))

    q = mp.Queue()
    procs = [mp.Process(target=_proc, args=(host, port, a.d, per, q, a.keepalive, a.rampup, proxies, i, a.warmup, a.warm_timeout))
             for i in range(a.p)]
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
    # in warmup mode the wall clock includes the (slow, proxy-bound) connect
    # phase; the actual burst window is exactly `-d` seconds, so rate it by that.
    rate_secs = float(a.d) if (a.warmup and a.keepalive) else secs

    total = sum(merged)

    def pct(pp):
        tgt = total * pp
        c = 0
        for b in range(NB):
            c += merged[b]
            if c >= tgt:
                return _bucket_ms(b)
        return _bucket_ms(NB - 1)

    print("\n================ loadbench (python/%s, %s) ================"
          % (loopname, "keep-alive" if a.keepalive else "close-per-req"))
    print("target          %s" % a.target)
    print("processes       %d   concurrency %d (%d/proc)" % (a.p, a.p * per, per))
    print("duration        %.1fs wall%s" % (secs, ("  (burst %.0fs)" % rate_secs) if rate_secs != secs else ""))
    print("completed       %d  (%.0f req/s)" % (ok, ok / rate_secs))
    print("errors          %d  (%.2f%%)" % (err, 100 * err / max(1, ok + err)))
    print("latency  p50    %.2f ms" % pct(0.50))
    print("         p90    %.2f ms" % pct(0.90))
    print("         p99    %.2f ms" % pct(0.99))
    print("         max   ~%.0f ms" % pct(0.999))
    print("=" * 56)


if __name__ == "__main__":
    main()
