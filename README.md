# mux

A transport-agnostic (TCP-primary) stream multiplexer that fans public ingress
landing on internet-facing servers down to backend workers behind NAT,
multiplexing many logical streams over a few long-lived tunnels.

See [`MUX.md`](MUX.md) for the original directional sketch. This README tracks
what is **actually built**.

## Why

- **Conntrack survival** — mux 200k public flows into ~3 tunnels so intermediate
  routers track ~3 flows instead of 200k.
- **Global balancing** — all streams funnel through one aggregation point with
  per-worker inflight visibility, so it balances correctly with no cross-node
  coordination.
- **Free pacing** — tunnels over TCP get congestion control for free; the tunnel
  paces to the bottleneck instead of overrunning it.

## Layout

```
libmux/        sans-io protocol core (C11): framing codec + session state machine
  include/mux.h
  src/frame.c    12-byte big-endian wire codec + TLV helpers
  src/session.c  stream lifecycle, two-level flow control, keepalive, handshake
tests/         unit + deterministic state-machine + fuzz
  test_frame.c   codec round-trip, golden bytes, partial feed, drain loop
  test_session.c two sessions wired through an in-memory pump
  fuzz/          libFuzzer target (+ portable standalone driver)
```

## Build & test

Requires a C11 compiler, CMake ≥ 3.20 and Ninja.

```sh
cmake -S . -B build -G Ninja          # Debug + ASan/UBSan by default
cmake --build build
ctest --test-dir build --output-on-failure
```

The build is sanitized (ASan + UBSan) and warning-clean under
`-Wall -Wextra -Wconversion -Wsign-conversion`.

### Fuzzing

The fuzz target uses the standard libFuzzer entry point. With a libFuzzer-capable
toolchain (mainline clang, or `brew install llvm`) CMake links a coverage-guided
binary; otherwise it builds a portable standalone driver (random-feed + corpus
replay) that still runs under ASan/UBSan via `ctest`. Direct campaign:

```sh
build/tests/fuzz_frame -max_len=512        # libFuzzer mode
build/tests/fuzz_frame corpus/*            # replay (either mode)
```

## libmux core

`libmux` is **sans-io**: it consumes transport bytes (`mux_recv`) and time
(`mux_on_timer`) and produces transport bytes (`mux_send_buf`) and events
(`mux_next_event`). It owns no sockets and no clock — the host loop does all I/O.

Notable design decisions (some deliberately diverge from `MUX.md`):

- **Two-level flow control, HTTP/2 style.** Per-stream windows *and* a
  connection-level window carried on stream id 0. Every DATA byte is debited from
  both, so N streams can never collectively buffer more than the connection cap —
  this is what bounds memory at 200k streams. `WINDOW_UPDATE` is batched at the
  half-window watermark.
- **`WRITABLE` event** for backpressure: the host learns when a window-0 stream
  can send again (not in the original sketch, but required for correct
  pause/resume).
- **Crypto-agnostic auth.** The core carries `AUTH`/`NONCE` TLVs opaquely and
  surfaces them on the `PEER_HELLO` event; HMAC verification lives in the daemon.
- **Zero-copy payload views.** `STREAM_DATA`/`STREAM_OPENED` point into the recv
  buffer and are valid until the next `mux_recv`.

## Topology

```
client ─▶ edge :accept-port ──mux tunnel──▶ edge-peer ──┬─▶ worker (libpeer) weight 1
          (public, terminates             (router,      ├─▶ worker (libpeer) weight 3
           public sockets)                 SWRR balance) └─▶ worker (libpeer) ...
```

- **edge** terminates public TCP and opens one logical stream per connection
  over the uplink tunnel. It is the stream initiator.
- **edge-peer** dials the edge (upstream) and a pool of workers (downstream),
  SWRR-balancing each inbound stream onto a worker by advertised weight and
  splicing stream↔stream with flow-control-coupled backpressure.
- **workers** embed `libpeer` (or the Python `muxpeer` binding) and terminate
  streams as socket-like conns over ONE tunnel fd — no per-connection fds.
  Each replica binds its own unix socket (the supervisord/`numprocs` model), so
  the worker pool is "a global SO_REUSEPORT across machines" with edge-peer
  doing the weighted balancing.

## Running the demo

```sh
cmake -S . -B build -G Ninja && cmake --build build
cd python && uv run --with setuptools python setup.py build_ext --inplace && cd ..
./deploy/run_demo.sh        # two Python workers (weights 1:3), 40 requests
# => ~10 handled by PY0, ~30 by PY1
```

A Python worker is just:

```python
import muxpeer
peer = muxpeer.listen("/run/app_00.sock", token="s3cr3t", id="W0", weight=4)
while (conn := peer.accept()) is not None:
    conn.recv(65536)                 # request; blocking, releases the GIL
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
    conn.close()
```

The pre-shared `--token` (or `MUX_TOKEN`) is proven on every tunnel via
HMAC-SHA256 over the peer's HELLO nonce. See `deploy/supervisord.conf` for the
N-replicas-one-socket-each deployment.

> macOS note: port 5000 is taken by AirPlay; the demo uses 15000/15001.

### Docker

Two images: `Dockerfile` builds the C daemons (`edge`/`edge-peer`/`http_worker`),
and `examples/python-app/Dockerfile` builds the Python backend — its own image
where `supervisord` runs four worker replicas, each binding its own
`/sockets/app_NN.sock`. Inside Linux containers the relay uses `epoll`.

```sh
MUX_TOKEN=s3cr3t docker compose -f deploy/docker-compose.yml up --build
curl localhost:8080/        # -> "hello from W0x ...", balanced across replicas
```

`deploy/docker-compose.yml` wires three services — **edge** (public), **app**
(the supervisord/4-replica Python image), and **edge-peer** (dials the edge and
each worker socket) — with the worker unix sockets on a volume shared between
`app` and `edge-peer`. Verified in-container: 40 requests split 10/10/10/10
across the replicas; 600 at 100-way concurrency all return 200.

## Status

| Piece | State |
|-------|-------|
| 1. Framing codec + TLV + fuzz | ✅ |
| 2. Session state machine | ✅ |
| 3. Two-level flow control + memory cap | ✅ |
| Adversarial review pass (18 findings fixed) | ✅ |
| PSK tunnel auth (HMAC-SHA256) | ✅ |
| 4. libpeer worker SDK (blocking, threaded) + unix listen | ✅ |
| Python `muxpeer` binding | ✅ |
| 5. edge daemon (epoll/kqueue event loop) | ✅ |
| 6. edge-peer router + SWRR balancing | ✅ |
| edge scalability: O(ready) loop + raised fd limit | ✅ |
| libpeer event-loop/selector API (`fileno`/`poll`) | ⬜ |
| 7. TLS/Noise transport wrapper | ⬜ |
| 8. P2C balancing + global capacity reporting | ⬜ |
| 9. io_uring/`splice` zero-copy backend | ⬜ |

> Event loop: `edge`/relay use `epoll` (Linux) / `kqueue` (macOS/BSD) via a small
> `evloop` shim — O(ready) per wait, so one thread holds tens of thousands of
> sockets. Daemons raise `RLIMIT_NOFILE`. `io_uring` + `splice` are a later
> throughput milestone; the edge-peer router still uses `poll()` (few fds).
