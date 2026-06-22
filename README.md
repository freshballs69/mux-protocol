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

## Running it

A complete proxy: `client → edge:accept-port → mux tunnel → edge-peer → backend`.

```sh
# backend (anything TCP; here a static file server)
python3 -m http.server 18080

# edge: public on :5000, uplink listener on :5001
./build/edge --accept-port 5000 --mux-port 5001 --token s3cr3t

# edge-peer: dials the edge, forwards each stream to the backend
./build/edge-peer --connect 127.0.0.1:5001 --backend 127.0.0.1:18080 --token s3cr3t

curl http://127.0.0.1:5000/        # flows through the mux to the backend
```

The pre-shared `--token` (or `MUX_TOKEN` env) is proven on both ends via
HMAC-SHA256 over the peer's HELLO nonce. Verified end-to-end: 4 MiB and 8
concurrent transfers are byte-perfect under ASan/UBSan.

> macOS note: port 5000 is taken by AirPlay; use another for local testing.

## Status

| Milestone | State |
|-----------|-------|
| 1. Framing codec + TLV + fuzz | ✅ done |
| 2. Session state machine | ✅ done |
| 3. Session-level flow control + memory cap | ✅ done (folded into 2) |
| —  Adversarial review pass (18 findings fixed) | ✅ done |
| —  PSK tunnel auth (HMAC-SHA256) | ✅ done |
| 5. edge daemon (`poll()`) | ✅ done (MVP) |
| 6. edge-peer (single backend; no SWRR yet) | ✅ done (MVP) |
| 4. libpeer worker SDK | ⬜ next |
| 6b. SWRR balancing + multi-worker | ⬜ |
| 7. TLS/Noise transport wrapper | ⬜ |

> Event loop: uses portable `poll()` (runs on Linux and macOS).
> `epoll`/`io_uring`/`kqueue` + `splice` are a later throughput milestone.
