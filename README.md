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

## Status

| Milestone | State |
|-----------|-------|
| 1. Framing codec + TLV + fuzz | ✅ done |
| 2. Session state machine | ✅ done |
| 3. Session-level flow control + memory cap | ✅ done (folded into 2) |
| 4. libpeer worker SDK | ⬜ next |
| 5. edge daemon (`poll()` v1) | ⬜ |
| 6. edge-peer router/balancer | ⬜ |

> Event loop: v1 uses portable `poll()` (runs on Linux and macOS).
> `epoll`/`io_uring`/`kqueue` + `splice` are a later throughput milestone.
