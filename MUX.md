# MUX — Distributed Stream Multiplexing System

> Specification for implementation. Hand to Claude Code milestone by milestone.

## 1. Overview

A transport-agnostic (TCP-primary) stream multiplexer that fans public ingress
landing on multiple internet-facing servers down to backend workers behind NAT,
multiplexing many logical streams over a small number of long-lived tunnels.

The design solves three concrete problems:

1. **Conntrack explosion** — a home/edge router dies tracking 200k public flows.
   By muxing everything into ~3 tunnels, intermediate routers see ~3 flows, not 200k.
2. **Balancing visibility** — all streams funnel through one aggregation point
   (`edge-peer`), which therefore has global inflight visibility per worker and
   can balance correctly without cross-node coordination.
3. **Uplink pacing** — running tunnels over TCP gives congestion control for free,
   so the tunnel paces to the bottleneck link instead of overrunning it (the
   failure mode of raw WireGuard/UDP).

### Non-goals (v1)
- No reliability layer of our own — we assume the transport gives an ordered,
  reliable byte stream (TCP/TLS/QUIC-stream). Datagram transports are out of scope.
- No built-in crypto — security is a transport wrapper (TLS/Noise), see §9.
- No multi-tenant isolation beyond per-tunnel auth.

## 2. Components & naming

| Component   | Lang        | Role                                                        | Links      |
|-------------|-------------|-------------------------------------------------------------|------------|
| `libmux`    | C11         | sans-io protocol core: framing codec + session state machine + flow control. Zero I/O, zero syscalls. | —          |
| `edge`      | C11 (epoll→io_uring) | VPS daemon. Public listener on :5000. Mux uplink to `edge-peer`. Stream **initiator** toward edge-peer. | `libmux`   |
| `edge-peer` | C11         | LAN daemon. Accepts tunnels from edges (stream **receiver**) and from workers. Balances + routes. Stream **initiator** toward workers. | `libmux`   |
| `libpeer`   | C11 + Go binding (CGo) | Worker-side SDK. Connects to `edge-peer`, exposes inbound logical streams to the app as conn-like objects. Stream **receiver**. | `libmux`   |

Language note: everything is C11 linking one `libmux` core, matching the
"C core + thin wrappers" approach and giving FFI for Go/Python worker apps.
The Go binding for `libpeer` is a milestone, not v1. Flip any of this if desired.

## 3. Topology & data flow

```
 public :5000      public :5000      public :5000
      |                 |                  |
  +---v----+        +---v----+         +---v----+
  | edge A |        | edge B |         | edge C |   terminate ~67k public sockets each
  +---+----+        +---+----+         +---+----+   mux each into ONE uplink tunnel
      |  tunnel         |  tunnel          |  tunnel   (TCP/TLS; pin to distinct NICs)
      +-----------------+------------------+
                  +-----v------+
                  | edge-peer  |   ~3 upstream + N downstream = ~few real fds
                  | (1 thread) |   holds 200k LOGICAL streams in userspace
                  +--+------+--+   balances streams across workers by weight
              tunnel |      | tunnel
            +--------v-+  +-v---------+
            | worker 1 |  | worker 2  |   embed libpeer; terminate streams into
            | w=8      |  | w=16      |   app logic directly (no unix-sock hop)
            +----------+  +-----------+
```

### Connection direction (configurable; defaults shown)
- `edge-peer` **dials** each `edge` (edges have public IPs; edge-peer is NAT'd).
- each `worker` (`libpeer`) **dials** `edge-peer`.
- The dialer is always the more-NAT'd side. The **stream initiator** is always the
  more-public side, because public ingress flows downward. These are independent:
  who dials TCP ≠ who opens logical streams.

### Stream mapping (1:1:1:1)
```
public TCP conn  <->  upstream stream (edge<->edge-peer)
                 <->  downstream stream (edge-peer<->worker)
                 <->  app handler (worker, via libpeer)
```
`edge-peer` maintains a bidirectional map:
`(upstream_session, upstream_sid) <-> (downstream_session, downstream_sid)`.
It is a stream-ID router/NAT — upstream and downstream IDs differ.

### Metadata propagation
On stream open, the SYN frame payload carries a TLV metadata block (PROXY-protocol-v2
or custom TLV): original client `src ip:port`, `dst`, SNI/ALPN. It flows
edge → edge-peer → worker so the app sees the real client, not the tunnel endpoint.

## 4. libmux — protocol core (definitive)

`libmux` is **sans-io**: it consumes byte buffers + timer ticks and produces byte
buffers + events. It never touches sockets or clocks. The host loop does all I/O.

### 4.1 Wire format

12-byte header, big-endian:

```
 0       1       2       3
+-------+-------+---------------+
|  Ver  | Type  |  Flags (2B)   |
+-------+-------+-------+-------+
|        Stream ID (4B)         |
+-------------------------------+
|         Length (4B)           |   length of payload that follows
+-------------------------------+
|        Payload (Length)       |
+-------------------------------+
```

- `Ver` = 0x01.
- `Length` capped (e.g. 16 MiB) — reject larger as a protocol error (anti-DoS).
- Big-endian load/store MUST be byte-wise (no unaligned `*(uint32_t*)` casts).

**Types**
```
0x00 DATA           payload = stream bytes
0x01 WINDOW_UPDATE  payload = uint32 credit (bytes)
0x02 PING           payload = 8B opaque; ACK flag = echo
0x03 GOAWAY         payload = uint32 reason + uint32 last_stream_id
0x10 HELLO          control (stream id MUST be 0): TLV
0x11 HELLO_ACK      control: TLV
0x12 CAPACITY       control: uint32 new_weight (0 = draining)
```

**Flags** (bitfield, applied on DATA / WINDOW_UPDATE)
```
0x0001 SYN   open stream
0x0002 ACK   acknowledge open
0x0004 FIN   half-close (no more data this direction)
0x0008 RST   abort stream
```

**Control-plane TLV** (payload of HELLO/HELLO_ACK/CAPACITY): `type:u16 | len:u16 | value`.
```
0x0001 PEER_ID       opaque
0x0002 WEIGHT        u32   (advertised cores/threads; balancing weight)
0x0003 MAX_STREAMS   u32   (concurrency cap negotiated by HELLO_ACK)
0x0004 AUTH          HMAC(token, session_nonce)
0x0005 INIT_WINDOW   u32   (per-stream initial flow-control window)
0x0006 HEARTBEAT_MS  u32
```

### 4.2 Stream lifecycle
- `DATA|SYN` opens a stream. Payload = metadata TLV only (may be empty); the stream
  body starts in subsequent DATA frames. Keeps the SYN parser trivial.
- `DATA|ACK` optionally confirms open (lets initiator learn early failure).
- `DATA|FIN` half-closes one direction → maps to `shutdown(SHUT_WR)`. Stream is fully
  closed only after FIN in both directions. **Half-close MUST be honored per-direction.**
- `DATA|RST` aborts. Receiving RST frees stream state immediately.

### 4.3 Flow control
- **Per-stream sliding window**, default 256 KiB (negotiable via INIT_WINDOW). Receiver
  credits bytes via WINDOW_UPDATE as the **application consumes** them (not as bytes
  arrive). Sender blocks a stream at window 0 without blocking other streams.
- **Session-level window / global byte cap** (required at the 200k-stream scale):
  cap total in-flight bytes across all streams of a session so 200k streams cannot
  each grab their per-stream window and OOM the process. Pause/resume at high/low
  watermarks. Negotiate `MAX_STREAMS`.
- No per-stream buffer is pre-allocated. Use a shared pool; allocate in-flight bytes
  lazily. (200k × 256 KiB eager = ~51 GiB = death.)

### 4.4 Stream ID allocation
The TCP dialer uses odd IDs, the acceptor uses even, to avoid collisions on a
symmetric/bidirectional session. ID 0 is reserved for control frames.

### 4.5 Keepalive & teardown
- PING every `HEARTBEAT_MS`; peer echoes with ACK. Missing echo past timeout → session dead.
- GOAWAY for graceful drain: stop opening streams above `last_stream_id`, finish active,
  then close transport.

### 4.6 sans-io API (C)

The codec layer (framing) is already started; this is the full core surface:

```c
/* --- framing codec (stateless, zero-copy) --- */
int  mux_parse(const uint8_t *buf, size_t len, mux_frame_t *out, size_t *consumed);
int  mux_craft_header(uint8_t *dst, size_t cap, uint8_t type, uint16_t flags,
                      uint32_t sid, uint32_t payload_len);
int  mux_craft(uint8_t *dst, size_t cap, uint8_t type, uint16_t flags,
               uint32_t sid, const uint8_t *payload, uint32_t plen);
/* TLV helpers for control payloads */
int  mux_tlv_put(uint8_t *buf, size_t cap, size_t off, uint16_t t,
                 const void *val, uint16_t vlen);
int  mux_tlv_next(const uint8_t *buf, size_t len, size_t *cursor,
                  uint16_t *t, const uint8_t **val, uint16_t *vlen);

/* --- session state machine (sans-io) --- */
typedef struct mux_session mux_session;

mux_session *mux_session_new(const mux_config *cfg, mux_role role); /* role: DIALER/ACCEPTOR */
void         mux_session_free(mux_session *s);

/* IN: bytes from transport -> parses frames, queues events */
int  mux_recv(mux_session *s, const uint8_t *buf, size_t len);
/* IN: application actions */
int      mux_open(mux_session *s, const uint8_t *meta, size_t meta_len); /* -> stream id, or <0 */
int      mux_write(mux_session *s, uint32_t sid, const uint8_t *p, size_t n); /* bounded by window */
void     mux_close(mux_session *s, uint32_t sid);   /* FIN */
void     mux_reset(mux_session *s, uint32_t sid);   /* RST */
void     mux_consume(mux_session *s, uint32_t sid, size_t n); /* app consumed -> WINDOW_UPDATE */
/* IN: time supplied externally */
uint64_t mux_on_timer(mux_session *s, uint64_t now_ms); /* -> next deadline ms */

/* OUT: bytes to push to transport (zero-copy view; advance after send) */
const uint8_t *mux_send_buf(mux_session *s, size_t *len);
void           mux_send_advance(mux_session *s, size_t n);
/* OUT: events produced by the core */
int  mux_next_event(mux_session *s, mux_event *ev); /* 1 = event, 0 = none */
```

**Events** surfaced via `mux_next_event`:
```
STREAM_OPENED { sid, meta_ptr, meta_len }   /* receiver: open downstream / dial app */
STREAM_DATA   { sid, data_ptr, data_len }   /* zero-copy view into recv buffer */
STREAM_CLOSED { sid }                        /* FIN received */
STREAM_RESET  { sid }
PEER_HELLO    { weight, peer_id, max_streams }
CAPACITY      { weight }                      /* 0 = draining */
GOAWAY        { reason, last_sid }
FATAL         { code }
```

**Invariants**: no malloc in steady-state hot path; payload pointers are valid until
the caller advances/overwrites the recv buffer (lifetime is the caller's job);
the core performs no semantic policy (e.g. "control frame must use sid 0" is enforced
here as a frame error, but routing/balancing decisions live in the daemons).

## 5. libpeer — worker SDK

Thin ergonomic layer over `libmux` for worker apps. Goal: the app's existing
per-connection handler (which expects a conn to Read/Write) works unchanged.

```c
typedef struct lp_client lp_client;
typedef struct lp_stream lp_stream;   /* conn-like: implements read/write/close */

lp_client *lp_connect(const lp_config *cfg);  /* dials edge-peer; HELLO w/ weight+auth */
/* blocking accept of next inbound stream (edge-peer initiated) */
lp_stream *lp_accept(lp_client *c);
ssize_t    lp_read (lp_stream *s, void *buf, size_t n);   /* blocks on per-stream queue */
ssize_t    lp_write(lp_stream *s, const void *buf, size_t n); /* bounded by window */
int        lp_close(lp_stream *s);                         /* FIN */
const uint8_t *lp_stream_meta(lp_stream *s, size_t *len);  /* client src/dst/SNI */
```

Responsibilities: connect + HELLO (advertised weight = configured threads, auth),
auto-reconnect with exponential backoff + jitter, surface inbound streams, map a
stream to a conn-like handle, translate app consumption to WINDOW_UPDATE,
CAPACITY/drain on graceful shutdown.

**Threading**: idiomatic one-handler-per-stream is fine to hundreds of thousands of
streams (Go goroutine ~2-4 KiB; 133k ≈ 270-530 MiB). Provide an event-driven /
bounded-pool mode for when profiling shows scheduler/stack pressure.

**Go binding** (milestone): `lp_stream` exposed as a type implementing `net.Conn`
(Read/Write/Close/Deadlines), so existing Go handlers accept it in place of a socket.

## 6. edge — VPS daemon

Responsibilities:
- Listen on configured public addr(s) (default :5000). Accept public TCP.
- Maintain one (or few) uplink tunnel(s) to `edge-peer` (dial or accept per config).
  Tunnel is a `libmux` session; **edge is the stream initiator**.
- On public accept: build metadata TLV (PROXY v2 / src,dst,SNI), `mux_open` on the
  uplink, then pipe bytes both ways between public socket and logical stream.
- Map per-direction half-close (public FIN → stream FIN; stream FIN → public shutdown).
- RST mapping: stream RST → close public conn (and vice versa).
- If the uplink dies: close all public conns it was carrying; reconnect with backoff.
- Backpressure: only read from a public socket when the stream's send window allows;
  only write to a public socket as fast as it drains.

Config: public listen addrs, edge-peer addr + connect direction, auth token,
TLS/Noise material, per-stream init window, heartbeat interval.

I/O backend: epoll for v1; io_uring as a later milestone (batched submit/complete).

## 7. edge-peer — LAN router & balancer

The aggregation point. Responsibilities:
- Accept (or dial) tunnels from edges — **stream receiver** on these.
- Accept tunnels from workers (via `libpeer`) — **stream initiator** on these;
  record each worker's advertised `WEIGHT` from HELLO and a live `inflight` counter.
- For each upstream `STREAM_OPENED`: pick a worker (balancing, below), `mux_open` on
  that worker's downstream session forwarding the metadata TLV, and record the
  bidirectional stream-ID mapping. Then pipe STREAM_DATA both ways by table lookup.
- Propagate FIN/RST across the mapping in both directions; on full close, drop the
  mapping and decrement worker `inflight`.

### 7.1 Balancing (defining feature)
- **v1: smooth weighted round-robin (SWRR)** over `WEIGHT` (nginx algorithm:
  deterministic, no bursts). On open: `inflight[w]++`; on close/reset: `inflight[w]--`.
- **v2: P2C (power of two choices) + load**: sample 2 workers weighted by `WEIGHT`,
  pick the one with the lower `inflight / WEIGHT` (optionally EWMA RTT from PINGs).
- **Draining**: worker sends `CAPACITY weight=0` → removed from the new-stream pool;
  existing streams continue until closed. Enables zero-drop deploys.
- **Worker death** (session dead / PING timeout): remove from pool; RST all its
  inflight streams; the RST propagates upstream → edge closes the public conn.

### 7.2 Single-thread router constraint
`edge-peer` is a **pure stream router**: it never terminates streams into sockets, so
it holds only ~few real fds (upstream + downstream tunnels) and 200k logical streams
as userspace state. One thread suffices because cost is throughput-bound (memcpy +
frame parse + table lookup), not connection-bound. Steady state must avoid per-stream
heap allocation (pool stream-map entries) and use zero-copy payload views. epoll v1,
io_uring + `splice` for the high-throughput milestone.

Config: edge listen/connect, worker listen/connect, balancing policy, auth,
TLS/Noise material, global memory cap, MAX_STREAMS per session.

## 8. Optional: global capacity reporting (balancing upgrade)
Because all streams funnel through one `edge-peer`, local balancing is already global.
If you later run **multiple** edge-peers (HA), workers periodically broadcast their
total inflight via `CAPACITY` (effective residual weight) so each edge-peer balances
on real global load, not static weight.

## 9. Transport & security
- `libmux` is crypto-agnostic. Tunnels run inside a transport wrapper:
  TLS (mutual) or Noise (XX, mutual auth). Application data is the tunnel byte stream.
- Per-tunnel auth in HELLO: `AUTH = HMAC(shared_token, session_nonce)`. Reject on mismatch.
- Public input is hostile: fuzz the framing parser hard; sandbox `edge` and worker
  processes (seccomp/namespaces) as units rather than splitting into more processes.
- WireGuard alternative: if used instead of TCP/TLS, the lack of congestion control
  must be compensated with egress shaping (`tc cake bandwidth ~0.9*uplink`) and correct
  MTU (1420) to avoid the "sends faster than the link" loss. TCP/TLS is preferred for
  the bottlenecked uplink because it self-paces.
- Multi-NIC: pin distinct tunnels to distinct interfaces (policy routing) to aggregate
  uplinks at tunnel granularity without MPTCP.

## 10. Observability
- Metrics (Prometheus-style): active streams (global + per worker), per-worker inflight
  and weight, bytes in/out per session, window-stall counts, reconnect counts,
  PING RTT, dropped/reset streams, memory-cap pauses.
- Structured logs with stream-id and session-id correlation.
- Optional debug STATS control frame.

## 11. Performance requirements
- `edge-peer`: 1 thread routes ≥200k concurrent logical streams over ~few fds;
  RAM in low hundreds of MiB with pooled buffers; no steady-state heap alloc.
- `edge` / worker (socket terminators): raise `ulimit -n` > target; tune small socket
  buffers (mux does its own flow control); shard accept with SO_REUSEPORT across cores.
- Zero-copy payload path end-to-end; io_uring/`splice` on the high-throughput milestone.

## 12. Repo layout
```
/libmux/        core: framing codec, session state machine, flow control  (C11)
  include/mux.h
  src/
/libpeer/       worker SDK over libmux (C11) + /go binding (CGo)
/edge/          VPS daemon
/edge-peer/     LAN router/balancer daemon
/tests/         unit, deterministic state-machine, fuzz, integration, load
/docs/
```
Build: CMake or Meson; `-Wall -Wextra -O2`; CI runs ASan + UBSan on unit/fuzz.

## 13. Implementation milestones (ordered, each independently testable)
1. **libmux framing codec** — header parse/craft, TLV, big-endian byte-wise,
   length cap. Unit round-trip + partial-feed + fuzz (ASan/UBSan).
2. **libmux session state machine** — open/data/fin/rst, per-stream flow control,
   ping, goaway, stream-id allocation. Deterministic sans-io tests
   (feed bytes → assert events + assert produced bytes; no sockets, no sleeps).
3. **libmux session-level flow control + global memory cap + MAX_STREAMS.**
4. **libpeer** — connect, HELLO/auth, reconnect/backoff, stream→conn API, drain.
5. **edge** — public listener, accept→open→pipe, half-close + RST mapping,
   single uplink tunnel, backpressure. epoll.
6. **edge-peer** — accept edge + worker tunnels, stream-id mapping table,
   SWRR balancing, draining, worker-death RST propagation. epoll. Single thread.
7. **Transport security** — TLS (mutual) or Noise wrapper; auth enforcement.
8. **Balancing v2** — P2C + load; optional global capacity reporting.
9. **io_uring backend** + `splice`/zero-copy for edge and edge-peer.
10. **Observability** — metrics, structured logs, STATS frame.
11. **libpeer Go binding** — `net.Conn` adapter via CGo.

## 14. Testing requirements
- **Unit**: codec round-trip, exact byte vectors, partial feed, oversized length,
  multiple frames in one buffer (drain loop).
- **Fuzz**: framing parser and TLV parser (libFuzzer) under ASan/UBSan.
- **Deterministic state-machine**: drive `mux_session` purely via `mux_recv` +
  actions + `mux_on_timer`; assert event sequence and output bytes byte-for-byte.
  Cover half-close races, window=0, RST during SYN, GOAWAY mid-stream.
- **Integration**: spin `edge` + `edge-peer` + fake workers; push N streams; assert
  routing, weighted distribution, half-close correctness, backpressure, draining,
  worker-death RST propagation.
- **Load**: ramp toward 200k concurrent streams; verify edge-peer single-thread
  headroom, memory ceiling, no steady-state allocation.