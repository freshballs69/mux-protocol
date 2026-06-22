/* libmux — sans-io stream multiplexing protocol core.
 *
 * This header declares the framing codec (milestone 1): a stateless,
 * zero-copy encoder/decoder for the 12-byte wire header plus TLV helpers
 * for control-frame payloads. The session state machine is layered on top
 * in later milestones and added to this header as it lands.
 *
 * Conventions:
 *   - All multi-byte wire fields are big-endian and accessed byte-wise
 *     (no unaligned word casts), so the codec is portable to any alignment.
 *   - The codec performs ZERO allocation and ZERO I/O. Callers own all
 *     buffers; decoded payload pointers are views into the caller's input.
 */
#ifndef MUX_H
#define MUX_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Wire constants                                                     */
/* ------------------------------------------------------------------ */

#define MUX_VERSION      0x01u
#define MUX_HEADER_SIZE  12u            /* ver+type+flags+sid+length     */
#define MUX_MAX_PAYLOAD  (16u * 1024u * 1024u)  /* 16 MiB hard cap       */

/* Control frames (HELLO/HELLO_ACK/CAPACITY/GOAWAY/PING) and any frame
 * that addresses the session itself rather than a logical stream use
 * stream id 0, which is reserved and never allocated to a stream. */
#define MUX_SID_CONTROL  0u

/* Frame types (header byte 1). */
enum mux_type {
    MUX_T_DATA          = 0x00, /* payload = stream bytes                    */
    MUX_T_WINDOW_UPDATE = 0x01, /* payload = u32 credit (bytes)              */
    MUX_T_PING          = 0x02, /* payload = 8B opaque; ACK flag = echo      */
    MUX_T_GOAWAY        = 0x03, /* payload = u32 reason + u32 last_stream_id */
    MUX_T_HELLO         = 0x10, /* control (sid 0): TLV                      */
    MUX_T_HELLO_ACK     = 0x11, /* control: TLV                             */
    MUX_T_CAPACITY      = 0x12  /* control: u32 new_weight (0 = draining)    */
};

/* Frame flags (header bytes 2-3, bitfield). Meaningful on DATA / WINDOW_UPDATE. */
enum mux_flag {
    MUX_F_SYN = 0x0001, /* open stream                                  */
    MUX_F_ACK = 0x0002, /* acknowledge open (also PING echo)            */
    MUX_F_FIN = 0x0004, /* half-close: no more data this direction      */
    MUX_F_RST = 0x0008  /* abort stream                                 */
};

/* Control-plane TLV types (payload of HELLO/HELLO_ACK/CAPACITY). */
enum mux_tlv_type {
    MUX_TLV_PEER_ID        = 0x0001, /* opaque                               */
    MUX_TLV_WEIGHT         = 0x0002, /* u32 advertised balancing weight      */
    MUX_TLV_MAX_STREAMS    = 0x0003, /* u32 concurrency cap                  */
    MUX_TLV_AUTH           = 0x0004, /* opaque HMAC(token, nonce) blob       */
    MUX_TLV_INIT_WINDOW    = 0x0005, /* u32 per-stream initial window        */
    MUX_TLV_HEARTBEAT_MS   = 0x0006, /* u32                                  */
    MUX_TLV_SESSION_WINDOW = 0x0007, /* u32 connection-level initial window  */
    MUX_TLV_NONCE          = 0x0008  /* opaque challenge nonce               */
};

/* GOAWAY reasons and RST/stream error codes (shared space). */
enum mux_code {
    MUX_CODE_NO_ERROR      = 0,
    MUX_CODE_PROTOCOL      = 1, /* malformed/illegal frame for the state     */
    MUX_CODE_FLOW_CONTROL  = 2, /* peer exceeded an advertised window        */
    MUX_CODE_STREAM_LIMIT  = 3, /* MAX_STREAMS exceeded                      */
    MUX_CODE_INTERNAL      = 4, /* local failure (e.g. out of stream slots)  */
    MUX_CODE_REFUSED       = 5  /* stream refused (e.g. after GOAWAY)        */
};

/* ------------------------------------------------------------------ */
/* Return codes                                                       */
/* ------------------------------------------------------------------ */
/* Codec functions return >= 0 on success (bytes written, or 0/1 where
 * documented) and one of these negative codes on failure. MUX_ERR_SHORT
 * is NOT a hard failure: it means "feed me more bytes and retry", which
 * lets a host loop drive the parser straight off a partially filled
 * socket buffer. MUX_ERR_PROTO is fatal for the session. */
enum mux_err {
    MUX_OK          =  0,
    MUX_ERR_SHORT   = -1, /* truncated input; need more bytes (not fatal)   */
    MUX_ERR_PROTO   = -2, /* protocol violation: bad version / oversized    */
    MUX_ERR_NOSPACE = -3, /* destination buffer too small                   */
    MUX_ERR_PARAM   = -4, /* invalid argument                               */
    MUX_ERR_STATE   = -5, /* operation illegal in the current state         */
    MUX_ERR_NOMEM   = -6, /* allocation failed / stream-table full          */
    MUX_ERR_NOSTREAM= -7  /* referenced stream id does not exist            */
};

/* ------------------------------------------------------------------ */
/* Framing codec (stateless, zero-copy)                               */
/* ------------------------------------------------------------------ */

/* A decoded frame. `payload` is a view into the buffer passed to
 * mux_parse and is valid only as long as that buffer is unmodified.
 * `payload` is NULL when `len` is 0. */
typedef struct {
    uint8_t        ver;
    uint8_t        type;
    uint16_t       flags;
    uint32_t       sid;
    uint32_t       len;     /* payload length (bytes following the header) */
    const uint8_t *payload; /* view into caller's input; NULL if len == 0  */
} mux_frame_t;

/* Parse one frame from the front of [buf, buf+len).
 *   - On a complete frame: fills *out, sets *consumed to the total bytes
 *     of header+payload, returns MUX_OK.
 *   - If fewer than a full header+payload are present: returns
 *     MUX_ERR_SHORT and leaves out/consumed untouched. Retry with more.
 *   - On bad version or payload length above MUX_MAX_PAYLOAD: returns
 *     MUX_ERR_PROTO.
 * `out` and `consumed` may not be NULL. */
int mux_parse(const uint8_t *buf, size_t len, mux_frame_t *out, size_t *consumed);

/* Write just the 12-byte header into [dst, dst+cap). Returns the number
 * of bytes written (MUX_HEADER_SIZE) on success, MUX_ERR_NOSPACE if cap
 * is too small, or MUX_ERR_PROTO if payload_len exceeds MUX_MAX_PAYLOAD. */
int mux_craft_header(uint8_t *dst, size_t cap, uint8_t type, uint16_t flags,
                     uint32_t sid, uint32_t payload_len);

/* Write a full frame (header + payload) into [dst, dst+cap). `payload`
 * may be NULL iff `plen` is 0. Returns total bytes written
 * (MUX_HEADER_SIZE + plen) on success, or a negative code. */
int mux_craft(uint8_t *dst, size_t cap, uint8_t type, uint16_t flags,
              uint32_t sid, const uint8_t *payload, uint32_t plen);

/* ------------------------------------------------------------------ */
/* TLV helpers (control-frame payloads): type:u16 | len:u16 | value    */
/* ------------------------------------------------------------------ */

/* Append one TLV at byte offset `off` within [buf, buf+cap). Returns the
 * new offset (off + 4 + vlen) on success, or MUX_ERR_NOSPACE. `val` may
 * be NULL iff `vlen` is 0. Designed for chaining:
 *     off = mux_tlv_put(buf, cap, off, T, v, n); if (off < 0) ...  */
int mux_tlv_put(uint8_t *buf, size_t cap, size_t off, uint16_t t,
                const void *val, uint16_t vlen);

/* Iterate TLVs in [buf, buf+len). *cursor must start at 0. On each call:
 *   - returns 1 and fills t, val and vlen for the next TLV, advancing *cursor;
 *   - returns 0 when *cursor has reached len (clean end);
 *   - returns MUX_ERR_PROTO if a TLV header or value is truncated.
 * `*val` is a view into `buf`. */
int mux_tlv_next(const uint8_t *buf, size_t len, size_t *cursor,
                 uint16_t *t, const uint8_t **val, uint16_t *vlen);

/* ================================================================== */
/* Session state machine (sans-io)                                    */
/* ================================================================== */
/*
 * A `mux_session` is a pure state machine over one transport byte stream.
 * It owns no sockets and no clock. The host loop drives it:
 *
 *   recv path:   socket -> mux_recv() -> drain mux_next_event()
 *   send path:   mux_open/write/close/... -> mux_send_buf()/advance() -> socket
 *   time path:   mux_on_timer(now_ms) on the returned deadline
 *
 * Lifetime contract for zero-copy views: STREAM_DATA/STREAM_OPENED (meta) and
 * PEER_HELLO (peer_id/auth/nonce) events carry pointers INTO the buffer most
 * recently passed to mux_recv(). They are valid only until the next mux_recv()
 * (or mux_session_free). Drain all events for a recv before issuing the next
 * recv; copy out anything kept.
 */

#define MUX_DEFAULT_INIT_WINDOW    (256u * 1024u)        /* per-stream      */
#define MUX_DEFAULT_SESSION_WINDOW (16u * 1024u * 1024u) /* connection      */
#define MUX_DEFAULT_MAX_STREAMS    65536u
#define MUX_DEFAULT_HEARTBEAT_MS   15000u
/* DATA writes are chunked into frames no larger than this so large writes
 * still interleave fairly with other streams' frames. */
#define MUX_MAX_DATA_FRAME         (64u * 1024u)
/* SYN metadata (PROXY header / TLVs) is bounded independently of the data
 * flow-control windows; a larger SYN payload is rejected as a protocol error. */
#define MUX_MAX_META               8192u
/* Hard ceiling on the internal output buffer (anti-DoS / backpressure). When
 * crossing it the session is failed rather than allocating without bound; a
 * well-behaved host drains via mux_send_buf and gates mux_recv on
 * mux_out_pending long before this. 0 in config selects this default. */
#define MUX_DEFAULT_MAX_OUT_BUFFER (64u * 1024u * 1024u)
/* Soft cap on the event queue: mux_recv stops consuming input once this many
 * events are pending so the host must drain them, bounding queue memory. */
#define MUX_EVENT_QUEUE_SOFT_CAP   4096u

/* Role fixes stream-id parity and who sends HELLO vs HELLO_ACK. It follows
 * the TCP dial direction and is independent of who opens logical streams:
 * the dialer uses odd ids and greets first; the acceptor uses even ids. */
typedef enum {
    MUX_DIALER   = 0,
    MUX_ACCEPTOR = 1
} mux_role;

/* Static per-session configuration. Zeroed fields take the documented
 * default. Pointer fields are copied into the session at creation, so the
 * caller need not keep them alive afterwards. */
typedef struct {
    uint32_t init_window;     /* our per-stream recv window  (0 => default) */
    uint32_t session_window;  /* our connection recv window  (0 => default) */
    uint32_t max_streams;     /* our concurrency cap         (0 => default) */
    uint32_t heartbeat_ms;    /* PING interval; 0 disables keepalive        */
    uint32_t keepalive_timeout_ms; /* dead if no echo within (0 => 3x hb)   */
    uint32_t weight;          /* advertised balancing weight                */
    uint32_t max_out_buffer;  /* output-buffer ceiling (0 => default)       */

    const uint8_t *peer_id;   size_t peer_id_len;   /* opaque identity      */
    const uint8_t *auth;      size_t auth_len;      /* opaque AUTH blob      */
    const uint8_t *nonce;     size_t nonce_len;     /* opaque challenge      */
} mux_config;

typedef struct mux_session mux_session;

/* Event types surfaced by mux_next_event. */
typedef enum {
    MUX_EV_NONE = 0,
    MUX_EV_STREAM_OPENED, /* peer opened a stream (SYN); u.opened carries meta */
    MUX_EV_STREAM_DATA,   /* stream bytes; u.data is a zero-copy recv view     */
    MUX_EV_STREAM_CLOSED, /* peer half-closed (FIN); no more inbound data      */
    MUX_EV_STREAM_RESET,  /* stream aborted (RST); u.reset.code                */
    MUX_EV_WRITABLE,      /* a specific stream's send window reopened; retry it */
    MUX_EV_PEER_HELLO,    /* handshake parameters from peer; u.hello           */
    MUX_EV_CAPACITY,      /* peer weight changed; u.capacity (0 = draining)    */
    MUX_EV_GOAWAY,        /* peer is draining; u.goaway                        */
    MUX_EV_FATAL          /* session is dead; u.fatal.code. Tear down.         */
} mux_event_type;

typedef struct {
    mux_event_type type;
    uint32_t       sid;
    union {
        struct { const uint8_t *meta; size_t meta_len; } opened;
        struct { const uint8_t *data; size_t data_len; } data;
        struct { uint32_t code; } reset;
        struct {
            uint32_t       weight;
            uint32_t       max_streams;
            uint32_t       init_window;
            const uint8_t *peer_id; size_t peer_id_len;
            const uint8_t *auth;    size_t auth_len;
            const uint8_t *nonce;   size_t nonce_len;
        } hello;
        struct { uint32_t weight; } capacity;
        struct { uint32_t reason; uint32_t last_sid; } goaway;
        struct { uint32_t code; } fatal;
    } u;
} mux_event;

/* Create/destroy. Returns NULL on allocation failure or bad config. */
mux_session *mux_session_new(const mux_config *cfg, mux_role role);
void         mux_session_free(mux_session *s);

/* Feed transport bytes. Parses as many whole frames as present, applying
 * state transitions and queueing events. Returns the number of bytes consumed
 * (>= 0; a trailing partial frame, or input beyond the event-queue soft cap,
 * is left unconsumed for the next call) or a negative code. A protocol
 * violation queues MUX_EV_FATAL and returns the bytes consumed up to (not
 * including) the offending frame. The caller MUST retain any unconsumed tail
 * and re-feed it, and SHOULD drain events between calls. */
int64_t mux_recv(mux_session *s, const uint8_t *buf, size_t len);

/* Open a new outbound stream carrying optional metadata (the SYN payload,
 * e.g. PROXY-protocol TLVs). Returns the new stream id (>= 1) or a negative
 * code (MUX_ERR_STATE before handshake, MUX_ERR_NOMEM at the stream cap). */
int64_t mux_open(mux_session *s, const uint8_t *meta, size_t meta_len);

/* Queue up to n bytes of stream data, bounded by the per-stream AND the
 * connection send windows. Returns bytes actually accepted (0..n); 0 means
 * the stream is window-blocked — wait for MUX_EV_WRITABLE. Negative on error
 * (e.g. MUX_ERR_STATE after local FIN, MUX_ERR_NOSTREAM). */
int64_t mux_write(mux_session *s, uint32_t sid, const uint8_t *p, size_t n);

/* Half-close the local send direction (FIN). The stream stays readable
 * until the peer also FINs. Idempotent. */
int mux_close(mux_session *s, uint32_t sid);

/* Abort a stream now (RST). Frees state immediately. */
int mux_reset(mux_session *s, uint32_t sid, uint32_t code);

/* Tell the core the application consumed n received bytes on a stream, so
 * it can credit the peer via WINDOW_UPDATE (batched at the half-window
 * watermark). Drives both per-stream and connection-level flow control. */
int mux_consume(mux_session *s, uint32_t sid, size_t n);

/* Advertise a new balancing weight to the peer (CAPACITY frame). weight 0
 * signals draining. */
int mux_send_capacity(mux_session *s, uint32_t weight);

/* Begin graceful drain: emit GOAWAY(reason) with the highest stream id we
 * have processed. After this, mux_open is refused locally. */
int mux_goaway(mux_session *s, uint32_t reason);

/* Advance time. Sends keepalive PINGs and detects a dead peer (queueing
 * MUX_EV_FATAL). Returns the absolute ms of the next deadline at which the
 * caller should invoke this again, or UINT64_MAX if no timer is armed. */
uint64_t mux_on_timer(mux_session *s, uint64_t now_ms);

/* Pending outbound bytes as a contiguous zero-copy view. Write them to the
 * transport, then call mux_send_advance with however many were accepted.
 * *len is set to the byte count (0 if nothing pending). */
const uint8_t *mux_send_buf(mux_session *s, size_t *len);
void           mux_send_advance(mux_session *s, size_t n);

/* Bytes currently pending in the output buffer. The host uses this to apply
 * transport backpressure: stop calling mux_recv (stop reading the tunnel) while
 * this stays high, so a slow transport cannot make the core buffer without
 * bound. */
size_t         mux_out_pending(mux_session *s);

/* Pop the next queued event into *ev. Returns 1 if one was written, 0 if
 * the queue is empty. */
int mux_next_event(mux_session *s, mux_event *ev);

#ifdef __cplusplus
}
#endif

#endif /* MUX_H */
