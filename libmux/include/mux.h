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
    MUX_TLV_PEER_ID      = 0x0001, /* opaque                                 */
    MUX_TLV_WEIGHT       = 0x0002, /* u32 advertised balancing weight        */
    MUX_TLV_MAX_STREAMS  = 0x0003, /* u32 concurrency cap                    */
    MUX_TLV_AUTH         = 0x0004, /* HMAC(token, session_nonce)             */
    MUX_TLV_INIT_WINDOW  = 0x0005, /* u32 per-stream initial window          */
    MUX_TLV_HEARTBEAT_MS = 0x0006  /* u32                                    */
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
    MUX_ERR_PARAM   = -4  /* invalid argument                               */
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

#ifdef __cplusplus
}
#endif

#endif /* MUX_H */
