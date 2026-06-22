/* libmux framing codec — see include/mux.h for the contract.
 *
 * Wire header (12 bytes, big-endian):
 *
 *   0       1       2       3
 *   +-------+-------+-------+-------+
 *   |  Ver  | Type  |    Flags      |
 *   +-------+-------+-------+-------+
 *   |          Stream ID            |
 *   +-------------------------------+
 *   |           Length              |
 *   +-------------------------------+
 *   |        Payload (Length)       |
 *   +-------------------------------+
 *
 * Everything here is stateless and allocation-free.
 */
#include "mux.h"

#include <string.h>

/* ---- big-endian load/store, strictly byte-wise (alignment-safe) ---- */

static inline void be_put16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v);
}

static inline void be_put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

static inline uint16_t be_get16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline uint32_t be_get32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | ((uint32_t)p[3]);
}

/* ------------------------------------------------------------------ */
/* Framing                                                            */
/* ------------------------------------------------------------------ */

int mux_parse(const uint8_t *buf, size_t len, mux_frame_t *out, size_t *consumed) {
    if (!buf || !out || !consumed)
        return MUX_ERR_PARAM;

    /* Not even a full header yet — ask for more. */
    if (len < MUX_HEADER_SIZE)
        return MUX_ERR_SHORT;

    uint8_t  ver   = buf[0];
    uint8_t  type  = buf[1];
    uint16_t flags = be_get16(buf + 2);
    uint32_t sid   = be_get32(buf + 4);
    uint32_t plen  = be_get32(buf + 8);

    /* Version and length are framing-level invariants: a mismatch means
     * the stream is unparseable, so this is fatal, not "need more". */
    if (ver != MUX_VERSION)
        return MUX_ERR_PROTO;
    if (plen > MUX_MAX_PAYLOAD)
        return MUX_ERR_PROTO;

    /* Header is valid but the payload hasn't fully arrived. The cap above
     * bounds how much we will ever wait for, so this can't be abused to
     * pin unbounded buffering. (size_t add can't overflow: plen capped at
     * 16 MiB, MUX_HEADER_SIZE is 12.) */
    size_t need = (size_t)MUX_HEADER_SIZE + (size_t)plen;
    if (len < need)
        return MUX_ERR_SHORT;

    out->ver     = ver;
    out->type    = type;
    out->flags   = flags;
    out->sid     = sid;
    out->len     = plen;
    out->payload = (plen > 0) ? (buf + MUX_HEADER_SIZE) : NULL;

    *consumed = need;
    return MUX_OK;
}

int mux_craft_header(uint8_t *dst, size_t cap, uint8_t type, uint16_t flags,
                     uint32_t sid, uint32_t payload_len) {
    if (!dst)
        return MUX_ERR_PARAM;
    if (payload_len > MUX_MAX_PAYLOAD)
        return MUX_ERR_PROTO;
    if (cap < MUX_HEADER_SIZE)
        return MUX_ERR_NOSPACE;

    dst[0] = MUX_VERSION;
    dst[1] = type;
    be_put16(dst + 2, flags);
    be_put32(dst + 4, sid);
    be_put32(dst + 8, payload_len);

    return (int)MUX_HEADER_SIZE;
}

int mux_craft(uint8_t *dst, size_t cap, uint8_t type, uint16_t flags,
              uint32_t sid, const uint8_t *payload, uint32_t plen) {
    if (!dst || (plen > 0 && !payload))
        return MUX_ERR_PARAM;
    if (plen > MUX_MAX_PAYLOAD)
        return MUX_ERR_PROTO;

    size_t total = (size_t)MUX_HEADER_SIZE + (size_t)plen;
    if (cap < total)
        return MUX_ERR_NOSPACE;

    /* header is already validated against cap >= total >= HEADER_SIZE */
    (void)mux_craft_header(dst, cap, type, flags, sid, plen);
    if (plen > 0)
        memcpy(dst + MUX_HEADER_SIZE, payload, plen);

    return (int)total;
}

/* ------------------------------------------------------------------ */
/* TLV                                                                */
/* ------------------------------------------------------------------ */

int mux_tlv_put(uint8_t *buf, size_t cap, size_t off, uint16_t t,
                const void *val, uint16_t vlen) {
    if (!buf || (vlen > 0 && !val))
        return MUX_ERR_PARAM;

    /* off + 4 + vlen, guarding against size_t wraparound on `off`. */
    if (off > cap)
        return MUX_ERR_NOSPACE;
    size_t avail = cap - off;
    if (avail < (size_t)4 + (size_t)vlen)
        return MUX_ERR_NOSPACE;

    uint8_t *p = buf + off;
    be_put16(p,     t);
    be_put16(p + 2, vlen);
    if (vlen > 0)
        memcpy(p + 4, val, vlen);

    return (int)(off + 4 + vlen);
}

int mux_tlv_next(const uint8_t *buf, size_t len, size_t *cursor,
                 uint16_t *t, const uint8_t **val, uint16_t *vlen) {
    if (!buf || !cursor || !t || !val || !vlen)
        return MUX_ERR_PARAM;

    size_t c = *cursor;
    if (c == len)
        return 0;               /* clean end */
    if (c > len || len - c < 4)
        return MUX_ERR_PROTO;   /* truncated header */

    uint16_t ty = be_get16(buf + c);
    uint16_t vl = be_get16(buf + c + 2);
    if (len - c - 4 < vl)
        return MUX_ERR_PROTO;   /* truncated value */

    *t    = ty;
    *vlen = vl;
    *val  = (vl > 0) ? (buf + c + 4) : NULL;
    *cursor = c + 4 + vl;
    return 1;
}
