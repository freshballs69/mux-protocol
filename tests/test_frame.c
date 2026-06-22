/* Unit tests for the libmux framing codec (milestone 1).
 *
 * No external test framework: a CHECK macro records failures and the
 * process exits non-zero if any fired, which is all CTest needs. */
#include "mux.h"

#include <stdio.h>
#include <string.h>

static int g_fail = 0;

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            fprintf(stderr, "FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
            g_fail++;                                                    \
        }                                                                \
    } while (0)

#define CHECK_EQ(a, b)                                                   \
    do {                                                                 \
        long long _a = (long long)(a), _b = (long long)(b);             \
        if (_a != _b) {                                                  \
            fprintf(stderr, "FAIL %s:%d  %s (%lld) != %s (%lld)\n",      \
                    __FILE__, __LINE__, #a, _a, #b, _b);                 \
            g_fail++;                                                    \
        }                                                                \
    } while (0)

/* ------------------------------------------------------------------ */

static void test_header_roundtrip(void) {
    uint8_t buf[64];
    int n = mux_craft_header(buf, sizeof buf, MUX_T_DATA,
                             MUX_F_SYN | MUX_F_FIN, 0x01020304u, 0);
    CHECK_EQ(n, MUX_HEADER_SIZE);

    mux_frame_t f;
    size_t consumed = 0;
    int r = mux_parse(buf, (size_t)n, &f, &consumed);
    CHECK_EQ(r, MUX_OK);
    CHECK_EQ(consumed, MUX_HEADER_SIZE);
    CHECK_EQ(f.ver, MUX_VERSION);
    CHECK_EQ(f.type, MUX_T_DATA);
    CHECK_EQ(f.flags, MUX_F_SYN | MUX_F_FIN);
    CHECK_EQ(f.sid, 0x01020304u);
    CHECK_EQ(f.len, 0);
    CHECK(f.payload == NULL);
}

/* Byte-exact wire layout: catches endian/offset regressions. */
static void test_golden_bytes(void) {
    uint8_t buf[64];
    const uint8_t payload[] = {0xde, 0xad, 0xbe, 0xef};
    int n = mux_craft(buf, sizeof buf, MUX_T_WINDOW_UPDATE,
                      MUX_F_ACK, 0xa1b2c3d4u, payload, sizeof payload);
    CHECK_EQ(n, MUX_HEADER_SIZE + sizeof payload);

    const uint8_t want[] = {
        0x01,                   /* ver                */
        0x01,                   /* type WINDOW_UPDATE  */
        0x00, 0x02,             /* flags ACK           */
        0xa1, 0xb2, 0xc3, 0xd4, /* sid (big-endian)    */
        0x00, 0x00, 0x00, 0x04, /* length (big-endian) */
        0xde, 0xad, 0xbe, 0xef, /* payload             */
    };
    CHECK_EQ(n, (int)sizeof want);
    CHECK(memcmp(buf, want, sizeof want) == 0);
}

static void test_payload_roundtrip(void) {
    uint8_t buf[64];
    const uint8_t payload[] = "hello-mux";
    uint32_t plen = (uint32_t)strlen((const char *)payload);
    int n = mux_craft(buf, sizeof buf, MUX_T_DATA, 0, 7, payload, plen);
    CHECK_EQ(n, MUX_HEADER_SIZE + plen);

    mux_frame_t f;
    size_t consumed = 0;
    CHECK_EQ(mux_parse(buf, (size_t)n, &f, &consumed), MUX_OK);
    CHECK_EQ(consumed, (size_t)n);
    CHECK_EQ(f.len, plen);
    CHECK(f.payload != NULL);
    CHECK(memcmp(f.payload, payload, plen) == 0);
}

/* Partial feed: short header and short payload both return SHORT, not PROTO. */
static void test_partial_feed(void) {
    uint8_t buf[64];
    const uint8_t payload[] = {1, 2, 3, 4, 5, 6, 7, 8};
    int n = mux_craft(buf, sizeof buf, MUX_T_DATA, 0, 9, payload, sizeof payload);
    CHECK(n > 0);

    mux_frame_t f;
    size_t consumed = 12345; /* must stay untouched on SHORT */

    /* every prefix shorter than the full header */
    for (size_t k = 0; k < MUX_HEADER_SIZE; k++) {
        CHECK_EQ(mux_parse(buf, k, &f, &consumed), MUX_ERR_SHORT);
    }
    /* header present, payload incomplete */
    for (size_t k = MUX_HEADER_SIZE; k < (size_t)n; k++) {
        CHECK_EQ(mux_parse(buf, k, &f, &consumed), MUX_ERR_SHORT);
    }
    CHECK_EQ(consumed, 12345); /* never written on SHORT */

    /* exactly complete now parses */
    CHECK_EQ(mux_parse(buf, (size_t)n, &f, &consumed), MUX_OK);
    CHECK_EQ(consumed, (size_t)n);
}

static void test_bad_version(void) {
    uint8_t buf[64];
    mux_craft_header(buf, sizeof buf, MUX_T_DATA, 0, 1, 0);
    buf[0] = 0x02; /* wrong version */
    mux_frame_t f;
    size_t consumed = 0;
    CHECK_EQ(mux_parse(buf, MUX_HEADER_SIZE, &f, &consumed), MUX_ERR_PROTO);
}

/* A length field above the cap is rejected even with no payload bytes
 * present — we must not wait forever for 4 GiB that will never come. */
static void test_oversized_length(void) {
    uint8_t hdr[MUX_HEADER_SIZE];
    mux_craft_header(hdr, sizeof hdr, MUX_T_DATA, 0, 1, 0);
    /* overwrite length with MUX_MAX_PAYLOAD + 1, big-endian */
    uint32_t big = MUX_MAX_PAYLOAD + 1;
    hdr[8]  = (uint8_t)(big >> 24);
    hdr[9]  = (uint8_t)(big >> 16);
    hdr[10] = (uint8_t)(big >> 8);
    hdr[11] = (uint8_t)(big);

    mux_frame_t f;
    size_t consumed = 0;
    CHECK_EQ(mux_parse(hdr, sizeof hdr, &f, &consumed), MUX_ERR_PROTO);

    /* exactly at the cap is allowed at the framing level */
    uint32_t ok = MUX_MAX_PAYLOAD;
    hdr[8]  = (uint8_t)(ok >> 24);
    hdr[9]  = (uint8_t)(ok >> 16);
    hdr[10] = (uint8_t)(ok >> 8);
    hdr[11] = (uint8_t)(ok);
    /* header valid, payload absent -> SHORT (not PROTO) */
    CHECK_EQ(mux_parse(hdr, sizeof hdr, &f, &consumed), MUX_ERR_SHORT);
}

/* Drain loop: several frames concatenated in one buffer parse one by one. */
static void test_drain_loop(void) {
    uint8_t buf[256];
    size_t off = 0;
    const uint8_t p0[] = {0xaa};
    const uint8_t p1[] = {0xbb, 0xcc};
    /* frame 0: DATA|SYN sid 1, 1 byte */
    int n0 = mux_craft(buf + off, sizeof buf - off, MUX_T_DATA, MUX_F_SYN, 1, p0, sizeof p0);
    off += (size_t)n0;
    /* frame 1: PING sid 0, 0 bytes */
    int n1 = mux_craft(buf + off, sizeof buf - off, MUX_T_PING, 0, 0, NULL, 0);
    off += (size_t)n1;
    /* frame 2: DATA|FIN sid 1, 2 bytes */
    int n2 = mux_craft(buf + off, sizeof buf - off, MUX_T_DATA, MUX_F_FIN, 1, p1, sizeof p1);
    off += (size_t)n2;

    size_t cursor = 0;
    int count = 0;
    for (;;) {
        mux_frame_t f;
        size_t consumed = 0;
        int r = mux_parse(buf + cursor, off - cursor, &f, &consumed);
        if (r == MUX_ERR_SHORT) break;
        CHECK_EQ(r, MUX_OK);
        cursor += consumed;
        if (count == 0) { CHECK_EQ(f.type, MUX_T_DATA); CHECK_EQ(f.flags, MUX_F_SYN); CHECK_EQ(f.len, 1); }
        if (count == 1) { CHECK_EQ(f.type, MUX_T_PING); CHECK_EQ(f.len, 0); }
        if (count == 2) { CHECK_EQ(f.type, MUX_T_DATA); CHECK_EQ(f.flags, MUX_F_FIN); CHECK_EQ(f.len, 2); }
        count++;
    }
    CHECK_EQ(count, 3);
    CHECK_EQ(cursor, off); /* consumed exactly, no trailing bytes */
}

static void test_craft_nospace(void) {
    uint8_t small[8];
    CHECK_EQ(mux_craft_header(small, sizeof small, MUX_T_DATA, 0, 1, 0), MUX_ERR_NOSPACE);
    uint8_t buf[16];
    const uint8_t payload[] = {1, 2, 3, 4, 5, 6, 7, 8};
    /* needs 12 + 8 = 20, only 16 available */
    CHECK_EQ(mux_craft(buf, sizeof buf, MUX_T_DATA, 0, 1, payload, sizeof payload), MUX_ERR_NOSPACE);
}

/* ------------------------------------------------------------------ */
/* TLV                                                                */

static void test_tlv_roundtrip(void) {
    uint8_t buf[128];
    size_t off = 0;
    uint32_t weight = 16;
    uint8_t wbe[4] = {(uint8_t)(weight>>24),(uint8_t)(weight>>16),(uint8_t)(weight>>8),(uint8_t)weight};
    const char *peer = "edge-A";

    int r;
    r = mux_tlv_put(buf, sizeof buf, off, MUX_TLV_PEER_ID, peer, (uint16_t)strlen(peer));
    CHECK(r > 0); off = (size_t)r;
    r = mux_tlv_put(buf, sizeof buf, off, MUX_TLV_WEIGHT, wbe, sizeof wbe);
    CHECK(r > 0); off = (size_t)r;
    r = mux_tlv_put(buf, sizeof buf, off, MUX_TLV_MAX_STREAMS, NULL, 0); /* empty value */
    CHECK(r > 0); off = (size_t)r;

    size_t cursor = 0;
    uint16_t t, vlen;
    const uint8_t *val;
    int got;

    got = mux_tlv_next(buf, off, &cursor, &t, &val, &vlen);
    CHECK_EQ(got, 1);
    CHECK_EQ(t, MUX_TLV_PEER_ID);
    CHECK_EQ(vlen, strlen(peer));
    CHECK(memcmp(val, peer, vlen) == 0);

    got = mux_tlv_next(buf, off, &cursor, &t, &val, &vlen);
    CHECK_EQ(got, 1);
    CHECK_EQ(t, MUX_TLV_WEIGHT);
    CHECK_EQ(vlen, 4);
    CHECK(memcmp(val, wbe, 4) == 0);

    got = mux_tlv_next(buf, off, &cursor, &t, &val, &vlen);
    CHECK_EQ(got, 1);
    CHECK_EQ(t, MUX_TLV_MAX_STREAMS);
    CHECK_EQ(vlen, 0);
    CHECK(val == NULL);

    got = mux_tlv_next(buf, off, &cursor, &t, &val, &vlen);
    CHECK_EQ(got, 0); /* clean end */
    CHECK_EQ(cursor, off);
}

static void test_tlv_nospace(void) {
    uint8_t buf[4];
    /* needs 4 + 4 = 8 bytes */
    CHECK_EQ(mux_tlv_put(buf, sizeof buf, 0, MUX_TLV_WEIGHT, "abcd", 4), MUX_ERR_NOSPACE);
}

static void test_tlv_truncated(void) {
    uint8_t buf[16];
    size_t off = (size_t)mux_tlv_put(buf, sizeof buf, 0, MUX_TLV_WEIGHT, "abcd", 4);
    /* Claim len 4 but only hand the iterator 6 bytes (header + 2 of value). */
    size_t cursor = 0;
    uint16_t t, vlen; const uint8_t *val;
    CHECK_EQ(mux_tlv_next(buf, 6, &cursor, &t, &val, &vlen), MUX_ERR_PROTO);

    /* Truncated header (only 3 bytes available). */
    cursor = 0;
    CHECK_EQ(mux_tlv_next(buf, 3, &cursor, &t, &val, &vlen), MUX_ERR_PROTO);
    (void)off;
}

/* ------------------------------------------------------------------ */

int main(void) {
    test_header_roundtrip();
    test_golden_bytes();
    test_payload_roundtrip();
    test_partial_feed();
    test_bad_version();
    test_oversized_length();
    test_drain_loop();
    test_craft_nospace();
    test_tlv_roundtrip();
    test_tlv_nospace();
    test_tlv_truncated();

    if (g_fail) {
        fprintf(stderr, "\n%d check(s) failed\n", g_fail);
        return 1;
    }
    printf("all framing-codec tests passed\n");
    return 0;
}
